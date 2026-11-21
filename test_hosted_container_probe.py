"""Offline tests only. Never launch real Chromium, start a listener or connect DB."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import asyncio
from types import SimpleNamespace
from unittest.mock import patch,MagicMock,AsyncMock

from hosted.deploy.probe.main import run,main
from hosted.deploy.probe.common import offline,ProbeFailure
from hosted.deploy.prepare_context import prepare,ROOT,MANIFEST


class ContainerProbeTests(unittest.TestCase):
    def test_offline_harness_checks_real_gateway_and_fake_browsers(self):
        with patch.dict(os.environ,{},clear=True),patch('catknows.hosted_browser_service.LoginBrowser.start')as start:
            result=run('all')
        self.assertEqual(result['result'],'PASS')
        self.assertFalse(result['real_chromium_checked']);self.assertFalse(result['container_runtime_checked'])
        self.assertEqual(len(result['checks']),20);start.assert_not_called()

    def test_environment_with_credentials_or_profiles_refused_without_reading_values(self):
        for name in ('SUPABASE_SERVICE_ROLE_KEY','SUPABASE_URL','HOSTED_DB_PASSWORD','PGPASSWORD',
                     'CATKNOWS_PROFILE_DIR','HOSTED_OWNER_PROFILE_DIR','BROWSER_SERVICE_SECRET','SKOOL_SESSION_ENCRYPTION_KEY'):
            with patch.dict(os.environ,{name:'synthetic-must-not-be-printed'},clear=True):
                out=io.StringIO()
                with contextlib.redirect_stdout(out):status=main(['--mode','all'])
                self.assertEqual(status,1)
                self.assertEqual(json.loads(out.getvalue()),{'result':'FAIL','code':'E_PROBE_ENV'})
                self.assertNotIn('synthetic-must-not-be-printed',out.getvalue())

    def test_live_browser_cannot_be_requested_from_local_mode(self):
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaisesRegex(ProbeFailure,'E_PROBE_LIVE_REQUIRES_CONTAINER'):run('browser',live_browser=True)
        with patch.dict(os.environ,{},clear=True),patch('os.geteuid',return_value=0):
            with self.assertRaisesRegex(ProbeFailure,'E_PROBE_CONTAINER_USER'):run('browser',True,True)

    def test_offline_mode_prevents_network_connections(self):
        import socket
        with offline():
            with self.assertRaisesRegex(ProbeFailure,'E_NETWORK_FORBIDDEN'):socket.getaddrinfo('example.test',443)
            with self.assertRaisesRegex(ProbeFailure,'E_NETWORK_FORBIDDEN'):socket.create_connection(('127.0.0.1',443))
            with socket.socket()as client:
                with self.assertRaisesRegex(ProbeFailure,'E_NETWORK_FORBIDDEN'):client.connect(('127.0.0.1',443))

    def test_failure_messages_are_fixed_and_listener_not_started(self):
        with patch('hosted.deploy.probe.main.run',side_effect=RuntimeError('synthetic private detail')), \
             patch('hosted.deploy.probe.main.serve')as serve:
            out=io.StringIO()
            with contextlib.redirect_stdout(out):status=main(['--mode','gateway','--serve'])
            self.assertEqual(status,1);serve.assert_not_called()
            self.assertEqual(json.loads(out.getvalue()),{'result':'FAIL','code':'E_PROBE_FAILED'})

    def test_probe_images_have_separate_allowlisted_contexts_and_no_runtime_credentials(self):
        manifest=json.loads(MANIFEST.read_text())
        for service in ('gateway-probe','browser-probe'):
            with tempfile.TemporaryDirectory()as folder:
                output=Path(folder)/'context';prepare(service,output)
                files={str(p.relative_to(output))for p in output.rglob('*')if p.is_file()}
                self.assertEqual(files,set(manifest[service])|{'.dockerignore'})
                docker=(output/f'hosted/deploy/{service}.Dockerfile').read_text()
                self.assertIn('hosted_probe.main',docker);self.assertIn('--private-service',docker)
                self.assertIn('--container',docker);self.assertIn('USER 10001:10001',docker)
                self.assertNotIn('COPY . ',docker);self.assertNotIn('--no-sandbox',docker)
                self.assertNotIn('ENV BROWSER_SERVICE_SECRET',docker)
                self.assertFalse(any(name.startswith(('local-e2e/','remote/','hosted/macos/','hosted/migrations/'))for name in files))
        for service in ('gateway','browser'):
            self.assertFalse(any('/probe/'in path for path in manifest[service]))

    def test_production_entry_points_do_not_import_probe(self):
        for name in ('catknows/hosted_server.py','catknows/hosted_browser_service.py'):
            self.assertNotIn('hosted_probe',(ROOT/name).read_text())

    def test_proc_snapshot_reports_read_failures_as_counts_only(self):
        from hosted.deploy.probe.browser import process_snapshot
        roots=[]
        for name,value in [('10','PPid:\t0\n'),('11',PermissionError('synthetic-sensitive')),
                           ('12',FileNotFoundError('synthetic-sensitive')),('13','PPid:\tinvalid\n')]:
            root=MagicMock();root.name=name;reader=root.__truediv__.return_value.read_text
            if isinstance(value,Exception):reader.side_effect=value
            else:reader.return_value=value
            roots.append(root)
        with patch('hosted.deploy.probe.browser.Path')as path,patch('os.getpid',return_value=10):
            path.return_value.iterdir.return_value=iter(roots)
            records,counts=process_snapshot()
        self.assertEqual(set(records),{10})
        for key in ('status_readable','status_denied','status_disappeared','status_invalid','self_status_present','parentless_statuses'):
            self.assertEqual(counts[key],1)
        self.assertEqual(counts['proc_entries'],4)
        self.assertNotIn('synthetic-sensitive',json.dumps(counts))

    def test_diagnostic_output_filters_sensitive_keys_values_and_still_exits(self):
        error=ProbeFailure('E_SANDBOX_UNVERIFIED',{'scan_attempts':4,'descendants':2,'cookies':'synthetic-sensitive',
            'proc_entries':True,'renderer_matches':-1,'pid':20})
        error.counts.update(cmdline_readable='synthetic-private-argument',credentials='synthetic-sensitive')
        with patch('hosted.deploy.probe.main.run',side_effect=error),patch('hosted.deploy.probe.main.serve')as serve:
            out=io.StringIO()
            with contextlib.redirect_stdout(out):status=main(['--mode','browser','--serve'])
        self.assertEqual(status,1);serve.assert_not_called()
        self.assertEqual(json.loads(out.getvalue()),dict(result='FAIL',code='E_SANDBOX_UNVERIFIED',
            sandbox_counts=dict(scan_attempts=4,descendants=2)))

    def fixture(self):
        def evidence(pid,ids,namespace,renderer=False):
            return dict(pid=pid,nspid=ids,uid=(10001,)*4,start=1000+pid,exe=(1,2),
                namespaces=dict(pid=(1,namespace),net=(2,namespace),user=(3,1)),
                NoNewPrivs=int(renderer),Seccomp=2,CapEff=0,Seccomp_filters=2 if renderer else 1)
        values={100:evidence(100,(100,10),1),110:evidence(110,(110,11),1),
                120:evidence(120,(120,12,1),2,True),210:evidence(210,(210,21),1),
                220:evidence(220,(220,22,1),3,True)}
        records={pid:(100 if pid in (110,210)else 0,{'NSpid':' '.join(map(str,v['nspid']))},None)
                 for pid,v in values.items()}
        inventories=[(11,(12,)),(21,(22,))]
        return values,records,inventories

    @contextlib.contextmanager
    def kernel(self,values=None,records=None):
        from hosted.deploy.probe import browser
        default_values,default_records,_=self.fixture()
        values=default_values if values is None else values
        records=default_records if records is None else records
        def read(pid,*,browser_expected=None,counts=None):
            value=values[pid].copy()
            if browser_expected is not None:
                self.assertEqual(value,browser_expected)
                value['arguments']=(b'/opt/playwright/chrome',b'synthetic-private-argument')
            return value
        with patch.object(browser,'process_evidence',side_effect=read), \
             patch.object(browser,'trusted_executable',return_value=(1,2)), \
             patch.object(browser,'process_snapshot',return_value=(records,{})), \
             patch.object(browser.os,'readlink',return_value='100'), \
             patch.object(browser.os,'getpid',return_value=10),patch.object(browser.os,'geteuid',return_value=10001):
            yield browser

    def test_cdp_maps_every_renderer_without_argv_or_renderer_ancestry(self):
        _,_,inventories=self.fixture();counts={}
        with self.kernel()as browser:evidence,observed=browser.kernel_verification(inventories,self.fixture()[1],counts)
        self.assertEqual(set(evidence),{100,110,120,210,220})
        self.assertEqual(set(observed),{110,120,210,220})
        self.assertEqual(counts['renderer_evidence_confirmed'],2)
        self.assertEqual(counts['cdp_renderer_descendants'],0)
        self.assertEqual(counts['extra_seccomp_filter_confirmed'],2)
        self.assertEqual(counts['namespace_confirmed'],2)
        self.assertTrue(all(type(value)is int for value in counts.values()))

    def test_all_renderers_must_meet_kernel_restrictions(self):
        cases=[('NoNewPrivs',0,'E_SANDBOX_PRIVILEGES'),('Seccomp',0,'E_SANDBOX_SECCOMP'),
               ('CapEff',1,'E_SANDBOX_CAPABILITIES'),('Seccomp_filters',1,'E_SANDBOX_INHERITED_SECCOMP'),
               ('Seccomp_filters',0,'E_SANDBOX_INHERITED_SECCOMP')]
        for field,value,code in cases:
            values,records,inventory=self.fixture();values[220][field]=value
            with self.subTest(field=field,value=value),self.kernel(values)as browser, self.assertRaisesRegex(ProbeFailure,code):
                browser.kernel_verification(inventory,records,{})

    def test_renderer_identity_and_namespace_fail_closed(self):
        for change,code in [('exe','E_SANDBOX_IDENTITY'),('uid','E_SANDBOX_IDENTITY'),
                            ('pid','E_SANDBOX_NAMESPACES'),('net','E_SANDBOX_NAMESPACES'),
                            ('depth','E_SANDBOX_NAMESPACES')]:
            values,records,inventory=self.fixture()
            if change in ('pid','net'):values[120]['namespaces'][change]=values[110]['namespaces'][change]
            elif change=='depth':values[120]['nspid']=(120,12)
            else:values[120][change]=(99,99)
            with self.subTest(change=change),self.kernel(values)as browser,self.assertRaisesRegex(ProbeFailure,code):
                browser.kernel_verification(inventory,records,{})

    def test_browser_must_be_owned_and_in_launcher_namespace(self):
        for change in ('parent','namespace','depth'):
            values,records,inventory=self.fixture()
            if change=='parent':records[110]=(0,records[110][1],None)
            elif change=='namespace':values[110]['namespaces']['pid']=(99,99)
            else:values[110]['nspid']=(110,11,1)
            with self.subTest(change=change),self.kernel(values,records)as browser,self.assertRaisesRegex(ProbeFailure,'E_SANDBOX_IDENTITY'):
                browser.kernel_verification(inventory,records,{})

    def test_missing_or_ambiguous_namespace_mapping_is_not_accepted(self):
        for ambiguous in (False,True):
            _,records,inventory=self.fixture()
            if ambiguous:records[121]=(0,{'NSpid':'121 12 2'},None)
            else:del records[120]
            with self.subTest(ambiguous=ambiguous),self.kernel(records=records)as browser, self.assertRaisesRegex(ProbeFailure,'E_SANDBOX_UNVERIFIED'):
                browser.kernel_verification(inventory,records,{})

    def instance(self,rows=None,error=None):
        rows=rows if rows is not None else [{'type':'browser','id':11},{'type':'renderer','id':12}]
        async def send(method):
            if method=='Browser.getBrowserCommandLine':
                raise RuntimeError('Command line not returned because --enable-automation not set.')
            if error:raise error
            self.assertEqual(method,'SystemInfo.getProcessInfo')
            return {'processInfo':rows}
        session=SimpleNamespace(send=AsyncMock(side_effect=send),detach=AsyncMock())
        return SimpleNamespace(browser=SimpleNamespace(new_browser_cdp_session=AsyncMock(return_value=session))),session

    def test_cdp_inventory_reads_only_process_roles_without_logging_them(self):
        from hosted.deploy.probe.browser import cdp_inventory
        instance,session=self.instance();counts={}
        result=asyncio.run(cdp_inventory([instance],counts))
        self.assertEqual(result[0][:2],(11,(12,)))
        self.assertEqual(counts,dict(cdp_queries_ok=1,cdp_renderer_ids=1))
        self.assertEqual([call.args[0]for call in session.send.await_args_list],
                         ['SystemInfo.getProcessInfo'])
        session.detach.assert_awaited_once();self.assertNotIn('synthetic-private-argument',json.dumps(counts))

    def test_cdp_malformed_duplicates_cross_browser_and_failures_are_denied(self):
        from hosted.deploy.probe.browser import cdp_inventory
        cases=[None,[],[{'type':'renderer','id':12}],
               [{'type':'browser','id':True},{'type':'renderer','id':12}],
               [{'type':'browser','id':11},{'type':'renderer','id':12},{'type':'renderer','id':12}],
               [{'type':'browser','id':11}]*4097]
        for rows in cases:
            instance,_=self.instance(error=RuntimeError('synthetic-sensitive'))if rows is None else self.instance(rows=rows)
            with self.subTest(rows_type=type(rows).__name__),self.assertRaises(ProbeFailure):asyncio.run(cdp_inventory([instance],{}))
        instance,_=self.instance()
        with self.assertRaisesRegex(ProbeFailure,'E_SANDBOX_CDP_PROCESS_INVALID'):asyncio.run(cdp_inventory([instance,instance],{}))

    @contextlib.contextmanager
    def proc_browser(self,arguments=b'/opt/playwright/chrome\0synthetic-private-argument\0'):
        from hosted.deploy.probe.browser import process_evidence
        with tempfile.TemporaryDirectory()as folder:
            root=Path(folder)/'120';(root/'ns').mkdir(parents=True)
            executable=Path(folder)/'synthetic-chrome';executable.write_bytes(b'synthetic')
            (root/'exe').symlink_to(executable)
            for name in ('pid','net','user'):(root/'ns'/name).write_text('synthetic')
            (root/'stat').write_text('120 (name) '+' '.join(['S']+['0']*18+['123']))
            (root/'status').write_text('Pid: 120\nNSpid: 120 12\nUid: 10001 10001 10001 10001\nNoNewPrivs: 0\nSeccomp: 2\nCapEff: 0\nSeccomp_filters: 1\n')
            (root/'cmdline').write_bytes(arguments)
            expected=process_evidence(120,Path(folder))
            with patch('hosted.deploy.probe.browser.trusted_executable',return_value=expected['exe'])as trusted:
                yield Path(folder),expected,trusted

    def test_sandbox_weakening_arguments_are_refused_without_launching(self):
        from hosted.deploy.probe.browser import process_evidence,DISABLED_SANDBOX_FLAGS
        for flag in DISABLED_SANDBOX_FLAGS:
            with self.subTest(flag=flag),self.proc_browser(b'/opt/playwright/chrome\0'+flag.encode()+b'=true\0')as(proc,expected,_):
                counts={}
                with self.assertRaisesRegex(ProbeFailure,'E_SANDBOX_DISABLED'):
                    process_evidence(120,proc,browser_expected=expected,counts=counts)
                self.assertEqual(counts,dict(cmdline_readable=1,sandbox_disabled=1))

    def test_refused_browser_command_line_does_not_block_full_verification(self):
        from hosted.deploy.probe.browser import verify_sandbox
        first,session=self.instance()
        second,_=self.instance(rows=[{'type':'browser','id':21},{'type':'renderer','id':22}])
        with self.assertRaisesRegex(RuntimeError,'enable-automation'):
            asyncio.run(session.send('Browser.getBrowserCommandLine'))
        session.send.reset_mock()
        with self.kernel():observed,counts=asyncio.run(verify_sandbox([first,second]))
        self.assertEqual(set(observed),{110,120,210,220})
        self.assertEqual(counts['renderer_evidence_confirmed'],2)
        self.assertEqual([call.args[0]for call in session.send.await_args_list],['SystemInfo.getProcessInfo']*2)
        self.assertNotIn('synthetic-private-argument',json.dumps(counts))

    def test_cdp_session_query_and_response_failures_have_distinct_categories(self):
        from hosted.deploy.probe.browser import cdp_inventory
        for stage,code,counter in (
                ('session','E_SANDBOX_CDP_SESSION','cdp_session_failed'),
                ('query','E_SANDBOX_CDP_PROCESS_QUERY','cdp_process_query_failed'),
                ('response','E_SANDBOX_CDP_PROCESS_INVALID','cdp_process_invalid')):
            instance,session=self.instance();counts={}
            if stage=='session':instance.browser.new_browser_cdp_session.side_effect=RuntimeError('synthetic-sensitive')
            elif stage=='query':session.send.side_effect=RuntimeError('synthetic-sensitive')
            else:session.send=AsyncMock(return_value={'processInfo':'synthetic-sensitive'})
            with self.subTest(stage=stage),self.assertRaisesRegex(ProbeFailure,code):
                asyncio.run(cdp_inventory([instance],counts))
            self.assertEqual(counts[counter],1);self.assertEqual(counts['cdp_queries_failed'],1)
            self.assertNotIn('synthetic-sensitive',json.dumps(counts))

    def test_browser_command_line_is_bounded_pinned_and_not_returned_in_counts(self):
        from hosted.deploy.probe.browser import process_evidence
        with self.proc_browser()as(proc,expected,trusted):
            real_open=os.open;opened=[]
            def read(path,flags,**kwargs):
                result=real_open(path,flags,**kwargs);opened.append((path,flags,kwargs.get('dir_fd'),result));return result
            counts={}
            with patch('os.open',side_effect=read):
                result=process_evidence(120,proc,browser_expected=expected,counts=counts)
            directory_fd=next(item[3]for item in opened if item[1]&os.O_DIRECTORY)
            command=next(item for item in opened if item[0]=='cmdline')
            self.assertEqual(command[2],directory_fd);self.assertTrue(command[1]&os.O_NOFOLLOW)
            self.assertEqual(result['arguments'],(b'/opt/playwright/chrome',b'synthetic-private-argument'))
            self.assertEqual(counts,dict(cmdline_readable=1,sandbox_disabled=0))
            trusted.assert_called_once_with(str(proc/'synthetic-chrome'))
            self.assertNotIn('synthetic-private-argument',json.dumps(counts))
            with self.assertRaises(OSError):os.fstat(directory_fd)

    def test_browser_identity_must_be_verified_before_command_line_read(self):
        from hosted.deploy.probe.browser import process_evidence
        for changed in ('identity','executable'):
            with self.subTest(changed=changed),self.proc_browser()as(proc,expected,trusted):
                if changed=='identity':expected={**expected,'start':999}
                else:trusted.return_value=(99,99)
                real_open=os.open;opened=[]
                def read(path,flags,**kwargs):opened.append(path);return real_open(path,flags,**kwargs)
                with patch('os.open',side_effect=read),self.assertRaisesRegex(ProbeFailure,'E_SANDBOX_IDENTITY'):
                    process_evidence(120,proc,browser_expected=expected)
                self.assertNotIn('cmdline',opened)

    def test_missing_denied_and_malformed_browser_command_lines_fail_closed(self):
        from hosted.deploy.probe.browser import process_evidence
        for error,code,counter in (
                (PermissionError('synthetic-sensitive'),'E_SANDBOX_CMDLINE_DENIED','cmdline_denied'),
                (FileNotFoundError('synthetic-sensitive'),'E_SANDBOX_CMDLINE_UNAVAILABLE','cmdline_disappeared'),
                (OSError('synthetic-sensitive'),'E_SANDBOX_CMDLINE_READ','cmdline_read_failed')):
            with self.subTest(code=code),self.proc_browser()as(proc,expected,_):
                real_open=os.open;counts={}
                def read(path,flags,**kwargs):
                    if path=='cmdline':raise error
                    return real_open(path,flags,**kwargs)
                with patch('os.open',side_effect=read),self.assertRaisesRegex(ProbeFailure,code)as caught:
                    process_evidence(120,proc,browser_expected=expected,counts=counts)
                self.assertEqual(counts[counter],1);self.assertNotIn('synthetic-sensitive',str(caught.exception))
        for raw in (b'',b'unterminated',b'\0',b'x\0'*4097,b'x'*65536+b'\0'):
            with self.subTest(size=len(raw)),self.proc_browser(raw)as(proc,expected,_):
                counts={}
                with self.assertRaisesRegex(ProbeFailure,'E_SANDBOX_CMDLINE_INVALID'):
                    process_evidence(120,proc,browser_expected=expected,counts=counts)
                self.assertEqual(counts,dict(cmdline_invalid=1))

    def test_command_line_errors_keep_counts_only_and_never_start_listener(self):
        from hosted.deploy.probe.browser import process_evidence
        with self.proc_browser(b'unterminated synthetic-private-argument')as(proc,expected,_):
            counts={}
            try:process_evidence(120,proc,browser_expected=expected,counts=counts)
            except ProbeFailure as exc:error=ProbeFailure(str(exc),counts)
            else:self.fail('Malformed command must fail')
            with patch('hosted.deploy.probe.main.run',side_effect=error),patch('hosted.deploy.probe.main.serve')as serve:
                out=io.StringIO()
                with contextlib.redirect_stdout(out):status=main(['--mode','browser','--serve'])
            self.assertEqual(status,1);serve.assert_not_called()
            self.assertEqual(json.loads(out.getvalue()),dict(result='FAIL',code='E_SANDBOX_CMDLINE_INVALID',sandbox_counts={'cmdline_invalid':1}))

    def test_bounded_discovery_retries_never_accept_cdp_alone(self):
        _,_,inventory=self.fixture()
        with self.kernel(records={})as browser, \
             patch.object(browser,'cdp_inventory',new=AsyncMock(return_value=inventory)), \
             patch.object(browser.asyncio,'sleep',new=AsyncMock())as sleep:
            with self.assertRaisesRegex(ProbeFailure,'E_SANDBOX_UNVERIFIED')as caught:asyncio.run(browser.verify_sandbox([object()]))
        self.assertEqual(sleep.await_count,3);self.assertEqual(caught.exception.counts['scan_attempts'],4)
        self.assertTrue(all(call.args==(.25,)for call in sleep.await_args_list))

    def test_late_discovery_rechecks_all_evidence(self):
        values,records,inventory=self.fixture()
        with self.kernel()as browser,patch.object(browser,'process_snapshot',side_effect=[({},{}),(records,{})]), \
             patch.object(browser,'cdp_inventory',new=AsyncMock(return_value=inventory)), \
             patch.object(browser.asyncio,'sleep',new=AsyncMock())as sleep:
            observed,counts=asyncio.run(browser.verify_sandbox([object()]))
        self.assertEqual(counts['scan_attempts'],2);self.assertEqual(counts['renderer_evidence_confirmed'],2)
        self.assertEqual(set(observed),{110,120,210,220});sleep.assert_awaited_once_with(.25)

    def test_unsafe_or_denied_evidence_is_not_retried(self):
        values,_,inventory=self.fixture();values[120]['CapEff']=1
        with self.kernel(values)as browser,patch.object(browser,'cdp_inventory',new=AsyncMock(return_value=inventory)), \
             patch.object(browser.asyncio,'sleep',new=AsyncMock())as sleep:
            with self.assertRaisesRegex(ProbeFailure,'E_SANDBOX_CAPABILITIES'):asyncio.run(browser.verify_sandbox([object()]))
        sleep.assert_not_awaited()
        with self.kernel()as browser,patch.object(browser,'cdp_inventory',new=AsyncMock(return_value=inventory)), \
             patch.object(browser,'process_evidence',side_effect=ProbeFailure('E_SANDBOX_EVIDENCE_DENIED')), \
             patch.object(browser.asyncio,'sleep',new=AsyncMock())as sleep:
            with self.assertRaisesRegex(ProbeFailure,'E_SANDBOX_EVIDENCE_DENIED'):asyncio.run(browser.verify_sandbox([object()]))
        sleep.assert_not_awaited()

    def test_pid_reuse_or_security_change_after_cdp_read_is_denied(self):
        import copy
        values,_,inventory=self.fixture()
        for field in ('start','Seccomp_filters','exe','namespaces'):
            reads={}
            def read(pid,*,browser_expected=None,counts=None):
                reads[pid]=reads.get(pid,0)+1;value=copy.deepcopy(values[pid])
                if pid==120 and reads[pid]>1:value[field]=None
                if browser_expected is not None:value['arguments']=(b'/opt/playwright/chrome',)
                return value
            with self.subTest(field=field),self.kernel()as browser, \
                 patch.object(browser,'process_evidence',side_effect=read), \
                 patch.object(browser,'cdp_inventory',new=AsyncMock(return_value=inventory)), \
                 self.assertRaisesRegex(ProbeFailure,'E_SANDBOX_IDENTITY'):
                asyncio.run(browser.verify_sandbox([object()]))

    def test_changed_browser_arguments_on_recheck_are_denied(self):
        _,_,inventory=self.fixture()
        with self.kernel()as browser:
            original=browser.process_evidence;reads={}
            def read(pid,**kwargs):
                value=original(pid,**kwargs)
                if kwargs.get('browser_expected')is not None:
                    reads[pid]=reads.get(pid,0)+1
                    if reads[pid]>1:value['arguments']=(b'/opt/playwright/chrome',b'changed')
                return value
            with patch.object(browser,'process_evidence',side_effect=read), \
                 patch.object(browser,'cdp_inventory',new=AsyncMock(return_value=inventory)), \
                 self.assertRaisesRegex(ProbeFailure,'E_SANDBOX_IDENTITY'):
                asyncio.run(browser.verify_sandbox([object()]))

    def test_second_cdp_query_failure_retains_fixed_stage_counter(self):
        _,_,inventory=self.fixture();calls=[]
        async def query(instances,counts):
            calls.append(1)
            if len(calls)>1:
                counts['cdp_process_query_failed']=1
                raise ProbeFailure('E_SANDBOX_CDP_PROCESS_QUERY')
            return inventory
        with self.kernel()as browser,patch.object(browser,'cdp_inventory',side_effect=query), \
             self.assertRaisesRegex(ProbeFailure,'E_SANDBOX_CDP_PROCESS_QUERY')as caught:
            asyncio.run(browser.verify_sandbox([object()]))
        self.assertEqual(caught.exception.counts['cdp_process_query_failed'],1)
        self.assertEqual(caught.exception.counts['renderer_evidence_confirmed'],2)

    def test_changing_cdp_inventory_cannot_pass(self):
        _,_,inventory=self.fixture()
        with self.kernel()as browser,patch.object(browser,'cdp_inventory',new=AsyncMock(side_effect=[inventory,[]]*4)), \
             patch.object(browser.asyncio,'sleep',new=AsyncMock())as sleep:
            with self.assertRaisesRegex(ProbeFailure,'E_SANDBOX_UNVERIFIED'):asyncio.run(browser.verify_sandbox([object()]))
        self.assertEqual(sleep.await_count,3)

    def test_proc_evidence_reads_pinned_directory_and_parses_tricky_stat_name(self):
        from hosted.deploy.probe.browser import process_evidence
        with tempfile.TemporaryDirectory()as folder:
            root=Path(folder)/'120';(root/'ns').mkdir(parents=True)
            for name in ('exe','ns/pid','ns/net','ns/user'):(root/name).write_text('synthetic')
            (root/'stat').write_text('120 (name ) with spaces) '+' '.join(['S']+['0']*18+['123']))
            status='Pid: 120\nNSpid: 120 12 1\nUid: 10001 10001 10001 10001\nNoNewPrivs: 1\nSeccomp: 2\nCapEff: 0000\nSeccomp_filters: 2\n'
            (root/'status').write_text(status)
            result=process_evidence(120,Path(folder));self.assertEqual(result['start'],123)
            self.assertEqual(result['nspid'],(120,12,1));self.assertEqual(result['Seccomp_filters'],2)
            for field in ('NSpid','Uid','Seccomp_filters','CapEff'):
                (root/'status').write_text('\n'.join(line for line in status.splitlines()if not line.startswith(field+':')))
                with self.subTest(field=field),self.assertRaisesRegex(ProbeFailure,'E_SANDBOX_EVIDENCE_INVALID'):
                    process_evidence(120,Path(folder))

    def test_proc_directory_is_pinned_and_start_time_race_fails_closed(self):
        from hosted.deploy.probe.browser import process_evidence
        with tempfile.TemporaryDirectory()as folder:
            root=Path(folder)/'120';(root/'ns').mkdir(parents=True)
            for name in ('exe','ns/pid','ns/net','ns/user'):(root/name).write_text('synthetic')
            def write_stat(start):(root/'stat').write_text('120 (name) '+' '.join(['S']+['0']*18+[str(start)]))
            write_stat(123)
            (root/'status').write_text('Pid: 120\nNSpid: 120 12 1\nUid: 10001 10001 10001 10001\nNoNewPrivs: 1\nSeccomp: 2\nCapEff: 0\nSeccomp_filters: 2\n')
            real_open=os.open;stat_reads=[];directory_fds=[]
            def opened(path,flags,**kwargs):
                if path=='stat':
                    stat_reads.append(kwargs['dir_fd'])
                    if len(stat_reads)==2:write_stat(124)
                result=real_open(path,flags,**kwargs)
                if flags&os.O_DIRECTORY:directory_fds.append(result)
                return result
            with patch('os.open',side_effect=opened),self.assertRaisesRegex(ProbeFailure,'E_SANDBOX_EVIDENCE_INVALID'):
                process_evidence(120,Path(folder))
            self.assertEqual(stat_reads,[directory_fds[0]]*2)
            with self.assertRaises(OSError):os.fstat(directory_fds[0])

    def test_proc_evidence_denial_and_disappearance_use_fixed_categories(self):
        from hosted.deploy.probe.browser import process_evidence
        for error,code in [(PermissionError('synthetic-sensitive'),'E_SANDBOX_EVIDENCE_DENIED'),
                           (FileNotFoundError('synthetic-sensitive'),'E_SANDBOX_UNVERIFIED')]:
            with patch('os.open',side_effect=error),self.assertRaisesRegex(ProbeFailure,code)as caught:process_evidence(120)
            self.assertNotIn('synthetic-sensitive',str(caught.exception))

    def test_executable_must_be_immutable_root_installed_playwright(self):
        from hosted.deploy.probe.browser import trusted_executable
        for path in ('relative/chrome','/private/tmp/chrome','/usr/bin/false'):
            with self.subTest(path=path),self.assertRaisesRegex(ProbeFailure,'E_SANDBOX_IDENTITY'):trusted_executable(path)
        with patch('hosted.deploy.probe.browser.Path')as constructor:
            path=constructor.return_value;path.is_absolute.return_value=True;path.resolve.return_value=path
            path.is_relative_to.return_value=True;path.parents=[]
            path.stat.return_value=SimpleNamespace(st_uid=0,st_mode=0o100755,st_dev=1,st_ino=2)
            self.assertEqual(trusted_executable('/opt/playwright/chrome'),(1,2))
            for uid,mode in [(10001,0o100755),(0,0o100775),(0,0o100644),(0,0o040755)]:
                path.stat.return_value=SimpleNamespace(st_uid=uid,st_mode=mode)
                with self.subTest(uid=uid,mode=mode),self.assertRaisesRegex(ProbeFailure,'E_SANDBOX_IDENTITY'):
                    trusted_executable('/opt/playwright/chrome')

    def cleanup_record(self,state='S',start=123,role='renderer'):
        return dict(pid=120,start=start,uid=(10001,)*4,nspid=(120,12),state=state,role=role)

    def cleanup_tracking(self,role='renderer'):
        from hosted.deploy.probe.browser import cleanup_identity
        return {120:dict(identity=cleanup_identity(self.cleanup_record()),role=role)}

    def test_cleanup_reads_zombie_identity_without_exe_or_namespace_links(self):
        from hosted.deploy.probe.browser import cleanup_process,cleanup_counts
        with self.proc_browser(b'')as(proc,expected,_):
            (proc/'120/exe').unlink()
            for name in ('pid','net','user'):(proc/'120/ns'/name).unlink()
            (proc/'120/stat').write_text('120 (name ) with spaces) '+' '.join(['Z']+['0']*18+['123']))
            value=cleanup_process(120,proc,read_role=True)
            self.assertEqual(value['state'],'Z');self.assertEqual(value['role'],'unknown')
            counts=cleanup_counts(self.cleanup_tracking(),proc)
            self.assertEqual(counts['cleanup_zombie'],1);self.assertEqual(counts['cleanup_renderer_zombie'],1)
            self.assertEqual(counts['cleanup_unreadable'],0)

    def test_cleanup_proc_reads_are_pinned_bounded_and_close_descriptors(self):
        from hosted.deploy.probe.browser import cleanup_process
        with self.proc_browser()as(proc,_,_):
            real_open=os.open;opened=[]
            def read(path,flags,**kwargs):
                result=real_open(path,flags,**kwargs);opened.append((path,flags,kwargs.get('dir_fd'),result));return result
            with patch('os.open',side_effect=read):value=cleanup_process(120,proc,read_role=True)
            fd=next(item[3]for item in opened if item[1]&os.O_DIRECTORY)
            self.assertEqual(value['start'],123)
            self.assertTrue(all(item[2]==fd and item[1]&os.O_NOFOLLOW for item in opened if not item[1]&os.O_DIRECTORY))
            with self.assertRaises(OSError):os.fstat(fd)
            (proc/'120/stat').write_text('x'*65537)
            with self.assertRaises(ValueError):cleanup_process(120,proc)

    def test_cleanup_process_race_is_unreadable_and_retains_first_identity(self):
        from hosted.deploy.probe.browser import cleanup_counts
        with self.proc_browser()as(proc,_,_):
            real_open=os.open;reads=[]
            def read(path,flags,**kwargs):
                if path=='stat':
                    reads.append(1)
                    if len(reads)==2:(proc/'120/stat').write_text('120 (name) '+' '.join(['S']+['0']*18+['124']))
                return real_open(path,flags,**kwargs)
            with patch('os.open',side_effect=read):counts=cleanup_counts(self.cleanup_tracking(),proc)
            self.assertEqual(counts['cleanup_unreadable'],1);self.assertEqual(counts['cleanup_gone'],0)

    def test_cleanup_role_hints_use_only_fixed_categories(self):
        from hosted.deploy.probe.browser import cleanup_process
        cases=[(b'/path/node\0','driver'),(b'/path/chrome\0','browser'),
               (b'/path/chrome-headless-shell\0','browser'),(b'/path/headless_shell\0','browser'),
               (b'/path/chrome_crashpad_handler\0','crash_handler'),
               (b'x\0--type=renderer\0','renderer'),(b'x\0--type=zygote\0','zygote'),
               (b'x\0--type=gpu-process\0','gpu'),(b'x\0--type=utility\0','utility'),
               (b'x\0--type=synthetic-sensitive\0','unknown'),
               (b'x\0--type=renderer\0--type=utility\0','unknown'),(b'unterminated','unknown')]
        for raw,expected in cases:
            with self.subTest(role=expected),self.proc_browser(raw)as(proc,_,_):
                value=cleanup_process(120,proc,read_role=True)
                self.assertEqual(value['role'],expected)
                self.assertNotIn('synthetic-sensitive',json.dumps(value))

    def test_cleanup_capture_keeps_first_identity_and_cdp_role(self):
        from hosted.deploy.probe.browser import track_cleanup,cleanup_identity
        first={**self.cleanup_record(), 'arguments':(b'synthetic-sensitive',)}
        tracked=track_cleanup([120],verified={120:first})
        replacement={**first,'start':999}
        self.assertEqual(track_cleanup([120],previous=tracked,verified={120:replacement}),tracked)
        self.assertEqual(tracked[120]['identity'],cleanup_identity(first));self.assertEqual(tracked[120]['role'],'browser')
        with patch('hosted.deploy.probe.browser.cleanup_process',side_effect=PermissionError('synthetic-sensitive')):
            unknown=track_cleanup([121],previous=tracked)
        self.assertIsNone(unknown[121]['identity']);self.assertEqual(unknown[121]['role'],'unknown')
        self.assertNotIn('synthetic-sensitive',repr(unknown))

    def test_cleanup_detects_reuse_of_start_uid_or_namespace_identity(self):
        from hosted.deploy.probe.browser import cleanup_counts
        for field,value in [('start',999),('uid',(10002,)*4),('nspid',(120,13))]:
            row={**self.cleanup_record(),field:value}
            with self.subTest(field=field),patch('hosted.deploy.probe.browser.cleanup_process',return_value=row):
                counts=cleanup_counts(self.cleanup_tracking())
            self.assertEqual(counts['cleanup_reused'],1);self.assertEqual(counts['cleanup_renderer_reused'],1)
            self.assertEqual(counts['cleanup_gone'],0)

    def test_cleanup_missing_inner_file_is_not_proof_of_exit(self):
        from hosted.deploy.probe.browser import cleanup_counts
        for absent in (False,True):
            with self.subTest(directory_absent=absent), \
                 patch('hosted.deploy.probe.browser.cleanup_process',side_effect=FileNotFoundError()), \
                 patch('hosted.deploy.probe.browser.proc_absent',return_value=absent):
                counts=cleanup_counts(self.cleanup_tracking())
            self.assertEqual(counts['cleanup_gone'],int(absent))
            self.assertEqual(counts['cleanup_unreadable'],int(not absent))
        with self.proc_browser()as(proc,_,_):
            (proc/'120/status').unlink()
            counts=cleanup_counts(self.cleanup_tracking(),proc)
            self.assertEqual(counts['cleanup_unreadable'],1)

    def test_cleanup_unreadable_baseline_and_invalid_state_do_not_pass(self):
        from hosted.deploy.probe.browser import cleanup_counts
        cases=[({120:dict(identity=None,role='unknown')},self.cleanup_record()),
               (self.cleanup_tracking(),self.cleanup_record(state='X'))]
        for tracked,row in cases:
            with patch('hosted.deploy.probe.browser.cleanup_process',return_value=row):counts=cleanup_counts(tracked)
            self.assertEqual(counts['cleanup_unreadable'],1);self.assertEqual(counts['cleanup_gone'],0)
        with patch('hosted.deploy.probe.browser.cleanup_process',side_effect=PermissionError('synthetic-sensitive')):
            counts=cleanup_counts(self.cleanup_tracking(role='synthetic-sensitive'))
        self.assertEqual(counts['cleanup_unknown_unreadable'],1)
        self.assertNotIn('synthetic-sensitive',json.dumps(counts))

    def test_cleanup_all_unresolved_states_fail_closed_with_same_budget(self):
        from hosted.deploy.probe.browser import check_child_cleanup
        cases=[('live',self.cleanup_record()),('zombie',self.cleanup_record(state='Z')),
               ('reused',self.cleanup_record(start=999)),('unreadable',PermissionError('synthetic-sensitive'))]
        for state,value in cases:
            reader=MagicMock(side_effect=value)if isinstance(value,Exception)else MagicMock(return_value=value)
            with self.subTest(state=state),patch('hosted.deploy.probe.browser.cleanup_process',reader), \
                 patch('hosted.deploy.probe.browser.asyncio.sleep',new=AsyncMock())as sleep, \
                 patch('os.kill',side_effect=AssertionError('Diagnostics must not send signals')):
                with self.assertRaisesRegex(ProbeFailure,'E_BROWSER_CHILD_CLEANUP')as caught:
                    asyncio.run(check_child_cleanup(self.cleanup_tracking(),{'sandbox_verified':1,'namespace_confirmed':2}))
            counts=caught.exception.counts
            self.assertEqual(counts['cleanup_'+state],1);self.assertEqual(counts['cleanup_poll_attempts'],30)
            self.assertEqual(counts['sandbox_verified'],1);self.assertEqual(counts['namespace_confirmed'],2)
            self.assertEqual(sleep.await_count,30)
            self.assertTrue(all(call.args==(.1,)for call in sleep.await_args_list))
            self.assertNotIn('synthetic-sensitive',json.dumps(counts))

    def test_cleanup_passes_only_when_all_tracked_entries_are_gone(self):
        from hosted.deploy.probe.browser import check_child_cleanup
        with patch('hosted.deploy.probe.browser.cleanup_process',side_effect=FileNotFoundError()), \
             patch('hosted.deploy.probe.browser.proc_absent',return_value=True), \
             patch('hosted.deploy.probe.browser.asyncio.sleep',new=AsyncMock())as sleep:
            counts=asyncio.run(check_child_cleanup(self.cleanup_tracking(),{'sandbox_verified':1}))
        self.assertEqual(counts['cleanup_tracked'],1);self.assertEqual(counts['cleanup_gone'],1)
        self.assertEqual(counts['cleanup_renderer_gone'],1);self.assertEqual(counts['cleanup_poll_attempts'],1)
        sleep.assert_not_awaited()

    def test_incomplete_tracking_remains_fail_closed_even_if_known_entries_exit(self):
        from hosted.deploy.probe.browser import check_child_cleanup
        with patch('hosted.deploy.probe.browser.cleanup_process',side_effect=FileNotFoundError()), \
             patch('hosted.deploy.probe.browser.proc_absent',return_value=True), \
             patch('hosted.deploy.probe.browser.asyncio.sleep',new=AsyncMock()):
            with self.assertRaisesRegex(ProbeFailure,'E_BROWSER_CHILD_CLEANUP')as caught:
                asyncio.run(check_child_cleanup(self.cleanup_tracking(),{'sandbox_verified':1,'cleanup_tracking_incomplete':1}))
        self.assertEqual(caught.exception.counts['cleanup_tracking_incomplete'],1)
        self.assertEqual(caught.exception.counts['cleanup_gone'],1)

    def test_cleanup_failure_reports_counts_without_raw_process_data_or_listener(self):
        from hosted.deploy.probe.browser import check_child_cleanup
        with patch('hosted.deploy.probe.browser.cleanup_process',return_value=self.cleanup_record(state='Z')), \
             patch('hosted.deploy.probe.browser.asyncio.sleep',new=AsyncMock()):
            try:asyncio.run(check_child_cleanup(self.cleanup_tracking(),{'sandbox_verified':1}))
            except ProbeFailure as exc:error=exc
            else:self.fail('Zombie must fail cleanup')
        error.counts.update(pid=120,start=123,arguments='synthetic-sensitive',role='synthetic-sensitive')
        with patch('hosted.deploy.probe.main.run',side_effect=error),patch('hosted.deploy.probe.main.serve')as serve:
            out=io.StringIO()
            with contextlib.redirect_stdout(out):status=main(['--mode','browser','--serve'])
        report=json.loads(out.getvalue());self.assertEqual(status,1);serve.assert_not_called()
        self.assertEqual(report['sandbox_counts']['cleanup_renderer_zombie'],1)
        self.assertEqual(report['sandbox_counts']['sandbox_verified'],1)
        self.assertNotIn('synthetic-sensitive',out.getvalue())
        self.assertTrue(all(type(value)is int for value in report['sandbox_counts'].values()))
        self.assertFalse({'pid','start','arguments','role'}&set(report['sandbox_counts']))

    def test_full_probe_attaches_cleanup_and_passed_sandbox_counts(self):
        from hosted.deploy.probe import browser
        class SyntheticBrowser(browser.FakeBrowser):
            def __init__(self):
                super().__init__();self.directory=tempfile.TemporaryDirectory(prefix='cleanup-test-')
                self.browser=SimpleNamespace(is_connected=lambda:not self.closed)
                self.context=SimpleNamespace(add_cookies=AsyncMock(),cookies=AsyncMock(return_value=[]))
            async def close(self):
                await super().close();self.directory.cleanup()
        original_sleep=asyncio.sleep
        async def wait(delay):await original_sleep(delay if delay==180 else 0)
        with patch.object(browser,'LoginBrowser',SyntheticBrowser), \
             patch.object(browser,'verify_sandbox',new=AsyncMock(return_value=(self.cleanup_tracking(),{'renderer_evidence_confirmed':2}))), \
             patch.object(browser,'process_snapshot',return_value=({},{})), \
             patch.object(browser,'cleanup_process',return_value=self.cleanup_record(state='Z')), \
             patch.object(browser.asyncio,'sleep',side_effect=wait):
            with self.assertRaisesRegex(ProbeFailure,'E_BROWSER_CHILD_CLEANUP')as caught:
                asyncio.run(browser.check_browser(True))
        self.assertEqual(caught.exception.counts['sandbox_verified'],1)
        self.assertEqual(caught.exception.counts['renderer_evidence_confirmed'],2)
        self.assertEqual(caught.exception.counts['cleanup_renderer_zombie'],1)


if __name__=='__main__':unittest.main()
