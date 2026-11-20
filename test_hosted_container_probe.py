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

    def test_sandbox_inspection_fails_closed_if_unverified(self):
        from hosted.deploy.probe.browser import sandbox_check
        with patch('hosted.deploy.probe.browser.descendants',return_value={}):
            with self.assertRaisesRegex(ProbeFailure,'E_SANDBOX_UNVERIFIED'):sandbox_check()

    def renderer(self,fields=None,disabled=False):
        root=MagicMock()
        args=b'chrome\0--type=renderer\0synthetic-private-argument\0'
        if disabled:args+=b'--no-sandbox\0'
        root.__truediv__.return_value.read_bytes.return_value=args
        return {20:(10,fields or dict(NoNewPrivs='1',Seccomp='2',CapEff='0'),root)}

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

    def test_verified_renderer_reports_counts_without_arguments_or_ids(self):
        from hosted.deploy.probe.browser import sandbox_check
        with patch('os.getpid',return_value=10):observed,counts=sandbox_check(self.renderer(),{'proc_entries':1})
        self.assertEqual(observed,{20})
        self.assertEqual(counts['renderer_matches'],1)
        self.assertEqual(counts['no_new_privs_confirmed'],1)
        self.assertEqual(counts['seccomp_filter_confirmed'],1)
        self.assertEqual(counts['zero_caps_confirmed'],1)
        self.assertNotIn('synthetic-private-argument',json.dumps(counts))
        self.assertTrue(all(type(value)is int for value in counts.values()))

    def test_unsafe_or_missing_security_fields_still_fail_closed(self):
        from hosted.deploy.probe.browser import sandbox_check
        cases=[({},True,'E_SANDBOX_DISABLED'),({'NoNewPrivs':'0','Seccomp':'2','CapEff':'0'},False,'E_SANDBOX_PRIVILEGES'),
            ({'NoNewPrivs':'1','Seccomp':'0','CapEff':'0'},False,'E_SANDBOX_SECCOMP'),
            ({'NoNewPrivs':'1','Seccomp':'2','CapEff':'1'},False,'E_SANDBOX_CAPABILITIES'),
            ({'NoNewPrivs':'1','Seccomp':'2','CapEff':'invalid'},False,'E_SANDBOX_CAPABILITIES')]
        for fields,disabled,code in cases:
            with self.subTest(code=code),patch('os.getpid',return_value=10),self.assertRaisesRegex(ProbeFailure,code):
                sandbox_check(self.renderer(fields,disabled),{})

    def test_discovery_retries_are_bounded_and_never_pass_on_cdp_alone(self):
        from hosted.deploy.probe.browser import verify_sandbox
        with patch('hosted.deploy.probe.browser.process_snapshot',return_value=({},{}))as scan, \
             patch('hosted.deploy.probe.browser.cdp_process_counts',new=AsyncMock(return_value={'cdp_renderer_ids':2})), \
             patch('hosted.deploy.probe.browser.asyncio.sleep',new=AsyncMock())as sleep:
            with self.assertRaisesRegex(ProbeFailure,'E_SANDBOX_UNVERIFIED')as caught:asyncio.run(verify_sandbox([]))
        self.assertEqual(scan.call_count,4);self.assertEqual(sleep.await_count,3)
        self.assertTrue(all(call.args==(.25,)for call in sleep.await_args_list))
        self.assertEqual(caught.exception.counts['scan_attempts'],4)
        self.assertEqual(caught.exception.counts['cdp_renderer_ids'],2)

    def test_late_renderer_must_satisfy_original_security_checks(self):
        from hosted.deploy.probe.browser import verify_sandbox
        with patch('os.getpid',return_value=10), \
             patch('hosted.deploy.probe.browser.process_snapshot',side_effect=[({},{}),(self.renderer(),{})]), \
             patch('hosted.deploy.probe.browser.cdp_process_counts',new=AsyncMock(return_value={})), \
             patch('hosted.deploy.probe.browser.asyncio.sleep',new=AsyncMock())as sleep:
            observed,counts=asyncio.run(verify_sandbox([]))
        self.assertEqual(observed,{20});self.assertEqual(counts['scan_attempts'],2)
        self.assertEqual(counts['renderer_matches'],1);sleep.assert_awaited_once_with(.25)

    def test_observed_unsafe_renderer_is_not_retried(self):
        from hosted.deploy.probe.browser import verify_sandbox
        with patch('os.getpid',return_value=10), \
             patch('hosted.deploy.probe.browser.process_snapshot',return_value=(self.renderer(disabled=True),{}))as scan, \
             patch('hosted.deploy.probe.browser.cdp_process_counts',new=AsyncMock(return_value={})), \
             patch('hosted.deploy.probe.browser.asyncio.sleep',new=AsyncMock())as sleep:
            with self.assertRaisesRegex(ProbeFailure,'E_SANDBOX_DISABLED'):asyncio.run(verify_sandbox([]))
        self.assertEqual(scan.call_count,1);sleep.assert_not_awaited()

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

    def test_cdp_diagnostics_expose_only_counts_and_not_process_metadata(self):
        from hosted.deploy.probe.browser import cdp_process_counts
        session=SimpleNamespace(send=AsyncMock(return_value={'processInfo':[
            {'type':'renderer','id':20,'extra':'synthetic-sensitive'}, {'type':'renderer','id':30}]}),detach=AsyncMock())
        good=SimpleNamespace(browser=SimpleNamespace(new_browser_cdp_session=AsyncMock(return_value=session)))
        bad=SimpleNamespace(browser=SimpleNamespace(new_browser_cdp_session=AsyncMock(side_effect=RuntimeError('synthetic-sensitive'))))
        counts=asyncio.run(cdp_process_counts([good,bad],{20:None},{20:None}))
        self.assertEqual(counts,dict(cdp_queries_ok=1,cdp_queries_failed=1,cdp_rows_truncated=0,
            cdp_renderer_ids=2,cdp_renderer_visible=1,cdp_renderer_descendants=1))
        session.send.assert_awaited_once_with('SystemInfo.getProcessInfo');session.detach.assert_awaited_once()
        self.assertNotIn('synthetic-sensitive',json.dumps(counts))

    def test_unreadable_renderer_command_still_fails_with_category(self):
        from hosted.deploy.probe.browser import sandbox_check
        records=self.renderer();records[20][2].__truediv__.return_value.read_bytes.side_effect=PermissionError('synthetic-sensitive')
        with patch('os.getpid',return_value=10),self.assertRaisesRegex(ProbeFailure,'E_SANDBOX_UNVERIFIED')as caught:
            sandbox_check(records,{})
        self.assertEqual(caught.exception.counts['cmdline_denied'],1)
        self.assertEqual(caught.exception.counts['renderer_matches'],0)


if __name__=='__main__':unittest.main()
