"""Offline owner proof coalescing, bounded tool queues and chart argument regressions."""
import asyncio
from datetime import datetime,timezone,timedelta
import io,json,logging,threading,time,unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock,Mock,patch

from catknows.auth import Session
from catknows.hosted_keys import keyring,encrypt_session
from catknows.hosted_oauth import hashed
from catknows.hosted_tools import register_tools
from catknows import hosted_analytics as analytics
from test_hosted_analytics import FakeClient,Registry,Batch
import test_hosted_popup as popup


class OwnerCacheTests(unittest.TestCase):
    def setUp(self):
        self.case=popup.PopupTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.bearer='st_a_'+'x'*43
        async def setup():
            c=self.case;account=await c.provider.call('account',skool_user_id=c.identity)
            c.store.paid.clear();c.store.owners[account['id']]='synthetic-group'
            version,keys=keyring()
            c.store.sessions[account['id']]=encrypt_session(account['id'],Session('synthetic-cookie','synthetic-auth','synthetic-waf'),version,keys[version])
            c.store.rpc=lambda name,p:c.store.sessions.get(p['p_account'])
            c.store.tokens[hashed(self.bearer)]=dict(kind='access',account_id=account['id'],client_id='synthetic-client',resource=c.settings.resource,
                generation=0,expires_at=(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat())
            self.reads=[];original=c.store.call
            def call(op,**p):
                if op=='token_get':self.reads.append(True)
                return original(op,**p)
            c.store.call=call
            c.provider.owner_reader=Mock(return_value='synthetic-group')
        asyncio.run(setup())

    def expire(self):
        c=self.case.provider
        for key,(_,binding)in list(c.owner_proofs.items()):c.owner_proofs[key]=(time.monotonic()-1,binding)

    def test_six_parallel_valid_owner_requests_all_pass_one_live_check(self):
        async def check():
            c=self.case
            def slow(*args):time.sleep(.25);return 'synthetic-group'
            c.provider.owner_reader.side_effect=slow
            results=await asyncio.gather(*(c.provider.load_access_token(self.bearer)for _ in range(6)))
            self.assertTrue(all(v is not None for v in results));self.assertEqual(c.provider.owner_reader.call_count,1)
            self.assertGreaterEqual(len(self.reads),12);self.assertEqual(len(c.provider.owner_proofs),1)
            deadline,_=c.provider.owner_proofs[hashed(self.bearer)]
            self.assertGreater(deadline,time.monotonic());self.assertLessEqual(deadline-time.monotonic(),60)
        asyncio.run(check())

    def test_distinct_tokens_wait_for_slots_without_exceeding_two_live_checks(self):
        async def check():
            c=self.case;active=[0];peak=[0];lock=threading.Lock()
            def slow(*args):
                with lock:active[0]+=1;peak[0]=max(peak[0],active[0])
                time.sleep(.2)
                with lock:active[0]-=1
                return 'synthetic-group'
            c.provider.owner_reader.side_effect=slow
            tokens=[self.bearer,'st_a_'+'y'*43,'st_a_'+'z'*43]
            for token in tokens[1:]:c.store.tokens[hashed(token)]=dict(c.store.tokens[hashed(self.bearer)])
            results=await asyncio.gather(*(c.provider.load_access_token(token)for token in tokens))
            self.assertTrue(all(value is not None for value in results));self.assertEqual(peak[0],2)
            self.assertEqual(c.provider.owner_reader.call_count,3)
        asyncio.run(check())

    def test_cache_hit_still_reads_database_and_is_bound_to_exact_token(self):
        async def check():
            c=self.case
            self.assertIsNotNone(await c.provider.load_access_token(self.bearer))
            self.assertIsNotNone(await c.provider.load_access_token(self.bearer))
            self.assertEqual(c.provider.owner_reader.call_count,1);self.assertGreaterEqual(len(self.reads),4)
            other='st_a_'+'y'*43;c.store.tokens[hashed(other)]=dict(c.store.tokens[hashed(self.bearer)])
            self.assertIsNotNone(await c.provider.load_access_token(other));self.assertEqual(c.provider.owner_reader.call_count,2)
        asyncio.run(check())

    def test_revocation_immediately_defeats_successful_cache(self):
        async def check():
            c=self.case
            self.assertIsNotNone(await c.provider.load_access_token(self.bearer));c.store.tokens.pop(hashed(self.bearer))
            self.assertIsNone(await c.provider.load_access_token(self.bearer));self.assertNotIn(hashed(self.bearer),c.provider.owner_proofs)
            self.assertEqual(c.provider.owner_reader.call_count,1)
        asyncio.run(check())

    def test_generation_change_cannot_reuse_cached_proof(self):
        async def check():
            c=self.case
            self.assertIsNotNone(await c.provider.load_access_token(self.bearer))
            c.store.tokens[hashed(self.bearer)]['generation']=1
            with patch.object(c.provider,'owner_access_live',new=AsyncMock(return_value=False)) as live:
                self.assertIsNone(await c.provider.load_access_token(self.bearer));live.assert_awaited_once()
        asyncio.run(check())

    def test_owner_loss_after_ttl_deletes_session_and_revokes_tokens(self):
        async def check():
            c=self.case
            self.assertIsNotNone(await c.provider.load_access_token(self.bearer))
            c.provider.owner_reader.return_value=None
            self.assertIsNotNone(await c.provider.load_access_token(self.bearer))  # Within the explicit 60s bound.
            self.expire();self.assertIsNone(await c.provider.load_access_token(self.bearer))
            self.assertEqual(c.store.sessions,{});self.assertEqual(c.store.tokens,{});self.assertEqual(c.provider.owner_proofs,{})
        asyncio.run(check())

    def test_expired_proof_never_falls_back_after_upstream_error(self):
        async def check():
            c=self.case
            self.assertIsNotNone(await c.provider.load_access_token(self.bearer));self.expire()
            saved=dict(c.store.sessions);c.provider.owner_reader.side_effect=RuntimeError('synthetic-private-error')
            self.assertIsNone(await c.provider.load_access_token(self.bearer));self.assertEqual(c.store.sessions,saved)
            self.assertNotIn(hashed(self.bearer),c.provider.owner_proofs)
            c.provider.owner_reader.side_effect=None
            self.assertIsNotNone(await c.provider.load_access_token(self.bearer));self.assertEqual(c.provider.owner_reader.call_count,3)
        asyncio.run(check())

    def test_database_failure_denies_even_with_cached_success(self):
        async def check():
            c=self.case
            self.assertIsNotNone(await c.provider.load_access_token(self.bearer));original=c.store.call
            def unavailable(op,**p):
                if op=='token_get':raise RuntimeError('synthetic-private-database')
                return original(op,**p)
            c.store.call=unavailable
            self.assertIsNone(await c.provider.load_access_token(self.bearer));self.assertEqual(c.provider.owner_reader.call_count,1)
        asyncio.run(check())

    def test_revocation_during_shared_check_denies_all_waiters(self):
        async def check():
            c=self.case;started=threading.Event();release=threading.Event()
            def slow(*args):started.set();release.wait(2);return 'synthetic-group'
            c.provider.owner_reader.side_effect=slow
            tasks=[asyncio.create_task(c.provider.load_access_token(self.bearer))for _ in range(6)]
            try:
                self.assertTrue(await asyncio.to_thread(started.wait,1));c.store.tokens.pop(hashed(self.bearer))
            finally:release.set()
            self.assertTrue(all(v is None for v in await asyncio.gather(*tasks)))
            self.assertEqual(c.provider.owner_proofs,{})
        asyncio.run(check())

    def test_cancelled_waiter_does_not_cancel_shared_check(self):
        async def check():
            c=self.case;started=threading.Event();release=threading.Event()
            def slow(*args):started.set();release.wait(2);return 'synthetic-group'
            c.provider.owner_reader.side_effect=slow
            first=asyncio.create_task(c.provider.load_access_token(self.bearer));second=asyncio.create_task(c.provider.load_access_token(self.bearer))
            try:
                self.assertTrue(await asyncio.to_thread(started.wait,1));first.cancel()
                with self.assertRaises(asyncio.CancelledError):await first
                self.assertFalse(second.done());self.assertEqual(c.provider.owner_reader.call_count,1)
            finally:release.set()
            self.assertIsNotNone(await second)
        asyncio.run(check())

    def test_success_cache_and_inflight_checks_are_bounded(self):
        async def check():
            c=self.case;row={'account_id':'synthetic'};release=asyncio.Event()
            async def live(*args):await release.wait();return True
            with patch('catknows.hosted_oauth.OWNER_CACHE_LIMIT',3),patch.object(c.provider,'owner_access_live',side_effect=live):
                tasks=[asyncio.create_task(c.provider.owner_access(row,'synthetic-'+str(i)))for i in range(3)]
                await asyncio.sleep(.01)
                self.assertFalse(await c.provider.owner_access(row,'synthetic-overflow'));self.assertEqual(len(c.provider.owner_checks),3)
                release.set();self.assertTrue(all(await asyncio.gather(*tasks)))
                for i in range(3,9):self.assertTrue(await c.provider.owner_access(row,'synthetic-'+str(i)))
                self.assertLessEqual(len(c.provider.owner_proofs),3)
        asyncio.run(check())


class ChartClient(FakeClient):
    def __init__(self,state,role='group-admin'):super().__init__('stealth',role);self.state=state
    def self_groups(self):
        return [{'id':'synthetic-group','name':'stealth','metadata':{'owner':json.dumps({'id':'stealth'})if self.role=='owner'else'synthetic-other',
            'member':json.dumps({'role':self.role})}}]
    def analytics_chart(self,gid,chart):
        self.state['charts'].append((gid,chart));return [{'date':'2026-11-01','mrr':100,'churn':-1,'retention_rate':.9,'attribution':'synthetic','total':2,'net':5}]
    def members(self,slug,**kwargs):self.state['members']+=1;return super().members(slug,**kwargs)


class ChartAndQueueTests(unittest.TestCase):
    def setup_registry(self,role='owner',method=None,verifier=None):
        self.state={'charts':[],'members':0,'clients':[]}
        state=self.state
        class Client(ChartClient):
            def analytics_chart(self,gid,chart):
                if method:method()
                return super().analytics_chart(gid,chart)
        def provider(subject):
            client=Client(state,role);state['clients'].append(client);return client
        registry=Registry();self.token=SimpleNamespace(subject='synthetic',token='synthetic')
        async def verify(_):return self.token
        register_tools(registry,provider,verifier or SimpleNamespace(verify_token=verify));return registry

    def test_each_friendly_chart_resolves_to_existing_upstream_parameter(self):
        async def check():
            reg=self.setup_registry()
            with patch('catknows.hosted_tools.get_access_token',return_value=self.token):
                for name,source in [('mrr','mrr'),*analytics.CHART_ALIASES.items()]:
                    result=await reg.tools['get_revenue_analytics']('stealth',name)
                    self.assertEqual(result['chart'],{'requested':name,'source':source})
                    self.assertEqual(self.state['charts'][-1],('synthetic-group',source))
                result=await reg.tools['get_revenue_by_tier']('stealth')
                self.assertEqual(result['label'],'estimated');self.assertEqual(result['data'][0]['monthly_amount_source_units'],1000)
        asyncio.run(check())

    def test_schema_requires_slug_and_advertises_aliases(self):
        async def check():
            from mcp.server.mcpserver import MCPServer
            server=MCPServer('synthetic-schema')
            async def verify(_):return self.token
            register_tools(server,lambda _:None,SimpleNamespace(verify_token=verify))
            tools=await server.list_tools();chart=next(t for t in tools if t.name=='get_revenue_analytics')
            self.assertIn('community_slug',chart.input_schema['required'])
            choices=set(chart.input_schema['properties']['chart']['enum'])
            self.assertEqual(choices,set(analytics.CHART_FIELDS)|set(analytics.CHART_ALIASES))
            self.assertEqual(chart.input_schema['properties']['chart']['default'],'mrr')
        asyncio.run(check())

    def test_aliases_preserve_owner_admin_authorization(self):
        async def check():
            for role in ('member','group-moderator','group-admin','owner'):
                reg=self.setup_registry(role)
                with patch('catknows.hosted_tools.get_access_token',return_value=self.token):
                    for chart in ('mrr','churn','retention','sources','cash_flow'):
                        if role in ('owner','group-admin'):
                            self.assertEqual((await reg.tools['get_revenue_analytics']('stealth',chart))['label'],'verified')
                        else:
                            with self.assertRaises(ValueError):await reg.tools['get_revenue_analytics']('stealth',chart)
                    if role not in ('owner','group-admin'):self.assertEqual(self.state['charts'],[])
        asyncio.run(check())

    def test_foreign_slug_and_invalid_chart_are_denied_before_reads(self):
        async def check():
            reg=self.setup_registry()
            with patch('catknows.hosted_tools.get_access_token',return_value=self.token):
                for chart in ('mrr','churn','cash_flow'):
                    with self.assertRaises(ValueError):await reg.tools['get_revenue_analytics']('synthetic-foreign',chart)
                with self.assertRaises(ValueError):await reg.tools['get_revenue_analytics']('stealth','synthetic-private-chart')
            self.assertEqual(self.state['charts'],[]);self.assertEqual(self.state['members'],0)
        asyncio.run(check())

    def test_eleven_same_account_calls_queue_and_preserve_single_active_read(self):
        async def check():
            active=[0];peak=[0];lock=threading.Lock()
            def slow():
                with lock:active[0]+=1;peak[0]=max(peak[0],active[0])
                time.sleep(.02)
                with lock:active[0]-=1
            reg=self.setup_registry(method=slow)
            with patch('catknows.hosted_tools.get_access_token',return_value=self.token):
                calls=[reg.tools['get_revenue_analytics']('stealth',chart)for chart in ('mrr','churn','retention','sources','cash_flow')]
                calls.append(reg.tools['get_revenue_by_tier']('stealth'))
                calls.extend(reg.tools['get_revenue_analytics']('stealth','mrr')for _ in range(5))
                results=await asyncio.gather(*calls)
            self.assertEqual(len(results),11);self.assertEqual(peak[0],1)
            self.assertTrue(all(c.closed for c in self.state['clients']))
        asyncio.run(check())

    def test_queue_timeout_is_bounded_and_never_constructs_second_client(self):
        async def check():
            started=threading.Event();release=threading.Event()
            def slow():started.set();release.wait(2)
            reg=self.setup_registry(method=slow)
            with patch('catknows.hosted_tools.get_access_token',return_value=self.token):
                first=asyncio.create_task(reg.tools['get_revenue_analytics']('stealth'))
                try:
                    self.assertTrue(await asyncio.to_thread(started.wait,1))
                    with patch('catknows.hosted_tools.TOOL_QUEUE_WAIT',.01):
                        with self.assertRaisesRegex(ValueError,'already running'):await reg.tools['get_revenue_analytics']('stealth')
                    self.assertEqual(len(self.state['clients']),1)
                finally:release.set()
                await first
        asyncio.run(check())

    def test_queued_cancellation_does_not_break_account_serialization(self):
        async def check():
            started=threading.Event();release=threading.Event()
            def slow():started.set();release.wait(2)
            reg=self.setup_registry(method=slow)
            with patch('catknows.hosted_tools.get_access_token',return_value=self.token):
                first=asyncio.create_task(reg.tools['get_revenue_analytics']('stealth'));second=None
                try:
                    self.assertTrue(await asyncio.to_thread(started.wait,1))
                    second=asyncio.create_task(reg.tools['get_revenue_analytics']('stealth'));await asyncio.sleep(.01);second.cancel()
                    with self.assertRaises(asyncio.CancelledError):await second
                    self.assertEqual(len(self.state['clients']),1)
                finally:release.set()
                await first;await reg.tools['get_revenue_analytics']('stealth')
                self.assertEqual(len(self.state['clients']),2)
        asyncio.run(check())

    def test_running_cancellation_keeps_lock_until_thread_stops_even_if_cancelled_twice(self):
        async def check():
            started=threading.Event();release=threading.Event()
            def slow():started.set();release.wait(2)
            reg=self.setup_registry(method=slow)
            with patch('catknows.hosted_tools.get_access_token',return_value=self.token):
                first=asyncio.create_task(reg.tools['get_revenue_analytics']('stealth'))
                try:
                    self.assertTrue(await asyncio.to_thread(started.wait,1));first.cancel();await asyncio.sleep(.01);first.cancel()
                    with patch('catknows.hosted_tools.TOOL_QUEUE_WAIT',.01):
                        with self.assertRaisesRegex(ValueError,'already running'):await reg.tools['get_revenue_analytics']('stealth')
                    self.assertEqual(len(self.state['clients']),1)
                finally:release.set()
                with self.assertRaises(asyncio.CancelledError):await first
                await reg.tools['get_revenue_analytics']('stealth')
        asyncio.run(check())

    def test_access_is_rechecked_after_wait_before_upstream_read(self):
        async def check():
            allowed=[True];started=threading.Event();release=threading.Event()
            async def verify(_):return self.token if allowed[0]else None
            def slow():started.set();release.wait(2)
            reg=self.setup_registry(method=slow,verifier=SimpleNamespace(verify_token=verify))
            with patch('catknows.hosted_tools.get_access_token',return_value=self.token):
                first=asyncio.create_task(reg.tools['get_revenue_analytics']('stealth'))
                self.assertTrue(await asyncio.to_thread(started.wait,1))
                second=asyncio.create_task(reg.tools['get_revenue_analytics']('stealth'));await asyncio.sleep(.01)
                allowed[0]=False;release.set()
                results=await asyncio.gather(first,second,return_exceptions=True)
                self.assertTrue(all(isinstance(v,BaseException)for v in results));self.assertEqual(len(self.state['clients']),1)
        asyncio.run(check())

    def test_native_sdk_accepts_aliases_and_default_but_requires_community(self):
        async def check():
            from mcp.server.mcpserver import MCPServer
            server=MCPServer('synthetic-calls');state={'charts':[],'members':0}
            token=SimpleNamespace(subject='synthetic',token='synthetic');created=[]
            async def verify(_):return token
            def provider(_):
                c=ChartClient(state,'owner');created.append(c);return c
            register_tools(server,provider,SimpleNamespace(verify_token=verify))
            with patch('catknows.hosted_tools.get_access_token',return_value=token):
                for chart in (None,'mrr','churn','retention','sources','cash_flow'):
                    arguments={'community_slug':'stealth'}
                    if chart is not None:arguments['chart']=chart
                    self.assertIsNotNone(await server.call_tool('get_revenue_analytics',arguments))
                self.assertIsNotNone(await server.call_tool('get_revenue_by_tier',{'community_slug':'stealth'}))
                before=len(created)
                with self.assertRaises(Exception):await server.call_tool('get_revenue_analytics',{})
                with self.assertRaises(Exception):await server.call_tool('get_revenue_analytics',{'community_slug':'stealth','chart':'unsupported'})
                self.assertEqual(len(created),before)
            self.assertEqual([chart for _,chart in state['charts']],['mrr','mrr','mrr','retention_members','signups_by_source','mrr_cashflow'])
            self.assertEqual(state['members'],1)
        asyncio.run(check())

    def test_queue_limit_rejects_overflow_without_extra_client_and_recovers(self):
        async def check():
            started=threading.Event();release=threading.Event()
            def slow():started.set();release.wait(2)
            reg=self.setup_registry(method=slow)
            with patch('catknows.hosted_tools.get_access_token',return_value=self.token),patch('catknows.hosted_tools.TOOL_QUEUE_LIMIT',2):
                first=asyncio.create_task(reg.tools['get_revenue_analytics']('stealth'));second=None
                try:
                    self.assertTrue(await asyncio.to_thread(started.wait,1))
                    second=asyncio.create_task(reg.tools['get_revenue_analytics']('stealth'));await asyncio.sleep(.01)
                    with self.assertRaisesRegex(ValueError,'pending'):await reg.tools['get_revenue_analytics']('stealth')
                    self.assertEqual(len(self.state['clients']),1)
                finally:release.set()
                await asyncio.gather(first,second);await reg.tools['get_revenue_analytics']('stealth')
                self.assertEqual(len(self.state['clients']),3)
        asyncio.run(check())

    def test_incomplete_member_pagination_still_fails_closed_with_fixed_reason(self):
        async def check():
            reg=self.setup_registry()
            batch=Batch([]);batch.incomplete=True
            with patch('catknows.hosted_tools.get_access_token',return_value=self.token),patch.object(ChartClient,'members',return_value=batch):
                with self.assertLogs('stealth.hosted.tool_failure',level='WARNING') as logs:
                    with self.assertRaises(ValueError):await reg.tools['get_revenue_by_tier']('stealth')
            self.assertIn('coverage_incomplete','\n'.join(logs.output))
            self.assertTrue(all(c.closed for c in self.state['clients']))
        asyncio.run(check())

    def test_fixed_failure_logs_never_include_arguments_or_exceptions(self):
        from catknows.hosted_security import install_private_logging,tool_failure,safe_tool_failure
        previous=logging.getLogRecordFactory();out=io.StringIO();handler=logging.StreamHandler(out)
        logger=logging.getLogger('stealth.hosted.tool_failure');logger.addHandler(handler)
        try:
            install_private_logging();tool_failure('get_revenue_analytics','community_denied')
            self.assertIn('tool_failure tool=get_revenue_analytics reason=community_denied',out.getvalue())
            for value in ({'tool':[],'reason':{}},{'tool':'synthetic-private','reason':'upstream_failed'},'synthetic-private',None):
                self.assertEqual(safe_tool_failure(value),'tool_failure_invalid');logger.warning(value)
            try:raise ValueError('synthetic-private-token')
            except ValueError:logger.exception({'tool':'get_revenue_by_tier','reason':'upstream_failed'})
            self.assertNotIn('synthetic-private',out.getvalue());self.assertNotIn('Traceback',out.getvalue())
        finally:logging.setLogRecordFactory(previous);logger.removeHandler(handler)
