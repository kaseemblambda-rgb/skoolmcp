"""Exact post-password navigation completion; synthetic ASGI/browser objects only."""
import asyncio
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlencode, urlsplit

from catknows.hosted_browser_service import LoginBrowser, allowed_request, build_browser_app, LOGIN
from catknows.hosted_server import build_app
import test_hosted_popup as popup
from test_hosted_login import request as private_request

ROOT = 'https://www.skool.com/'
PASSWORD = 'https://api2.skool.com/auth/login'


def attach(browser, auth='synthetic-auth'):
    page=SimpleNamespace(close=AsyncMock(),evaluate=AsyncMock(),screenshot=AsyncMock(return_value=b'synthetic-frame'),
        mouse=SimpleNamespace(click=AsyncMock()),keyboard=SimpleNamespace(type=AsyncMock(),insert_text=AsyncMock(),press=AsyncMock()),frames=[])
    page.main_frame=SimpleNamespace(page=page,url=LOGIN)
    browser.page=page
    browser.context=SimpleNamespace(cookies=AsyncMock(return_value=[
        {'name':'auth_token','value':auth},{'name':'aws-waf-token','value':'synthetic-waf'}]))
    return browser


def browser():
    return attach(LoginBrowser())


def response(worker,status=200,url=PASSWORD,method='POST',kind='fetch',frame=None):
    req=SimpleNamespace(url=url,method=method,resource_type=kind,frame=frame or worker.page.main_frame)
    return SimpleNamespace(url=url,status=status,request=req)


def root_route(worker,url=ROOT,method='GET',kind='document',frame=None):
    return SimpleNamespace(request=SimpleNamespace(url=url,method=method,resource_type=kind,
        frame=frame or worker.page.main_frame),continue_=AsyncMock(),abort=AsyncMock(),fulfill=AsyncMock())


class CompletionTests(unittest.TestCase):
    def test_success_root_is_stopped_locally_and_uses_origin_scoped_cookies(self):
        async def check():
            for url in (ROOT,'https://www.skool.com:443/'):
                worker=browser();worker.observe_response(response(worker));route=root_route(worker,url)
                self.assertFalse(allowed_request(url,'GET','document'))
                await worker.route_request(route)
                route.fulfill.assert_awaited_once_with(status=204,headers={'Cache-Control':'no-store'},body='')
                route.continue_.assert_not_awaited();route.abort.assert_not_awaited()
                result=await worker.command({'type':'frame'})
                self.assertEqual(result['session']['auth_token'],'synthetic-auth')
                self.assertEqual(result['session']['waf_token'],'synthetic-waf')
                worker.context.cookies.assert_awaited_once_with([ROOT])
                worker.page.screenshot.assert_not_awaited();worker.page.close.assert_not_awaited()
                await worker.close();self.assertIsNone(worker._completion)
        asyncio.run(check())

    def test_root_before_login_aborts_and_never_captures_even_if_cookie_mock_has_data(self):
        async def check():
            worker=browser();route=root_route(worker)
            await worker.route_request(route)
            route.abort.assert_awaited_once_with('blockedbyclient');route.fulfill.assert_not_awaited()
            route.continue_.assert_not_awaited();worker.context.cookies.assert_not_awaited()
            with self.assertRaises(ValueError):await worker.command({'type':'frame'})
            self.assertIsNone(worker._completion)
            await worker.close()
        asyncio.run(check())

    def test_wrong_origins_ports_paths_queries_and_fragments_never_signal_success(self):
        async def check():
            for url in ('http://www.skool.com/','https://www.skool.com:444/','https://www.skool.com.evil.test/',
                'https://user@www.skool.com/','https://user:synthetic@www.skool.com/','https://www.skool.com./',
                'https://www.skool.com/stealth','https://www.skool.com/home','https://www.skool.com//',
                'https://www.skool.com/?next=home','https://www.skool.com/#home','https://127.0.0.1/'):
                worker=browser();worker.observe_response(response(worker));route=root_route(worker,url)
                self.assertFalse(worker.success_redirect(url),url)
                await worker.route_request(route)
                route.abort.assert_awaited_once();route.fulfill.assert_not_awaited();route.continue_.assert_not_awaited()
                worker.context.cookies.assert_not_awaited();self.assertIsNone(worker._completion)
                await worker.close()
        asyncio.run(check())

    def test_root_requires_main_frame_get_document_from_this_browser(self):
        async def check():
            for variant in ('subframe','other-page','post','fetch'):
                worker=browser();worker.observe_response(response(worker))
                frame=worker.page.main_frame;method='GET';kind='document'
                if variant=='subframe':frame=SimpleNamespace(page=worker.page)
                if variant=='other-page':frame=SimpleNamespace(page=SimpleNamespace())
                if variant=='post':method='POST'
                if variant=='fetch':kind='fetch'
                route=root_route(worker,method=method,kind=kind,frame=frame)
                await worker.route_request(route)
                route.abort.assert_awaited_once();route.fulfill.assert_not_awaited()
                self.assertIsNone(worker._completion);worker.context.cookies.assert_not_awaited()
                await worker.close()
        asyncio.run(check())

    def test_only_own_successful_password_post_response_arms_completion(self):
        async def check():
            for changes in ({'status':403},{'status':500},{'status':201},{'method':'GET'},
                {'url':'https://api2.skool.com/auth/login-with-code'},
                {'url':'https://api2.skool.com.evil.test/auth/login'},
                {'url':'https://api2.skool.com:444/auth/login'},
                {'url':'https://017ae153ccc5.edge.sdk.awswaf.com/verify'}):
                worker=browser();worker.observe_response(response(worker,**changes))
                self.assertFalse(worker.success_redirect(ROOT));await worker.close()
            worker=browser();foreign=SimpleNamespace(page=SimpleNamespace())
            worker.observe_response(response(worker,frame=foreign));self.assertFalse(worker.success_redirect(ROOT))
            # Diagnostic status alone is deliberately not an auth-success signal.
            worker.network.login_status=200;self.assertFalse(worker.success_redirect(ROOT))
            await worker.close()
        asyncio.run(check())

    def test_new_password_attempt_and_failed_response_clear_previous_success(self):
        async def check():
            worker=browser();worker.observe_response(response(worker));self.assertTrue(worker.success_redirect(ROOT))
            req=response(worker).request
            route=SimpleNamespace(request=req,continue_=AsyncMock(),abort=AsyncMock())
            await worker.route_request(route);self.assertFalse(worker.success_redirect(ROOT))
            worker.observe_response(response(worker));self.assertTrue(worker.success_redirect(ROOT))
            worker.observe_response(response(worker,status=403));self.assertFalse(worker.success_redirect(ROOT))
            await worker.close()
        asyncio.run(check())

    def test_navigation_event_race_and_error_document_do_not_close_completion(self):
        async def check():
            worker=browser();worker.observe_response(response(worker))
            worker.page.main_frame.url=ROOT
            await worker.check_navigation(worker.page.main_frame)
            worker.page.evaluate.assert_awaited_once_with('window.stop()')
            task=worker._completion
            await worker.route_request(root_route(worker));self.assertIs(worker._completion,task)
            worker.page.main_frame.url='chrome-error://chromewebdata/'
            await worker.check_navigation(worker.page.main_frame)
            self.assertIn('session',await worker.command({'type':'frame'}))
            worker.page.close.assert_not_awaited();worker.page.screenshot.assert_not_awaited()
            await worker.close()
        asyncio.run(check())

    def test_unarmed_error_document_and_bad_navigation_still_close_page(self):
        async def check():
            for url in ('chrome-error://chromewebdata/','https://www.skool.com/stealth',ROOT):
                worker=browser();worker.page.main_frame.url=url
                await worker.check_navigation(worker.page.main_frame)
                worker.page.close.assert_awaited_once();self.assertIsNone(worker._completion)
                with self.assertRaises(ValueError):await worker.command({'type':'frame'})
                await worker.close()
        asyncio.run(check())

    def test_interrupted_click_returns_completion_only_after_exact_signal(self):
        async def check():
            worker=browser()
            async def click(*args):
                worker.observe_response(response(worker));await worker.route_request(root_route(worker))
                raise RuntimeError('synthetic interrupted action')
            worker.page.mouse.click.side_effect=click
            self.assertIn('session',await worker.command({'type':'click','x':10,'y':10}))
            await worker.close()
            worker=browser();worker.page.mouse.click.side_effect=RuntimeError('synthetic interrupted action')
            with self.assertRaises(RuntimeError):await worker.command({'type':'click','x':10,'y':10})
            await worker.close()
        asyncio.run(check())

    def test_screenshot_race_returns_session_instead_of_blank_frame(self):
        async def check():
            worker=browser()
            worker.context.cookies.side_effect=[[],[{'name':'auth_token','value':'synthetic-auth'},
                {'name':'aws-waf-token','value':'synthetic-waf'}]]
            async def screenshot(**kwargs):
                worker.observe_response(response(worker));await worker.route_request(root_route(worker))
                raise RuntimeError('synthetic interrupted document')
            worker.page.screenshot.side_effect=screenshot
            self.assertIn('session',await worker.command({'type':'frame'}))
            await worker.close()
        asyncio.run(check())

    def test_cookie_settling_is_bounded_and_incomplete_sessions_fail_closed(self):
        async def check():
            for cookies in ([],[{'name':'auth_token','value':'synthetic-auth'}],[{'name':'aws-waf-token','value':'synthetic-waf'}]):
                worker=browser();worker.context.cookies.return_value=cookies;worker.observe_response(response(worker))
                await worker.route_request(root_route(worker))
                with self.assertRaisesRegex(ValueError,'^Skool session unavailable$'):
                    await worker.command({'type':'frame'})
                worker.page.screenshot.assert_not_awaited();await worker.close()
        with patch('catknows.hosted_browser_service.SESSION_CAPTURE_TIMEOUT',.01):asyncio.run(check())

    def test_cookie_settling_can_finish_after_the_success_navigation_is_stopped(self):
        async def check():
            worker=browser()
            worker.context.cookies.side_effect=[[],[{'name':'auth_token','value':'synthetic-auth'},
                {'name':'aws-waf-token','value':'synthetic-waf'}]]
            worker.observe_response(response(worker));route=root_route(worker)
            await worker.route_request(route)
            result=await worker.command({'type':'frame'})
            self.assertIn('session',result);self.assertEqual(worker.context.cookies.await_count,2)
            route.continue_.assert_not_awaited();worker.page.screenshot.assert_not_awaited()
            await worker.close()
        asyncio.run(check())

    def test_cookie_api_errors_are_fixed_and_drop_original_exception_context(self):
        async def check():
            worker=browser();worker.context.cookies.side_effect=RuntimeError('synthetic-private-cookie')
            worker.observe_response(response(worker));await worker.route_request(root_route(worker))
            with self.assertRaisesRegex(ValueError,'^Skool session unavailable$') as error:
                await worker.command({'type':'frame'})
            self.assertIsNone(error.exception.__context__);self.assertIsNone(error.exception.__cause__)
            self.assertNotIn('synthetic-private-cookie',repr(error.exception));await worker.close()
        asyncio.run(check())

    def test_screenshot_race_failure_does_not_retain_ui_exception_context(self):
        async def check():
            worker=browser();worker.context.cookies.side_effect=[[],RuntimeError('synthetic-private-cookie')]
            async def screenshot(**kwargs):
                worker.observe_response(response(worker));await worker.route_request(root_route(worker))
                raise RuntimeError('synthetic-private-ui')
            worker.page.screenshot.side_effect=screenshot
            with self.assertRaisesRegex(ValueError,'^Skool session unavailable$') as error:
                await worker.command({'type':'frame'})
            self.assertIsNone(error.exception.__context__)
            self.assertNotIn('synthetic-private',repr(error.exception));await worker.close()
        asyncio.run(check())

    def test_disallowed_navigation_after_success_signal_still_blocks_session_return(self):
        async def check():
            worker=browser();worker.observe_response(response(worker));await worker.route_request(root_route(worker))
            worker.page.main_frame.url='https://www.skool.com/stealth'
            await worker.check_navigation(worker.page.main_frame)
            worker.page.close.assert_awaited_once()
            with self.assertRaises(ValueError):await worker.command({'type':'frame'})
            await worker.close();self.assertIsNone(worker._completion)
        asyncio.run(check())

    def test_close_cancels_capture_and_browser_state_is_isolated(self):
        async def check():
            first=browser();second=browser();first.observe_response(response(first))
            never=asyncio.Event()
            async def cookies(*args):await never.wait()
            first.context.cookies.side_effect=cookies
            await first.route_request(root_route(first));task=first._completion
            await asyncio.sleep(0);await first.close()
            self.assertTrue(task.done());self.assertIsNone(first._completion)
            self.assertFalse(second.success_redirect(ROOT));self.assertIsNone(second._completion)
            self.assertFalse(second._closed);second.context.cookies.assert_not_awaited()
            await second.close()
        asyncio.run(check())


class CompletionFlowTests(unittest.TestCase):
    def setUp(self):
        self.case=popup.PopupTests();self.case.setUp();self.addCleanup(self.case.doCleanups)

    async def flow(self,paid):
        case=self.case
        if not paid:case.store.paid.clear()
        created=[]
        class SyntheticBrowser(LoginBrowser):
            async def start(self):attach(self);created.append(self);self.signalled=False;self.closes=0
            async def command(self,value):
                if not self.signalled:
                    self.signalled=True;self.observe_response(response(self));self.redirect=root_route(self)
                    await self.route_request(self.redirect)
                return await super().command(value)
            async def close(self):
                await super().close();self.closes+=1
        secret='synthetic-private-service-secret-only'
        private=build_browser_app(SyntheticBrowser,secret)
        loop=asyncio.get_running_loop()
        async def call(operation,job,command):
            status,messages=await private_request(private,'/job',
                {'operation':operation,'job':job,'command':command},{'x-browser-secret':secret})
            self.assertEqual(status,200)
            return json.loads(b''.join(m.get('body',b'')for m in messages))
        class Bridge:
            def call(self,operation,job,command=None):
                return asyncio.run_coroutine_threadsafe(call(operation,job,command),loop).result(timeout=3)
        case.app=build_app(case.settings,oauth_provider=case.provider,browser_factory=Bridge,identity_reader=lambda _:case.identity)
        async with private.router.lifespan_context(private),case.app.router.lifespan_context(case.app):
            await case.begin();messages=await case.stream()
            self.assertEqual(len(created),1);self.assertEqual(created[0].closes,1)
            self.assertTrue(created[0]._closed);self.assertIsNone(created[0]._completion)
            created[0].redirect.fulfill.assert_awaited_once();created[0].redirect.continue_.assert_not_awaited()
            if not paid:
                self.assertEqual(messages,[{'error':'Paid SFC membership is required.'}])
                self.assertEqual(case.store.sessions,{});self.assertEqual(case.store.codes,{})
                self.assertEqual(case.store.flows,{})
                return
            self.assertEqual(messages,[{'ready':True}]);self.assertEqual(case.store.sessions,{})
            status,_,body=await case.decide();self.assertEqual(status,200)
            query=parse_qs(urlsplit(json.loads(body)['redirect']).query)
            self.assertEqual(set(query),{'code','state','iss'})
            fields=dict(grant_type='authorization_code',client_id=case.client.client_id,
                code=query['code'][0],code_verifier=case.verifier,redirect_uri=case.callback,resource=case.settings.resource)
            status,_,body=await popup.http(case.app,'/token','POST',urlencode(fields).encode(),
                {'content-type':'application/x-www-form-urlencoded'})
            self.assertEqual(status,200);token=json.loads(body)['access_token']
            status,_,_=await popup.http(case.app,'/mcp','POST',{'jsonrpc':'2.0','id':1,'method':'tools/call',
                'params':{'name':'status','arguments':{}}},{'authorization':'Bearer '+token,'content-type':'application/json'})
            self.assertEqual(status,200)
            self.assertEqual(len(case.store.sessions),1)
            self.assertNotIn('synthetic-auth',json.dumps(case.store.sessions))

    def test_success_redirect_capture_paid_check_consent_token_and_browser_close(self):
        asyncio.run(self.flow(True))

    def test_same_success_redirect_cannot_bypass_unpaid_membership_denial(self):
        asyncio.run(self.flow(False))


class LifecycleTests(unittest.TestCase):
    def run_race(self,step,cookies=True):
        async def check():
            worker=browser();worker.context.cookies.return_value=[]
            started=asyncio.Event();cancelled=asyncio.Event()
            async def stuck(*args,**kwargs):
                started.set()
                try:await asyncio.Event().wait()
                finally:cancelled.set()
            if step=='input':worker.page.mouse.click.side_effect=stuck
            elif step=='cookies':worker.context.cookies.side_effect=stuck
            else:worker.page.screenshot.side_effect=stuck
            command=asyncio.create_task(worker.command({'type':'click','x':1,'y':1} if step=='input' else {'type':'frame'}))
            await asyncio.wait_for(started.wait(),1)
            worker.context.cookies.side_effect=None
            worker.context.cookies.return_value=attach(browser()).context.cookies.return_value if cookies else []
            worker.observe_response(response(worker));await worker.route_request(root_route(worker))
            if cookies:
                value=await asyncio.wait_for(command,.5)
                self.assertIn('session',value)
            else:
                with self.assertRaisesRegex(ValueError,'Skool session unavailable'):
                    await asyncio.wait_for(command,.5)
            self.assertTrue(cancelled.is_set());await worker.close()
        asyncio.run(check())

    def test_completion_interrupts_hung_input(self):self.run_race('input')
    def test_completion_interrupts_hung_screenshot(self):self.run_race('screenshot')
    def test_completion_interrupts_pre_redirect_cookie_read(self):self.run_race('cookies')
    def test_failed_capture_interrupts_hung_screenshot_without_secret_exception(self):
        with patch('catknows.hosted_browser_service.SESSION_CAPTURE_TIMEOUT',.01):self.run_race('screenshot',False)

    def test_poll_cancellation_drains_action_and_waiter(self):
        async def check():
            worker=browser();worker.context.cookies.return_value=[]
            started=asyncio.Event();stopped=asyncio.Event()
            async def screenshot(*args,**kwargs):
                started.set()
                try:await asyncio.Event().wait()
                finally:stopped.set()
            worker.page.screenshot.side_effect=screenshot
            command=asyncio.create_task(worker.command({'type':'frame'}));await started.wait()
            command.cancel()
            with self.assertRaises(asyncio.CancelledError):await command
            self.assertTrue(stopped.is_set());self.assertIsNone(worker._completion)
            await worker.close();await asyncio.sleep(0)
            self.assertEqual([t for t in asyncio.all_tasks()if t is not asyncio.current_task()],[])
        asyncio.run(check())

    def capture_logs(self,mode):
        async def check():
            worker=browser()
            if mode=='no_auth':worker.context.cookies.return_value=[{'name':'aws-waf-token','value':'synthetic-private-waf'}]
            elif mode=='no_waf':worker.context.cookies.return_value=[{'name':'auth_token','value':'synthetic-private-auth'}]
            elif mode in ('timeout','closed'):
                async def stuck(*args):await asyncio.Event().wait()
                worker.context.cookies.side_effect=stuck
            elif mode=='error':worker.context.cookies.side_effect=RuntimeError('synthetic-private-cookie@example.test')
            with self.assertLogs('stealth.hosted.login_lifecycle',level='INFO') as log:
                worker.observe_response(response(worker));await worker.route_request(root_route(worker))
                if mode=='closed':
                    await asyncio.sleep(0);await worker.close()
                else:
                    if mode=='denied':worker._navigation_denied=True
                    if mode=='ok':self.assertIn('session',await worker.command({'type':'frame'}))
                    else:
                        with self.assertRaisesRegex(ValueError,'Skool session unavailable'):
                            await worker.command({'type':'frame'}) if mode!='denied' else await worker._completion
                    await worker.close()
            output='\n'.join(log.output)
            self.assertIn('login_post_status=200',output);self.assertIn('completion_started',output)
            expected='completion_ok' if mode=='ok' else 'completion_failed reason='+('timeout' if mode=='error' else mode)
            self.assertIn(expected,output)
            for private in ('synthetic-private','synthetic-auth','synthetic-waf','cookie@example','https://','Traceback'):
                self.assertNotIn(private,output)
        with patch('catknows.hosted_browser_service.SESSION_CAPTURE_TIMEOUT',.01):asyncio.run(check())

    def test_success_lifecycle_logged(self):self.capture_logs('ok')
    def test_no_auth_lifecycle_logged(self):self.capture_logs('no_auth')
    def test_no_waf_lifecycle_logged(self):self.capture_logs('no_waf')
    def test_cookie_timeout_lifecycle_logged(self):self.capture_logs('timeout')
    def test_cookie_error_lifecycle_never_logs_exception(self):self.capture_logs('error')
    def test_closed_lifecycle_logged(self):self.capture_logs('closed')
    def test_denied_lifecycle_logged(self):self.capture_logs('denied')

    def test_lifecycle_factory_removes_arbitrary_arguments_tracebacks_and_values(self):
        import io,logging
        from catknows.hosted_security import install_private_logging,login_lifecycle,safe_login_lifecycle
        old=logging.getLogRecordFactory();stream=io.StringIO();handler=logging.StreamHandler(stream)
        logger=logging.getLogger('stealth.hosted.login_lifecycle');logger.addHandler(handler)
        try:
            install_private_logging()
            for value in ('completion_started','completion_ok','session_received','membership_check=paid','membership_check=not_paid',
                'membership_check=error','oauth_complete','login_post_status=403','completion_failed reason=no_waf'):
                login_lifecycle(value);self.assertIn(value,stream.getvalue())
            for value in ('login_post_status=200 private@example.test','completion_failed reason=synthetic-secret',{'secret':'synthetic-secret'},None):
                self.assertEqual(safe_login_lifecycle(value),'login_lifecycle_invalid');login_lifecycle(value)
            try:raise ValueError('synthetic-private-password')
            except ValueError:logger.exception('completion_ok',extra={})
            logger.info('session_received %s','synthetic-private-token')
            for value in ('synthetic-secret','synthetic-private','private@example.test','Traceback'):
                self.assertNotIn(value,stream.getvalue())
        finally:
            logger.removeHandler(handler);logging.setLogRecordFactory(old)


class StreamLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.case=popup.PopupTests();self.case.setUp();self.addCleanup(self.case.doCleanups)

    async def gateway(self,behavior='poll',paid=True):
        case=self.case
        if not paid:case.store.paid.clear()
        calls=[]
        class Bridge:
            def call(self,op,job,command=None):
                if op=='command':
                    calls.append(command)
                    if behavior=='raise':raise ValueError('synthetic-private-cookie-and-token')
                    if behavior=='error':return {'error':'synthetic-private-cookie-and-token'}
                    if len(calls)==1:return {'frame':'synthetic-frame'}
                    return {'session':{'cookie_header':'synthetic-cookie=value','auth_token':'synthetic-auth','waf_token':'synthetic-waf'}}
                return {'ok':True}
        if behavior=='identity':
            def identity(_):raise RuntimeError('synthetic-private-identity')
        else:identity=lambda _:case.identity
        if behavior=='membership':
            original=case.store.call
            def call(op,**kwargs):
                if op=='paid':raise RuntimeError('synthetic-private-membership')
                return original(op,**kwargs)
            case.store.call=call
        case.app=build_app(case.settings,oauth_provider=case.provider,browser_factory=Bridge,identity_reader=identity)
        queue=asyncio.Queue();messages=[]
        async def send(value):
            messages.append(value)
            if value['type']=='websocket.send' and 'frame' in json.loads(value['text']):
                await queue.put({'type':'websocket.receive','text':json.dumps({'type':'frame'})})
        with self.assertLogs('stealth.hosted.login_lifecycle',level='INFO') as logs:
            async with case.app.router.lifespan_context(case.app):
                await case.begin()
                await popup.http(case.app,'/connect/start','POST',{},
                    {'origin':case.settings.public_origin,'x-stealth-csrf':'1','x-stealth-flow':case.flow,'cookie':case.cookie})
                await queue.put({'type':'websocket.connect'})
                await queue.put({'type':'websocket.receive','text':json.dumps({'flow':case.flow})})
                await case.app(dict(type='websocket',asgi={'version':'3.0'},scheme='wss',path='/connect/stream',raw_path=b'/connect/stream',query_string=b'',
                    headers=[(b'origin',case.settings.public_origin.encode()),(b'cookie',case.cookie.encode())],
                    server=('mcp.example.test',443),client=('127.0.0.1',1),subprotocols=[]),queue.get,send)
        output='\n'.join(logs.output)
        values=[json.loads(m['text'])for m in messages if m['type']=='websocket.send']
        self.assertNotIn('synthetic-private',output+json.dumps(values));self.assertNotIn('synthetic-cookie',output+json.dumps(values))
        return output,values,calls

    def test_gateway_continues_frame_polls_until_session_then_checks_paid(self):
        async def check():
            output,values,calls=await self.gateway()
            self.assertEqual(calls,[{'type':'frame'},{'type':'frame'}]);self.assertEqual(values[-1],{'ready':True})
            for event in ('stream_started','browser_command=frame','browser_reply=frame','session_received','membership_check=paid','consent_ready'):
                self.assertIn(event,output)
            self.assertNotIn('oauth_complete',output)  # Not complete until token exchange.
        asyncio.run(check())

    def test_gateway_unpaid_session_is_denied_and_logged(self):
        async def check():
            output,values,_=await self.gateway(paid=False)
            self.assertIn('session_received',output);self.assertIn('membership_check=not_paid',output)
            self.assertEqual(values[-1],{'error':'Paid SFC membership is required.'});self.assertEqual(self.case.store.flows,{})
        asyncio.run(check())

    def test_gateway_bridge_exception_is_logged_and_member_sees_generic_error(self):
        async def check():
            output,values,_=await self.gateway('raise')
            self.assertIn('browser_command_failed',output);self.assertIn('stream_failed stage=browser',output)
            self.assertIn('error',values[-1]);self.assertEqual(self.case.store.flows,{})
        asyncio.run(check())

    def test_gateway_error_reply_is_logged_and_member_sees_generic_error(self):
        async def check():
            output,values,_=await self.gateway('error');self.assertIn('browser_reply=error',output)
            self.assertIn('error',values[-1]);self.assertEqual(self.case.store.flows,{})
        asyncio.run(check())

    def test_gateway_identity_failure_is_logged_without_claiming_membership_check(self):
        async def check():
            output,values,_=await self.gateway('identity');self.assertIn('stream_failed stage=identity',output)
            self.assertNotIn('membership_check=',output);self.assertIn('error',values[-1]);self.assertEqual(self.case.store.flows,{})
        asyncio.run(check())

    def test_gateway_membership_error_is_logged_and_denied(self):
        async def check():
            output,values,_=await self.gateway('membership');self.assertIn('membership_check=error',output)
            self.assertIn('error',values[-1]);self.assertEqual(self.case.store.flows,{})
        asyncio.run(check())


    def test_oauth_complete_only_after_code_exchange_not_consent(self):
        async def check():
            case=self.case
            with self.assertLogs('stealth.hosted.login_lifecycle',level='INFO') as logs:
                async with case.app.router.lifespan_context(case.app):
                    await case.begin();self.assertEqual(await case.stream(),[{'ready':True}])
                    status,_,body=await case.decide();self.assertEqual(status,200)
                    self.assertNotIn('oauth_complete','\n'.join(logs.output))
                    query=parse_qs(urlsplit(json.loads(body)['redirect']).query)
                    fields=dict(grant_type='authorization_code',client_id=case.client.client_id,
                        code=query['code'][0],code_verifier=case.verifier,redirect_uri=case.callback,resource=case.settings.resource)
                    status,_,_=await popup.http(case.app,'/token','POST',urlencode(fields).encode(),
                        {'content-type':'application/x-www-form-urlencoded'})
                    self.assertEqual(status,200)
                    self.assertEqual(sum('oauth_complete' in line for line in logs.output),1)
                    status,_,_=await popup.http(case.app,'/token','POST',urlencode(fields).encode(),
                        {'content-type':'application/x-www-form-urlencoded'})
                    self.assertEqual(status,400)
                    self.assertEqual(sum('oauth_complete' in line for line in logs.output),1)
        asyncio.run(check())


class PrivateCompletionFailureTests(unittest.TestCase):
    def test_capture_failure_returns_fixed_error_and_destroys_private_browser(self):
        async def check():
            created=[]
            class Worker(LoginBrowser):
                async def start(self):attach(self);self.context.cookies.return_value=[];created.append(self)
                async def command(self,value):
                    self.observe_response(response(self));await self.route_request(root_route(self))
                    return await super().command(value)
            secret='synthetic-private-browser-secret'
            app=build_browser_app(Worker,secret)
            async with app.router.lifespan_context(app):
                status,_=await private_request(app,'/job',{'operation':'start','job':'a'*64},{'x-browser-secret':secret})
                self.assertEqual(status,200)
                with self.assertLogs('stealth.hosted.login_lifecycle',level='INFO') as logs:
                    status,messages=await private_request(app,'/job',{'operation':'command','job':'a'*64,'command':{'type':'frame'}},
                        {'x-browser-secret':secret})
                self.assertEqual(status,400)
                self.assertEqual(json.loads(b''.join(m.get('body',b'')for m in messages)),{'error':'Login browser unavailable'})
                self.assertIn('completion_failed reason=no_auth','\n'.join(logs.output))
                self.assertIn('browser_command_failed','\n'.join(logs.output))
                self.assertTrue(created[0]._closed);self.assertIsNone(created[0]._completion)
        with patch('catknows.hosted_browser_service.SESSION_CAPTURE_TIMEOUT',.01):asyncio.run(check())
