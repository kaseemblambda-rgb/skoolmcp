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
