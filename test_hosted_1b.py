"""Step 1b boundary regressions, synthetic data only."""
import asyncio
import io
import json
import logging
import os
import socket
import threading
import unittest
from datetime import datetime,timezone,timedelta
from contextvars import ContextVar
from types import SimpleNamespace
from unittest.mock import AsyncMock,patch
from uuid import uuid4
from urllib.parse import urlencode,parse_qs,urlsplit

from catknows.hosted_browser_service import LoginBrowser,allowed_request,public_host_rules,WAF_HOST,BROWSER_HOSTS
from catknows.hosted_security import ClientIPResolver,RateBudget,install_private_logging
from catknows.hosted_tools import register_tools
from catknows.hosted_oauth import SkoolOAuthProvider,hashed
from catknows.hosted_popup import COOKIE,MANAGEMENT_COOKIE
import test_hosted_popup as popup_tests
http=popup_tests.http
from test_hosted_analytics import FakeClient,Registry


class BrowserPolicyTests(unittest.TestCase):
    def test_exact_waf_host_accepts_dynamic_challenge_posts(self):
        for path in ('/opaque-one/opaque-two/opaque-three','/other-endpoint','/verify','/'):
            for kind in ('fetch','xhr'):
                self.assertTrue(allowed_request('https://'+WAF_HOST+path,'POST',kind))
        self.assertTrue(allowed_request('https://'+WAF_HOST+'/opaque/challenge.js','GET','script'))
        self.assertTrue(allowed_request('https://'+WAF_HOST+'/inputs','GET','fetch'))

    def test_waf_post_exception_preserves_auth_origin_and_resource_denials(self):
        for path in ('/auth','/auth/login','/auth/google','/auth/apple','/auth/login-with-code'):
            for kind in ('fetch','xhr','document'):
                self.assertFalse(allowed_request('https://'+WAF_HOST+path,'POST',kind))
        for host in ('other.edge.sdk.awswaf.com',WAF_HOST+'.evil.test'):
            self.assertFalse(allowed_request('https://'+host+'/a/b/c','POST','fetch'))
        for method,kind in (('GET','fetch'),('PUT','fetch'),('DELETE','xhr'),('POST','script'),('POST','other'),('POST','document')):
            self.assertFalse(allowed_request('https://'+WAF_HOST+'/a/b/c',method,kind))
        for url in ('http://'+WAF_HOST+'/a/b/c','https://'+WAF_HOST+':444/a/b/c','https://user@'+WAF_HOST+'/a/b/c'):
            self.assertFalse(allowed_request(url,'POST','fetch'))

    def test_www_next_static_get_accepts_other_and_static_resource_types(self):
        url='https://www.skool.com/_next/static/chunks/synthetic-asset.js'
        for kind in ('other','script','stylesheet','image','font','media','texttrack','manifest','fetch','xhr'):
            self.assertTrue(allowed_request(url,'GET',kind),kind)
        for kind in ('document','websocket'):
            self.assertFalse(allowed_request(url,'GET',kind))
        for method in ('POST','PUT','DELETE','OPTIONS'):
            self.assertFalse(allowed_request(url,method,'other'))

    def test_static_exception_does_not_expand_auth_paths_hosts_or_prefix(self):
        for path in ('/_next/static','/_next/static-lookalike/chunk.js','/_next/data/build/community.json',
                     '/auth','/auth/google','/auth/login','/auth/login-with-code','/stealth','/'):
            self.assertFalse(allowed_request('https://www.skool.com'+path,'GET','other'))
        for host in ('fonts.googleapis.com','fonts.gstatic.com','js.stripe.com','sentry.io',
                     'example.ingest.sentry.io','www.skool.com.evil.test','random.example.test'):
            self.assertFalse(allowed_request('https://'+host+'/_next/static/chunk.js','GET','other'))
            self.assertFalse(allowed_request('https://'+host+'/a/b/c','POST','fetch'))
        self.assertTrue(allowed_request('https://api2.skool.com/auth/login','POST','fetch'))
        for path in ('/auth/google','/auth/apple','/auth/login-with-code','/auth/login-with-code-init'):
            self.assertFalse(allowed_request('https://api2.skool.com'+path,'POST','fetch'))

    def test_route_continues_observed_waf_post_and_next_static_other(self):
        browser=LoginBrowser();page=SimpleNamespace();frame=SimpleNamespace(page=page);page.main_frame=frame;browser.page=page
        async def check():
            for url,method,kind in (('https://'+WAF_HOST+'/opaque-one/opaque-two/opaque-three','POST','fetch'),
                ('https://'+WAF_HOST+'/opaque-one/opaque-two/opaque-three','POST','xhr'),
                ('https://www.skool.com/_next/static/chunks/synthetic-asset.js','GET','other')):
                route=SimpleNamespace(request=SimpleNamespace(url=url,method=method,resource_type=kind,frame=frame),
                    continue_=AsyncMock(),abort=AsyncMock())
                await browser.route_request(route)
                route.continue_.assert_awaited_once();route.abort.assert_not_awaited()
        asyncio.run(check())

    def test_exact_skool_tracking_host_allows_background_requests_only(self):
        self.assertIn('www.skool.com',BROWSER_HOSTS)
        self.assertIn('ct.skool.com',BROWSER_HOSTS)
        self.assertIn('017ae153ccc5.edge.sdk.awswaf.com',BROWSER_HOSTS)
        for method,kind in (('GET','script'),('GET','image'),('GET','fetch'),('POST','fetch'),('POST','xhr'),('POST','ping')):
            self.assertTrue(allowed_request('https://ct.skool.com/collect',method,kind))
        for method,kind in (('GET','document'),('POST','document'),('PUT','xhr'),('GET','websocket')):
            self.assertFalse(allowed_request('https://ct.skool.com/collect',method,kind))
        for path in ('/auth/google','/auth/apple','/auth/login-with-code','/auth/login'):
            self.assertFalse(allowed_request('https://ct.skool.com'+path,'POST','fetch'))

    def test_required_external_services_and_nonexact_waf_hosts_remain_blocked(self):
        for host in ('fonts.googleapis.com','js.stripe.com','sentry.io','example.ingest.sentry.io',
                     'other.edge.sdk.awswaf.com','017ae153ccc5.edge.sdk.awswaf.com.evil.test',
                     'ct.skool.com.evil.test'):
            for resource in ('script','fetch','image','document'):
                self.assertFalse(allowed_request('https://'+host+'/challenge.js','GET',resource),host)
        for url in ('http://ct.skool.com/collect','https://ct.skool.com:444/collect',
                    'https://user@ct.skool.com/collect'):
            self.assertFalse(allowed_request(url,'POST','fetch'))

    def test_dns_pins_requested_hosts_without_wildcard_egress(self):
        with patch('catknows.hosted_browser_service.socket.getaddrinfo',
            return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('93.184.216.34',443))]):
            rules=public_host_rules()
        for host in ('www.skool.com','ct.skool.com',WAF_HOST):
            self.assertIn('MAP '+host+' 93.184.216.34',rules)
        self.assertTrue(rules.endswith('MAP * ~NOTFOUND'))
        self.assertNotIn('MAP *.edge',rules)

    def test_allowed_host_still_obeys_path_method_and_resource_policy(self):
        # Reproduce why the old hostname-only message cannot diagnose a loop.
        self.assertFalse(allowed_request('https://www.skool.com/','GET','document'))
        self.assertFalse(allowed_request('https://www.skool.com/_next/data/build/group.json','GET','fetch'))
        self.assertTrue(allowed_request('https://'+WAF_HOST+'/other-endpoint','POST','xhr'))
        self.assertTrue(allowed_request('https://www.skool.com/login','GET','document'))
        self.assertTrue(allowed_request('https://'+WAF_HOST+'/inputs','GET','xhr'))

    def test_temporary_block_diagnostic_redacts_query_userinfo_and_opaque_path(self):
        from catknows.hosted_security import blocked_request
        previous=logging.getLogRecordFactory();install_private_logging();output=io.StringIO()
        handler=logging.StreamHandler(output);logger=logging.getLogger('stealth.hosted.blocked_request');logger.addHandler(handler)
        try:
            blocked_request('https://synthetic-user:synthetic-password@www.skool.com/_next/data/synthetic-token/synthetic-group.json?secret=synthetic-query#synthetic-fragment',
                'GET','fetch')
            value=output.getvalue()
            self.assertIn('www.skool.com',value);self.assertIn('/_next/data/<redacted>/<redacted>',value)
            self.assertIn('GET',value);self.assertIn('fetch',value)
            for secret in ('synthetic-user','synthetic-password','synthetic-token','synthetic-group','synthetic-query','synthetic-fragment','https://','?'):
                self.assertNotIn(secret,value)
        finally:logger.removeHandler(handler);logging.setLogRecordFactory(previous)

    def test_login_statuses_and_counts_stay_in_server_logs_once_per_change(self):
        from catknows.hosted_browser_service import LoginDiagnostics
        from catknows.auth import Session
        previous=logging.getLogRecordFactory();install_private_logging();output=io.StringIO()
        handler=logging.StreamHandler(output);logger=logging.getLogger('stealth.hosted.login_diagnostics');logger.addHandler(handler)
        try:
            diagnostics=LoginDiagnostics()
            diagnostics.response('https://api2.skool.com/auth/login?secret=synthetic-query',200)
            diagnostics.response('https://'+WAF_HOST+'/inputs?secret=synthetic-query',200)
            diagnostics.blocked();diagnostics.failed()
            session=Session('synthetic-cookie','synthetic-auth','synthetic-waf')
            diagnostics.snapshot(session);diagnostics.snapshot(session)
            value=output.getvalue()
            self.assertEqual(len(value.splitlines()),1)
            self.assertIn('"waf_status":200',value);self.assertIn('"blocked_requests":1',value)
            self.assertIn('"failed_requests":1',value);self.assertIn('"login_status":200',value)
            for secret in ('synthetic-query','synthetic-cookie','synthetic-auth','synthetic-waf','https://'):
                self.assertNotIn(secret,value)
        finally:logger.removeHandler(handler);logging.setLogRecordFactory(previous)

    def test_diagnostic_loggers_reject_unbounded_or_secret_bearing_fields(self):
        previous=logging.getLogRecordFactory();install_private_logging();output=io.StringIO()
        handler=logging.StreamHandler(output)
        login=logging.getLogger('stealth.hosted.login_diagnostics')
        blocked=logging.getLogger('stealth.hosted.blocked_request')
        login.addHandler(handler);blocked.addHandler(handler)
        try:
            login.warning({'waf_status':200,'login_status':'synthetic-secret','blocked_requests':True,
                'failed_requests':-1,'headers':'synthetic-header','body':'synthetic-body'})
            blocked.warning({'method':'synthetic-secret','resource_type':'fetch','host':'www.skool.com',
                'path':'/inputs?token=synthetic-query','headers':'synthetic-header','cookie':'synthetic-cookie'})
            lines=output.getvalue().splitlines()
            self.assertEqual(json.loads(lines[0].split('=',1)[1]),{'waf_status':200})
            context=json.loads(lines[1].split('=',1)[1])
            self.assertEqual(set(context),{'method','resource_type','host','path'})
            self.assertEqual(context['path'],'/<redacted>')
            for value in ('synthetic-secret','synthetic-header','synthetic-body','synthetic-query','synthetic-cookie'):
                self.assertNotIn(value,output.getvalue())
        finally:
            login.removeHandler(handler);blocked.removeHandler(handler);logging.setLogRecordFactory(previous)

    def test_connect_html_and_javascript_have_no_member_debug_line(self):
        from catknows.hosted_popup import PAGE,SCRIPT
        from catknows.hosted_connect import PAGE as legacy_page,SCRIPT as legacy_script
        for value in (PAGE,SCRIPT,legacy_page,legacy_script):
            self.assertNotIn('id="diagnostics"',value)
            self.assertNotIn('Security check HTTP',value)
            self.assertNotIn('Blocked requests:',value)
            self.assertNotIn('Failed requests:',value)
            self.assertNotIn('v.diagnostics',value)

    def test_actual_allowed_host_denial_emits_safe_request_context(self):
        previous=logging.getLogRecordFactory();install_private_logging();output=io.StringIO()
        handler=logging.StreamHandler(output);logger=logging.getLogger('stealth.hosted.blocked_request');logger.addHandler(handler)
        try:
            browser=LoginBrowser();page=SimpleNamespace();frame=SimpleNamespace(page=page);page.main_frame=frame;browser.page=page
            route=SimpleNamespace(request=SimpleNamespace(url='https://www.skool.com/_next/data/opaque-build/opaque-group.json?token=synthetic-secret',
                method='GET',resource_type='fetch',frame=frame),continue_=AsyncMock(),abort=AsyncMock())
            asyncio.run(browser.route_request(route))
            route.abort.assert_awaited_once_with('blockedbyclient');route.continue_.assert_not_awaited()
            value=output.getvalue()
            self.assertIn('"resource_type":"fetch"',value)
            self.assertIn('"method":"GET"',value);self.assertIn('"host":"www.skool.com"',value)
            for secret in ('synthetic-secret','opaque-build','opaque-group','?token='):
                self.assertNotIn(secret,value)
        finally:logger.removeHandler(handler);logging.setLogRecordFactory(previous)

    def test_active_connect_stream_sends_frame_without_private_diagnostics(self):
        case=popup_tests.PopupTests();case.setUp();self.addCleanup(case.doCleanups)
        class Bridge:
            def __init__(self):self.frames=0
            def call(self,operation,job,command=None):
                if operation!='command':return {'ok':True}
                self.frames+=1
                if self.frames==1:
                    return {'frame':'synthetic-frame','diagnostics':{'waf_status':200,'blocked_requests':3,'failed_requests':2}}
                return {'session':{'cookie_header':'synthetic-cookie=value','auth_token':'synthetic-auth','waf_token':'synthetic-waf'}}
        from catknows.hosted_server import build_app
        case.app=build_app(case.settings,oauth_provider=case.provider,browser_factory=Bridge,identity_reader=lambda _:case.identity)
        async def check():
            await case.begin()
            status,_,_=await http(case.app,'/connect/start','POST',{},
                {'origin':case.settings.public_origin,'x-stealth-csrf':'1','x-stealth-flow':case.flow,'cookie':case.cookie})
            self.assertEqual(status,200)
            queue=asyncio.Queue();messages=[]
            for message in ({'type':'websocket.connect'},
                {'type':'websocket.receive','text':json.dumps({'flow':case.flow})},
                {'type':'websocket.receive','text':json.dumps({'type':'frame'})}):
                await queue.put(message)
            async def send(message):messages.append(message)
            await case.app(dict(type='websocket',asgi={'version':'3.0'},scheme='wss',path='/connect/stream',
                raw_path=b'/connect/stream',query_string=b'',headers=[(b'origin',case.settings.public_origin.encode()),
                    (b'cookie',case.cookie.encode())],server=('mcp.example.test',443),client=('127.0.0.1',1),subprotocols=[]),queue.get,send)
            frames=[json.loads(message['text'])for message in messages if message['type']=='websocket.send']
            self.assertEqual(frames,[{'frame':'synthetic-frame'},{'ready':True}])
        asyncio.run(check())

    def test_route_actually_aborts_social_codes_external_navigation_and_private_ips(self):
        browser=LoginBrowser();page=SimpleNamespace();main=SimpleNamespace(page=page);page.main_frame=main;browser.page=page
        urls=[('https://accounts.google.com/o/oauth2/auth','GET','document'),
              ('https://appleid.apple.com/auth/authorize','GET','document'),
              ('https://random.example.test/asset.js','GET','script'),
              ('https://www.skool.com/stealth','GET','document'),
              ('https://www.skool.com/auth/google','POST','fetch'),
              ('https://api2.skool.com/auth/apple','POST','xhr'),
              ('https://api2.skool.com/auth/login-with-code','POST','fetch'),
              ('https://api2.skool.com/auth/login-with-code-init','POST','fetch'),
              ('https://api2.skool.com/auth/login-with-token','POST','xhr'),
              ('https://api2.skool.com/auth/login','GET','document'),
              ('https://169.254.169.254/latest/meta-data/','GET','fetch'),
              ('https://metadata.google.internal/computeMetadata/v1/','GET','fetch'),
              ('https://127.0.0.1/','GET','fetch'),('https://10.0.0.1/','GET','image'),
              ('https://[::1]/','GET','fetch'),('https://[fd00::1]/','GET','fetch'),
              ('https://'+WAF_HOST+'/inputs','GET','document'),
              ('https://'+WAF_HOST+'/auth/login','POST','fetch'),
              ('https://other.edge.sdk.awswaf.com/challenge.js','GET','script'),
              ('https://fonts.googleapis.com/css','GET','stylesheet')]
        urls += [('https://'+host+'/external','GET',kind)for host in ('accounts.google.com','appleid.apple.com','random.example.test')for kind in ('script','xhr','image')]
        async def check():
            for url,method,kind in urls:
                with self.subTest(url=url):
                    route=SimpleNamespace(request=SimpleNamespace(url=url,method=method,resource_type=kind,frame=main),
                        continue_=AsyncMock(),abort=AsyncMock())
                    await browser.route_request(route)
                    route.abort.assert_awaited_once_with('blockedbyclient');route.continue_.assert_not_awaited()
            for url,method,kind in [('https://www.skool.com/login','GET','document'),
                ('https://api2.skool.com/auth/login','POST','fetch'),
                ('https://'+WAF_HOST+'/challenge.js','GET','script'),
                ('https://'+WAF_HOST+'/inputs?client=browser','GET','xhr'),
                ('https://'+WAF_HOST+'/verify','POST','xhr'),
                ('https://'+WAF_HOST+'/captcha.png','GET','image')]:
                route=SimpleNamespace(request=SimpleNamespace(url=url,method=method,resource_type=kind,frame=main),
                    continue_=AsyncMock(),abort=AsyncMock())
                await browser.route_request(route);route.continue_.assert_awaited_once();route.abort.assert_not_awaited()
            foreign=SimpleNamespace(page=SimpleNamespace())
            route=SimpleNamespace(request=SimpleNamespace(url='https://www.skool.com/login',method='GET',resource_type='document',frame=foreign),
                continue_=AsyncMock(),abort=AsyncMock())
            await browser.route_request(route);route.abort.assert_awaited_once()
        asyncio.run(check())

    def test_new_pages_close_and_dns_is_public_pinned_and_fail_closed(self):
        browser=LoginBrowser();primary=SimpleNamespace(close=AsyncMock());popup=SimpleNamespace(close=AsyncMock())
        async def check():
            browser.opened_page(primary);browser.opened_page(popup);await asyncio.sleep(0)
            primary.close.assert_not_awaited();popup.close.assert_awaited_once()
        asyncio.run(check())
        def answer(host,port,**kwargs):return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('93.184.216.34',443))]
        with patch('catknows.hosted_browser_service.socket.getaddrinfo',side_effect=answer)as dns:
            rules=public_host_rules()
            self.assertIn('MAP * ~NOTFOUND',rules)
            self.assertEqual({call.args[0]for call in dns.call_args_list},BROWSER_HOSTS)
        for ip in ('127.0.0.1','169.254.169.254','10.0.0.1','::1','fd00::1','224.0.0.1','0.0.0.0','255.255.255.255'):
            with patch('catknows.hosted_browser_service.socket.getaddrinfo',return_value=[(socket.AF_INET,1,6,'',(ip,443))]):
                with self.assertRaises(ValueError):public_host_rules()

    def test_block_logging_has_only_hostname_not_url_body_or_credentials(self):
        previous=logging.getLogRecordFactory();install_private_logging();output=io.StringIO()
        handler=logging.StreamHandler(output);logger=logging.getLogger('stealth.hosted.blocked_host');logger.addHandler(handler)
        try:
            browser=LoginBrowser();page=SimpleNamespace();frame=SimpleNamespace(page=page);page.main_frame=frame;browser.page=page
            route=SimpleNamespace(request=SimpleNamespace(url='https://accounts.google.com/private?cookie=synthetic-cookie',method='GET',resource_type='document',frame=frame),continue_=AsyncMock(),abort=AsyncMock())
            asyncio.run(browser.route_request(route));value=output.getvalue()
            self.assertIn('blocked_host=accounts.google.com',value)
            for secret in ('private','synthetic-cookie','https://','?cookie='):self.assertNotIn(secret,value)
        finally:logger.removeHandler(handler);logging.setLogRecordFactory(previous)

    def test_worker_global_capacity_returns_429_and_releases_on_close(self):
        from catknows.hosted_browser_service import build_browser_app
        from test_hosted_login import request
        created=[]
        class Browser:
            async def start(self):created.append(self)
            async def command(self,command):return {'frame':'synthetic'}
            async def close(self):pass
        app=build_browser_app(Browser,'synthetic-'*5)
        async def check():
            async with app.router.lifespan_context(app):
                headers={'x-browser-secret':'synthetic-'*5}
                for job,status in [('a',200),('b',200),('c',429)]:
                    actual,messages=await request(app,'/job',{'operation':'start','job':job*64},headers)
                    self.assertEqual(actual,status)
                    self.assertEqual(dict(messages[0]['headers'])[b'x-content-type-options'],b'nosniff')
                self.assertEqual(len(created),2)
                await request(app,'/job',{'operation':'close','job':'a'*64},headers)
                self.assertEqual((await request(app,'/job',{'operation':'start','job':'c'*64},headers))[0],200)
        asyncio.run(check())


class TrustedProxyTests(unittest.TestCase):
    def test_only_render_peers_can_supply_forwarded_addresses(self):
        resolver=ClientIPResolver(['10.77.0.0/24'],['173.245.48.0/20'])
        def scope(peer,xff):return {'client':(peer,1),'headers':[(b'x-forwarded-for',xff.encode())]}
        self.assertEqual(resolver.resolve(scope('10.77.0.9','1.1.1.1, 8.8.8.8, 173.245.48.2')),'8.8.8.8')
        self.assertEqual(resolver.resolve(scope('10.77.0.9','9.9.9.9, 8.8.8.8, 173.245.48.2')),'8.8.8.8')
        self.assertEqual(resolver.resolve(scope('8.8.4.4','forged-non-ip')),'8.8.4.4')
        self.assertEqual(resolver.resolve(scope('10.77.0.9','::ffff:8.8.8.8')),'8.8.8.8')
        for chain in ('','not-an-ip','8.8.8.8:123','173.245.48.2'):
            with self.assertRaises(ValueError):resolver.resolve(scope('10.77.0.9',chain))
        with self.assertRaises(ValueError):resolver.resolve({'client':('10.77.0.9',1),'headers':[]})
        with self.assertRaises(ValueError):ClientIPResolver(['0.0.0.0/0'],[])
        with patch.dict(os.environ,{'RENDER':'true','HOSTED_RENDER_PROXY_CIDRS':'[]'}):
            with self.assertRaises(ValueError):ClientIPResolver()


class PopupHardeningTests(popup_tests.PopupTests):
    # Reuse the fixture without re-running the parent's cases in this subclass.
    def test_authorize_rate_limit_uses_resolved_client_not_leftmost_or_proxy(self):
        async def check():
            self.app.ips=ClientIPResolver(['10.77.0.0/24'],['173.245.48.0/20'])
            self.app.authorization_budget=RateBudget(1)
            for xff,expected in [('1.1.1.1,8.8.8.8,173.245.48.2',400),('9.9.9.9,8.8.8.8,173.245.48.2',429),('1.1.1.1,8.8.4.4,173.245.48.2',400)]:
                status,_,_=await http(self.app,'/authorize',headers={'x-forwarded-for':xff},client=('10.77.0.9',1))
                self.assertEqual(status,expected)
            self.assertEqual(set(self.app.authorization_budget.entries),{'8.8.8.8','8.8.4.4'})
        asyncio.run(check())

    def test_explicit_s256_redirect_mismatch_and_security_headers(self):
        async def check():
            fields={'client_id':self.client.client_id,'redirect_uri':self.callback,'response_type':'code','code_challenge':self.challenge,'resource':self.settings.resource}
            for method in (None,'plain'):
                query={**fields}
                if method:query['code_challenge_method']=method
                status,_,_=await http(self.app,'/authorize?'+urlencode(query));self.assertEqual(status,400)
                status,_,_=await http(self.app,'/authorize','POST',urlencode(query).encode(),{'content-type':'application/x-www-form-urlencoded'});self.assertEqual(status,400)
            await self.begin();await self.stream()
            status,headers,body=await self.decide();self.assertEqual(status,200)
            management=[v for v in headers[b'set-cookie'].decode().split('\n')if v.startswith(MANAGEMENT_COOKIE+'=')][0].split(';')[0].split('=',1)[1]
            old=self.cookie.split('=',1)[1];self.assertNotEqual(management,old);self.assertTrue(management.startswith('st_m_'))
            code=parse_qs(urlsplit(json.loads(body)['redirect']).query)['code'][0]
            token_fields=dict(grant_type='authorization_code',client_id=self.client.client_id,code=code,code_verifier=self.verifier,
                redirect_uri='https://wrong.example.test/callback',resource=self.settings.resource)
            status,_,body=await http(self.app,'/token','POST',urlencode(token_fields).encode(),{'content-type':'application/x-www-form-urlencoded'})
            self.assertEqual(status,400);self.assertEqual(json.loads(body)['error'],'invalid_request')
            for path,method,body in [('/connect/skool','GET',None),('/connect/popup.js','GET',None),('/connect/bootstrap','POST',{})]:
                status,headers,_=await http(self.app,path,method,body)
                self.assertEqual(headers[b'x-frame-options'],b'DENY');self.assertEqual(headers[b'x-content-type-options'],b'nosniff')
        asyncio.run(check())

    def test_expired_authorization_code_is_rejected_at_token_endpoint(self):
        async def check():
            await self.begin();await self.stream()
            status,_,body=await self.decide();self.assertEqual(status,200)
            code=parse_qs(urlsplit(json.loads(body)['redirect']).query)['code'][0]
            self.store.codes[hashed(code)]['expires_at']=(datetime.now(timezone.utc)-timedelta(seconds=5)).isoformat()
            fields=dict(grant_type='authorization_code',client_id=self.client.client_id,code=code,
                code_verifier=self.verifier,redirect_uri=self.callback,resource=self.settings.resource)
            status,_,body=await http(self.app,'/token','POST',urlencode(fields).encode(),{'content-type':'application/x-www-form-urlencoded'})
            self.assertEqual(status,400);self.assertEqual(json.loads(body)['error'],'invalid_grant')
            self.assertEqual(self.store.tokens,{})
        asyncio.run(check())

    def test_global_browser_limit_returns_429_before_websocket_and_cleans_flow(self):
        async def check():
            for _ in range(2):
                await self.begin()
                status,_,_=await http(self.app,'/connect/start','POST',{},headers={'origin':self.settings.public_origin,'x-stealth-csrf':'1','x-stealth-flow':self.flow,'cookie':self.cookie})
                self.assertEqual(status,200)
            await self.begin();rejected=self.flow
            status,_,_=await http(self.app,'/connect/start','POST',{},headers={'origin':self.settings.public_origin,'x-stealth-csrf':'1','x-stealth-flow':self.flow,'cookie':self.cookie})
            self.assertEqual(status,429);self.assertNotIn(rejected,self.store.flows);self.assertEqual(self.bridge_calls,[])
        asyncio.run(check())

    def test_nonmember_and_stream_failure_remove_flow_immediately(self):
        async def check():
            await self.begin();self.identity='synthetic-skool-b';await self.stream();self.assertEqual(self.store.flows,{})
            await self.begin();self.identity='synthetic-skool-a'
            with patch.object(self.provider.store,'call',wraps=self.provider.store.call)as calls:
                # An identity verifier failure after receiving the session must clean the claimed flow.
                self.identity='../../invalid';await self.stream()
                self.assertEqual(self.store.flows,{})
                self.assertTrue(any(c.args[0]=='flow_abort'for c in calls.call_args_list))
            self.assertEqual(self.store.sessions,{})
        asyncio.run(check())

    def test_stream_close_and_failure_after_encryption_delete_pending_data(self):
        from catknows.hosted_popup import routes
        from starlette.applications import Starlette
        async def check():
            await self.begin()
            parent=self
            class FrameBridge:
                def call(self,operation,job,command=None):
                    parent.bridge_calls.append(operation)
                    return {'frame':'synthetic'} if operation=='command' else {'ok':True}
            async def run_stream(app,fail_ready=False):
                headers={'origin':self.settings.public_origin,'x-stealth-csrf':'1','cookie':self.cookie,'x-stealth-flow':self.flow}
                self.assertEqual((await http(self.app,'/connect/start','POST',{},headers))[0],200)
                queue=asyncio.Queue();await queue.put({'type':'websocket.connect'})
                await queue.put({'type':'websocket.receive','text':json.dumps({'flow':self.flow})})
                await queue.put({'type':'websocket.disconnect','code':1000})
                async def send(message):
                    if fail_ready and message.get('text')==json.dumps({'ready':True},separators=(',',':')):
                        raise RuntimeError('synthetic connection lost')
                await app(dict(type='websocket',asgi={'version':'3.0'},scheme='wss',path='/connect/stream',raw_path=b'/connect/stream',query_string=b'',
                    headers=[(b'origin',self.settings.public_origin.encode()),(b'cookie',self.cookie.encode())],
                    server=('mcp.example.test',443),client=('127.0.0.1',1),subprotocols=[]),queue.get,send)
            app=Starlette(routes=routes(self.settings,self.provider,lambda s:'synthetic-skool-a',FrameBridge))
            await run_stream(app);self.assertEqual(self.store.flows,{})
            await self.begin()
            class SessionBridge:
                def call(self,operation,job,command=None):
                    if operation=='command':return {'session':{'cookie_header':'synthetic=value','auth_token':'synthetic','waf_token':'synthetic'}}
                    return {'ok':True}
            app=Starlette(routes=routes(self.settings,self.provider,lambda s:'synthetic-skool-a',SessionBridge))
            await run_stream(app,True);self.assertEqual(self.store.flows,{})
            self.assertEqual(self.store.sessions,{})
        asyncio.run(check())


class NativeProviderToolTests(unittest.TestCase):
    def test_native_provider_denies_expired_members_and_nonadmins(self):
        from test_hosted_popup import SyntheticStore
        from catknows.hosted_server import Settings
        store=SyntheticStore();aid=str(uuid4());store.accounts['synthetic-skool-a']={'id':aid}
        raw='st_a_synthetic';store.tokens[hashed(raw)]={'kind':'access','client_id':'synthetic','account_id':aid,
            'resource':'https://mcp.example.test/mcp','expires_at':(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat()}
        provider=SkoolOAuthProvider(Settings('https://mcp.example.test','https://db.example.test','synthetic',frozenset({'premium'})),store,[])
        registry=Registry();created=[]
        def sessions(subject):
            c=FakeClient(subject,'member');created.append(c);return c
        register_tools(registry,sessions,provider)
        async def check():
            token=await provider.verify_token(raw)
            with patch('catknows.hosted_tools.get_access_token',return_value=token):
                with self.assertRaises(ValueError):await registry.tools['get_revenue_analytics'](aid)
                store.paid.clear()
                with self.assertRaises(PermissionError):await registry.tools['get_revenue_analytics'](aid)
            self.assertEqual(len(created),1);self.assertTrue(created[0].closed)
        asyncio.run(check())

    def test_native_provider_keeps_per_user_and_four_request_concurrency_limits(self):
        from test_hosted_popup import SyntheticStore
        from catknows.hosted_server import Settings
        store=SyntheticStore();ids=[str(uuid4())for _ in range(5)];raws=['st_a_synthetic_'+str(i)for i in range(5)]
        for i,aid in enumerate(ids):
            name='synthetic-skool-'+str(i);store.paid.add(name);store.accounts[name]={'id':aid}
            store.tokens[hashed(raws[i])]={'kind':'access','client_id':'synthetic','account_id':aid,
                'resource':'https://mcp.example.test/mcp','expires_at':(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat()}
        provider=SkoolOAuthProvider(Settings('https://mcp.example.test','https://db.example.test','synthetic',frozenset({'premium'})),store,[])
        registry=Registry();created=[];release=threading.Event();first_started=threading.Event();started=threading.Event();lock=threading.Lock();count=[0]
        class Client(FakeClient):
            def analytics_chart(self,gid,chart):
                with lock:
                    count[0]+=1
                    first_started.set()
                    if count[0]==4:started.set()
                if not release.wait(3):raise RuntimeError('Synthetic test timed out')
                return super().analytics_chart(gid,chart)
        def sessions(subject):
            c=Client(subject);created.append(c);return c
        register_tools(registry,sessions,provider);identity=ContextVar('native-concurrency')
        async def call(i):
            identity.set(await provider.verify_token(raws[i]))
            return await registry.tools['get_revenue_analytics'](ids[i])
        async def check():
            with patch('catknows.hosted_tools.get_access_token',side_effect=lambda:identity.get()):
                tasks=[asyncio.create_task(call(0))]
                try:
                    self.assertTrue(await asyncio.to_thread(first_started.wait,2))
                    with self.assertRaisesRegex(ValueError,'already running'):await call(0)
                    self.assertEqual(len(created),1)
                    tasks.extend(asyncio.create_task(call(i))for i in range(1,4))
                    self.assertTrue(await asyncio.to_thread(started.wait,2))
                    with self.assertRaisesRegex(ValueError,'busy'):await call(4)
                    self.assertEqual(len(created),4)
                finally:release.set()
                results=await asyncio.gather(*tasks)
                self.assertEqual(len(results),4);self.assertTrue(all(c.closed for c in created))
        asyncio.run(check())

# Do not inherit the base test methods a second time.
for _name in list(popup_tests.PopupTests.__dict__):
    if _name.startswith('test_') and _name not in PopupHardeningTests.__dict__:
        setattr(PopupHardeningTests,_name,None)
