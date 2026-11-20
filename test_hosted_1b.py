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
