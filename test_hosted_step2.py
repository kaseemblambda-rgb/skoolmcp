"""Step 2 HTTP safety tests. Synthetic data, no browser or live credentials."""
import asyncio
import unittest
from datetime import datetime,timezone,timedelta
from unittest.mock import AsyncMock
from starlette.responses import Response
from catknows.hosted_security import OAuthBoundary,ClientIPResolver
from catknows.hosted_oauth import SkoolOAuthProvider,hashed
from catknows.hosted_server import Settings,build_app
from test_hosted_popup import http,SyntheticStore

class Step2Tests(unittest.TestCase):
    def test_failed_bearer_budget_is_per_ip_and_does_not_charge_success(self):
        seen=[]
        async def downstream(scope,receive,send):
            seen.append(scope['stealth.client_ip'])
            status=200 if dict(scope['headers']).get(b'authorization')==b'Bearer synthetic-valid' else 401
            await Response(status_code=status)(scope,receive,send)
        app=OAuthBoundary(downstream,'https://mcp.example.test/mcp')
        async def check():
            for _ in range(30):
                self.assertEqual((await http(app,'/mcp',headers={'Authorization':'Bearer synthetic-valid'}))[0],200)
            for _ in range(300):
                self.assertEqual((await http(app,'/mcp',headers={'Authorization':'Bearer synthetic-invalid'}))[0],401)
            before=len(seen)
            self.assertEqual((await http(app,'/mcp',headers={'Authorization':'Bearer synthetic-invalid'}))[0],429)
            self.assertEqual(len(seen),before) # SQL/token verification is never reached
            self.assertEqual((await http(app,'/mcp',client=('203.0.113.9',1234)))[0],401)
            app.failed_bearer_budget.clock=lambda:10**12
            self.assertEqual((await http(app,'/mcp'))[0],401)
        asyncio.run(check())

    def test_fifty_concurrent_valid_requests_from_one_ip_all_succeed(self):
        async def check(prior_failures):
            release=asyncio.Event();entered=asyncio.Event();count=0
            settings=Settings('https://mcp.example.test','https://db.example.test','synthetic-key',frozenset({'premium'}))
            store=SyntheticStore()
            store.accounts['synthetic-skool-a']={'id':'synthetic-account'}
            token='st_a_synthetic-valid'
            store.tokens[hashed(token)]={'kind':'access','account_id':'synthetic-account','client_id':'synthetic-client',
                'resource':settings.resource,'expires_at':(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat()}
            provider=SkoolOAuthProvider(settings,store=store,redirect_uris=[])
            async def downstream(scope,receive,send):
                nonlocal count
                bearer=dict(scope['headers'])[b'authorization'].decode().removeprefix('Bearer ')
                verified=await provider.load_access_token(bearer)
                count+=1
                if count==50:entered.set()
                await release.wait()
                await Response(status_code=200 if verified else 401)(scope,receive,send)
            app=OAuthBoundary(downstream,settings.resource)
            for _ in range(prior_failures):app.failed_bearer_budget.allow('127.0.0.1')
            before=dict(app.failed_bearer_budget.entries)
            tasks=[asyncio.create_task(http(app,'/mcp',headers={'Authorization':'Bearer '+token})) for _ in range(50)]
            await asyncio.wait_for(entered.wait(),2)
            self.assertEqual(app.failed_bearer_budget.entries,before)
            release.set()
            self.assertTrue(all(result[0]==200 for result in await asyncio.gather(*tasks)))
            self.assertEqual(app.failed_bearer_budget.entries,before)
        for prior in (0,299):
            with self.subTest(completed_failures=prior):asyncio.run(check(prior))

    def test_in_flight_401s_are_not_counted_until_completed(self):
        async def check():
            release=asyncio.Event();entered=asyncio.Event()
            async def downstream(scope,receive,send):
                # Send headers but hold completion: neither headers nor reservation charge.
                await send({'type':'http.response.start','status':401,'headers':[]})
                entered.set()
                await release.wait()
                await send({'type':'http.response.body','body':b''})
            app=OAuthBoundary(downstream,'https://mcp.example.test/mcp')
            task=asyncio.create_task(http(app,'/mcp'))
            await asyncio.wait_for(entered.wait(),2)
            self.assertEqual(app.failed_bearer_budget.entries,{})
            release.set();self.assertEqual((await task)[0],401)
            self.assertEqual(next(iter(app.failed_bearer_budget.entries.values()))[1],1)
        asyncio.run(check())

    def test_registration_budget_allows_one_hundred_per_shared_ip(self):
        async def downstream(scope,receive,send):
            await Response(status_code=200)(scope,receive,send)
        app=OAuthBoundary(downstream,'https://mcp.example.test/mcp')
        async def check():
            for _ in range(100):
                self.assertEqual((await http(app,'/register',method='POST',data={}))[0],200)
            self.assertEqual((await http(app,'/register',method='POST',data={}))[0],429)
            self.assertEqual((await http(app,'/register',method='POST',data={},client=('203.0.113.9',1234)))[0],200)
        asyncio.run(check())

    def test_real_mcp_missing_and_invalid_bearers_hit_budget(self):
        settings=Settings('https://mcp.example.test','https://db.example.test','synthetic-key',frozenset({'premium'}))
        provider=SkoolOAuthProvider(settings,store=SyntheticStore(),redirect_uris=[])
        app=build_app(settings,oauth_provider=provider)
        async def check():
            for i in range(300):
                status,_,_=await http(app,'/mcp',method='POST',data={},headers={'Authorization':'Bearer st_a_synthetic-invalid'} if i%2 else {})
                self.assertEqual(status,401)
            self.assertEqual((await http(app,'/mcp',method='POST',data={}))[0],429)
        asyncio.run(check())

    def test_render_health_without_forwarded_ip_and_protected_routes_fail_closed(self):
        downstream=AsyncMock()
        app=OAuthBoundary(downstream,'https://mcp.example.test/mcp')
        app.ips=ClientIPResolver(render_peers=['10.0.0.0/8'],forwarded_hops=[])
        async def check():
            for method in ('GET','HEAD'):
                status,headers,body=await http(app,'/healthz',method=method,client=('10.1.2.3',1234))
                self.assertEqual(status,200)
                self.assertEqual(headers[b'x-frame-options'],b'DENY')
                self.assertEqual(headers[b'x-content-type-options'],b'nosniff')
            for path in ('/mcp','/authorize','/connect/skool','/healthz/not-public'):
                self.assertEqual((await http(app,path,client=('10.1.2.3',1234)))[0],400)
            self.assertEqual((await http(app,'/healthz',method='POST',data={},client=('10.1.2.3',1234)))[0],400)
            downstream.assert_not_awaited()
        asyncio.run(check())

    def test_bearer_database_failure_denies_without_deletion_call(self):
        calls=[]
        class Unavailable:
            def call(self,op,**p):
                calls.append(op)
                raise RuntimeError('synthetic database unavailable')
        settings=Settings('https://mcp.example.test','https://db.example.test','synthetic-key',frozenset({'premium'}))
        provider=SkoolOAuthProvider(settings,store=Unavailable(),redirect_uris=[])
        for token in (None,'invalid-prefix','st_a_'+('x'*129)):
            self.assertIsNone(asyncio.run(provider.load_access_token(token)))
        self.assertEqual(calls,[]) # cheap format checks happen before the database
        self.assertIsNone(asyncio.run(provider.load_access_token('st_a_synthetic')))
        self.assertEqual(calls,['token_get'])

if __name__=='__main__':unittest.main()
