"""Offline security boundaries using synthetic accounts and secrets only."""
import asyncio
import io
import json
import logging
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from datetime import datetime, timezone
from uuid import uuid4

from catknows.hosted_security import ReadOnlyTransport, install_private_logging, audit
from catknows.hosted_server import Settings, MemberVerifier, build_app
from catknows.hosted_sessions import SessionProvider
from catknows.hosted_tools import register_tools
from test_hosted_analytics import FakeClient, Registry


class HostedSecurityTests(unittest.TestCase):
    def test_rate_budget_bounds_users_and_resets_without_eviction_bypass(self):
        from catknows.hosted_security import RateBudget
        clock=[0];budget=RateBudget(2,capacity=2,clock=lambda:clock[0])
        self.assertTrue(budget.allow('account-a'));self.assertTrue(budget.allow('account-a'))
        self.assertFalse(budget.allow('account-a'))
        self.assertTrue(budget.allow('account-b'))
        self.assertFalse(budget.allow('account-c'))
        self.assertFalse(budget.allow('account-a'))
        clock[0]=60
        self.assertTrue(budget.allow('account-c'));self.assertTrue(budget.allow('account-a'))

    def test_logs_drop_inputs_secrets_pii_and_exception_tracebacks(self):
        old=logging.getLogRecordFactory()
        stream=io.StringIO(); handler=logging.StreamHandler(stream)
        logger=logging.getLogger('synthetic.sdk');logger.addHandler(handler);logger.setLevel(logging.DEBUG)
        audit_logger=logging.getLogger('stealth.hosted.audit');audit_logger.addHandler(handler)
        try:
            install_private_logging()
            logger.warning('Authorization: Bearer %s member=%s','synthetic-secret','private@example.test')
            try:
                raise ValueError('cookie=synthetic-cookie user=private@example.test')
            except ValueError:
                logger.exception('validation input=%r',{'password':'synthetic-password'})
            audit('tool_succeeded')
            text=stream.getvalue()
            self.assertIn('hosted_diagnostic',text);self.assertIn('tool_succeeded',text)
            for private in ('synthetic-secret','private@example.test','synthetic-cookie','synthetic-password','Traceback'):
                self.assertNotIn(private,text)
            with self.assertRaises(ValueError):audit('private@example.test')
        finally:
            logging.setLogRecordFactory(old);logger.removeHandler(handler);audit_logger.removeHandler(handler)

    def test_all_builders_enable_private_logging(self):
        from catknows.hosted_browser_service import build_browser_app
        old=logging.getLogRecordFactory()
        try:
            build_app(Settings('https://mcp.example.test','https://auth.example.test','synthetic',frozenset({'paid'})))
            self.assertTrue(getattr(logging.getLogRecordFactory(),'_stealth_private',False))
            self.assertTrue(logging.getLogger('uvicorn.access').disabled)
            logging.setLogRecordFactory(logging.LogRecord)
            build_browser_app(secret='synthetic-'*5)
            self.assertTrue(getattr(logging.getLogRecordFactory(),'_stealth_private',False))
        finally:logging.setLogRecordFactory(old)

    def test_transport_blocks_writes_and_credentials_following_redirects(self):
        underlying=Mock();underlying.get.return_value=SimpleNamespace(status_code=200)
        transport=ReadOnlyTransport(underlying)
        transport.get('https://api2.skool.com/self',headers={'Cookie':'synthetic-cookie'},allow_redirects=True)
        self.assertFalse(underlying.get.call_args.kwargs['allow_redirects'])
        for method in ('post','put','patch','delete','request','head','options'):
            with self.assertRaises(PermissionError):getattr(transport,method)('https://api2.skool.com/self')
        for url in ('http://api2.skool.com/self','https://api2.skool.com.evil.test/self',
                    'https://user:pass@www.skool.com/','https://127.0.0.1/','https://www.skool.com:444/',
                    'https://api2.skool.com/self#secret'):
            with self.assertRaises(PermissionError):transport.get(url)
        for status in (301,302,303,307,308):
            underlying.get.return_value=SimpleNamespace(status_code=status)
            with self.assertRaises(PermissionError):transport.get('https://www.skool.com/')
        transport.close();underlying.close.assert_called_once()
        underlying.post.assert_not_called();underlying.put.assert_not_called()

    def test_login_rate_limit_stops_rpc_and_changed_subject_never_loads_session(self):
        from starlette.applications import Starlette
        from catknows.hosted_connect import routes, COOKIE
        from test_hosted_login import request
        settings=Settings('https://mcp.example.test','https://auth.example.test','synthetic',frozenset({'paid'}))
        subject=str(uuid4())
        class Account:
            async def verify_token(self,value):return subject
        store=SimpleNamespace(rpc=Mock(return_value={'generation':1}))
        app=Starlette(routes=routes(settings,store,Account()))
        async def login_check():
            headers={'origin':settings.public_origin,'x-stealth-csrf':'1','cookie':COOKIE+'=synthetic'}
            for expected in (200,200,200,429):
                status,_=await request(app,'/account/skool/start',headers=headers)
                self.assertEqual(status,expected)
        asyncio.run(login_check());self.assertEqual(store.rpc.call_count,3)
        token=SimpleNamespace(subject='account-a',token='synthetic')
        class Verifier:
            async def verify_token(self,value):return SimpleNamespace(subject='account-b')
        registry=Registry();provider=Mock()
        register_tools(registry,provider,Verifier())
        async def token_check():
            with patch('catknows.hosted_tools.get_access_token',return_value=token):
                with self.assertRaises(PermissionError):await registry.tools['list_my_communities']()
        asyncio.run(token_check());provider.assert_not_called()

    def test_session_provider_is_subject_scoped_encrypted_and_read_only(self):
        import os
        from catknows.auth import Session
        from catknows.hosted_keys import encrypt_session
        subject,other=str(uuid4()),str(uuid4());key=os.urandom(32)
        row={**encrypt_session(subject,Session("synthetic=value","synthetic","synthetic"),"v1",key),"revoked_at":None}
        settings=Settings('https://mcp.example.test','https://auth.example.test','synthetic',frozenset({'paid'}))
        provider=SessionProvider(settings)
        fake=SimpleNamespace(http=SimpleNamespace(_http=Mock()))
        with patch('catknows.hosted_sessions.get_json',return_value=[row])as get, \
             patch('catknows.hosted_keys.keyring',return_value=('v1',{'v1':key})), \
             patch('catknows.hosted_sessions.SkoolClient',return_value=fake)as create:
            client=provider(subject)
            self.assertIn('user_id=eq.'+subject,get.call_args.args[0])
            self.assertIsInstance(client.http._http,ReadOnlyTransport)
            with self.assertRaises(PermissionError):client.http._write_api2('POST','/synthetic',{})
            with self.assertRaises(PermissionError):client.http.put_bytes('https://example.test',b'')
            with self.assertRaises(Exception):provider(other)
            self.assertEqual(create.call_count,1)

    def test_session_changes_during_read_suppress_results(self):
        settings=Settings('https://mcp.example.test','https://auth.example.test','synthetic',frozenset({'paid'}))
        provider=SessionProvider(settings);subject=str(uuid4())
        row=dict(ciphertext='synthetic',nonce='synthetic',key_version='v1',revoked_at=None)
        client=SimpleNamespace(_hosted_session_snapshot=row)
        with patch('catknows.hosted_sessions.get_json',return_value=[row])as get:
            provider.assert_current(subject,client)
            self.assertIn(subject,get.call_args.args[0])
        for rows in ([],[{**row,'revoked_at':'2026-01-01'}],[{**row,'ciphertext':'replaced'}]):
            with patch('catknows.hosted_sessions.get_json',return_value=rows):
                with self.assertRaises(PermissionError):provider.assert_current(subject,client)

    def test_every_community_tool_denies_members_and_cross_community_reads(self):
        registry=Registry();created=[]
        def provider(subject):
            c=FakeClient(subject,'member');created.append(c);return c
        token=SimpleNamespace(subject='account-a',token='synthetic')
        class Verifier:
            async def verify_token(self,value):return token
        register_tools(registry,provider,Verifier())
        args={
            'get_growth':{},'get_revenue_analytics':{},'get_revenue_by_tier':{},'get_member_value_by_country':{},
            'get_trial_conversion':{},'list_members':{},'get_member_profile':{'member_id':'synthetic'},
            'get_member_activity':{'start':'2026-10-01T00:00:00Z','end':'2026-11-01T00:00:00Z'},
            'compare_member_activity':{'previous_start':'2026-09-01T00:00:00Z','start':'2026-10-01T00:00:00Z','end':'2026-11-01T00:00:00Z'},
            'list_posts':{},'get_post':{'post_slug':'synthetic'},'get_post_comments':{'post_slug':'synthetic'},
            'get_post_likes':{'post_slug':'synthetic'},'search_community':{'start':'2026-10-01T00:00:00Z','end':'2026-11-01T00:00:00Z'},
            'list_join_requests':{},'get_community_about':{},'get_leaderboard':{},'get_calendar':{},'get_classroom':{},
            'get_course_tree':{'course_id':'synthetic'}}
        self.assertEqual(set(args),set(registry.tools)-{'list_my_communities'})
        async def check():
            with patch('catknows.hosted_tools.get_access_token',return_value=token):
                for slug in ('account-a','account-b'):
                    for name,extra in args.items():
                        with self.subTest(tool=name,slug=slug):
                            with self.assertRaises(ValueError):await registry.tools[name](slug,**extra)
                discovered=await registry.tools['list_my_communities']()
                self.assertEqual(discovered['data'][0]['role'],'member')
        asyncio.run(check());self.assertTrue(all(c.closed for c in created))

    def test_owner_admin_positive_and_revalidation_subject_binding(self):
        from catknows import hosted_analytics as analytics
        for role in ('group-admin','owner'):
            c=FakeClient('account-a',role)
            self.assertIn(analytics.authorized(c,'account-a')['role'],('owner','admin'))
        token=SimpleNamespace(subject='account-a',token='synthetic');registry=Registry();created=[]
        class Verifier:
            calls=0
            async def verify_token(self,value):
                self.calls+=1
                return token if self.calls==1 else None
        verifier=Verifier()
        def provider(subject):
            c=FakeClient(subject);created.append(c);return c
        register_tools(registry,provider,verifier)
        async def check():
            with patch('catknows.hosted_tools.get_access_token',return_value=token):
                with self.assertRaises(ValueError):await registry.tools['get_revenue_analytics']('account-a')
            verifier.calls=1
            with patch('catknows.hosted_tools.get_access_token',return_value=SimpleNamespace(subject='account-b',token='synthetic')):
                with self.assertRaises(PermissionError):await registry.tools['list_my_communities']()
        asyncio.run(check());self.assertEqual(len(created),1);self.assertTrue(created[0].closed)
