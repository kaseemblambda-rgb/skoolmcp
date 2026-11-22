"""Synthetic owner-only exception. No live Skool or database access."""
import asyncio
import json
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import urlencode,parse_qs,urlsplit

from catknows.auth import Session
from catknows.hosted_oauth import verified_sfc_owner,hashed
import test_hosted_popup as popup


class OwnerEvidenceTests(unittest.TestCase):
    def check(self,owner='synthetic-owner',identity='synthetic-owner',name='stealth',role='group-admin'):
        client=SimpleNamespace(self_user=Mock(return_value={'id':'synthetic-owner'}),
            group_info=Mock(return_value={'id':'synthetic-sfc-group','name':name,
                'metadata':{'owner':owner,'member':json.dumps({'role':role,'userId':'forged-user'})}}),
            http=SimpleNamespace(_http=SimpleNamespace(close=Mock())))
        raw=client.http._http
        try:
            with patch('catknows.client.SkoolClient',return_value=client):
                result=verified_sfc_owner(Session('synthetic-cookie','synthetic-auth','synthetic-waf'),identity)
            client.group_info.assert_called_once_with('stealth')
            return result
        finally:
            raw.close.assert_called_once()

    def test_actual_sfc_owner_allowed_even_if_membership_role_is_admin(self):
        self.assertEqual(self.check(),'synthetic-sfc-group')

    def test_both_documented_owner_metadata_shapes(self):
        for value in (json.dumps('synthetic-owner'),json.dumps({'id':'synthetic-owner'}),{'userId':'synthetic-owner'}):
            self.assertEqual(self.check(owner=value),'synthetic-sfc-group')

    def test_non_owner_admin_is_not_exception(self):self.assertIsNone(self.check(owner='synthetic-someone-else'))
    def test_role_owner_label_cannot_replace_owner_identity(self):self.assertIsNone(self.check(owner='synthetic-someone-else',role='owner'))
    def test_owner_of_other_community_is_not_exception(self):
        with self.assertRaisesRegex(ValueError,'SFC role unavailable'):self.check(name='different-community')
    def test_mismatched_verified_identity_is_denied(self):
        with self.assertRaisesRegex(ValueError,'Skool identity unavailable'):self.check(identity='forged-user')
    def test_missing_or_malformed_owner_data_is_unknown_not_exception(self):
        for value in (None,{},123,'',{'id':[]},'bad/owner',{'id':'synthetic-owner','userId':'different-owner'}):
            with self.assertRaises(ValueError):self.check(owner=value)


class OwnerFlowTests(unittest.TestCase):
    def setUp(self):
        self.case=popup.PopupTests();self.case.setUp();self.addCleanup(self.case.doCleanups)

    def test_owner_without_paid_entitlement_reaches_consent_and_tools(self):
        async def check():
            c=self.case;c.store.paid.clear();seen=[]
            def owner(session,identity):
                self.assertTrue(session.is_valid);self.assertEqual(identity,c.identity)
                seen.append(identity);return 'synthetic-sfc-group'
            c.provider.owner_reader=owner
            def rpc(name,fields):
                self.assertEqual(name,'hosted_server_session')
                return c.store.sessions.get(fields['p_account'])
            c.store.rpc=rpc
            async with c.app.router.lifespan_context(c.app):
                await c.begin()
                with self.assertLogs('stealth.hosted.login_lifecycle',level='INFO') as logs:
                    self.assertEqual(await c.stream(),[{'ready':True}])
                self.assertIn('membership_check=owner','\n'.join(logs.output));self.assertEqual(c.store.sessions,{})
                status,_,body=await c.decide();self.assertEqual(status,200)
                query=parse_qs(urlsplit(json.loads(body)['redirect']).query)
                fields=dict(grant_type='authorization_code',client_id=c.client.client_id,code=query['code'][0],
                    code_verifier=c.verifier,redirect_uri=c.callback,resource=c.settings.resource)
                status,_,body=await popup.http(c.app,'/token','POST',urlencode(fields).encode(),{'content-type':'application/x-www-form-urlencoded'})
                self.assertEqual(status,200);token=json.loads(body)['access_token']
                self.assertIsNotNone(await c.provider.load_access_token(token));self.assertGreaterEqual(len(seen),2)
                c.provider.owner_reader=lambda session,identity:None
                self.assertIsNone(await c.provider.load_access_token(token))
                self.assertEqual(c.store.sessions,{});self.assertEqual(c.store.owners,{})
                self.assertIsNone(await c.provider.load_access_token(token))
        asyncio.run(check())

    def test_paid_member_allowed_without_owner_lookup(self):
        async def check():
            c=self.case;c.provider.owner_reader=Mock(side_effect=AssertionError('Unexpected role bypass'))
            async with c.app.router.lifespan_context(c.app):
                await c.begin();self.assertEqual(await c.stream(),[{'ready':True}]);c.provider.owner_reader.assert_not_called()
        asyncio.run(check())

    def test_trial_free_expired_cancelled_and_unpaid_admin_denied(self):
        async def check():
            c=self.case;c.store.paid.clear();c.provider.owner_reader=lambda session,identity:None
            async with c.app.router.lifespan_context(c.app):
                for state in ('trial','free','cancelled_after_paid_through','non_owner_admin'):
                    with self.subTest(state=state):
                        await c.begin();self.assertEqual(await c.stream(),[{'error':'Paid SFC membership is required.'}])
                        self.assertEqual(c.store.owners,{});self.assertEqual(c.store.sessions,{})
        asyncio.run(check())

    def test_client_claim_of_owner_and_other_identity_is_ignored(self):
        async def check():
            c=self.case;c.store.paid.clear();seen=[]
            c.provider.owner_reader=lambda session,identity:seen.append(identity)
            async with c.app.router.lifespan_context(c.app):
                await c.begin()  # stream fixture includes forged client user_id.
                self.assertEqual(await c.stream(),[{'error':'Paid SFC membership is required.'}])
                self.assertEqual(seen,[c.identity]);self.assertEqual(c.store.owners,{})
        asyncio.run(check())

    def test_role_lookup_failure_denies_without_creating_proof(self):
        async def check():
            c=self.case;c.store.paid.clear();c.provider.owner_reader=Mock(side_effect=ValueError('synthetic-private-role-error'))
            async with c.app.router.lifespan_context(c.app):
                await c.begin();messages=await c.stream()
                self.assertIn('error',messages[0]);self.assertNotIn('synthetic-private',json.dumps(messages))
                self.assertEqual(c.store.owners,{});self.assertEqual(c.store.sessions,{})
        asyncio.run(check())

    def test_bearer_role_failure_denies_without_deleting_encrypted_session(self):
        async def check():
            c=self.case
            from catknows.hosted_keys import keyring,encrypt_session
            account=await c.provider.call('account',skool_user_id=c.identity)
            version,keys=keyring()
            encrypted=encrypt_session(account['id'],Session('synthetic-cookie','synthetic-auth','synthetic-waf'),version,keys[version])
            c.store.sessions[account['id']]=encrypted
            row=dict(account_id=account['id'],skool_user_id=c.identity,sfc_group_id='synthetic-sfc-group')
            c.store.rpc=lambda name,fields:c.store.sessions.get(fields['p_account'])
            c.provider.owner_reader=Mock(side_effect=ValueError('synthetic-upstream-error'))
            self.assertFalse(await c.provider.owner_access(row,'st_a_'+'x'*43))
            self.assertEqual(c.store.sessions,{account['id']:encrypted})
        asyncio.run(check())

    def test_owner_check_concurrency_slot_not_released_until_thread_stops(self):
        async def check():
            import threading
            c=self.case;c.provider.owner_slots=asyncio.Semaphore(1)
            started=threading.Event();release=threading.Event()
            def slow(*args):started.set();release.wait(2);return None
            # No real session: replace decrypt only, retaining the bounded verifier.
            c.store.rpc=lambda *args:{'key_version':'v1'}
            c.provider.owner_reader=slow
            with patch('catknows.hosted_sessions.decrypt_session',return_value=Session('synthetic','synthetic','synthetic')):
                task=asyncio.create_task(c.provider.owner_access(dict(account_id='synthetic',skool_user_id=c.identity,sfc_group_id='synthetic'),'st_a_'+'x'*43))
                while not started.is_set():await asyncio.sleep(.001)
                task.cancel();await asyncio.sleep(.01);self.assertTrue(c.provider.owner_slots.locked())
                release.set()
                with self.assertRaises(asyncio.CancelledError):await task
                self.assertFalse(c.provider.owner_slots.locked())
        asyncio.run(check())
