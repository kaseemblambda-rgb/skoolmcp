"""Offline public-CA and RFC 9207 regressions. ASGI/mocks only; no live login."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from mcp.server.auth.provider import AuthorizeError
from mcp.shared.auth import OAuthClientInformationFull
from catknows.hosted_database import DatabaseConfig
from catknows.hosted_server import Settings, build_app
import test_hosted_popup as popup
http = popup.http

ROOT = Path(__file__).resolve().parent
CA = 'hosted/deploy/certs/supabase-prod-ca-2021.crt'
FILE_SHA = '700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7'
DER_SHA = '807025ad50d4ed219d2c9c7d299c004f824eb00cf7f65afef607d07b72e6cafa'
BASE = 'FROM python:3.13-slim-bookworm@sha256:f3dac913ab53b78c64f26d5518fcd7043d5a1a46522d6a493b598c3ed12f62a6'
CHATGPT = 'https://chatgpt.com/connector_platform_oauth_redirect'
CLAUDE = 'https://claude.ai/api/mcp/auth_callback'


class PublicCATests(unittest.TestCase):
    def test_exact_public_certificate_self_signature_and_fingerprints(self):
        data = (ROOT/CA).read_bytes()
        self.assertRegex(data,rb'\A-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END CERTIFICATE-----\r?\n?\Z')
        self.assertNotIn(b'PRIVATE KEY',data)
        cert = x509.load_pem_x509_certificate(data)
        self.assertEqual(cert.subject,cert.issuer)
        cert.verify_directly_issued_by(cert)
        self.assertTrue(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertEqual(cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,'Supabase Root 2021 CA')
        self.assertEqual(hashlib.sha256(data).hexdigest(),FILE_SHA)
        self.assertEqual(cert.fingerprint(hashes.SHA256()).hex(),DER_SHA)
        self.assertEqual((ROOT/(CA+'.sha256')).read_text(),FILE_SHA+'  '+CA+'\n')

    def test_gateway_build_pins_permissions_checksum_and_unchanged_command(self):
        docker = (ROOT/'hosted/deploy/gateway.Dockerfile').read_text()
        self.assertEqual(docker.splitlines()[0],BASE)
        self.assertIn('RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt',docker)
        self.assertIn('RUN install -d -o root -g root -m 0755 /app/certs',docker)
        self.assertIn('COPY --chown=0:0 --chmod=0644 '+CA+' /app/certs/supabase-prod-ca-2021.crt',docker)
        self.assertIn('COPY --chown=0:0 --chmod=0644 '+CA+'.sha256 /tmp/supabase-prod-ca-2021.crt.sha256',docker)
        self.assertIn('echo "'+FILE_SHA+'  '+CA+'" | cmp - /tmp/supabase-prod-ca-2021.crt.sha256',docker)
        self.assertIn('echo "'+FILE_SHA+'  /app/certs/supabase-prod-ca-2021.crt" | sha256sum -c -',docker)
        self.assertLess(docker.index('COPY --chown=0:0'),docker.index('USER 10001:10001'))
        self.assertTrue(docker.endswith('USER 10001:10001\nCMD ["python", "-m", "catknows.hosted_server"]\n'))
        for forbidden in ('ADD ','curl ','wget ','--no-sandbox'):
            self.assertNotIn(forbidden,docker)

    def test_certificate_in_gateway_context_only_and_dockerignore_allows_it(self):
        manifest = json.loads((ROOT/'hosted/deploy/context-manifest.json').read_text())
        for path in (CA,CA+'.sha256'):
            self.assertIn(path,manifest['gateway'])
            self.assertNotIn(path,manifest['browser'])
            self.assertNotIn(path,manifest['browser-probe'])
            self.assertIn('!'+path,(ROOT/'.dockerignore').read_text())
        browser = (ROOT/'hosted/deploy/browser.Dockerfile').read_text()
        self.assertNotIn('supabase-prod-ca',browser)
        self.assertEqual(hashlib.sha256(browser.encode()).hexdigest(),'7f642da7bb94ba5237145bf7af73419ee4f3796c8af8d2410293530832275342')

    def env(self,path):
        return dict(HOSTED_DB_HOST='aws-0-example.pooler.supabase.com',HOSTED_DB_PORT='5432',
            HOSTED_DB_NAME='postgres',HOSTED_DB_USER='hosted_server.syntheticref',
            HOSTED_DB_PASSWORD='synthetic-offline-only-value-32-characters',HOSTED_DB_SSLROOTCERT=str(path))

    def test_database_accepts_absolute_safe_owned_or_root_regular_ca(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'ca.crt'; path.write_bytes((ROOT/CA).read_bytes()); path.chmod(0o644)
            with patch.dict(os.environ,self.env(path),clear=True):
                self.assertEqual(DatabaseConfig.from_env().ca_file,str(path))
                for uid in (0,os.getuid()):
                    with patch('catknows.hosted_database.Path.stat',return_value=SimpleNamespace(st_mode=stat.S_IFREG|0o644,st_uid=uid)):
                        self.assertEqual(DatabaseConfig.from_env().ca_file,str(path))

    def test_database_rejects_symlink_writable_relative_and_nonregular_ca(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'ca.crt'; path.write_bytes((ROOT/CA).read_bytes()); path.chmod(0o644)
            link = Path(folder)/'link.crt'; link.symlink_to(path)
            for candidate in (link,Path('relative-ca.crt'),Path(folder)):
                with patch.dict(os.environ,self.env(candidate),clear=True),self.assertRaises(ValueError):
                    DatabaseConfig.from_env()
            for mode in (0o664,0o646,0o666):
                path.chmod(mode)
                with patch.dict(os.environ,self.env(path),clear=True),self.assertRaises(ValueError):
                    DatabaseConfig.from_env()


class IssuerIdentificationTests(unittest.TestCase):
    def setUp(self):
        self.flow = popup.PopupTests(); self.flow.setUp(); self.addCleanup(self.flow.doCleanups)
        self.flow.provider.redirect_uris = frozenset((CHATGPT,CLAUDE))
        self.app = self.flow.app

    def metadata_request(self,callback):
        return dict(client_name='Synthetic Connector',redirect_uris=[callback],scope='mcp:read',
            token_endpoint_auth_method='none',grant_types=['authorization_code','refresh_token'],response_types=['code'])

    async def register(self,callback):
        status,_,body = await http(self.app,'/register','POST',self.metadata_request(callback),{'content-type':'application/json'})
        self.assertEqual(status,201)
        data = json.loads(body)
        self.assertFalse(data.get('client_secret'))
        self.flow.client = OAuthClientInformationFull.model_validate(data)
        self.flow.callback = callback
        return data

    async def metadata(self):
        status,_,body = await http(self.app,'/.well-known/oauth-authorization-server')
        self.assertEqual(status,200); metadata = json.loads(body)
        status,_,body = await http(self.app,'/.well-known/oauth-protected-resource/mcp')
        self.assertEqual(status,200); resource = json.loads(body)
        self.assertTrue(metadata['authorization_response_iss_parameter_supported'])
        self.assertEqual(metadata['issuer'],resource['authorization_servers'][0])
        self.assertNotIn('client_id_metadata_document_supported',metadata)
        return metadata,resource

    def test_metadata_exact_issuer_and_other_fields_unchanged(self):
        async def check():
            from mcp.server.auth.routes import build_metadata
            from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
            actual,_ = await self.metadata()
            auth = AuthSettings(issuer_url=self.flow.settings.public_origin,resource_server_url=self.flow.settings.resource,
                required_scopes=['mcp:read'],validate_token_resource=True,
                client_registration_options=ClientRegistrationOptions(enabled=True,valid_scopes=['mcp:read'],default_scopes=['mcp:read']),
                revocation_options=RevocationOptions(enabled=True))
            expected = build_metadata(auth.issuer_url,None,auth.client_registration_options,auth.revocation_options).model_dump(mode='json',exclude_none=True)
            expected['token_endpoint_auth_methods_supported'] = ['none']
            expected['revocation_endpoint_auth_methods_supported'] = ['none']
            self.assertEqual({k:v for k,v in actual.items() if k!='authorization_response_iss_parameter_supported'},expected)
        asyncio.run(check())

    async def complete(self,callback):
        await self.register(callback); metadata,_ = await self.metadata()
        async with self.app.router.lifespan_context(self.app):
            await self.flow.begin(); self.assertEqual(await self.flow.stream(),[{'ready':True}])
            status,_,body = await self.flow.decide(); self.assertEqual(status,200)
            redirect = json.loads(body)['redirect']; parts = urlsplit(redirect); query = parse_qs(parts.query)
            self.assertEqual(parts.scheme+'://'+parts.netloc+parts.path,callback)
            self.assertEqual(set(query),{'code','state','iss'})
            self.assertEqual(query['iss'],[metadata['issuer']]); self.assertEqual(query['state'],['synthetic-state'])
            fields = dict(grant_type='authorization_code',client_id=self.flow.client.client_id,code=query['code'][0],
                code_verifier=self.flow.verifier,redirect_uri=callback,resource=self.flow.settings.resource)
            status,_,body = await http(self.app,'/token','POST',urlencode(fields).encode(),{'content-type':'application/x-www-form-urlencoded'})
            self.assertEqual(status,200); tokens = json.loads(body)
            status,_,_ = await http(self.app,'/mcp','POST',{'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'status','arguments':{}}},
                {'authorization':'Bearer '+tokens['access_token'],'content-type':'application/json'})
            self.assertEqual(status,200)
            access = await self.flow.provider.load_access_token(tokens['access_token'])
            self.assertEqual(access.claims['iss'],self.flow.settings.public_origin)  # Existing token claim unchanged.

    def test_complete_chatgpt_dcr_pkce_consent_token_and_mcp_flow(self):
        asyncio.run(self.complete(CHATGPT))

    def test_complete_claude_dcr_pkce_consent_token_and_mcp_flow(self):
        asyncio.run(self.complete(CLAUDE))

    def test_every_advertised_method_registers_for_claude_and_chatgpt(self):
        async def check():
            metadata,_ = await self.metadata()
            for name in ('token_endpoint_auth_methods_supported','revocation_endpoint_auth_methods_supported'):
                self.assertEqual(metadata[name],['none'])
                for method in metadata[name]:
                    for callback in (CLAUDE,CHATGPT):
                        fields = self.metadata_request(callback)
                        fields['token_endpoint_auth_method'] = method
                        status,_,body = await http(self.app,'/register','POST',fields,{'content-type':'application/json'})
                        self.assertEqual(status,201)
                        data = json.loads(body)
                        self.assertEqual(data['token_endpoint_auth_method'],'none')
                        self.assertIsNone(data.get('client_secret'))
                        self.assertIsNone(data.get('client_secret_expires_at'))
        asyncio.run(check())

    def test_omitted_method_defaults_to_none_for_both_clients(self):
        async def check():
            for callback in (CLAUDE,CHATGPT):
                fields = self.metadata_request(callback)
                del fields['token_endpoint_auth_method']
                raw = json.dumps(fields).encode()
                status,_,body = await http(self.app,'/register','POST',raw,
                    {'content-type':'application/json','content-length':str(len(raw))})
                self.assertEqual(status,201)
                data = json.loads(body)
                self.assertEqual(data['token_endpoint_auth_method'],'none')
                self.assertIsNone(data.get('client_secret'))
                stored = self.flow.store.clients[data['client_id']]
                self.assertEqual(stored['token_endpoint_auth_method'],'none')
                self.assertNotIn('client_secret',stored)
        asyncio.run(check())

    def test_explicit_secret_unknown_and_null_methods_still_rejected(self):
        async def check():
            for method in ('client_secret_post','client_secret_basic','private_key_jwt','unknown','',None,False):
                fields = self.metadata_request(CLAUDE)
                fields['token_endpoint_auth_method'] = method
                before = dict(self.flow.store.clients)
                status,_,_ = await http(self.app,'/register','POST',fields,{'content-type':'application/json'})
                self.assertEqual(status,400)
                self.assertEqual(self.flow.store.clients,before)
        asyncio.run(check())

    def test_omitted_method_cannot_bypass_exact_redirect_allowlist(self):
        async def check():
            for redirects in (['https://unlisted.example/callback'],[CLAUDE+'/'],
                ['https://chatgpt.com/connector/oauth/abc'],[CHATGPT+'/'],
                [CHATGPT.replace('https:','http:')],[CLAUDE,'https://unlisted.example/callback']):
                fields = self.metadata_request(CLAUDE)
                del fields['token_endpoint_auth_method']
                fields['redirect_uris'] = redirects
                before = dict(self.flow.store.clients)
                status,_,_ = await http(self.app,'/register','POST',fields,{'content-type':'application/json'})
                self.assertEqual(status,400)
                self.assertEqual(self.flow.store.clients,before)
        asyncio.run(check())

    def test_omitted_method_cannot_accept_any_client_secret_field(self):
        async def check():
            for value in ('synthetic-client-secret',None,''):
                fields = self.metadata_request(CLAUDE)
                del fields['token_endpoint_auth_method']
                fields['client_secret'] = value
                before = dict(self.flow.store.clients)
                status,_,_ = await http(self.app,'/register','POST',fields,{'content-type':'application/json'})
                self.assertEqual(status,400)
                self.assertEqual(self.flow.store.clients,before)
        asyncio.run(check())

    def test_complete_claude_flow_with_omitted_registration_method(self):
        original = self.metadata_request
        def omitted(callback):
            fields = original(callback)
            del fields['token_endpoint_auth_method']
            return fields
        with patch.object(self,'metadata_request',side_effect=omitted):
            asyncio.run(self.complete(CLAUDE))

    def test_complete_chatgpt_flow_with_omitted_registration_method(self):
        original = self.metadata_request
        def omitted(callback):
            fields = original(callback)
            del fields['token_endpoint_auth_method']
            return fields
        with patch.object(self,'metadata_request',side_effect=omitted):
            asyncio.run(self.complete(CHATGPT))

    def test_deny_for_both_clients_has_exact_issuer_and_saves_nothing(self):
        async def check():
            metadata,_ = await self.metadata()
            for callback in (CHATGPT,CLAUDE):
                await self.register(callback); await self.flow.begin(); await self.flow.stream()
                status,_,body = await self.flow.decide(False); self.assertEqual(status,200)
                query = parse_qs(urlsplit(json.loads(body)['redirect']).query)
                self.assertEqual(query,dict(error=['access_denied'],state=['synthetic-state'],iss=[metadata['issuer']]))
                self.assertEqual(self.flow.store.sessions,{})
        asyncio.run(check())

    async def authorize(self,**changes):
        fields = dict(client_id=self.flow.client.client_id,redirect_uri=self.flow.callback,response_type='code',
            scope='mcp:read',state='state with & = and Unicode ü',code_challenge=self.flow.challenge,
            code_challenge_method='S256',resource=self.flow.settings.resource)
        fields.update(changes)
        return await http(self.app,'/authorize?'+urlencode(fields))

    def test_sdk_validation_error_redirects_include_issuer_and_original_state(self):
        async def check():
            await self.register(CHATGPT); metadata,_ = await self.metadata()
            for fields,error in (({'scope':'mcp:write'},'invalid_scope'),({'response_type':'token'},'unsupported_response_type'),
                                 ({'resource':'https://wrong.example/mcp'},'invalid_request')):
                status,headers,_ = await self.authorize(**fields); self.assertEqual(status,302)
                query = parse_qs(urlsplit(headers[b'location'].decode()).query)
                self.assertEqual(query['error'],[error]); self.assertEqual(query['iss'],[metadata['issuer']])
                self.assertEqual(query['state'],['state with & = and Unicode ü'])
        asyncio.run(check())

    def test_all_provider_authorization_error_redirects_include_issuer(self):
        async def check():
            await self.register(CHATGPT); metadata,_ = await self.metadata()
            for error in ('invalid_request','access_denied','server_error','invalid_scope','temporarily_unavailable','unsupported_response_type'):
                with patch.object(self.flow.provider,'authorize',side_effect=AuthorizeError(error,'Synthetic rejection')):
                    status,headers,_ = await self.authorize()
                self.assertEqual(status,302); query = parse_qs(urlsplit(headers[b'location'].decode()).query)
                self.assertEqual(query['error'],[error]); self.assertEqual(query['iss'],[metadata['issuer']])
        asyncio.run(check())

    def test_sdk_unexpected_exception_error_redirect_contains_issuer(self):
        async def check():
            await self.register(CHATGPT); metadata,_ = await self.metadata()
            with patch.object(self.flow.provider,'authorize',side_effect=RuntimeError('synthetic unavailable')):
                status,headers,_ = await self.authorize()
            self.assertEqual(status,302); query = parse_qs(urlsplit(headers[b'location'].decode()).query)
            self.assertEqual(query['error'],['server_error']); self.assertEqual(query['iss'],[metadata['issuer']])
        asyncio.run(check())

    def test_unknown_client_and_unregistered_redirect_never_redirect(self):
        async def check():
            await self.register(CHATGPT)
            for fields in ({'client_id':'unknown-synthetic'}, {'redirect_uri':'https://evil.example/callback'},
                           {'redirect_uri':CHATGPT+'/'}, {'redirect_uri':'https://chatgpt.com/connector/oauth/abc'}):
                status,headers,_ = await self.authorize(**fields)
                self.assertEqual(status,400); self.assertNotIn(b'location',headers)
        asyncio.run(check())

    def test_dcr_exact_allowlist_and_no_secret_requests(self):
        async def check():
            cases = [dict(redirect_uris=[uri]) for uri in ('https://unlisted.example/callback',
                'https://chatgpt.com/connector/oauth/abc',CHATGPT+'/',CHATGPT.replace('https:','http:'))]
            cases += [dict(redirect_uris=[CHATGPT,'https://evil.example/callback']),
                      dict(client_secret='synthetic-not-a-real-client-secret'),
                      dict(token_endpoint_auth_method='client_secret_post')]
            for changes in cases:
                fields = self.metadata_request(CHATGPT); fields.update(changes); before = dict(self.flow.store.clients)
                status,headers,_ = await http(self.app,'/register','POST',fields,{'content-type':'application/json'})
                self.assertEqual(status,400); self.assertNotIn(b'location',headers)
                self.assertEqual(self.flow.store.clients,before)
        asyncio.run(check())

    def test_post_authorize_errors_also_include_issuer(self):
        async def check():
            await self.register(CLAUDE); metadata,_ = await self.metadata()
            fields = dict(client_id=self.flow.client.client_id,redirect_uri=CLAUDE,response_type='code',scope='invalid',
                state='synthetic-state',code_challenge=self.flow.challenge,code_challenge_method='S256',resource=self.flow.settings.resource)
            status,headers,_ = await http(self.app,'/authorize','POST',urlencode(fields).encode(),{'content-type':'application/x-www-form-urlencoded'})
            self.assertEqual(status,302); query = parse_qs(urlsplit(headers[b'location'].decode()).query)
            self.assertEqual(query['iss'],[metadata['issuer']])
        asyncio.run(check())

    def test_pydantic_serialized_issuer_is_used_without_manual_normalization(self):
        async def check():
            for origin in ('https://mcp.example.test/','https://MCP.EXAMPLE.TEST:443','https://mcp.example.test:38443'):
                from catknows.hosted_oauth import SkoolOAuthProvider, authorization_redirect
                settings = Settings(origin,'https://db.example.test','synthetic',frozenset({'premium'}))
                provider = SkoolOAuthProvider(settings,self.flow.store,[CHATGPT])
                app = build_app(settings,oauth_provider=provider)
                status,_,body = await http(app,'/.well-known/oauth-authorization-server'); self.assertEqual(status,200)
                issuer = json.loads(body)['issuer']
                status,_,body = await http(app,'/.well-known/oauth-protected-resource/mcp'); self.assertEqual(status,200)
                self.assertEqual(json.loads(body)['authorization_servers'],[issuer])
                self.assertEqual(parse_qs(urlsplit(authorization_redirect(provider,CHATGPT,error='access_denied')).query)['iss'],[issuer])
                self.assertEqual(settings.public_origin,origin)  # Token issuer configuration was not rewritten.
        asyncio.run(check())
