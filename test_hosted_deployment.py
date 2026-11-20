"""Offline deployment configuration, least-privilege adapter and build tests."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from uuid import uuid4

from catknows.hosted_database import DatabaseConfig,RestrictedDatabase
from catknows.hosted_server import Settings,build_app
from catknows.hosted_sessions import SessionProvider
from hosted.deploy.prepare_context import prepare,MANIFEST,ROOT


class DeploymentTests(unittest.TestCase):
    def env(self,folder):
        ca=Path(folder)/'ca.pem';ca.write_text('synthetic public CA');ca.chmod(0o600)
        return dict(PUBLIC_BASE_URL='https://mcp.example.test',SFC_PAID_TIERS='premium,standard',
            HOSTED_DB_HOST='aws-0-synthetic.pooler.supabase.com',HOSTED_DB_PORT='5432',
            HOSTED_DB_NAME='postgres',HOSTED_DB_USER='hosted_server.syntheticref',
            HOSTED_DB_PASSWORD='synthetic-password-for-offline-tests-only',HOSTED_DB_SSLROOTCERT=str(ca))

    def test_production_configuration_is_lazy_and_rejects_legacy_admin_keys_and_wrong_tiers(self):
        with tempfile.TemporaryDirectory() as folder,patch('psycopg_pool.ConnectionPool') as pool:
            env=self.env(folder)
            with patch.dict(os.environ,env,clear=True):
                settings=Settings.from_env()
            self.assertEqual(settings.service_key,'');self.assertEqual(settings.supabase_origin,'')
            self.assertIsNotNone(settings.database);pool.return_value.open.assert_not_called()
            self.assertNotIn(env['HOSTED_DB_PASSWORD'],repr(settings))
            for bad in ({'SUPABASE_SERVICE_ROLE_KEY':'synthetic'}, {'HOSTED_OWNER_PROFILE_DIR':'/synthetic'},
                        {'SFC_PAID_TIERS':'free'}, {'CATKNOWS_ALLOW_WRITE':'1'}):
                with patch.dict(os.environ,{**env,**bad},clear=True),self.assertRaises(ValueError):Settings.from_env()

    def test_database_role_host_tls_and_ca_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            env=self.env(folder)
            with patch.dict(os.environ,env,clear=True):
                config=DatabaseConfig.from_env();self.assertNotIn(env['HOSTED_DB_PASSWORD'],repr(config))
            for bad in ({'HOSTED_DB_USER':'postgres.syntheticref'},{'HOSTED_DB_USER':'hosted_exporter.syntheticref'},
                        {'HOSTED_DB_HOST':'127.0.0.1'},{'HOSTED_DB_PORT':'6543'},
                        {'HOSTED_DB_PASSWORD':'short'},{'HOSTED_DB_NAME':'other'}):
                with patch.dict(os.environ,{**env,**bad},clear=True),self.assertRaises(ValueError):DatabaseConfig.from_env()
            Path(env['HOSTED_DB_SSLROOTCERT']).chmod(0o666)
            with patch.dict(os.environ,env,clear=True),self.assertRaises(ValueError):DatabaseConfig.from_env()

    def test_adapter_bound_parameters_commit_on_denial_and_sanitizes_errors(self):
        with patch('psycopg_pool.ConnectionPool') as factory:
            db=RestrictedDatabase(DatabaseConfig('synthetic.pooler.supabase.com',5432,'hosted_server.syntheticref','synthetic-secret','/synthetic/ca'))
            options=factory.call_args.kwargs
            self.assertEqual(options['kwargs']['sslmode'],'verify-full')
            self.assertEqual(options['max_size'],4);self.assertFalse(options['open'])
            connection=factory.return_value.connection.return_value.__enter__.return_value
            connection.execute.return_value.fetchone.return_value=(None,)
            self.assertIsNone(db.rpc('hosted_oauth',{'p_op':'token_get','p':{'token_hash':'synthetic'}}))
            statement,parameters=connection.execute.call_args.args
            self.assertEqual(statement,'select public.hosted_server_oauth(%s,%s)')
            self.assertEqual(parameters[0],'token_get')
            factory.return_value.connection.return_value.__exit__.assert_called_with(None,None,None)
            with self.assertRaises(PermissionError):db.rpc('reconcile_hosted_memberships',{})
            with self.assertRaises(PermissionError):db.rpc('hosted_oauth',{'p_op':'token_get','p':{},'extra':'x'})
            connection.execute.side_effect=RuntimeError('synthetic-secret raw query')
            with self.assertRaisesRegex(ValueError,'^Hosted database unavailable$'):db.rpc('hosted_oauth',{'p_op':'token_get','p':{}})
            db.close();factory.return_value.close.assert_called_once()

    def test_session_sql_uses_request_token_hash_and_subject_binding(self):
        subject=str(uuid4());token='st_a_'+('synthetic'*6);db=MagicMock()
        settings=Settings('https://mcp.example.test','','',frozenset({'premium','standard'}),db)
        provider=SessionProvider(settings);row={'ciphertext':'synthetic','nonce':'synthetic','key_version':'v1','revoked_at':None}
        db.rpc.return_value=row
        access=SimpleNamespace(subject=subject,token=token)
        with patch('mcp.server.auth.middleware.auth_context.get_access_token',return_value=access):
            self.assertEqual(provider.rows(subject),[row])
            name,payload=db.rpc.call_args.args
            self.assertEqual(name,'hosted_server_session');self.assertEqual(payload['p_token_hash'],hashlib.sha256(token.encode()).hexdigest())
            self.assertNotIn(token,str(payload))
            with self.assertRaises(PermissionError):provider.rows(str(uuid4()))
            db.rpc.return_value=None
            with self.assertRaises(PermissionError):provider.assert_current(subject,SimpleNamespace(_hosted_session_snapshot=row))
        with patch('mcp.server.auth.middleware.auth_context.get_access_token',return_value=None):
            with self.assertRaises(PermissionError):provider.rows(subject)

    def test_database_closed_after_mcp_lifespan(self):
        import asyncio
        db=MagicMock();settings=Settings('https://mcp.example.test','','',frozenset({'premium','standard'}),db)
        app=build_app(settings)
        async def check():
            async with app.app.router.lifespan_context(app.app):pass
        asyncio.run(check());db.close.assert_called_once()

    def test_build_context_excludes_all_unlisted_files_and_secret_markers(self):
        manifest=json.loads(MANIFEST.read_text())
        for service in ('gateway','browser'):
            with tempfile.TemporaryDirectory() as folder:
                output=Path(folder)/'context'
                count=prepare(service,output)
                actual={str(p.relative_to(output)) for p in output.rglob('*') if p.is_file()}
                self.assertEqual(actual,set(manifest[service])|{'.dockerignore'});self.assertEqual(count,len(actual))
                self.assertFalse(any(p.startswith(('.git/','.env','.skool-profile/','local-e2e/','remote/')) for p in actual))
                text=(output/f'hosted/deploy/{service}.Dockerfile').read_text()
                self.assertIn('USER 10001:10001',text);self.assertNotIn('COPY . ',text)
                self.assertNotIn('--no-sandbox',text);self.assertNotIn('ARG ',text)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'source';root.mkdir()
            for name in manifest['gateway']:
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((ROOT/name).read_bytes())
            (root/'.dockerignore').write_bytes((ROOT/'.dockerignore').read_bytes())
            (root/'catknows/hosted_server.py').write_text('-----BEGIN PRIVATE KEY-----\nsynthetic')
            with self.assertRaises(ValueError):prepare('gateway',Path(folder)/'context',root)
            self.assertFalse((Path(folder)/'context').exists())
            (root/'catknows/hosted_server.py').unlink();(root/'catknows/hosted_server.py').symlink_to(ROOT/'catknows/hosted_server.py')
            with self.assertRaises(ValueError):prepare('gateway',Path(folder)/'context2',root)


if __name__=='__main__':unittest.main()
