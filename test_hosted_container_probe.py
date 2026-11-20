"""Offline tests only. Never launch real Chromium, start a listener or connect DB."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch,MagicMock

from hosted.deploy.probe.main import run,main
from hosted.deploy.probe.common import offline,ProbeFailure
from hosted.deploy.prepare_context import prepare,ROOT,MANIFEST


class ContainerProbeTests(unittest.TestCase):
    def test_offline_harness_checks_real_gateway_and_fake_browsers(self):
        with patch.dict(os.environ,{},clear=True),patch('catknows.hosted_browser_service.LoginBrowser.start')as start:
            result=run('all')
        self.assertEqual(result['result'],'PASS')
        self.assertFalse(result['real_chromium_checked']);self.assertFalse(result['container_runtime_checked'])
        self.assertEqual(len(result['checks']),20);start.assert_not_called()

    def test_environment_with_credentials_or_profiles_refused_without_reading_values(self):
        for name in ('SUPABASE_SERVICE_ROLE_KEY','SUPABASE_URL','HOSTED_DB_PASSWORD','PGPASSWORD',
                     'CATKNOWS_PROFILE_DIR','HOSTED_OWNER_PROFILE_DIR','BROWSER_SERVICE_SECRET','SKOOL_SESSION_ENCRYPTION_KEY'):
            with patch.dict(os.environ,{name:'synthetic-must-not-be-printed'},clear=True):
                out=io.StringIO()
                with contextlib.redirect_stdout(out):status=main(['--mode','all'])
                self.assertEqual(status,1)
                self.assertEqual(json.loads(out.getvalue()),{'result':'FAIL','code':'E_PROBE_ENV'})
                self.assertNotIn('synthetic-must-not-be-printed',out.getvalue())

    def test_live_browser_cannot_be_requested_from_local_mode(self):
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaisesRegex(ProbeFailure,'E_PROBE_LIVE_REQUIRES_CONTAINER'):run('browser',live_browser=True)
        with patch.dict(os.environ,{},clear=True),patch('os.geteuid',return_value=0):
            with self.assertRaisesRegex(ProbeFailure,'E_PROBE_CONTAINER_USER'):run('browser',True,True)

    def test_offline_mode_prevents_network_connections(self):
        import socket
        with offline():
            with self.assertRaisesRegex(ProbeFailure,'E_NETWORK_FORBIDDEN'):socket.getaddrinfo('example.test',443)
            with self.assertRaisesRegex(ProbeFailure,'E_NETWORK_FORBIDDEN'):socket.create_connection(('127.0.0.1',443))
            with socket.socket()as client:
                with self.assertRaisesRegex(ProbeFailure,'E_NETWORK_FORBIDDEN'):client.connect(('127.0.0.1',443))

    def test_failure_messages_are_fixed_and_listener_not_started(self):
        with patch('hosted.deploy.probe.main.run',side_effect=RuntimeError('synthetic private detail')), \
             patch('hosted.deploy.probe.main.serve')as serve:
            out=io.StringIO()
            with contextlib.redirect_stdout(out):status=main(['--mode','gateway','--serve'])
            self.assertEqual(status,1);serve.assert_not_called()
            self.assertEqual(json.loads(out.getvalue()),{'result':'FAIL','code':'E_PROBE_FAILED'})

    def test_probe_images_have_separate_allowlisted_contexts_and_no_runtime_credentials(self):
        manifest=json.loads(MANIFEST.read_text())
        for service in ('gateway-probe','browser-probe'):
            with tempfile.TemporaryDirectory()as folder:
                output=Path(folder)/'context';prepare(service,output)
                files={str(p.relative_to(output))for p in output.rglob('*')if p.is_file()}
                self.assertEqual(files,set(manifest[service])|{'.dockerignore'})
                docker=(output/f'hosted/deploy/{service}.Dockerfile').read_text()
                self.assertIn('hosted_probe.main',docker);self.assertIn('--private-service',docker)
                self.assertIn('--container',docker);self.assertIn('USER 10001:10001',docker)
                self.assertNotIn('COPY . ',docker);self.assertNotIn('--no-sandbox',docker)
                self.assertNotIn('ENV BROWSER_SERVICE_SECRET',docker)
                self.assertFalse(any(name.startswith(('local-e2e/','remote/','hosted/macos/','hosted/migrations/'))for name in files))
        for service in ('gateway','browser'):
            self.assertFalse(any('/probe/'in path for path in manifest[service]))

    def test_production_entry_points_do_not_import_probe(self):
        for name in ('catknows/hosted_server.py','catknows/hosted_browser_service.py'):
            self.assertNotIn('hosted_probe',(ROOT/name).read_text())

    def test_sandbox_inspection_fails_closed_if_unverified(self):
        from hosted.deploy.probe.browser import sandbox_check
        with patch('hosted.deploy.probe.browser.descendants',return_value={}):
            with self.assertRaisesRegex(ProbeFailure,'E_SANDBOX_UNVERIFIED'):sandbox_check()


if __name__=='__main__':unittest.main()
