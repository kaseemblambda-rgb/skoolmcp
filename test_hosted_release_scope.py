"""Publication scope and shared helpers; no owner session, Mac APIs or SQL."""
import ast
from datetime import datetime,timezone,timedelta
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parent


class HostedReleaseScopeTests(unittest.TestCase):
    def test_manifest_and_test_gate_exclude_mac_runtime_and_migrations(self):
        files=json.loads((ROOT/'hosted/deploy/probe/publish-manifest.json').read_text())['files']
        for name in files:
            self.assertFalse(name.startswith(('hosted/macos/','hosted/migrations/','remote/','local-e2e/')))
            self.assertFalse(name.startswith(('catknows/hosted_export','catknows/hosted_owner','catknows/hosted_keychain','catknows/hosted_monitor')))
            self.assertTrue((ROOT/name).is_file(),name)
        gate=json.loads((ROOT/'hosted/deploy/test-gate.json').read_text())
        self.assertTrue(all(name+'.py'in files for name in gate['modules']))

    def test_release_cannot_import_mac_modules_from_original_checkout(self):
        for name in ('catknows.hosted_export_db','catknows.hosted_owner_browser','catknows.hosted_keychain','hosted.macos.run_entitlements'):
            try:spec=importlib.util.find_spec(name)
            except (ModuleNotFoundError,ImportError):spec=None
            self.assertIsNone(spec,name)
        policy=ast.parse((ROOT/'catknows/hosted_membership.py').read_text())
        self.assertEqual({n.name for n in policy.body if isinstance(n,ast.FunctionDef)}, {'timestamp','eligible'})

    def test_retained_legacy_helpers_keep_expiry_boundary_and_invalid_denials(self):
        from catknows.hosted_membership import eligible,timestamp
        now=datetime(2026,11,20,tzinfo=timezone.utc)
        row=dict(tier='premium',lifecycle='cancelling',observed_at=now.isoformat(),paid_through_at=now.isoformat())
        self.assertFalse(eligible(row,{'premium'},now))
        self.assertTrue(eligible({**row,'paid_through_at':(now+timedelta(seconds=1)).isoformat()},{'premium'},now))
        self.assertFalse(eligible({**row,'paid_through_at':'invalid'},{'premium'},now))
        self.assertEqual(timestamp(now.isoformat()),now)
