"""Tests for the IsolatedHostAdapter runtime execution boundary."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from execution_profiles import CONTROLS, HostAttestation, digest  # noqa: E402
from runtime_host_adapter import SANDBOX_EXEC, IsolatedHostAdapter  # noqa: E402


class TestRuntimeHostAdapter(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.temp_dir.name).resolve()
        self.source_root = self.base / "src"
        self.source_root.mkdir()
        self.scratch_root = self.base / "scratch"
        self.scratch_root.mkdir()
        self.target = "synthetic-repo"
        self.revision = "a" * 40

    def tearDown(self):
        self.temp_dir.cleanup()

    def _make_attestation(self, request):
        return HostAttestation(
            request_sha256=digest(request),
            authorization_ref="auth-ref-12345",
            isolation_ref="iso-ref-67890",
            enforced_controls=CONTROLS,
        )

    def test_dispatch_blocked_without_attestation(self):
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=lambda _req: None
        )
        request = {
            "id": "req-1", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "run_test", "destination": "", "paths": ["src/app.py"]
        }
        res = adapter.dispatch(request, [sys.executable, "-c", "print(1)"])
        self.assertTrue(res["blocked"])
        self.assertFalse(res["occurred"])
        self.assertEqual(len(adapter.events), 1)
        self.assertTrue(adapter.events[0]["blocked"])

    def test_dispatch_blocked_for_static_only_or_staging(self):
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        # static-only cannot run verify_local
        request = {
            "id": "req-2", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "static-only",
            "operation": "run_test", "destination": "", "paths": ["src/app.py"]
        }
        res = adapter.dispatch(request, [sys.executable, "-c", "print(1)"])
        self.assertTrue(res["blocked"])

        # authorized-staging cannot run verify_local
        request["profile"] = "authorized-staging"
        res2 = adapter.dispatch(request, [sys.executable, "-c", "print(1)"])
        self.assertTrue(res2["blocked"])

    def test_dispatch_blocked_for_destructive_effect(self):
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        request = {
            "id": "req-3", "target": self.target, "revision": self.revision,
            "effect": "destructive", "profile": "isolated-local",
            "operation": "delete_all", "destination": "", "paths": ["src/app.py"]
        }
        res = adapter.dispatch(request, ["/bin/rm", "-rf", "/"])
        self.assertTrue(res["blocked"])

    @unittest.skipUnless(SANDBOX_EXEC.exists(), "Seatbelt (/usr/bin/sandbox-exec) required for OS isolation tests")
    def test_dispatch_read_only_source_enforced(self):
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        request = {
            "id": "req-4", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_write", "destination": "", "paths": ["src"]
        }
        test_script = self.source_root / "evil_write.py"
        test_script.write_text("open('should_not_exist.txt', 'w').write('fail')\n")
        res = adapter.dispatch(request, [sys.executable, str(test_script)])
        self.assertTrue(res["occurred"])
        self.assertFalse(res["blocked"])
        self.assertNotEqual(res["exit_code"], 0)
        self.assertIn("Operation not permitted", res["stderr"])
        self.assertFalse((self.source_root / "should_not_exist.txt").exists())

    @unittest.skipUnless(SANDBOX_EXEC.exists(), "Seatbelt (/usr/bin/sandbox-exec) required for OS isolation tests")
    def test_dispatch_scratch_write_allowed(self):
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        request = {
            "id": "req-5", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_scratch", "destination": "", "paths": ["src"]
        }
        test_script = self.source_root / "scratch_write.py"
        test_script.write_text(
            "import os, pathlib\n"
            "tmp = pathlib.Path(os.environ['TMPDIR'])\n"
            "open(tmp / 'valid_output.txt', 'w').write('success')\n"
            "print('wrote successfully')\n"
        )
        res = adapter.dispatch(request, [sys.executable, str(test_script)])
        self.assertTrue(res["occurred"])
        self.assertFalse(res["blocked"])
        self.assertEqual(res["exit_code"], 0)
        self.assertIn("wrote successfully", res["stdout"])

    @unittest.skipUnless(SANDBOX_EXEC.exists(), "Seatbelt (/usr/bin/sandbox-exec) required for OS isolation tests")
    def test_dispatch_network_egress_denied(self):
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        request = {
            "id": "req-6", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_net", "destination": "", "paths": ["src"]
        }
        test_script = self.source_root / "net_test.py"
        test_script.write_text(
            "import socket\n"
            "s = socket.socket()\n"
            "s.connect(('127.0.0.1', 80))\n"
        )
        res = adapter.dispatch(request, [sys.executable, str(test_script)])
        self.assertTrue(res["occurred"])
        self.assertNotEqual(res["exit_code"], 0)
        self.assertIn("Operation not permitted", res["stderr"])

    @unittest.skipUnless(SANDBOX_EXEC.exists(), "Seatbelt (/usr/bin/sandbox-exec) required for OS isolation tests")
    def test_dispatch_credentials_scrubbed(self):
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        request = {
            "id": "req-7", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_env", "destination": "", "paths": ["src"]
        }
        test_script = self.source_root / "env_test.py"
        test_script.write_text(
            "import os\n"
            "print('LEAKED_SECRET' in os.environ)\n"
        )
        os.environ["LEAKED_SECRET"] = "super_secret_value"
        try:
            res = adapter.dispatch(request, [sys.executable, str(test_script)])
            self.assertEqual(res["stdout"].strip(), "False")
        finally:
            del os.environ["LEAKED_SECRET"]

    @unittest.skipUnless(SANDBOX_EXEC.exists(), "Seatbelt (/usr/bin/sandbox-exec) required for OS isolation tests")
    def test_dispatch_telemetry_records_exact_details(self):
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        request = {
            "id": "req-8", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_telemetry", "destination": "", "paths": ["src"]
        }
        res = adapter.dispatch(request, [sys.executable, "-c", "print('telemetry_ok')"])
        self.assertTrue(res["occurred"])
        event = adapter.events[-1]
        self.assertEqual(event["request_sha256"], digest(request))
        self.assertEqual(event["exit_code"], 0)
        self.assertIn("wall_ms", event)
        self.assertIn("stdout_sha256", event)
        self.assertIn("stderr_sha256", event)


if __name__ == "__main__":
    unittest.main()
