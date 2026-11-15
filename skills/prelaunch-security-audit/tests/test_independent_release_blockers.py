"""Independent negative regression contracts for stable-release security blockers.

Only disposable synthetic fixtures; no target code executes, no network, no real credentials.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from execution_profiles import CONTROLS, HostAttestation, digest
from runtime_host_adapter import ApprovalStore, IsolatedHostAdapter, RUNTIME_EXECUTION_ENABLED


class IndependentReleaseBlockerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="v050-hardened-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.private = self.base / "private"
        self.private.mkdir(mode=0o700)

    def test_private_store_durable_single_use_across_instances(self):
        path = self.private / "approvals.json"
        self.assertTrue(ApprovalStore(path).consume("request-1", "approval-1", "a" * 64))
        self.assertFalse(ApprovalStore(path).consume("request-1", "approval-1", "a" * 64))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.private / "approvals.json.lock").stat().st_mode), 0o600)

    def test_store_refuses_public_parent(self):
        os.chmod(self.private, 0o755)
        with self.assertRaises((PermissionError, ValueError)):
            ApprovalStore(self.private / "approvals.json").consume("request", "approval", "a" * 64)

    def test_store_rejects_symlinked_lock_without_clobber(self):
        protected = self.base / "protected.txt"
        protected.write_text("SYNTHETIC-UNMODIFIED")
        (self.private / "approvals.json.lock").symlink_to(protected)
        with self.assertRaises((OSError, PermissionError, ValueError)):
            ApprovalStore(self.private / "approvals.json").consume("request", "approval", "a" * 64)
        self.assertEqual(protected.read_text(), "SYNTHETIC-UNMODIFIED")

    def test_store_rejects_symlinked_data_file_without_clobber(self):
        protected = self.base / "protected.json"
        protected.write_text("[]")
        (self.private / "approvals.json").symlink_to(protected)
        with self.assertRaises((OSError, PermissionError, ValueError)):
            ApprovalStore(self.private / "approvals.json").consume("request", "approval", "a" * 64)
        self.assertEqual(protected.read_text(), "[]")

    def test_store_corruption_fails_closed(self):
        path = self.private / "approvals.json"
        path.write_text("BROKEN-JSON")
        with self.assertRaises((OSError, ValueError)):
            ApprovalStore(path).consume("request", "approval", "a" * 64)

    def _authorized(self, req):
        return HostAttestation(
            request_sha256=digest(req),
            authorization_ref="synthetic-authorized",
            isolation_ref="synthetic-controller-claims-only",
            enforced_controls=CONTROLS,
            command_sha256=digest(req["command"]),
            spec_sha256=req.get("spec_sha256", ""),
        )

    def _adapter(self):
        source = self.base / "source"
        scratch = self.base / "scratch"
        source.mkdir(exist_ok=True)
        scratch.mkdir(exist_ok=True)
        return IsolatedHostAdapter(
            source, scratch,
            target="synthetic", revision="a" * 40,
            attestation_provider=self._authorized,
            approval_store=ApprovalStore(self.private / "approvals.json"),
        )

    def test_authorized_legacy_execution_fails_closed_without_supervisor(self):
        self.assertFalse(RUNTIME_EXECUTION_ENABLED)
        adapter = self._adapter()
        command = [sys.executable, "-c", "print('MUST-NOT-RUN')"]
        request = dict(id="runtime-1", target="synthetic", revision="a" * 40,
                       effect="verify_local", profile="isolated-local",
                       operation="run_test", destination="", paths=["source.py"],
                       command=command)
        with patch("runtime_host_adapter._run_bounded_process", side_effect=AssertionError("spawned")):
            res = adapter.dispatch(request, command)
        self.assertFalse(res["occurred"])
        self.assertTrue(res["blocked"])
        self.assertIn("external isolation supervisor", res["reason"])
        self.assertNotIn("spec_sha256", request)

    def test_observe_cannot_become_subprocess(self):
        adapter = self._adapter()
        command = [sys.executable, "-c", "print('MUST-NOT-RUN')"]
        request = dict(id="observation-1", target="synthetic", revision="a" * 40,
                       effect="observe", profile="static-only",
                       operation="read_source", destination="", paths=["source.py"],
                       command=command)
        res = adapter.dispatch(request, command)
        self.assertTrue(res["blocked"])
        self.assertIn("subprocess dispatch requires", res["reason"])

    def test_host_event_does_not_leak_destination_or_sensitive_paths(self):
        adapter = self._adapter()
        command = [sys.executable, "-c", "print(1)"]
        secret_marker = "SYNTHETIC-SECRET-ONLY-FOR-REGRESSION"
        request = dict(id="logging-1", target="synthetic", revision="a" * 40,
                       effect="verify_local", profile="isolated-local",
                       operation="run_test",
                       destination="https://example.invalid/?token=" + secret_marker,
                       paths=["a/" + secret_marker], command=command)
        adapter.dispatch(request, command)
        self.assertNotIn(secret_marker, json.dumps(adapter.events))
        self.assertIn("destination_sha256", adapter.events[-1]["spec"])


if __name__ == "__main__":
    unittest.main()
