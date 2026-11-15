"""Comprehensive regression and hardening tests for IsolatedHostAdapter (R-01 through R-04)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from execution_profiles import CONTROLS, HostAttestation, digest  # noqa: E402
from runtime_host_adapter import (  # noqa: E402
    SANDBOX_EXEC,
    RUNTIME_EXECUTION_ENABLED,
    ApprovalStore,
    ExecutionSpec,
    IsolatedHostAdapter,
    _make_seatbelt_profile,
    get_default_approval_store,
)


class TestRuntimeHostAdapterHardening(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.temp_dir.name).resolve()
        self.source_root = self.base / "src"
        self.source_root.mkdir()
        self.scratch_root = self.base / "scratch"
        self.scratch_root.mkdir(mode=0o700)
        self.target = "synthetic-repo"
        self.revision = "a" * 40
        get_default_approval_store().clear()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _make_attestation(self, request):
        cmd = request.get("command")
        cmd_sha = digest(cmd) if cmd else ""
        spec_sha = request.get("spec_sha256", "")
        return HostAttestation(
            request_sha256=digest(request),
            authorization_ref="auth-ref-12345",
            isolation_ref="iso-ref-67890",
            enforced_controls=CONTROLS,
            command_sha256=cmd_sha,
            spec_sha256=spec_sha,
        )

    # -------------------------------------------------------------------------
    # Baseline authorization and policy tests
    # -------------------------------------------------------------------------

    def test_dispatch_blocked_without_attestation(self):
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=lambda _req: None
        )
        cmd = [sys.executable, "-c", "print(1)"]
        request = {
            "id": "req-1", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "run_test", "destination": "", "paths": ["src/app.py"],
            "command": cmd
        }
        res = adapter.dispatch(request, cmd)
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
        cmd = [sys.executable, "-c", "print(1)"]
        # static-only cannot run verify_local
        request = {
            "id": "req-2", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "static-only",
            "operation": "run_test", "destination": "", "paths": ["src/app.py"],
            "command": cmd
        }
        res = adapter.dispatch(request, cmd)
        self.assertTrue(res["blocked"])

        # authorized-staging cannot run verify_local
        request["profile"] = "authorized-staging"
        res2 = adapter.dispatch(request, cmd)
        self.assertTrue(res2["blocked"])

    def test_dispatch_blocked_for_destructive_effect(self):
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        cmd = ["/bin/rm", "-rf", "/"]
        request = {
            "id": "req-3", "target": self.target, "revision": self.revision,
            "effect": "destructive", "profile": "isolated-local",
            "operation": "delete_all", "destination": "", "paths": ["src/app.py"],
            "command": cmd
        }
        res = adapter.dispatch(request, cmd)
        self.assertTrue(res["blocked"])

    def test_target_and_revision_mismatch_blocked(self):
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        cmd = [sys.executable, "-c", "print(1)"]
        # Target mismatch
        req_wrong_target = {
            "id": "req-mismatch-1", "target": "foreign-repo", "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test", "destination": "", "paths": ["src"],
            "command": cmd
        }
        res1 = adapter.dispatch(req_wrong_target, cmd)
        self.assertTrue(res1["blocked"])
        self.assertIn("target or revision mismatch", res1["reason"])

        # Revision mismatch
        req_wrong_rev = {
            "id": "req-mismatch-2", "target": self.target, "revision": "b" * 40,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test", "destination": "", "paths": ["src"],
            "command": cmd
        }
        res2 = adapter.dispatch(req_wrong_rev, cmd)
        self.assertTrue(res2["blocked"])
        self.assertIn("target or revision mismatch", res2["reason"])

    # -------------------------------------------------------------------------
    # R-01: Filesystem read exposure and boundary enforcement
    # -------------------------------------------------------------------------

    @unittest.skipUnless(SANDBOX_EXEC.exists() and RUNTIME_EXECUTION_ENABLED, "Legacy Seatbelt execution disabled; external isolation required")
    def test_r01_host_secret_read_denied(self):
        """R-01: Child process cannot read synthetic secrets in neighboring directories."""
        secret_dir = self.base / "host_secrets"
        secret_dir.mkdir()
        secret_file = secret_dir / "id_rsa"
        secret_file.write_text("TOP_SECRET_SSH_KEY\n")

        test_script = self.source_root / "read_secret.py"
        test_script.write_text(f"open('{secret_file}').read()\n")

        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        cmd = [sys.executable, str(test_script)]
        request = {
            "id": "r01-req-1", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "read_secret", "destination": "", "paths": ["src"],
            "command": cmd
        }
        res = adapter.dispatch(request, cmd)
        self.assertTrue(res["occurred"])
        self.assertNotEqual(res["exit_code"], 0)
        self.assertTrue(
            "PermissionError" in res["stderr"] or "Operation not permitted" in res["stderr"],
            f"Expected permission denial in stderr: {res['stderr']}"
        )
        self.assertNotIn("TOP_SECRET_SSH_KEY", res["stdout"])

    @unittest.skipUnless(SANDBOX_EXEC.exists() and RUNTIME_EXECUTION_ENABLED, "Legacy Seatbelt execution disabled; external isolation required")
    def test_r01_cross_workspace_read_denied(self):
        """R-01: Child process cannot read neighboring workspace files."""
        other_ws = self.base / "other_workspace"
        other_ws.mkdir()
        secret_doc = other_ws / "proprietary_code.py"
        secret_doc.write_text("CONFIDENTIAL_ALGORITHM\n")

        test_script = self.source_root / "read_other.py"
        test_script.write_text(f"open('{secret_doc}').read()\n")

        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        cmd = [sys.executable, str(test_script)]
        request = {
            "id": "r01-req-2", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "read_other", "destination": "", "paths": ["src"],
            "command": cmd
        }
        res = adapter.dispatch(request, cmd)
        self.assertTrue(res["occurred"])
        self.assertNotEqual(res["exit_code"], 0)
        self.assertTrue(
            "PermissionError" in res["stderr"] or "Operation not permitted" in res["stderr"]
        )

    @unittest.skipUnless(SANDBOX_EXEC.exists() and RUNTIME_EXECUTION_ENABLED, "Legacy Seatbelt execution disabled; external isolation required")
    def test_r01_symlink_escape_denied(self):
        """R-01: Symlinks inside scratch pointing to external secret cannot be followed."""
        secret_dir = self.base / "host_secrets"
        secret_dir.mkdir(exist_ok=True)
        secret_file = secret_dir / "cloud_token.txt"
        secret_file.write_text("CLOUD_CREDENTIAL_DATA\n")

        test_script = self.source_root / "symlink_test.py"
        test_script.write_text(
            "import os, pathlib\n"
            f"target_secret = pathlib.Path('{secret_file}')\n"
            "scratch = pathlib.Path(os.environ['TMPDIR'])\n"
            "link = scratch / 'link_to_secret'\n"
            "link.symlink_to(target_secret)\n"
            "print('Symlink created')\n"
            "open(link).read()\n"
        )

        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        cmd = [sys.executable, str(test_script)]
        request = {
            "id": "r01-req-3", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_symlink", "destination": "", "paths": ["src"],
            "command": cmd
        }
        res = adapter.dispatch(request, cmd)
        self.assertTrue(res["occurred"])
        self.assertNotEqual(res["exit_code"], 0)
        self.assertTrue(
            "PermissionError" in res["stderr"] or "Operation not permitted" in res["stderr"]
        )
        self.assertNotIn("CLOUD_CREDENTIAL_DATA", res["stdout"])

    @unittest.skipUnless(SANDBOX_EXEC.exists() and RUNTIME_EXECUTION_ENABLED, "Legacy Seatbelt execution disabled; external isolation required")
    def test_r01_authorized_source_read_and_scratch_write_allowed(self):
        """R-01: Reading authorized source and writing authorized scratch succeed cleanly."""
        source_file = self.source_root / "data.txt"
        source_file.write_text("authorized_input_data\n")

        test_script = self.source_root / "good_job.py"
        test_script.write_text(
            "import os, pathlib\n"
            "inp = open('data.txt').read().strip()\n"
            "scratch = pathlib.Path(os.environ['TMPDIR'])\n"
            "out = scratch / 'result.txt'\n"
            "out.write_text(f'processed: {inp}')\n"
            "print('SUCCESS_PROCESSED')\n"
        )

        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        cmd = [sys.executable, str(test_script)]
        request = {
            "id": "r01-req-4", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_good", "destination": "", "paths": ["src"],
            "command": cmd
        }
        res = adapter.dispatch(request, cmd)
        self.assertTrue(res["occurred"])
        self.assertEqual(res["exit_code"], 0)
        self.assertIn("SUCCESS_PROCESSED", res["stdout"])

    @unittest.skipUnless(SANDBOX_EXEC.exists() and RUNTIME_EXECUTION_ENABLED, "Legacy Seatbelt execution disabled; external isolation required")
    def test_r01_write_to_source_denied(self):
        """R-01: Writing to source_root is strictly denied by the Seatbelt profile."""
        test_script = self.source_root / "evil_write.py"
        test_script.write_text("open('should_fail.txt', 'w').write('fail')\n")

        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        cmd = [sys.executable, str(test_script)]
        request = {
            "id": "r01-req-5", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_write", "destination": "", "paths": ["src"],
            "command": cmd
        }
        res = adapter.dispatch(request, cmd)
        self.assertTrue(res["occurred"])
        self.assertNotEqual(res["exit_code"], 0)
        self.assertIn("Operation not permitted", res["stderr"])
        self.assertFalse((self.source_root / "should_fail.txt").exists())

    # -------------------------------------------------------------------------
    # R-02: Cryptographic/structural command binding and replay prevention
    # -------------------------------------------------------------------------

    def test_r02_unbound_command_rejected_before_dispatch(self):
        """R-02: Dispatching without command in request is rejected before execution."""
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        cmd = [sys.executable, "-c", "print('unbound')"]
        request = {
            "id": "r02-req-1", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "run_test", "destination": "", "paths": ["src"],
            # 'command' omitted from request
        }
        res = adapter.dispatch(request, cmd)
        self.assertTrue(res["blocked"])
        self.assertFalse(res["occurred"])
        self.assertIn("command is not cryptographically or structurally bound", res["reason"])

    def test_r02_command_mismatch_rejected_before_dispatch(self):
        """R-02: Dispatching with different command than approved is rejected."""
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        approved_cmd = [sys.executable, "-c", "print('safe')"]
        malicious_cmd = [sys.executable, "-c", "print('malicious_override')"]
        request = {
            "id": "r02-req-2", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "run_test", "destination": "", "paths": ["src"],
            "command": approved_cmd,
        }
        res = adapter.dispatch(request, malicious_cmd)
        self.assertTrue(res["blocked"])
        self.assertFalse(res["occurred"])
        self.assertIn("command is not cryptographically or structurally bound", res["reason"])

    def test_r02_substituted_arguments_rejected(self):
        """R-02: Modifying arguments after request formulation invalidates authorization."""
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        approved_cmd = [sys.executable, "test.py", "--check-only"]
        altered_cmd = [sys.executable, "test.py", "--overwrite-all"]
        request = {
            "id": "r02-req-3", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "run_test", "destination": "", "paths": ["src"],
            "command": approved_cmd,
        }
        res = adapter.dispatch(request, altered_cmd)
        self.assertTrue(res["blocked"])
        self.assertFalse(res["occurred"])

    @unittest.skipUnless(SANDBOX_EXEC.exists() and RUNTIME_EXECUTION_ENABLED, "Legacy Seatbelt execution disabled; external isolation required")
    def test_r02_replay_attack_rejected(self):
        """R-02: Replaying an already-dispatched approval is blocked."""
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        cmd = [sys.executable, "-c", "print('run_once')"]
        request = {
            "id": "r02-req-4", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "run_test", "destination": "", "paths": ["src"],
            "command": cmd,
        }
        res1 = adapter.dispatch(request, cmd)
        self.assertTrue(res1["occurred"])
        self.assertFalse(res1["blocked"])

        # Second dispatch with identical approval must be blocked as replay
        res2 = adapter.dispatch(request, cmd)
        self.assertTrue(res2["blocked"])
        self.assertFalse(res2["occurred"])
        self.assertIn("authorization replay rejected", res2["reason"])

    @unittest.skipUnless(SANDBOX_EXEC.exists() and RUNTIME_EXECUTION_ENABLED, "Legacy Seatbelt execution disabled; external isolation required")
    def test_r02_execution_spec_telemetry_recorded(self):
        """R-02: Immutable ExecutionSpec and its digest are stored in telemetry events."""
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        cmd = [sys.executable, "-c", "print('spec_telemetry')"]
        request = {
            "id": "r02-req-5", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "telemetry_test", "destination": "", "paths": ["src"],
            "command": cmd,
        }
        res = adapter.dispatch(request, cmd)
        self.assertTrue(res["occurred"])
        event = adapter.events[-1]
        self.assertIn("spec_sha256", event)
        self.assertIn("spec", event)
        self.assertEqual(event["spec"]["command_sha256"], digest(cmd))
        self.assertEqual(event["spec"]["executable"], Path(cmd[0]).name)
        self.assertEqual(event["spec"]["command_arg_count"], len(cmd))
        self.assertNotIn("command", event)
        self.assertEqual(event["spec"]["target"], self.target)
        self.assertEqual(event["spec"]["revision"], self.revision)

    # -------------------------------------------------------------------------
    # R-03: Network egress denial and fail-closed network_read
    # -------------------------------------------------------------------------

    def test_r03_network_read_effect_blocked_fail_closed(self):
        """R-03: Arbitrary child process dispatch with network_read effect fails closed."""
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        cmd = [sys.executable, "-c", "print('net')"]
        request = {
            "id": "r03-req-1", "target": self.target, "revision": self.revision,
            "effect": "network_read", "profile": "isolated-local",
            "operation": "fetch_api", "destination": "https://api.example.com", "paths": [],
            "command": cmd,
        }
        res = adapter.dispatch(request, cmd)
        self.assertTrue(res["blocked"])
        self.assertFalse(res["occurred"])
        self.assertIn("arbitrary target code socket egress is prohibited", res["reason"])

    def test_r03_external_write_effect_blocked_fail_closed(self):
        """R-03: Arbitrary child process dispatch with external_write effect fails closed."""
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        cmd = [sys.executable, "-c", "print('net_write')"]
        request = {
            "id": "r03-req-2", "target": self.target, "revision": self.revision,
            "effect": "external_write", "profile": "isolated-local",
            "operation": "push_data", "destination": "https://upload.example.com", "paths": [],
            "command": cmd,
        }
        res = adapter.dispatch(request, cmd)
        self.assertTrue(res["blocked"])
        self.assertFalse(res["occurred"])

    @unittest.skipUnless(SANDBOX_EXEC.exists() and RUNTIME_EXECUTION_ENABLED, "Legacy Seatbelt execution disabled; external isolation required")
    def test_r03_seatbelt_profile_denies_network_connections(self):
        """R-03: Child process attempting socket connection is denied by Seatbelt."""
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]

            test_script = self.source_root / "connect_test.py"
            test_script.write_text(
                "import socket\n"
                "s = socket.socket()\n"
                f"s.connect(('127.0.0.1', {port}))\n"
            )

            adapter = IsolatedHostAdapter(
                self.source_root, self.scratch_root,
                target=self.target, revision=self.revision,
                attestation_provider=self._make_attestation
            )
            cmd = [sys.executable, str(test_script)]
            request = {
                "id": "r03-req-3", "target": self.target, "revision": self.revision,
                "effect": "verify_local", "profile": "isolated-local",
                "operation": "test_socket", "destination": "", "paths": ["src"],
                "command": cmd,
            }
            res = adapter.dispatch(request, cmd)
            self.assertTrue(res["occurred"])
            self.assertNotEqual(res["exit_code"], 0)
            self.assertIn("Operation not permitted", res["stderr"])

    def test_r03_seatbelt_profile_unconditionally_denies_network(self):
        """R-03: Generated Seatbelt profile text always includes unconditional (deny network*)."""
        profile_text = _make_seatbelt_profile(self.source_root, self.scratch_root)
        self.assertIn("(deny network*)", profile_text)

    # -------------------------------------------------------------------------
    # R-04: Bounded stream collection and process group cleanup
    # -------------------------------------------------------------------------

    @unittest.skipUnless(SANDBOX_EXEC.exists() and RUNTIME_EXECUTION_ENABLED, "Legacy Seatbelt execution disabled; external isolation required")
    def test_r04_normal_output_bounded(self):
        """R-04: Normal output within limits is captured without truncation."""
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation,
            max_bytes=1000
        )
        cmd = [sys.executable, "-c", "print('normal_stdout'); import sys; sys.stderr.write('normal_stderr\\n')"]
        request = {
            "id": "r04-req-1", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_normal", "destination": "", "paths": ["src"],
            "command": cmd,
        }
        res = adapter.dispatch(request, cmd)
        self.assertTrue(res["occurred"])
        self.assertEqual(res["exit_code"], 0)
        self.assertIn("normal_stdout", res["stdout"])
        self.assertIn("normal_stderr", res["stderr"])
        self.assertFalse(res["output_truncated"])
        self.assertFalse(res["timed_out"])

    @unittest.skipUnless(SANDBOX_EXEC.exists() and RUNTIME_EXECUTION_ENABLED, "Legacy Seatbelt execution disabled; external isolation required")
    def test_r04_massive_stdout_truncated_and_terminated(self):
        """R-04: Massive output is bounded at max_bytes, terminates process group."""
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation,
            max_bytes=256
        )
        # Child attempts to write 500,000 characters
        cmd = [sys.executable, "-c", "import sys; sys.stdout.write('X' * 500000)"]
        request = {
            "id": "r04-req-2", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_massive", "destination": "", "paths": ["src"],
            "command": cmd,
        }
        res = adapter.dispatch(request, cmd)
        self.assertTrue(res["occurred"])
        self.assertTrue(res["output_truncated"])
        self.assertLessEqual(len(res["stdout"].encode("utf-8")), 256)
        # Child process was terminated by SIGKILL (-9) or exit nonzero
        self.assertNotEqual(res["exit_code"], 0)

    @unittest.skipUnless(SANDBOX_EXEC.exists() and RUNTIME_EXECUTION_ENABLED, "Legacy Seatbelt execution disabled; external isolation required")
    def test_r04_concurrent_stdout_stderr_bounded(self):
        """R-04: Concurrent massive stdout and stderr are both bounded."""
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation,
            max_bytes=200
        )
        cmd = [
            sys.executable, "-c",
            "import sys; sys.stdout.write('A' * 200000); sys.stderr.write('B' * 200000)"
        ]
        request = {
            "id": "r04-req-3", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_both_massive", "destination": "", "paths": ["src"],
            "command": cmd,
        }
        res = adapter.dispatch(request, cmd)
        self.assertTrue(res["occurred"])
        self.assertTrue(res["output_truncated"])
        self.assertLessEqual(len(res["stdout"].encode("utf-8")), 200)
        self.assertLessEqual(len(res["stderr"].encode("utf-8")), 200)

    @unittest.skipUnless(SANDBOX_EXEC.exists() and RUNTIME_EXECUTION_ENABLED, "Legacy Seatbelt execution disabled; external isolation required")
    def test_r04_timeout_kills_process_group(self):
        """R-04: Child timing out is terminated via process group kill."""
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation,
            timeout=1
        )
        cmd = [sys.executable, "-c", "import time; time.sleep(15)"]
        request = {
            "id": "r04-req-4", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_timeout", "destination": "", "paths": ["src"],
            "command": cmd,
        }
        started = time.monotonic()
        res = adapter.dispatch(request, cmd)
        elapsed = time.monotonic() - started
        self.assertTrue(res["occurred"])
        self.assertTrue(res["timed_out"])
        self.assertLess(elapsed, 5.0, "Timeout handler should have terminated child within ~1-2 seconds")

    @unittest.skipUnless(SANDBOX_EXEC.exists() and RUNTIME_EXECUTION_ENABLED, "Legacy Seatbelt execution disabled; external isolation required")
    def test_r04_disposable_scratch_cleanup(self):
        """R-04: Disposable sub-scratch directory is removed cleanly after execution."""
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        cmd = [sys.executable, "-c", "print('clean_me')"]
        request = {
            "id": "r04-req-5", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_cleanup", "destination": "", "paths": ["src"],
            "command": cmd,
        }
        res = adapter.dispatch(request, cmd)
        self.assertTrue(res["occurred"])
        # Verify no run-scratch-* directories remain in scratch_root
        remaining_runs = list(self.scratch_root.glob("run-scratch-*"))
        self.assertEqual(len(remaining_runs), 0, f"Found lingering scratch directories: {remaining_runs}")

    # -------------------------------------------------------------------------
    # Additional trust boundary checks (Section 6)
    # -------------------------------------------------------------------------

    @unittest.skipUnless(SANDBOX_EXEC.exists() and RUNTIME_EXECUTION_ENABLED, "Legacy Seatbelt execution disabled; external isolation required")
    def test_credentials_and_user_site_scrubbed_from_environment(self):
        """Child process receives scrubbed environment and PYTHONNOUSERSITE=1."""
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        test_script = self.source_root / "env_check.py"
        test_script.write_text(
            "import os\n"
            "print('HAS_SECRET=' + str('TEST_SECRET_VAR' in os.environ))\n"
            "print('USER_SITE=' + str(os.environ.get('PYTHONNOUSERSITE', '')))\n"
        )
        os.environ["TEST_SECRET_VAR"] = "unauthorized_token"
        try:
            cmd = [sys.executable, str(test_script)]
            request = {
                "id": "env-req-1", "target": self.target, "revision": self.revision,
                "effect": "verify_local", "profile": "isolated-local",
                "operation": "test_env", "destination": "", "paths": ["src"],
                "command": cmd,
            }
            res = adapter.dispatch(request, cmd)
            self.assertIn("HAS_SECRET=False", res["stdout"])
            self.assertIn("USER_SITE=1", res["stdout"])
        finally:
            del os.environ["TEST_SECRET_VAR"]

    def test_unsupported_host_sandbox_fails_closed(self):
        """When SANDBOX_EXEC does not exist, dispatch fails closed."""
        with patch("runtime_host_adapter.SANDBOX_EXEC", Path("/nonexistent/sandbox-exec")):
            adapter = IsolatedHostAdapter(
                self.source_root, self.scratch_root,
                target=self.target, revision=self.revision,
                attestation_provider=self._make_attestation
            )
            cmd = [sys.executable, "-c", "print(1)"]
            req = {
                "id": "unsupported-1", "target": self.target, "revision": self.revision,
                "effect": "verify_local", "profile": "isolated-local",
                "operation": "test", "destination": "", "paths": ["src"],
                "command": cmd,
            }
            res = adapter.dispatch(req, cmd)
            self.assertTrue(res["blocked"])
            self.assertFalse(res["occurred"])
            self.assertIn("external isolation supervisor" if not RUNTIME_EXECUTION_ENABLED else "host sandbox facility", res["reason"])

    # -------------------------------------------------------------------------
    # R-05: Genuine default-deny filesystem read isolation
    # -------------------------------------------------------------------------

    @unittest.skipUnless(SANDBOX_EXEC.exists() and RUNTIME_EXECUTION_ENABLED, "Legacy Seatbelt execution disabled; external isolation required")
    def test_r05_default_deny_blocks_unallowlisted_paths(self):
        """R-05: Genuine default-deny blocks reads to unallowlisted host files (/etc/passwd, synthetic secrets)."""
        secret_file = self.base / "external_secret.txt"
        secret_file.write_text("OUTSIDE_DENYLIST_SECRET\n")

        test_script = self.source_root / "read_tests.py"
        test_script.write_text(
            f"try:\n"
            f"    open('{secret_file}').read()\n"
            f"    print('LEAKED_SECRET')\n"
            f"except Exception:\n"
            f"    pass\n"
            f"try:\n"
            f"    open('/etc/passwd').read()\n"
            f"    print('LEAKED_PASSWD')\n"
            f"except Exception:\n"
            f"    pass\n"
            f"print('CHECK_FINISHED')\n"
        )
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        cmd = [sys.executable, str(test_script)]
        req = {
            "id": "r05-req-1", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_r05", "destination": "", "paths": ["src"],
            "command": cmd,
        }
        res = adapter.dispatch(req, cmd)
        self.assertTrue(res["occurred"])
        self.assertEqual(res["exit_code"], 0)
        self.assertNotIn("LEAKED_SECRET", res["stdout"])
        self.assertNotIn("LEAKED_PASSWD", res["stdout"])
        self.assertIn("CHECK_FINISHED", res["stdout"])

    def test_r05_profile_has_genuine_default_deny(self):
        """R-05: Seatbelt profile begins with (deny default) and does not permit allow default."""
        profile_text = _make_seatbelt_profile(self.source_root, self.scratch_root)
        self.assertIn("(deny default)", profile_text)
        self.assertNotIn("(allow default)", profile_text)
        self.assertIn("(deny network*)", profile_text)
        self.assertIn("(deny file-write*)", profile_text)

    def test_r05_py_prefix_equal_home_fails_closed(self):
        """R-05: If Python runtime prefix matches user home, dispatch fails closed."""
        with patch("runtime_host_adapter.sys") as mock_sys:
            mock_sys.prefix = str(Path.home())
            mock_sys.base_prefix = str(Path.home())
            with self.assertRaises(ValueError):
                _make_seatbelt_profile(self.source_root, self.scratch_root)

    # -------------------------------------------------------------------------
    # R-06: Complete process lifecycle cleanup & descendant termination
    # -------------------------------------------------------------------------

    @unittest.skipUnless(SANDBOX_EXEC.exists() and RUNTIME_EXECUTION_ENABLED, "Legacy Seatbelt execution disabled; external isolation required")
    def test_r06_parent_exit_terminates_background_grandchild(self):
        """R-06: Grandchild process spawned by direct child is terminated when direct child exits."""
        script = self.source_root / "spawn_child.py"
        script.write_text(
            "import subprocess, sys, time\n"
            "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
            "print(f'GRANDCHILD_PID={p.pid}', flush=True)\n"
            "sys.exit(0)\n"
        )
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        cmd = [sys.executable, str(script)]
        req = {
            "id": "r06-req-1", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_r06", "destination": "", "paths": ["src"],
            "command": cmd,
        }
        res = adapter.dispatch(req, cmd)
        self.assertTrue(res["occurred"])
        self.assertEqual(res["exit_code"], 0)
        m = re.search(r"GRANDCHILD_PID=(\d+)", res["stdout"])
        self.assertIsNotNone(m, f"Could not find grandchild PID in stdout: {res['stdout']}")
        gpid = int(m.group(1))
        # Verify grandchild PID is dead
        time.sleep(0.2)
        try:
            os.kill(gpid, 0)
            alive = True
        except OSError:
            alive = False
        self.assertFalse(alive, f"Descendant process {gpid} survived direct child exit!")

    @unittest.skipUnless(SANDBOX_EXEC.exists() and RUNTIME_EXECUTION_ENABLED, "Legacy Seatbelt execution disabled; external isolation required")
    def test_r06_grandchild_closing_pipes_terminated(self):
        """R-06: Grandchild closing pipes is terminated cleanly without hanging."""
        script = self.source_root / "spawn_close.py"
        script.write_text(
            "import subprocess, sys, time\n"
            "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],\n"
            "                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            "print(f'GRANDCHILD_CLOSED_PID={p.pid}', flush=True)\n"
            "sys.exit(0)\n"
        )
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation,
            timeout=5
        )
        cmd = [sys.executable, str(script)]
        req = {
            "id": "r06-req-2", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_r06_pipe", "destination": "", "paths": ["src"],
            "command": cmd,
        }
        res = adapter.dispatch(req, cmd)
        self.assertTrue(res["occurred"])
        m = re.search(r"GRANDCHILD_CLOSED_PID=(\d+)", res["stdout"])
        self.assertIsNotNone(m, f"Could not find grandchild PID in stdout: {res['stdout']}")
        gpid = int(m.group(1))
        time.sleep(0.2)
        try:
            os.kill(gpid, 0)
            alive = True
        except OSError:
            alive = False
        self.assertFalse(alive, f"Grandchild process {gpid} with closed pipes survived!")

    # -------------------------------------------------------------------------
    # R-07: Strengthen authorization & telemetry integrity
    # -------------------------------------------------------------------------

    @unittest.skipUnless(SANDBOX_EXEC.exists() and RUNTIME_EXECUTION_ENABLED, "Legacy Seatbelt execution disabled; external isolation required")
    def test_r07_cross_instance_replay_rejected(self):
        """R-07: Replaying an approval on a separate adapter instance is rejected."""
        cmd = [sys.executable, "-c", "print('run_once')"]
        req = {
            "id": "r07-req-1", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_replay", "destination": "", "paths": ["src"],
            "command": cmd,
        }
        adapter1 = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        res1 = adapter1.dispatch(req, cmd)
        self.assertTrue(res1["occurred"])
        self.assertFalse(res1["blocked"])

        # Create separate adapter instance
        adapter2 = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        res2 = adapter2.dispatch(req, cmd)
        self.assertTrue(res2["blocked"])
        self.assertFalse(res2["occurred"])
        self.assertIn("authorization replay rejected", res2["reason"])

    def test_r07_file_backed_approval_store_atomic_replay_prevention(self):
        """R-07: ApprovalStore with file persistence enforces cross-process single-use consumption."""
        store_path = self.scratch_root / "approvals.json"
        store1 = ApprovalStore(store_path)
        self.assertTrue(store1.consume("req-1", "auth-1", "spec-hash-1"))

        # Second consumption in same store returns False
        self.assertFalse(store1.consume("req-1", "auth-1", "spec-hash-1"))

        # New store pointing to same file path also returns False (cross-process simulated)
        store2 = ApprovalStore(store_path)
        self.assertFalse(store2.consume("req-1", "auth-1", "spec-hash-1"))

    @unittest.skipUnless(SANDBOX_EXEC.exists() and RUNTIME_EXECUTION_ENABLED, "Legacy Seatbelt execution disabled; external isolation required")
    def test_r07_telemetry_sanitizes_command_arguments(self):
        """R-07: Telemetry retains hashes and lengths, never sensitive raw command arguments."""
        secret_arg = "--api-secret-key=SUPER_SECRET_TOKEN_VALUE_XYZ"
        cmd = [sys.executable, "-c", "print('sanitized')", secret_arg]
        req = {
            "id": "r07-req-3", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_telemetry_scrub", "destination": "", "paths": ["src"],
            "command": cmd,
        }
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        res = adapter.dispatch(req, cmd)
        self.assertTrue(res["occurred"])
        event = adapter.events[-1]
        self.assertNotIn(secret_arg, json.dumps(event))
        self.assertEqual(event["executable"], Path(sys.executable).name)
        self.assertEqual(event["command_sha256"], digest(cmd))
        self.assertEqual(event["command_arg_count"], 4)

    def test_r07_spec_digest_mismatch_invalidates_authorization(self):
        """R-07: Tampering with spec_sha256 in request blocks execution before process creation."""
        cmd = [sys.executable, "-c", "print(1)"]
        req = {
            "id": "r07-req-4", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_spec_tamper", "destination": "", "paths": ["src"],
            "command": cmd,
            "spec_sha256": "tampered_spec_digest_12345",
        }
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation
        )
        res = adapter.dispatch(req, cmd)
        self.assertTrue(res["blocked"])
        self.assertFalse(res["occurred"])
        self.assertIn("execution spec digest does not match", res["reason"])

    # -------------------------------------------------------------------------
    # WORKSTREAM A: Final Runtime Security Contract Review
    # -------------------------------------------------------------------------

    def test_a1_cross_process_replay_prevention(self):
        """A1: Separate host processes cannot reuse a consumed authorization."""
        store_path = self.base / "cross_proc_approvals.json"
        helper_code = (
            f"import sys; sys.path.insert(0, '{ROOT / 'scripts'}'); "
            f"from runtime_host_adapter import ApprovalStore; "
            f"from pathlib import Path; "
            f"store = ApprovalStore(Path('{store_path}')); "
            f"ok = store.consume('req-p1', 'auth-p1', 'spec-p1'); "
            f"sys.exit(0 if ok else 1)"
        )
        # First process consumes approval -> exits 0
        p1 = subprocess.run([sys.executable, "-c", helper_code], capture_output=True, text=True)
        self.assertEqual(p1.returncode, 0)

        # Second separate process attempts replay -> exits 1
        p2 = subprocess.run([sys.executable, "-c", helper_code], capture_output=True, text=True)
        self.assertEqual(p2.returncode, 1)

    def test_a1_approval_store_corruption_fails_closed(self):
        """A1: ApprovalStore safe corruption handling fails closed without allowing replay."""
        store_path = self.base / "corrupt_approvals.json"
        store_path.write_text("{{INVALID_JSON_CORRUPT_BYTES", encoding="utf-8")
        store = ApprovalStore(store_path)

        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation,
            approval_store=store,
        )
        cmd = [sys.executable, "-c", "print(1)"]
        req = {
            "id": "a1-req-1", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_corrupt", "destination": "", "paths": ["src"],
            "command": cmd,
        }
        res = adapter.dispatch(req, cmd)
        self.assertTrue(res["blocked"])
        self.assertFalse(res["occurred"])
        self.assertIn("approval store error", res["reason"])

    def test_a1_approval_store_permissions_secure(self):
        """A1: ApprovalStore enforces 0o600 file permissions and 0o700 directory permissions."""
        store_dir = self.base / "secure_store_dir"
        store_path = store_dir / "approvals.json"
        store = ApprovalStore(store_path)
        self.assertTrue(store.consume("req-sec", "auth-sec", "spec-sec"))

        mode = store_path.stat().st_mode & 0o777
        self.assertEqual(oct(mode), oct(0o600))

    def test_a2_missing_spec_sha256_in_attestation_blocks_local_execution(self):
        """A2: Host attestation omitting spec_sha256 fails closed for verify_local."""
        def attest_no_spec(request):
            att = self._make_attestation(request)
            return HostAttestation(
                request_sha256=att.request_sha256,
                authorization_ref=att.authorization_ref,
                isolation_ref=att.isolation_ref,
                enforced_controls=att.enforced_controls,
                command_sha256=att.command_sha256,
                spec_sha256="",  # Omitted
            )

        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=attest_no_spec,
        )
        cmd = [sys.executable, "-c", "print(1)"]
        req = {
            "id": "a2-req-1", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_no_spec", "destination": "", "paths": ["src"],
            "command": cmd,
        }
        res = adapter.dispatch(req, cmd)
        self.assertTrue(res["blocked"])
        self.assertFalse(res["occurred"])
        self.assertIn("missing mandatory spec_sha256", res["reason"])

    def test_a2_missing_command_sha256_in_attestation_blocks_local_execution(self):
        """A2: Host attestation omitting command_sha256 fails closed for verify_local."""
        def attest_no_cmd(request):
            att = self._make_attestation(request)
            return HostAttestation(
                request_sha256=att.request_sha256,
                authorization_ref=att.authorization_ref,
                isolation_ref=att.isolation_ref,
                enforced_controls=att.enforced_controls,
                command_sha256="",  # Omitted
                spec_sha256=att.spec_sha256,
            )

        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=attest_no_cmd,
        )
        cmd = [sys.executable, "-c", "print(1)"]
        req = {
            "id": "a2-req-2", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_no_cmd", "destination": "", "paths": ["src"],
            "command": cmd,
        }
        res = adapter.dispatch(req, cmd)
        self.assertTrue(res["blocked"])
        self.assertFalse(res["occurred"])
        self.assertIn("missing mandatory command_sha256", res["reason"])

    def test_a2_mismatched_spec_sha256_in_attestation_blocks_local_execution(self):
        """A2: Host attestation with forged or mismatched spec_sha256 is rejected."""
        def attest_mismatched_spec(request):
            att = self._make_attestation(request)
            return HostAttestation(
                request_sha256=att.request_sha256,
                authorization_ref=att.authorization_ref,
                isolation_ref=att.isolation_ref,
                enforced_controls=att.enforced_controls,
                command_sha256=att.command_sha256,
                spec_sha256="0" * 64,  # Mismatched forged digest
            )

        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=attest_mismatched_spec,
        )
        cmd = [sys.executable, "-c", "print(1)"]
        req = {
            "id": "a2-req-3", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_mismatch_spec", "destination": "", "paths": ["src"],
            "command": cmd,
        }
        res = adapter.dispatch(req, cmd)
        self.assertTrue(res["blocked"])
        self.assertFalse(res["occurred"])
        self.assertIn("execution specification does not match", res["reason"])

    @unittest.skipUnless(SANDBOX_EXEC.exists() and RUNTIME_EXECUTION_ENABLED, "Legacy Seatbelt execution disabled; external isolation required")
    def test_a3_posix_process_group_cleanup_contained_descendants(self):
        """A3: Process group cleanup terminates multiple background worker processes."""
        script = self.source_root / "multi_workers.py"
        script.write_text(
            "import os, sys, time\n"
            "pids = []\n"
            "for i in range(3):\n"
            "    p = os.fork()\n"
            "    if p == 0:\n"
            "        time.sleep(30)\n"
            "        sys.exit(0)\n"
            "    pids.append(p)\n"
            "print('PIDS=' + ','.join(map(str, pids)))\n"
            "sys.exit(0)\n"
        )
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation,
        )
        cmd = [sys.executable, str(script)]
        req = {
            "id": "a3-req-1", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_workers", "destination": "", "paths": ["src"],
            "command": cmd,
        }
        res = adapter.dispatch(req, cmd)
        self.assertTrue(res["occurred"])
        match = re.search(r"PIDS=([0-9,]+)", res["stdout"])
        self.assertIsNotNone(match)
        pids = [int(p) for p in match.group(1).split(",")]
        time.sleep(0.2)
        for pid in pids:
            with self.assertRaises(OSError, msg=f"Worker PID {pid} survived cleanup!"):
                os.kill(pid, 0)

    @unittest.skipUnless(SANDBOX_EXEC.exists() and RUNTIME_EXECUTION_ENABLED, "Legacy Seatbelt execution disabled; external isolation required")
    def test_a3_setsid_escape_limitation_documented(self):
        """A3: Documents technical limitation where grandchild calling setsid() escapes POSIX process group.

        Verifies that while normal process-group cleanup functions, macOS Seatbelt cannot prevent setsid()
        without kernel-level process namespaces / cgroups. Documents why multi-tenant execution requires
        external container/VM isolation.
        """
        script = self.source_root / "setsid_test.py"
        script.write_text(
            "import os, sys, time\n"
            "p = os.fork()\n"
            "if p == 0:\n"
            "    p2 = os.fork()\n"
            "    if p2 == 0:\n"
            "        os.setsid()\n"
            "        print(f'SETSID_PID={os.getpid()}', flush=True)\n"
            "        sys.stdin.close()\n"
            "        sys.stdout.close()\n"
            "        sys.stderr.close()\n"
            "        time.sleep(10)\n"
            "        sys.exit(0)\n"
            "    sys.exit(0)\n"
            "os.waitpid(p, 0)\n"
        )
        adapter = IsolatedHostAdapter(
            self.source_root, self.scratch_root,
            target=self.target, revision=self.revision,
            attestation_provider=self._make_attestation,
        )
        cmd = [sys.executable, str(script)]
        req = {
            "id": "a3-req-2", "target": self.target, "revision": self.revision,
            "effect": "verify_local", "profile": "isolated-local",
            "operation": "test_setsid", "destination": "", "paths": ["src"],
            "command": cmd,
        }
        res = adapter.dispatch(req, cmd)
        self.assertTrue(res["occurred"])
        match = re.search(r"SETSID_PID=(\d+)", res["stdout"])
        self.assertIsNotNone(match)
        escaped_pid = int(match.group(1))
        # The setsid child escapes killpg(saved_pgid)
        escaped_alive = False
        try:
            os.kill(escaped_pid, 0)
            escaped_alive = True
            # Clean up the test process safely
            os.kill(escaped_pid, signal.SIGKILL)
        except OSError:
            escaped_alive = False
        # Documented limitation: escaped_alive is True under POSIX without cgroups!
        self.assertTrue(escaped_alive, "Limitation documentation: setsid() detached from saved_pgid")



if __name__ == "__main__":
    unittest.main()
