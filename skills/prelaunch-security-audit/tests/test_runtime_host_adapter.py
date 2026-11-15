"""Comprehensive regression and hardening tests for IsolatedHostAdapter (R-01 through R-04)."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import socket
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from execution_profiles import CONTROLS, HostAttestation, digest  # noqa: E402
from runtime_host_adapter import (  # noqa: E402
    SANDBOX_EXEC,
    ExecutionSpec,
    IsolatedHostAdapter,
    _make_seatbelt_profile,
)


class TestRuntimeHostAdapterHardening(unittest.TestCase):
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
        cmd = request.get("command")
        cmd_sha = digest(cmd) if cmd else ""
        return HostAttestation(
            request_sha256=digest(request),
            authorization_ref="auth-ref-12345",
            isolation_ref="iso-ref-67890",
            enforced_controls=CONTROLS,
            command_sha256=cmd_sha,
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

    @unittest.skipUnless(SANDBOX_EXEC.exists(), "Seatbelt (/usr/bin/sandbox-exec) required")
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

    @unittest.skipUnless(SANDBOX_EXEC.exists(), "Seatbelt (/usr/bin/sandbox-exec) required")
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

    @unittest.skipUnless(SANDBOX_EXEC.exists(), "Seatbelt (/usr/bin/sandbox-exec) required")
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

    @unittest.skipUnless(SANDBOX_EXEC.exists(), "Seatbelt (/usr/bin/sandbox-exec) required")
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

    @unittest.skipUnless(SANDBOX_EXEC.exists(), "Seatbelt (/usr/bin/sandbox-exec) required")
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
        self.assertEqual(list(event["spec"]["command"]), cmd)
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

    @unittest.skipUnless(SANDBOX_EXEC.exists(), "Seatbelt (/usr/bin/sandbox-exec) required")
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

    @unittest.skipUnless(SANDBOX_EXEC.exists(), "Seatbelt (/usr/bin/sandbox-exec) required")
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

    @unittest.skipUnless(SANDBOX_EXEC.exists(), "Seatbelt (/usr/bin/sandbox-exec) required")
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

    @unittest.skipUnless(SANDBOX_EXEC.exists(), "Seatbelt (/usr/bin/sandbox-exec) required")
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

    @unittest.skipUnless(SANDBOX_EXEC.exists(), "Seatbelt (/usr/bin/sandbox-exec) required")
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

    @unittest.skipUnless(SANDBOX_EXEC.exists(), "Seatbelt (/usr/bin/sandbox-exec) required")
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

    @unittest.skipUnless(SANDBOX_EXEC.exists(), "Seatbelt (/usr/bin/sandbox-exec) required")
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


if __name__ == "__main__":
    unittest.main()
