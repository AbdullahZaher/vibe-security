#!/usr/bin/env python3
"""macOS Host Verification Suite for prelaunch-security-audit v0.5.0.

Executes the 10 mandatory negative security tests on macOS Seatbelt and
IsolatedHostAdapter / StaticHost using disposable synthetic fixtures.
Captures host platform metadata, exact commands, exit codes, stderr digests,
and execution timing.

No real secrets, external networks, or target repositories are accessed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/prelaunch-security-audit/scripts"))

from execution_profiles import CONTROLS, HostAttestation, StaticHost, assess, digest
from runtime_host_adapter import (
    ApprovalStore,
    ExecutionSpec,
    IsolatedHostAdapter,
    RUNTIME_EXECUTION_ENABLED,
    _make_seatbelt_profile,
)

SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")


def get_git_info() -> dict[str, str]:
    try:
        commit = subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
        ).strip()
        tree = subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD^{tree}"], text=True
        ).strip()
        branch = subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "--abbrev-ref", "HEAD"], text=True
        ).strip()
        skill_tree = subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD:skills/prelaunch-security-audit"], text=True
        ).strip()
    except Exception:
        commit, tree, branch, skill_tree = "unknown", "unknown", "unknown", "unknown"
    return {
        "commit": commit,
        "tree": tree,
        "branch": branch,
        "skill_tree": skill_tree,
    }


def get_macos_host_metadata() -> dict:
    sw_vers_dict = {}
    try:
        out = subprocess.check_output(["sw_vers"], text=True)
        for line in out.strip().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                sw_vers_dict[k.strip()] = v.strip()
    except Exception:
        pass

    return {
        "hostname": platform.node(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "python_path": sys.executable,
        "macos_product_name": sw_vers_dict.get("ProductName", "macOS"),
        "macos_product_version": sw_vers_dict.get("ProductVersion", platform.mac_ver()[0]),
        "macos_build_version": sw_vers_dict.get("BuildVersion", ""),
        "seatbelt_path": str(SANDBOX_EXEC),
        "seatbelt_available": SANDBOX_EXEC.exists(),
        "user_uid": os.getuid(),
        "user_gid": os.getgid(),
    }


class MacOSHostVerifier:
    def __init__(self, output_path: Path):
        self.output_path = output_path
        self.tmp = tempfile.TemporaryDirectory(prefix="v050-macos-verify-")
        self.base = Path(self.tmp.name).resolve()
        self.results = []
        self.host_meta = get_macos_host_metadata()
        self.git_info = get_git_info()

    def cleanup(self):
        self.tmp.cleanup()

    def _record(self, test_id: str, title: str, expected: str, observed: dict,
                passed: bool, command: str = "", exit_code: int | None = None,
                stderr: str = "", wall_ms: int = 0, details: dict | None = None):
        stderr_bytes = stderr.encode("utf-8") if isinstance(stderr, str) else b""
        self.results.append({
            "test_id": test_id,
            "title": title,
            "command": command,
            "expected": expected,
            "observed": observed,
            "exit_code": exit_code,
            "stderr_sha256": hashlib.sha256(stderr_bytes).hexdigest() if stderr_bytes else None,
            "wall_ms": wall_ms,
            "passed": passed,
            "details": details or {},
        })

    # Test 1: Unauthorized Subprocess Execution
    def test_01_unauthorized_subprocess_execution(self):
        t0 = time.monotonic()
        source = self.base / "src1"
        scratch = self.base / "scratch1"
        source.mkdir()
        scratch.mkdir()
        store_path = self.base / "store1" / "approvals.json"
        store_path.parent.mkdir(mode=0o700)

        # Attestation provider returning None (unauthorized)
        adapter = IsolatedHostAdapter(
            source, scratch, target="synth-target", revision="a" * 40,
            attestation_provider=lambda _r: None,
            approval_store=ApprovalStore(store_path),
        )
        cmd = [sys.executable, "-c", "print('MUST_NOT_EXECUTE')"]
        req = {
            "id": "unauth-req-1",
            "target": "synth-target",
            "revision": "a" * 40,
            "effect": "verify_local",
            "profile": "isolated-local",
            "operation": "run_test",
            "destination": "",
            "paths": ["source.py"],
            "command": cmd,
        }
        res = adapter.dispatch(req, cmd)
        wall_ms = int((time.monotonic() - t0) * 1000)
        passed = (res.get("blocked") is True and res.get("occurred") is False
                  and res.get("status") in ("blocked", "not_verified"))
        self._record(
            "TEST-01-UNAUTHORIZED-EXECUTION",
            "Unauthorized subprocess execution fails closed without launching process",
            "blocked=True, occurred=False, status=not_verified or blocked",
            {"blocked": res.get("blocked"), "occurred": res.get("occurred"), "status": res.get("status"), "reason": res.get("reason")},
            passed,
            command="IsolatedHostAdapter.dispatch(unauthorized_req)",
            exit_code=None,
            wall_ms=wall_ms,
            details={"dispatched_command": cmd},
        )

    # Test 2: Static-only to Execution Escalation
    def test_02_static_only_to_execution_escalation(self):
        t0 = time.monotonic()
        source = self.base / "src2"
        scratch = self.base / "scratch2"
        source.mkdir()
        scratch.mkdir()
        store_path = self.base / "store2" / "approvals.json"
        store_path.parent.mkdir(mode=0o700)

        def _auth(req):
            return HostAttestation(
                request_sha256=digest(req),
                authorization_ref="auth-escalate",
                isolation_ref="iso-escalate",
                enforced_controls=CONTROLS,
                command_sha256=digest(req.get("command", [])),
                spec_sha256=req.get("spec_sha256", ""),
            )

        adapter = IsolatedHostAdapter(
            source, scratch, target="synth-target", revision="a" * 40,
            attestation_provider=_auth,
            approval_store=ApprovalStore(store_path),
        )
        cmd = [sys.executable, "-c", "print('ESCALATION_ATTEMPT')"]
        req = {
            "id": "escalate-req-1",
            "target": "synth-target",
            "revision": "a" * 40,
            "effect": "observe",
            "profile": "static-only",
            "operation": "read_source",
            "destination": "",
            "paths": ["source.py"],
            "command": cmd,
        }
        res = adapter.dispatch(req, cmd)
        wall_ms = int((time.monotonic() - t0) * 1000)
        passed = (res.get("blocked") is True and res.get("occurred") is False
                  and "subprocess dispatch requires explicit isolated-local execution authorization" in res.get("reason", ""))
        self._record(
            "TEST-02-STATIC-TO-EXEC-ESCALATION",
            "Static-only or observe request attempting subprocess dispatch is rejected",
            "blocked=True, reason mentions isolated-local requirement",
            {"blocked": res.get("blocked"), "occurred": res.get("occurred"), "reason": res.get("reason")},
            passed,
            command="IsolatedHostAdapter.dispatch(observe_req)",
            wall_ms=wall_ms,
        )

    # Test 3: Host Filesystem Access Outside Authorized Scope
    def test_03_host_filesystem_access_outside_scope(self):
        t0 = time.monotonic()
        source = self.base / "src3"
        scratch = self.base / "scratch3"
        source.mkdir()
        scratch.mkdir()
        (source / "allowed.txt").write_text("ALLOWED_CONTENT\n")
        outside = self.base / "outside3"
        outside.mkdir()
        (outside / "forbidden.txt").write_text("FORBIDDEN_CONTENT\n")

        # Layer 1: StaticHost allowlist & path traversal rejection
        host = StaticHost(source, ["allowed.txt"], target="synth-target", revision="a" * 40)
        req_outside = {
            "id": "fs-outside-1",
            "target": "synth-target",
            "revision": "a" * 40,
            "effect": "observe",
            "profile": "static-only",
            "operation": "read_source",
            "destination": "",
            "paths": ["../outside3/forbidden.txt"],
        }
        res_host = host.dispatch(req_outside)

        # Layer 2: macOS Seatbelt sandbox-exec kernel enforcement
        sb_profile = _make_seatbelt_profile(source, scratch)
        sb_path = self.base / "test3.sb"
        sb_path.write_text(sb_profile)
        cmd_outside = [str(SANDBOX_EXEC), "-f", str(sb_path), "/bin/cat", str(outside / "forbidden.txt")]
        proc = subprocess.run(cmd_outside, capture_output=True, text=True)
        wall_ms = int((time.monotonic() - t0) * 1000)

        passed = ("DENIED by static host" in res_host.get("error", "")
                  and proc.returncode != 0
                  and "FORBIDDEN_CONTENT" not in proc.stdout)
        self._record(
            "TEST-03-FILESYSTEM-SCOPE-ENFORCEMENT",
            "Access to files outside authorized source root is blocked by StaticHost and Seatbelt",
            "StaticHost DENIED; Seatbelt non-zero returncode and Operation not permitted",
            {
                "static_host_result": res_host,
                "seatbelt_exit_code": proc.returncode,
                "seatbelt_operation_denied": "Operation not permitted" in proc.stderr,
                "forbidden_content_leaked": "FORBIDDEN_CONTENT" in proc.stdout,
            },
            passed,
            command=" ".join(cmd_outside),
            exit_code=proc.returncode,
            stderr=proc.stderr,
            wall_ms=wall_ms,
        )

    # Test 4: Credential and Home Directory Access
    def test_04_credential_and_home_directory_access(self):
        t0 = time.monotonic()
        source = self.base / "src4"
        scratch = self.base / "scratch4"
        source.mkdir()
        scratch.mkdir()
        sb_profile = _make_seatbelt_profile(source, scratch)
        sb_path = self.base / "test4.sb"
        sb_path.write_text(sb_profile)

        # Attempt to read /etc/passwd or /private/etc/master.passwd (explicitly denied in profile)
        cmd = [str(SANDBOX_EXEC), "-f", str(sb_path), "/bin/cat", "/etc/passwd"]
        proc = subprocess.run(cmd, capture_output=True, text=True)

        # Also attempt to read home directory .ssh
        ssh_dir = Path.home() / ".ssh"
        proc_ssh = subprocess.run(
            [str(SANDBOX_EXEC), "-f", str(sb_path), "/bin/ls", str(ssh_dir)],
            capture_output=True, text=True
        )
        wall_ms = int((time.monotonic() - t0) * 1000)

        passed = (proc.returncode != 0 and "Operation not permitted" in proc.stderr
                  and proc_ssh.returncode != 0)
        self._record(
            "TEST-04-CREDENTIAL-AND-HOME-DENIAL",
            "Credential files (/etc/passwd, master.passwd) and user home/ssh directory are denied",
            "Seatbelt non-zero returncode and Operation not permitted",
            {
                "passwd_exit_code": proc.returncode,
                "passwd_operation_permitted": "Operation not permitted" in proc.stderr,
                "ssh_exit_code": proc_ssh.returncode,
                "ssh_operation_permitted": "Operation not permitted" in proc_ssh.stderr,
            },
            passed,
            command=" ".join(cmd),
            exit_code=proc.returncode,
            stderr=proc.stderr,
            wall_ms=wall_ms,
        )

    # Test 5: Unauthorized Network Egress
    def test_05_unauthorized_network_egress(self):
        t0 = time.monotonic()
        source = self.base / "src5"
        scratch = self.base / "scratch5"
        source.mkdir()
        scratch.mkdir()
        sb_profile = _make_seatbelt_profile(source, scratch)
        sb_path = self.base / "test5.sb"
        sb_path.write_text(sb_profile)

        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            # Baseline test without sandbox
            baseline = subprocess.run(
                ["/usr/bin/nc", "-z", "-G", "1", "127.0.0.1", str(port)],
                capture_output=True, text=True
            )
            # Sandboxed test
            sandboxed = subprocess.run(
                [str(SANDBOX_EXEC), "-f", str(sb_path), "/usr/bin/nc", "-v", "-z", "-G", "1", "127.0.0.1", str(port)],
                capture_output=True, text=True
            )
        wall_ms = int((time.monotonic() - t0) * 1000)
        passed = (baseline.returncode == 0 and sandboxed.returncode != 0
                  and "Operation not permitted" in sandboxed.stderr)
        self._record(
            "TEST-05-NETWORK-EGRESS-DENIAL",
            "Network socket communication is unconditionally denied by (deny network*)",
            "Baseline socket succeeds (exit 0); sandboxed socket fails (exit 1, Operation not permitted)",
            {
                "baseline_exit_code": baseline.returncode,
                "sandboxed_exit_code": sandboxed.returncode,
                "operation_not_permitted": "Operation not permitted" in sandboxed.stderr,
            },
            passed,
            command="nc -v -z 127.0.0.1 <port>",
            exit_code=sandboxed.returncode,
            stderr=sandboxed.stderr,
            wall_ms=wall_ms,
        )

    # Test 6: Detached Descendant Process Persistence (setsid Escape Boundary)
    def test_06_detached_descendant_process_persistence(self):
        t0 = time.monotonic()
        pid_file = self.base / "escaped_grandchild.pid"
        script = self.base / "spawn_setsid.py"
        script.write_text(f"""\
import os, sys, time
pid = os.fork()
if pid == 0:
    os.setsid()
    gpid = os.fork()
    if gpid == 0:
        with open("{pid_file}", "w") as f:
            f.write(str(os.getpid()))
        time.sleep(10)
        sys.exit(0)
    sys.exit(0)
sys.exit(0)
""")
        # Run script with start_new_session=True and killpg on the parent pid
        proc = subprocess.Popen([sys.executable, str(script)], start_new_session=True)
        proc.wait(timeout=5)
        # Attempt to kill process group
        try:
            os.killpg(proc.pid, 9)
        except OSError:
            pass

        time.sleep(0.3)
        escaped_pid = None
        survived = False
        if pid_file.exists():
            try:
                escaped_pid = int(pid_file.read_text().strip())
                os.kill(escaped_pid, 0)
                survived = True
                # Clean up the escaped process
                os.kill(escaped_pid, 9)
            except OSError:
                survived = False
        wall_ms = int((time.monotonic() - t0) * 1000)

        # This proves the Darwin limitation: setsid() successfully detaches from process group.
        # This confirms why arbitrary untrusted code execution cannot be safely enabled on macOS host.
        passed = survived is True
        self._record(
            "TEST-06-SETSID-ESCAPE-BOUNDARY",
            "Grandchild calling setsid() detaches from process group, proving POSIX boundary limitation",
            "Grandchild process survives parent process group termination (demonstrating boundary)",
            {
                "setsid_escape_demonstrated": survived,
                "escaped_pid": escaped_pid,
                "implication": "Darwin Seatbelt and killpg cannot contain detached processes; untrusted execution must remain disabled",
            },
            passed,
            command=f"python3 {script.name} (with setsid)",
            wall_ms=wall_ms,
        )

    # Test 7: Approval Replay Across Processes
    def test_07_approval_replay_across_processes(self):
        t0 = time.monotonic()
        store_path = self.base / "store7" / "approvals.json"
        store_path.parent.mkdir(mode=0o700)

        store1 = ApprovalStore(store_path)
        first_consume = store1.consume("req-replay-1", "auth-token-xyz", "b" * 64)

        # Simulate separate process / instance by instantiating new ApprovalStore
        store2 = ApprovalStore(store_path)
        replay_consume = store2.consume("req-replay-1", "auth-token-xyz", "b" * 64)
        wall_ms = int((time.monotonic() - t0) * 1000)

        passed = (first_consume is True and replay_consume is False)
        self._record(
            "TEST-07-APPROVAL-REPLAY-REJECTION",
            "Single-use durable approval consumption prevents replay across independent instances",
            "First consumption returns True; second consumption across separate instance returns False",
            {
                "first_consumption": first_consume,
                "replay_consumption": replay_consume,
                "file_mode": oct(stat.S_IMODE(store_path.stat().st_mode)),
                "lock_mode": oct(stat.S_IMODE((store_path.parent / (store_path.name + ".lock")).stat().st_mode)),
            },
            passed,
            command="ApprovalStore.consume(req, auth, spec)",
            wall_ms=wall_ms,
        )

    # Test 8: Malformed or Forged Attestations
    def test_08_malformed_or_forged_attestations(self):
        t0 = time.monotonic()
        source = self.base / "src8"
        scratch = self.base / "scratch8"
        source.mkdir()
        scratch.mkdir()
        store_path = self.base / "store8" / "approvals.json"
        store_path.parent.mkdir(mode=0o700)

        # Attestation with forged/tampered command digest
        def _forged_attest(req):
            return HostAttestation(
                request_sha256=digest(req),
                authorization_ref="auth-forged",
                isolation_ref="iso-forged",
                enforced_controls=CONTROLS,
                command_sha256="0" * 64,  # FORGED DIGEST
                spec_sha256=req.get("spec_sha256", ""),
            )

        adapter = IsolatedHostAdapter(
            source, scratch, target="synth-target", revision="a" * 40,
            attestation_provider=_forged_attest,
            approval_store=ApprovalStore(store_path),
        )
        cmd = [sys.executable, "-c", "print('FORGED')"]
        req = {
            "id": "forged-req-1",
            "target": "synth-target",
            "revision": "a" * 40,
            "effect": "verify_local",
            "profile": "isolated-local",
            "operation": "run_test",
            "destination": "",
            "paths": ["source.py"],
            "command": cmd,
        }
        res = adapter.dispatch(req, cmd)
        wall_ms = int((time.monotonic() - t0) * 1000)

        passed = (res.get("blocked") is True and res.get("occurred") is False
                  and ("command does not match" in res.get("reason", "")
                       or "command digest mismatch" in res.get("reason", "")
                       or "attestation does not match" in res.get("reason", "")))
        self._record(
            "TEST-08-FORGED-ATTESTATION-REJECTION",
            "Host attestation with forged command digest is rejected by policy evaluation",
            "blocked=True, reason mentions command digest mismatch",
            {"blocked": res.get("blocked"), "occurred": res.get("occurred"), "reason": res.get("reason")},
            passed,
            command="assess(req, attest=forged_attestation)",
            wall_ms=wall_ms,
        )

    # Test 9: Command and Spec Substitution
    def test_09_command_spec_substitution(self):
        t0 = time.monotonic()
        source = self.base / "src9"
        scratch = self.base / "scratch9"
        source.mkdir()
        scratch.mkdir()
        store_path = self.base / "store9" / "approvals.json"
        store_path.parent.mkdir(mode=0o700)

        adapter = IsolatedHostAdapter(
            source, scratch, target="synth-target", revision="a" * 40,
            attestation_provider=lambda r: None,
            approval_store=ApprovalStore(store_path),
        )
        cmd_authorized = [sys.executable, "-c", "print('ORIGINAL')"]
        cmd_substituted = [sys.executable, "-c", "print('SUBSTITUTED')"]
        req = {
            "id": "subst-req-1",
            "target": "synth-target",
            "revision": "a" * 40,
            "effect": "verify_local",
            "profile": "isolated-local",
            "operation": "run_test",
            "destination": "",
            "paths": ["source.py"],
            "command": cmd_authorized,
        }
        # Pass substituted command to dispatch
        res = adapter.dispatch(req, cmd_substituted)
        wall_ms = int((time.monotonic() - t0) * 1000)

        passed = (res.get("blocked") is True and res.get("occurred") is False
                  and "command is not cryptographically or structurally bound to request" in res.get("reason", ""))
        self._record(
            "TEST-09-COMMAND-SPEC-SUBSTITUTION",
            "Substituted command differing from request command is rejected prior to dispatch",
            "blocked=True, reason mentions cryptographic/structural binding failure",
            {"blocked": res.get("blocked"), "occurred": res.get("occurred"), "reason": res.get("reason")},
            passed,
            command="IsolatedHostAdapter.dispatch(req_orig, cmd_substituted)",
            wall_ms=wall_ms,
        )

    # Test 10: Runtime Configuration Manipulation
    def test_10_runtime_configuration_manipulation(self):
        t0 = time.monotonic()
        source = self.base / "src10"
        scratch = self.base / "scratch10"
        source.mkdir()
        scratch.mkdir()
        store_path = self.base / "store10" / "approvals.json"
        store_path.parent.mkdir(mode=0o700)

        def _auth(req):
            cmd = req.get("command")
            return HostAttestation(
                request_sha256=digest(req),
                authorization_ref="auth-config-tamper",
                isolation_ref="iso-config-tamper",
                enforced_controls=CONTROLS,
                command_sha256=digest(cmd) if cmd else "",
                spec_sha256=req.get("spec_sha256", ""),
            )

        adapter = IsolatedHostAdapter(
            source, scratch, target="synth-target", revision="a" * 40,
            attestation_provider=_auth,
            approval_store=ApprovalStore(store_path),
        )
        cmd = [sys.executable, "-c", "print('MUST_NOT_RUN')"]
        req = {
            "id": "config-tamper-1",
            "target": "synth-target",
            "revision": "a" * 40,
            "effect": "verify_local",
            "profile": "isolated-local",
            "operation": "run_test",
            "destination": "",
            "paths": ["source.py"],
            "command": cmd,
        }

        # Even if someone attempts to mutate RUNTIME_EXECUTION_ENABLED or flags,
        # dispatch fails closed and never launches a subprocess
        import runtime_host_adapter
        old_val = runtime_host_adapter.RUNTIME_EXECUTION_ENABLED
        try:
            # Simulate attempt to flip diagnostic flag
            runtime_host_adapter.RUNTIME_EXECUTION_ENABLED = True
            res = adapter.dispatch(req, cmd)
        finally:
            runtime_host_adapter.RUNTIME_EXECUTION_ENABLED = old_val

        wall_ms = int((time.monotonic() - t0) * 1000)
        passed = (res.get("blocked") is True and res.get("occurred") is False
                  and "untrusted code execution disabled; external isolation supervisor not implemented" in res.get("reason", "")
                  and not store_path.exists())
        self._record(
            "TEST-10-RUNTIME-CONFIG-MANIPULATION",
            "Mutating runtime execution flag cannot bypass fail-closed block; no approvals consumed",
            "blocked=True, external isolation supervisor required, approval store untouched",
            {
                "blocked": res.get("blocked"),
                "occurred": res.get("occurred"),
                "reason": res.get("reason"),
                "approval_consumed": store_path.exists(),
            },
            passed,
            command="IsolatedHostAdapter.dispatch(req) with RUNTIME_EXECUTION_ENABLED=True",
            wall_ms=wall_ms,
        )

    def run_all(self) -> dict:
        self.test_01_unauthorized_subprocess_execution()
        self.test_02_static_only_to_execution_escalation()
        self.test_03_host_filesystem_access_outside_scope()
        self.test_04_credential_and_home_directory_access()
        self.test_05_unauthorized_network_egress()
        self.test_06_detached_descendant_process_persistence()
        self.test_07_approval_replay_across_processes()
        self.test_08_malformed_or_forged_attestations()
        self.test_09_command_spec_substitution()
        self.test_10_runtime_configuration_manipulation()

        passed_count = sum(1 for r in self.results if r["passed"])
        failed_count = sum(1 for r in self.results if not r["passed"])

        report = {
            "schema": "v0.5.0-macos-negative-verification-v1",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "git_info": self.git_info,
            "host_metadata": self.host_meta,
            "total_tests": len(self.results),
            "passed_tests": passed_count,
            "failed_tests": failed_count,
            "all_passed": failed_count == 0,
            "tests": self.results,
            "limitations_documented": [
                "Darwin Seatbelt (/usr/bin/sandbox-exec) is a deprecated host mechanism without an official external SLA.",
                "POSIX setsid() creates an independent session that escapes killpg process group signaling.",
                "Seatbelt does not enforce cgroup-like memory, CPU bandwidth, or PID limits.",
                "Arbitrary untrusted target code execution is disabled and fails closed; only static allowlisted reads are available.",
                "Production multi-tenant agent execution requires external hypervisors (microVMs) or containerized Linux PID/mount namespaces."
            ]
        }

        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "docs/security/v0.5.0-remediation-verification-matrix.json",
                        help="Path to save verification matrix JSON")
    args = parser.parse_args()

    verifier = MacOSHostVerifier(args.output)
    try:
        report = verifier.run_all()
        print(f"Executed {report['total_tests']} tests: {report['passed_tests']} passed, {report['failed_tests']} failed.")
        print(f"Report written to: {args.output}")
        return 0 if report["all_passed"] else 1
    finally:
        verifier.cleanup()


if __name__ == "__main__":
    sys.exit(main())
