#!/usr/bin/env python3
"""Minimal host runtime adapter enforcing isolated execution boundaries.

Integrates directly with execution_profiles.assess() and HostAttestation.
Enforces technical sandbox controls: read-only source access, writable
disposable scratch space, network egress denial, credential scrubbing,
resource limits, and trusted host-side execution logging.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from audit_artifacts import MAX_BYTES, require, trusted_root
from execution_profiles import CONTROLS, HostAttestation, assess, digest, validate_request

SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
SAFE_ENV_KEYS = frozenset({"PATH", "TMPDIR", "PYTHONPATH"})


def _quote_sb(path: Path) -> str:
    return str(path.resolve()).replace("\\", "\\\\").replace('"', '\\"')


def _make_seatbelt_profile(source_root: Path, scratch_root: Path, *, allow_network: bool = False) -> str:
    rules = [
        "(version 1)",
        "(allow default)",
    ]
    if not allow_network:
        rules.append("(deny network*)")
    rules.extend([
        "(deny file-write*)",
        f'(allow file-write* (subpath "{_quote_sb(scratch_root)}"))',
    ])
    return "\n".join(rules) + "\n"


class IsolatedHostAdapter:
    """Technically enforced execution adapter for prelaunch security audit dispatch.

    Dispatches commands ONLY when authorized by execution_profiles.assess().
    Records trusted host-side telemetry for every requested action.
    """

    def __init__(self, source_root: Path, scratch_root: Path, *,
                 target: str, revision: str, attestation_provider=None,
                 timeout: int = 15, max_bytes: int = MAX_BYTES):
        self.source_root = Path(source_root).resolve()
        self.scratch_root = Path(scratch_root).resolve()
        self.target = target
        self.revision = revision
        self.attestation_provider = attestation_provider
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.events: list[dict] = []

    def dispatch(self, request: dict, command: list[str]) -> dict:
        event = {
            "sequence": len(self.events) + 1,
            "request_sha256": digest(request),
            "command": list(command),
            "occurred": False,
            "blocked": True,
            "exit_code": None,
            "timestamp": time.time(),
        }
        self.events.append(event)

        verdict = assess(request, attest=self.attestation_provider)
        if verdict.get("status") != "eligible_for_host_dispatch":
            event["reason"] = verdict.get("reason", "not eligible for dispatch")
            return {
                "occurred": False,
                "blocked": True,
                "status": verdict.get("status", "blocked"),
                "reason": verdict.get("reason"),
            }

        if request.get("target") != self.target or request.get("revision") != self.revision:
            event["reason"] = "target or revision mismatch with host configuration"
            return {"occurred": False, "blocked": True, "reason": event["reason"]}

        if not SANDBOX_EXEC.exists():
            event["reason"] = "host sandbox facility (/usr/bin/sandbox-exec) unavailable"
            return {"occurred": False, "blocked": True, "reason": event["reason"]}

        # Prepare disposable sub-scratch directory for this run
        run_scratch = Path(tempfile.mkdtemp(prefix="run-scratch-", dir=self.scratch_root)).resolve()
        sb_profile_path = run_scratch / "run.sb"
        sb_profile_text = _make_seatbelt_profile(
            self.source_root, run_scratch,
            allow_network=(request.get("effect") == "network_read")
        )
        sb_profile_path.write_text(sb_profile_text, encoding="utf-8")

        # Clean environment: strip credentials, retain only minimal safe variables
        scrubbed_env = {
            "PATH": os.environ.get("PATH", os.defpath),
            "TMPDIR": str(run_scratch),
        }

        # Apply preexec_fn for CPU limits where available
        def _set_rlimits():
            try:
                import resource
                resource.setrlimit(resource.RLIMIT_CPU, (10, 15))
            except (ImportError, OSError):
                pass

        full_command = [str(SANDBOX_EXEC), "-f", str(sb_profile_path), *command]
        started = time.monotonic()
        try:
            proc = subprocess.Popen(
                full_command,
                cwd=str(self.source_root),
                env=scrubbed_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=_set_rlimits if os.name != "nt" else None,
            )
            stdout_data, stderr_data = b"", b""
            timed_out = False
            try:
                stdout_data, stderr_data = proc.communicate(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                proc.kill()
                stdout_data, stderr_data = proc.communicate()

            wall_ms = int((time.monotonic() - started) * 1000)
            stdout_str = stdout_data[:self.max_bytes].decode("utf-8", errors="replace")
            stderr_str = stderr_data[:self.max_bytes].decode("utf-8", errors="replace")

            event.update({
                "occurred": True,
                "blocked": False,
                "exit_code": proc.returncode,
                "timed_out": timed_out,
                "wall_ms": wall_ms,
                "stdout_sha256": hashlib.sha256(stdout_data).hexdigest(),
                "stderr_sha256": hashlib.sha256(stderr_data).hexdigest(),
                "output_truncated": len(stdout_data) > self.max_bytes or len(stderr_data) > self.max_bytes,
            })

            return {
                "occurred": True,
                "blocked": False,
                "exit_code": proc.returncode,
                "stdout": stdout_str,
                "stderr": stderr_str,
                "timed_out": timed_out,
                "wall_ms": wall_ms,
            }
        finally:
            shutil.rmtree(run_scratch, ignore_errors=True)
