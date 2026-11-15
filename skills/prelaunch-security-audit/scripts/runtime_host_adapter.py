#!/usr/bin/env python3
"""Host runtime adapter enforcing technical isolation boundaries.

Integrates directly with execution_profiles.assess(), ExecutionSpec, and
HostAttestation. Enforces technical sandbox controls: least-privilege filesystem
isolation (read-only source, denied host secrets, denied user directories,
denied cross-workspace trees, writable disposable scratch), unconditional network
egress denial, cryptographic authorization binding to executed commands, replay
prevention, incremental output bounding, process group cleanup, and trusted
host-side telemetry logging.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from audit_artifacts import MAX_BYTES, require, trusted_root
from execution_profiles import CONTROLS, HostAttestation, assess, digest, validate_request

SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
SAFE_ENV_KEYS = frozenset({"PATH", "TMPDIR", "PYTHONPATH", "PYTHONNOUSERSITE"})


@dataclass(frozen=True)
class ExecutionSpec:
    """Immutable technical execution specification bound to host authorization."""
    target: str
    revision: str
    command: tuple[str, ...]
    cwd: str
    effect: str
    profile: str
    operation: str
    destination: str
    paths: tuple[str, ...]
    env_keys: tuple[str, ...]
    timeout: int
    max_bytes: int
    authorization_ref: str

    def digest(self) -> str:
        data = {
            "target": self.target,
            "revision": self.revision,
            "command": list(self.command),
            "cwd": self.cwd,
            "effect": self.effect,
            "profile": self.profile,
            "operation": self.operation,
            "destination": self.destination,
            "paths": list(self.paths),
            "env_keys": sorted(self.env_keys),
            "timeout": self.timeout,
            "max_bytes": self.max_bytes,
            "authorization_ref": self.authorization_ref,
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _quote_sb(path: Path) -> str:
    return str(path.resolve()).replace("\\", "\\\\").replace('"', '\\"')


def _make_seatbelt_profile(source_root: Path, scratch_root: Path) -> str:
    """Generate minimal least-privilege Seatbelt profile.

    Enforces:
    - Default-deny network egress (R-03: unconditional deny network*).
    - Read-only source access.
    - Write access strictly denied except inside scratch_root.
    - Read access denied for host user directories (/Users, Path.home()),
      cloud credentials, external volumes (/Volumes), and temporary directories
      outside source_root and scratch_root (R-01).
    - Runtime dependency read access explicitly granted for active Python sys.prefix.
    """
    source_root = source_root.resolve()
    scratch_root = scratch_root.resolve()
    home = Path.home().resolve()

    rules = [
        "(version 1)",
        "(allow default)",
        "(deny network*)",
        "(deny file-write*)",
        f'(allow file-write* (subpath "{_quote_sb(scratch_root)}"))',
        "",
        ";; Least-privilege filesystem read policy (R-01)",
        '(deny file-read* (subpath "/Users"))',
        '(deny file-read* (subpath "/Volumes"))',
        f'(deny file-read* (subpath "{_quote_sb(home)}"))',
        '(deny file-read* (subpath "/private/var/folders"))',
        '(deny file-read* (subpath "/var/folders"))',
        '(deny file-read* (subpath "/private/tmp"))',
        '(deny file-read* (subpath "/tmp"))',
        '(deny file-read* (subpath "/private/var/tmp"))',
        '(deny file-read* (subpath "/var/tmp"))',
    ]

    system_roots = {Path("/"), Path("/private"), Path("/private/var"), Path("/var"), Path("/usr")}
    if source_root.parent not in system_roots:
        rules.append(f'(deny file-read* (subpath "{_quote_sb(source_root.parent)}"))')
    if scratch_root.parent not in system_roots and scratch_root.parent != source_root.parent:
        rules.append(f'(deny file-read* (subpath "{_quote_sb(scratch_root.parent)}"))')

    # Allow reading active Python interpreter and standard library runtime
    py_prefix = Path(sys.prefix).resolve()
    py_base_prefix = Path(sys.base_prefix).resolve()
    rules.append(f'(allow file-read* (subpath "{_quote_sb(py_prefix)}"))')
    if py_base_prefix != py_prefix:
        rules.append(f'(allow file-read* (subpath "{_quote_sb(py_base_prefix)}"))')

    # Explicitly permit reading the authorized source and scratch roots
    rules.append(f'(allow file-read* (subpath "{_quote_sb(source_root)}"))')
    rules.append(f'(allow file-read* (subpath "{_quote_sb(scratch_root)}"))')
    return "\n".join(rules) + "\n"


def _run_bounded_process(
    full_command: list[str],
    cwd: str,
    env: dict[str, str],
    timeout: int,
    max_bytes: int,
    preexec_fn=None,
) -> dict:
    """Execute process with strict incremental output bounding and process group termination (R-04)."""
    started = time.monotonic()
    proc = subprocess.Popen(
        full_command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        close_fds=True,
        preexec_fn=preexec_fn,
    )

    sel = selectors.DefaultSelector()
    os.set_blocking(proc.stdout.fileno(), False)
    os.set_blocking(proc.stderr.fileno(), False)
    sel.register(proc.stdout, selectors.EVENT_READ, data="stdout")
    sel.register(proc.stderr, selectors.EVENT_READ, data="stderr")

    stdout_buf = bytearray()
    stderr_buf = bytearray()
    truncated = False
    timed_out = False
    deadline = started + timeout

    def _kill_group():
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGKILL)
        except OSError:
            pass

    try:
        while sel.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _kill_group()
                break

            events = sel.select(timeout=max(0.01, min(remaining, 0.1)))
            for key, mask in events:
                stream_name = key.data
                fileobj = key.fileobj
                try:
                    chunk = fileobj.read(4096)
                except OSError:
                    chunk = b""
                if not chunk:
                    sel.unregister(fileobj)
                    continue

                if stream_name == "stdout":
                    if len(stdout_buf) < max_bytes:
                        stdout_buf.extend(chunk[:max_bytes - len(stdout_buf)])
                    if len(stdout_buf) >= max_bytes:
                        truncated = True
                        _kill_group()
                        sel.unregister(fileobj)
                else:
                    if len(stderr_buf) < max_bytes:
                        stderr_buf.extend(chunk[:max_bytes - len(stderr_buf)])
                    if len(stderr_buf) >= max_bytes:
                        truncated = True
                        _kill_group()
                        sel.unregister(fileobj)

            if proc.poll() is not None and not sel.select(timeout=0):
                # Drain remaining if available without blocking
                for key in list(sel.get_map().values()):
                    stream_name = key.data
                    fileobj = key.fileobj
                    try:
                        chunk = fileobj.read(4096)
                    except OSError:
                        chunk = b""
                    if chunk:
                        buf = stdout_buf if stream_name == "stdout" else stderr_buf
                        if len(buf) < max_bytes:
                            buf.extend(chunk[:max_bytes - len(buf)])
                        if len(buf) >= max_bytes:
                            truncated = True
                    sel.unregister(fileobj)
                break
    finally:
        sel.close()
        try:
            proc.stdout.close()
            proc.stderr.close()
        except OSError:
            pass
        if proc.poll() is None:
            _kill_group()
            proc.wait()

    wall_ms = int((time.monotonic() - started) * 1000)
    return {
        "exit_code": proc.returncode,
        "stdout_bytes": bytes(stdout_buf),
        "stderr_bytes": bytes(stderr_buf),
        "truncated": truncated,
        "timed_out": timed_out,
        "wall_ms": wall_ms,
    }


class IsolatedHostAdapter:
    """Technically enforced execution adapter for prelaunch security audit dispatch.

    Dispatches commands ONLY when authorized by execution_profiles.assess(),
    structurally bound via ExecutionSpec, and validated by HostAttestation.
    Enforces technical boundaries at dispatch and retains trusted host-side telemetry.
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
        self._dispatched_approvals: set[tuple[str, str]] = set()

    def dispatch(self, request: dict, command: list[str]) -> dict:
        event = {
            "sequence": len(self.events) + 1,
            "request_sha256": digest(request) if isinstance(request, dict) else None,
            "command": list(command) if isinstance(command, (list, tuple)) else None,
            "occurred": False,
            "blocked": True,
            "exit_code": None,
            "timestamp": time.time(),
        }
        self.events.append(event)

        # R-02: Cryptographic / structural binding check before any action
        if not isinstance(command, list) or not command or any(not isinstance(c, str) or not c.strip() for c in command):
            event["reason"] = "command must be a non-empty list of non-empty strings"
            return {"occurred": False, "blocked": True, "reason": event["reason"]}

        if not isinstance(request, dict) or "command" not in request or request["command"] != command:
            event["reason"] = "command is not cryptographically or structurally bound to request"
            return {"occurred": False, "blocked": True, "reason": event["reason"]}

        # R-03: Arbitrary target code network access is prohibited; fail closed
        if request.get("effect") in {"network_read", "external_write"}:
            event["reason"] = "arbitrary target code socket egress is prohibited; host sandbox cannot guarantee destination-level L7 filtering"
            return {"occurred": False, "blocked": True, "status": "blocked", "reason": event["reason"]}

        # Assess request against policy and host attestation
        try:
            verdict = assess(request, attest=self.attestation_provider)
        except Exception as exc:
            event["reason"] = f"request validation failed: {exc}"
            return {"occurred": False, "blocked": True, "status": "blocked", "reason": event["reason"]}

        if verdict.get("status") != "eligible_for_host_dispatch":
            event["reason"] = verdict.get("reason", "not eligible for dispatch")
            return {
                "occurred": False,
                "blocked": True,
                "status": verdict.get("status", "blocked"),
                "reason": verdict.get("reason"),
            }

        # R-02: Replay prevention check
        auth_ref = verdict.get("authorization_ref", "")
        req_id = request.get("id", "")
        approval_key = (req_id, auth_ref)
        if approval_key in self._dispatched_approvals:
            event["reason"] = "authorization replay rejected: approval already consumed"
            return {"occurred": False, "blocked": True, "reason": event["reason"]}
        self._dispatched_approvals.add(approval_key)

        # Target and revision verification
        if request.get("target") != self.target or request.get("revision") != self.revision:
            event["reason"] = "target or revision mismatch with host configuration"
            return {"occurred": False, "blocked": True, "reason": event["reason"]}

        # Host sandbox availability
        if not SANDBOX_EXEC.exists():
            event["reason"] = "host sandbox facility (/usr/bin/sandbox-exec) unavailable"
            return {"occurred": False, "blocked": True, "reason": event["reason"]}

        # Prepare disposable sub-scratch directory for this run
        run_scratch = Path(tempfile.mkdtemp(prefix="run-scratch-", dir=self.scratch_root)).resolve()
        sb_profile_path = run_scratch / "run.sb"
        sb_profile_text = _make_seatbelt_profile(self.source_root, run_scratch)
        sb_profile_path.write_text(sb_profile_text, encoding="utf-8")

        # Clean environment: strip credentials, enforce clean user site exclusion
        scrubbed_env = {
            "PATH": os.environ.get("PATH", os.defpath),
            "TMPDIR": str(run_scratch),
            "PYTHONNOUSERSITE": "1",
        }

        # Construct immutable ExecutionSpec binding all parameters
        spec = ExecutionSpec(
            target=self.target,
            revision=self.revision,
            command=tuple(command),
            cwd=str(self.source_root),
            effect=request.get("effect", ""),
            profile=request.get("profile", ""),
            operation=request.get("operation", ""),
            destination=request.get("destination", ""),
            paths=tuple(request.get("paths", [])),
            env_keys=tuple(sorted(scrubbed_env.keys())),
            timeout=self.timeout,
            max_bytes=self.max_bytes,
            authorization_ref=auth_ref,
        )
        event["spec_sha256"] = spec.digest()
        event["spec"] = asdict(spec)

        # Apply preexec_fn for CPU limits where available
        def _set_rlimits():
            try:
                import resource
                resource.setrlimit(resource.RLIMIT_CPU, (10, 15))
            except (ImportError, OSError):
                pass

        full_command = [str(SANDBOX_EXEC), "-f", str(sb_profile_path), *command]
        try:
            run_res = _run_bounded_process(
                full_command,
                cwd=str(self.source_root),
                env=scrubbed_env,
                timeout=self.timeout,
                max_bytes=self.max_bytes,
                preexec_fn=_set_rlimits if os.name != "nt" else None,
            )

            stdout_bytes = run_res["stdout_bytes"]
            stderr_bytes = run_res["stderr_bytes"]
            stdout_str = stdout_bytes.decode("utf-8", errors="replace")
            stderr_str = stderr_bytes.decode("utf-8", errors="replace")

            event.update({
                "occurred": True,
                "blocked": False,
                "exit_code": run_res["exit_code"],
                "timed_out": run_res["timed_out"],
                "wall_ms": run_res["wall_ms"],
                "stdout_sha256": hashlib.sha256(stdout_bytes).hexdigest(),
                "stderr_sha256": hashlib.sha256(stderr_bytes).hexdigest(),
                "output_truncated": run_res["truncated"],
            })

            return {
                "occurred": True,
                "blocked": False,
                "exit_code": run_res["exit_code"],
                "stdout": stdout_str,
                "stderr": stderr_str,
                "timed_out": run_res["timed_out"],
                "wall_ms": run_res["wall_ms"],
                "output_truncated": run_res["truncated"],
            }
        finally:
            shutil.rmtree(run_scratch, ignore_errors=True)
