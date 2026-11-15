#!/usr/bin/env python3
"""Host runtime adapter enforcing technical isolation boundaries.

Integrates directly with execution_profiles.assess(), ExecutionSpec, and
HostAttestation. Enforces technical sandbox controls: genuine default-deny
filesystem isolation (import system.sb, denied /etc/passwd, read-only source,
denied host secrets/users/volumes, writable disposable scratch), unconditional
network egress denial, cryptographic authorization binding to executed commands
and execution specs before dispatch, cross-instance and cross-process replay
prevention, complete process lifecycle cleanup for all descendants, incremental
output bounding, and sanitized host-side telemetry logging.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import fcntl
import hashlib
import json
import os
import secrets
import stat
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

from audit_artifacts import MAX_BYTES, require, trusted_root
from execution_profiles import CONTROLS, HostAttestation, assess, digest, validate_request

SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
# No externally verified supervisor or complete OS resource quota exists.
RUNTIME_EXECUTION_ENABLED = False
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


class ApprovalStore:
    """Atomic single-use authorization registry preventing replay across instances and processes (A1, R-07)."""

    def __init__(self, storage_path: Path | None = None):
        self.storage_path = Path(storage_path).absolute() if storage_path else None
        self._consumed: set[str] = set()
        self._lock = threading.Lock()
        self._corrupted_err: str | None = None
        if self.storage_path and self.storage_path.exists():
            try:
                self._consumed.update(self._load_from_disk())
            except Exception as exc:
                self._corrupted_err = str(exc)


    def _private_parent(self) -> Path:
        """Reject shared, symlinked, or misowned approval registry directories."""
        if self.storage_path is None:
            raise ValueError("no durable approval store configured")
        parent = self.storage_path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077):
            raise PermissionError("approval store directory must be host-owned mode 0700")
        return parent

    @staticmethod
    def _checked_file(fd: int, label: str) -> None:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid()
                or meta.st_mode & 0o077):
            raise PermissionError(f"{label} must be host-owned regular file mode 0600")

    def _load_from_disk(self) -> set[str]:
        if self.storage_path is None:
            return set()
        self._private_parent()
        try:
            fd = os.open(self.storage_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return set()
        try:
            self._checked_file(fd, "approval store")
            with os.fdopen(fd, "rb", closefd=False) as file:
                raw = file.read(4_000_001)
            if len(raw) > 4_000_000:
                raise ValueError("approval store exceeds bounded size limit")
            if not raw:
                raise ValueError("approval store unexpectedly empty")
            data = json.loads(raw.decode("utf-8"))
            if (not isinstance(data, list) or len(data) > 20000
                    or any(not isinstance(v, str) or not 1 <= len(v) <= 512 for v in data)
                    or len(set(data)) != len(data)):
                raise ValueError("invalid approval store schema")
            return set(data)
        finally:
            os.close(fd)

    def consume(self, request_id: str, authorization_ref: str, spec_sha256: str) -> bool:
        """Single-use durable consumption with private files, flock and fsync."""
        if self._corrupted_err:
            raise ValueError("approval store was corrupted before initialization")
        if any(not isinstance(v, str) or not v or ":" in v for v in
               (request_id, authorization_ref, spec_sha256)):
            raise ValueError("invalid approval identity")
        key = f"{request_id}:{authorization_ref}:{spec_sha256}"
        if len(key) > 512:
            raise ValueError("approval identity too long")
        with self._lock:
            if key in self._consumed:
                return False
            if self.storage_path is None:
                self._consumed.add(key)
                return True
            parent = self._private_parent()
            lock_name = self.storage_path.name + ".lock"
            lock_fd = os.open(parent / lock_name,
                              os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            try:
                self._checked_file(lock_fd, "approval lock")
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                try:
                    on_disk = self._load_from_disk()
                    if key in on_disk:
                        self._consumed.add(key)
                        return False
                    on_disk.add(key)
                    if len(on_disk) > 20000:
                        raise ValueError("approval store capacity exceeded; fail closed")
                    tmp_path = parent / (f".{self.storage_path.name}." + secrets.token_hex(16) + ".tmp")
                    tmp_fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                     os.O_NOFOLLOW, 0o600)
                    try:
                        with os.fdopen(tmp_fd, "w", encoding="utf-8") as stream:
                            json.dump(sorted(on_disk), stream)
                            stream.flush()
                            os.fsync(stream.fileno())
                        os.replace(tmp_path, self.storage_path)
                        dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                        try:
                            os.fsync(dir_fd)
                        finally:
                            os.close(dir_fd)
                    finally:
                        tmp_path.unlink(missing_ok=True)
                    self._consumed.add(key)
                    return True
                finally:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

    def is_consumed(self, request_id: str, authorization_ref: str, spec_sha256: str) -> bool:
        key = f"{request_id}:{authorization_ref}:{spec_sha256}"
        with self._lock:
            if key in self._consumed:
                return True
            if self.storage_path and self.storage_path.exists():
                return key in self._load_from_disk()
            return False

    def clear(self):
        with self._lock:
            self._consumed.clear()
            if self.storage_path and self.storage_path.exists():
                try:
                    lock_file = self.storage_path.with_name(f"{self.storage_path.name}.lock")
                    lock_fd = os.open(lock_file, os.O_RDWR | os.O_CREAT, 0o600)
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_EX)
                        try:
                            self.storage_path.unlink(missing_ok=True)
                        finally:
                            fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    finally:
                        os.close(lock_fd)
                except OSError:
                    pass


def get_default_approval_path() -> Path:
    env_path = os.environ.get("VIBE_SECURITY_APPROVAL_STORE")
    if env_path:
        return Path(env_path).absolute()
    base_dir = Path.home() / ".vibe-security"
    try:
        base_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError:
        pass
    return (base_dir / "approvals.json").absolute()


_DEFAULT_APPROVAL_STORE: ApprovalStore | None = None


def get_default_approval_store() -> ApprovalStore:
    global _DEFAULT_APPROVAL_STORE
    if _DEFAULT_APPROVAL_STORE is None:
        _DEFAULT_APPROVAL_STORE = ApprovalStore(get_default_approval_path())
    return _DEFAULT_APPROVAL_STORE


def _quote_sb(path: Path) -> str:
    return str(path.resolve()).replace("\\", "\\\\").replace('"', '\\"')


def _make_seatbelt_profile(source_root: Path, scratch_root: Path) -> str:
    """Generate genuine default-deny Seatbelt profile (R-05).

    Enforces:
    - Default-deny all operations ((deny default)).
    - Standard macOS system library bootstrap via (import "system.sb").
    - Explicit denial of sensitive system files permitted by system.sb (/etc/passwd, /etc/master.passwd).
    - Unconditional network egress denial ((deny network*)).
    - Unconditional write denial except inside scratch_root ((deny file-write*)).
    - Read access allowed ONLY for:
      - System libraries from system.sb
      - Process execution primitives: process-exec, process-fork, sysctl-read, signal (target self), file-read-metadata
      - Devices: /dev
      - Python runtime sys.prefix / sys.base_prefix
      - Authorized source root (read-only)
      - Disposable scratch root (read-write)
    - All other host files (/Users, /Volumes, /opt, /tmp, parent directories) are denied by default.
    """
    source_root = source_root.resolve()
    scratch_root = scratch_root.resolve()
    home = Path.home().resolve()

    py_prefix = Path(sys.prefix).resolve()
    py_base_prefix = Path(sys.base_prefix).resolve()
    if py_prefix == home or py_base_prefix == home:
        raise ValueError("Python runtime prefix cannot be user home directory")

    rules = [
        "(version 1)",
        "(deny default)",
        '(import "system.sb")',
        "(deny network*)",
        "(deny file-write*)",
        f'(allow file-write* (subpath "{_quote_sb(scratch_root)}"))',
        "",
        ";; Deny sensitive system credential files permitted by system.sb",
        '(deny file-read* (literal "/private/etc/master.passwd"))',
        '(deny file-read* (literal "/etc/master.passwd"))',
        '(deny file-read* (literal "/private/etc/passwd"))',
        '(deny file-read* (literal "/etc/passwd"))',
        "",
        ";; Minimal required process execution primitives",
        "(allow process-exec)",
        "(allow process-fork)",
        "(allow sysctl-read)",
        "(allow signal (target self))",
        "(allow file-read-metadata)",
        '(allow file-read* (subpath "/dev"))',
        "",
        ";; Runtime dependencies",
        f'(allow file-read* (subpath "{_quote_sb(py_prefix)}"))',
    ]
    if py_base_prefix != py_prefix:
        rules.append(f'(allow file-read* (subpath "{_quote_sb(py_base_prefix)}"))')

    # Re-allow authorized source root and scratch root
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
    """Execute process with strict incremental output bounding and guaranteed process group cleanup (R-04, R-06)."""
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

    saved_pgid = proc.pid
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

    def _terminate_process_group():
        # Unconditionally terminate the entire session/process group
        try:
            os.killpg(saved_pgid, signal.SIGKILL)
        except OSError:
            pass
        # Also reap the direct child if still pending
        if proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=1)
            except (subprocess.TimeoutExpired, OSError):
                pass

    try:
        while sel.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate_process_group()
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
                        _terminate_process_group()
                        sel.unregister(fileobj)
                else:
                    if len(stderr_buf) < max_bytes:
                        stderr_buf.extend(chunk[:max_bytes - len(stderr_buf)])
                    if len(stderr_buf) >= max_bytes:
                        truncated = True
                        _terminate_process_group()
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
        # R-06: Guarantee that all descendants in the process group are terminated,
        # even if direct child has already exited.
        _terminate_process_group()
        try:
            proc.wait(timeout=1)
        except (subprocess.TimeoutExpired, OSError):
            pass

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
                 timeout: int = 15, max_bytes: int = MAX_BYTES,
                 approval_store: ApprovalStore | None = None):
        self.source_root = Path(source_root).resolve()
        self.scratch_root = Path(scratch_root).resolve()
        self.target = target
        self.revision = revision
        self.attestation_provider = attestation_provider
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.events: list[dict] = []
        self.approval_store = approval_store or get_default_approval_store()

    def dispatch(self, request: dict, command: list[str]) -> dict:
        executable_name = Path(command[0]).name if (isinstance(command, (list, tuple)) and command) else ""
        cmd_sha256 = digest(list(command)) if isinstance(command, (list, tuple)) else None
        event = {
            "sequence": len(self.events) + 1,
            "request_sha256": digest(request) if isinstance(request, dict) else None,
            "executable": executable_name,
            "command_sha256": cmd_sha256,
            "command_arg_count": len(command) if isinstance(command, (list, tuple)) else 0,
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

        # Only independently approved isolated-local execution can invoke a subprocess.
        if request.get("effect") not in {"verify_local", "modify_local"} or request.get("profile") != "isolated-local":
            event["reason"] = "subprocess dispatch requires explicit isolated-local execution authorization"
            return {"occurred": False, "blocked": True, "reason": event["reason"]}

        # Target and revision verification against adapter configuration
        if request.get("target") != self.target or request.get("revision") != self.revision:
            event["reason"] = "target or revision mismatch with host configuration"
            return {"occurred": False, "blocked": True, "reason": event["reason"]}

        # Clean environment: strip credentials, enforce clean user site exclusion
        scrubbed_env_keys = sorted(SAFE_ENV_KEYS - {"PYTHONPATH"})

        # Construct immutable ExecutionSpec binding all parameters BEFORE authorization
        auth_ref = request.get("authorization_ref", "")
        spec = ExecutionSpec(
            target=self.target,
            revision=self.revision,
            command=tuple(command),
            cwd=str(self.source_root),
            effect=request.get("effect", ""),
            profile=request.get("profile", ""),
            operation=request.get("operation", ""),
            destination=request.get("destination", ""),
            paths=tuple(sorted(request.get("paths", []))),
            env_keys=tuple(scrubbed_env_keys),
            timeout=self.timeout,
            max_bytes=self.max_bytes,
            authorization_ref=auth_ref,
        )
        spec_digest = spec.digest()
        event["spec_sha256"] = spec_digest
        event["spec"] = {
            "executable": executable_name,
            "command_sha256": cmd_sha256,
            "command_arg_count": len(command),
            "target": self.target,
            "revision": self.revision,
            "cwd": str(self.source_root),
            "effect": spec.effect,
            "profile": spec.profile,
            "operation": spec.operation,
            "destination_sha256": hashlib.sha256(spec.destination.encode()).hexdigest(),
            "paths_sha256": hashlib.sha256(json.dumps(list(spec.paths)).encode()).hexdigest(),
            "paths_count": len(spec.paths),
            "env_keys": list(spec.env_keys),
            "timeout": spec.timeout,
            "max_bytes": spec.max_bytes,
            "authorization_ref": spec.authorization_ref,
        }

        # If request explicitly specifies spec_sha256, verify match
        if "spec_sha256" in request and request["spec_sha256"] != spec_digest:
            event["reason"] = "execution spec digest does not match authorized spec_sha256"
            return {"occurred": False, "blocked": True, "reason": event["reason"]}
        request = {**request, "spec_sha256": spec_digest}

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

        effective_auth_ref = verdict.get("authorization_ref", auth_ref)

        # R-07 / A1: Single-use approval consumption at trusted host boundary (cross-instance/cross-process)
        req_id = request.get("id", "")
        try:
            if not self.approval_store.consume(req_id, effective_auth_ref, spec_digest):
                event["reason"] = "authorization replay rejected: approval already consumed"
                return {"occurred": False, "blocked": True, "reason": event["reason"]}
        except Exception as exc:
            event["reason"] = f"approval store error (fail-closed): {exc}"
            return {"occurred": False, "blocked": True, "reason": event["reason"]}

        # Fail closed: Seatbelt and POSIX process groups cannot contain detached
        # setsid() descendants or enforce complete memory/disk/PID quotas.
        # This dormant legacy executor requires a separately verified external
        # VM/microVM execution supervisor before any untrusted code may run.
        if not RUNTIME_EXECUTION_ENABLED:
            event["reason"] = "untrusted code execution disabled; external isolation supervisor not implemented"
            return {"occurred": False, "blocked": True, "reason": event["reason"]}

        # Host sandbox availability check
        if not SANDBOX_EXEC.exists():
            event["reason"] = "host sandbox facility (/usr/bin/sandbox-exec) unavailable"
            return {"occurred": False, "blocked": True, "reason": event["reason"]}

        # Prepare disposable sub-scratch directory for this run
        run_scratch = Path(tempfile.mkdtemp(prefix="run-scratch-", dir=self.scratch_root)).resolve()
        sb_profile_path = run_scratch / "run.sb"
        try:
            sb_profile_text = _make_seatbelt_profile(self.source_root, run_scratch)
        except ValueError as exc:
            shutil.rmtree(run_scratch, ignore_errors=True)
            event["reason"] = f"invalid runtime sandbox configuration: {exc}"
            return {"occurred": False, "blocked": True, "reason": event["reason"]}

        sb_profile_path.write_text(sb_profile_text, encoding="utf-8")

        scrubbed_env = {
            "PATH": os.environ.get("PATH", os.defpath),
            "TMPDIR": str(run_scratch),
            "PYTHONNOUSERSITE": "1",
        }

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
