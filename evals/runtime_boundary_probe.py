#!/usr/bin/env python3
"""Disposable macOS host-boundary probe for the v0.5 security Skill.

Runs only fixed, reviewed commands against synthetic fixtures created by this
script. It never reads a real target repository, host secret or external
network destination. Results describe what this host platform can enforce; they
are not an attestation that the Skill bundles an arbitrary-code sandbox.

Usage (from a trusted checkout):
    python3 evals/runtime_boundary_probe.py --output /private/probe.json

Exit codes: 0 all checks behaved as expected, 2 unexpected result,
3 unsupported host (no sandbox-exec).
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/prelaunch-security-audit/scripts"))
from audit_artifacts import bounded_command  # noqa: E402
from execution_profiles import StaticHost, assess  # noqa: E402

SANDBOX = Path("/usr/bin/sandbox-exec")
MAX_WALL = 15


def quote(value: Path) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def profile(base: Path, *, allow_network: bool = False, fork: bool = True) -> str:
    rules = ["(version 1)", "(allow default)"]
    if not allow_network:
        rules.append("(deny network*)")
    rules += ["(deny file-write*)",
              f'(allow file-write* (subpath "{quote(base / "scratch")}"))',
              f'(deny file-read* (subpath "{quote(base / "secret")}"))']
    if not fork:
        rules.append("(deny process-fork)")
    return "\n".join(rules) + "\n"


def run(command: list[str], timeout: int = MAX_WALL) -> dict:
    started = time.monotonic()
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return {"exit_code": completed.returncode, "stdout": completed.stdout,
                "stderr": completed.stderr, "timed_out": False,
                "wall_ms": int((time.monotonic() - started) * 1000)}
    except subprocess.TimeoutExpired:
        return {"exit_code": None, "stdout": "", "stderr": "", "timed_out": True,
                "wall_ms": int((time.monotonic() - started) * 1000)}


class Probe:
    def __init__(self, base: Path):
        self.base = base
        self.results: list[dict] = []

    def add(self, ident, layer, command, expected, observed, ok, *, exit_code=None,
            stderr=b"", extra=None):
        self.results.append({
            "id": ident, "layer": layer, "command": command, "expected": expected,
            "observed": observed, "result": "pass" if ok else "fail",
            "exit_code": exit_code,
            "stderr_sha256": __import__("hashlib").sha256(stderr).hexdigest() if stderr else None,
            "extra": extra or {},
        })

    def sandboxed(self, name, command, expected_rc, *, check, allow_network=False, fork=True,
                  profile_file=None):
        path = profile_file or (self.base / f"{name}.sb")
        if profile_file is None:
            path.write_text(profile(self.base, allow_network=allow_network, fork=fork),
                            encoding="utf-8")
        completed = run([str(SANDBOX), "-f", str(path), *command])
        ok = check(completed) if expected_rc == "any" else (
            completed["exit_code"] == expected_rc and not completed["timed_out"])
        self.add(name, "os_sandbox", " ".join(command), expected_rc,
                 {"exit_code": completed["exit_code"], "timed_out": completed["timed_out"],
                  "stdout_bytes": len(completed["stdout"].encode()),
                  "stderr_bytes": len(completed["stderr"].encode())},
                 ok, exit_code=completed["exit_code"], stderr=completed["stderr"].encode())
        return completed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="Fresh JSON report outside the Git checkout")
    args = parser.parse_args()
    if not SANDBOX.exists():
        print(json.dumps({"supported": False, "reason": "sandbox-exec unavailable",
                          "no_checks_executed": True}))
        return 3
    output = args.output.absolute()
    if output.resolve().is_relative_to(ROOT) or output.exists():
        parser.error("output must be a fresh path outside the Git checkout")

    base = Path(tempfile.mkdtemp(prefix="v050-boundary-")).resolve()
    try:
        fixture, scratch = base / "fixture", base / "scratch"
        secret, other = base / "secret", base / "other"
        for directory in (fixture, scratch, secret, other):
            directory.mkdir()
        (fixture / "source.txt").write_text("synthetic source\n", encoding="utf-8")
        (secret / "host-secret.txt").write_text("SYNTHETIC-HOST-SECRET\n", encoding="utf-8")
        (other / "note.txt").write_text("other workspace\n", encoding="utf-8")
        probe = Probe(base)

        probe.sandboxed("os_read_fixture_allowed", ["/bin/cat", str(fixture / "source.txt")], 0,
                        check=lambda c: c["stdout"] == "synthetic source\n")
        probe.sandboxed("os_write_scratch_allowed", ["/usr/bin/touch", str(scratch / "ok.txt")], 0,
                        check=lambda c: (scratch / "ok.txt").is_file())
        probe.sandboxed("os_write_fixture_denied",
                        ["/usr/bin/touch", str(fixture / "denied.txt")], "any",
                        check=lambda c: c["exit_code"] not in (0, None)
                        and not (fixture / "denied.txt").exists())
        probe.sandboxed("os_write_other_workspace_denied",
                        ["/usr/bin/touch", str(other / "denied.txt")], "any",
                        check=lambda c: c["exit_code"] not in (0, None)
                        and not (other / "denied.txt").exists())
        probe.sandboxed("os_read_host_secret_denied",
                        ["/bin/cat", str(secret / "host-secret.txt")], "any",
                        check=lambda c: c["exit_code"] not in (0, None)
                        and "SYNTHETIC-HOST-SECRET" not in c["stdout"])
        (scratch / "escape.txt").symlink_to(secret / "host-secret.txt")
        probe.sandboxed("os_symlink_escape_denied",
                        ["/bin/cat", str(scratch / "escape.txt")], "any",
                        check=lambda c: c["exit_code"] not in (0, None)
                        and "SYNTHETIC-HOST-SECRET" not in c["stdout"])

        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            baseline = run(["/usr/bin/nc", "-z", "-G", "2", "127.0.0.1", str(port)])
            probe.add("network_listener_reachable_baseline", "network_fixture",
                      f"nc -z 127.0.0.1 {port}", 0,
                      {"exit_code": baseline["exit_code"]}, baseline["exit_code"] == 0,
                      exit_code=baseline["exit_code"])
            probe.sandboxed("os_network_loopback_denied",
                            ["/usr/bin/nc", "-z", "-G", "2", "127.0.0.1", str(port)], "any",
                            check=lambda c: baseline["exit_code"] == 0
                            and c["exit_code"] not in (0, None))

        interpreter = sys.executable
        probe.sandboxed("os_subprocess_fork_denied",
                        [interpreter, "-c",
                         "import subprocess; print(subprocess.run(['/bin/echo','child'],"
                         "capture_output=True,text=True).stdout.strip())"], "any",
                        check=lambda c: c["exit_code"] not in (0, None) and "child" not in c["stdout"],
                        fork=False)

        loop = base / "loop.py"
        loop.write_text("while True:\n    pass\n", encoding="utf-8")
        limited = run(["/bin/sh", "-c",
                       f'ulimit -t 1; exec "{interpreter}" "{loop}"'])
        probe.add("rlimit_cpu_time_kills_child", "rlimit",
                  "sh -c 'ulimit -t 1; exec python3 loop.py'", "nonzero within 15s",
                  {"exit_code": limited["exit_code"], "timed_out": limited["timed_out"],
                   "wall_ms": limited["wall_ms"]},
                  limited["exit_code"] not in (0, None) and not limited["timed_out"],
                  exit_code=limited["exit_code"], stderr=limited["stderr"].encode())

        try:
            bounded_command([interpreter, "-c", "print('x' * 5000)"],
                            {"PATH": os.defpath}, max_bytes=100)
            output_bounded = False
            detail = "ValueError not raised"
        except ValueError as exc:
            output_bounded = "exceeds limit" in str(exc)
            detail = "ValueError: " + str(exc)
        probe.add("controller_child_output_bounded", "controller",
                  "bounded_command(max_bytes=100) with 5000-byte child", "ValueError",
                  detail, output_bounded)

        host = StaticHost(fixture, ["source.txt"], target="synthetic", revision="a" * 40)
        request = {"id": "probe-1", "target": "synthetic", "revision": "a" * 40,
                   "effect": "observe", "profile": "static-only", "operation": "read_source",
                   "destination": "", "paths": ["source.txt"]}
        allowed = host.dispatch(dict(request))
        denied = host.dispatch({**request, "id": "probe-2", "effect": "network_read",
                                "profile": "isolated-local",
                                "destination": "http://127.0.0.1:9"})
        events = host.events
        probe.add("controller_static_host_read_allowed", "controller",
                  "StaticHost.dispatch(read_source)", "content", "content" in allowed,
                  "content" in allowed)
        probe.add("controller_static_host_network_denied", "controller",
                  "StaticHost.dispatch(network_read)", "DENIED",
                  "DENIED" in denied.get("error", ""), "DENIED" in denied.get("error", ""),
                  extra={"events": events})
        staging = {"id": "probe-3", "target": "synthetic", "revision": "a" * 40,
                   "effect": "modify_local", "profile": "authorized-staging",
                   "operation": "write", "destination": "", "paths": ["scratch/x"]}
        verdict = assess(staging, attest=lambda _r: None)
        probe.add("controller_staging_local_write_blocked", "controller",
                  "assess(authorized-staging, modify_local)", "blocked",
                  verdict["status"], verdict["status"] == "blocked")

        failed = [row for row in probe.results if row["result"] != "pass"]
        report = {
            "format": "vibe-security-runtime-boundary-probe-v1",
            "platform": {"system": "Darwin", "sandbox_exec": str(SANDBOX),
                         "python": sys.version.split()[0]},
            "scope": ("Synthetic disposable fixtures created by this script. "
                      "No target repository, real secret or external network was accessed."),
            "skill_bundled_arbitrary_code_sandbox": False,
            "host_platform_controls_verified": not failed,
            "checks": probe.results,
            "failures": [row["id"] for row in failed],
            "limitations": [
                "sandbox-exec is host-platform enforcement, not a Skill runtime adapter.",
                "This probe does not authenticate model output or retained evidence.",
                "No Docker, VM or container isolation was tested.",
                "The probe exercises only fixed synthetic commands on one macOS host.",
            ],
        }
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
        print(json.dumps({"checks": len(probe.results), "failures": len(failed),
                          "output": str(output)}))
        return 0 if not failed else 2
    finally:
        shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
