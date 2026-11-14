#!/usr/bin/env python3
"""Offline immutable-Git diff and conservative, declared security-impact analysis.

Never executes target code, follows Git hooks, fetches refs or carries a PASS to
another revision. Dependency edges are reviewer input, not parser completeness.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import subprocess
import time

from audit_artifacts import safe_relative_path

SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
DEPENDENCY_NAMES = frozenset({"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "bun.lock", "bun.lockb", "requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile.lock",
    "Cargo.toml", "Cargo.lock", "go.mod", "go.sum", "composer.json", "composer.lock", "Gemfile.lock"})


def _path(value):
    safe_relative_path(value)
    return value


def _revision(value):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise ValueError("revision must be a full immutable Git SHA")
    return value


def _bounded_metadata(command, env, max_bytes=2_000_000, timeout=30):
    """Drain metadata incrementally; target metadata cannot allocate unbounded output."""
    deadline = time.monotonic() + timeout
    chunks = bytearray()
    with subprocess.Popen(command, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL) as process:
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise ValueError("Git metadata read timed out")
                    part = os.read(process.stdout.fileno(), min(65536, max_bytes + 1 - len(chunks)))
                    if not part:
                        break
                    chunks.extend(part)
                    if len(chunks) > max_bytes:
                        raise ValueError("Git metadata exceeds limit; narrow the reviewed scope")
            code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except BaseException:
            process.kill()
            process.wait()
            raise
    return subprocess.CompletedProcess(command, code, bytes(chunks), b"")


def _git(root, *args, check=True):
    # No inherited Git config injection, SSH/credential/socket env or home config.
    env = {"PATH": os.defpath, "LANG": "C", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1"}
    command = ["git", "--no-replace-objects", "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=" + os.devnull, "-c", "diff.external=",
        "-c", "core.attributesFile=" + os.devnull, "-c", "protocol.allow=never", "-C", str(root), *args]
    result = _bounded_metadata(command, env)
    if check and result.returncode:
        raise ValueError("Git snapshot unavailable (no fetch or target code execution attempted)")
    return result


def git_changes(root: Path, baseline: str, current: str | None = None) -> dict:
    """Compare committed snapshots, including renames; never inspect dirty files."""
    _revision(baseline)
    root = Path(root).resolve(strict=True)
    if current is None:
        current = _git(root, "rev-parse", "HEAD").stdout.decode().strip()
    _revision(current)
    _git(root, "cat-file", "-e", current + "^{commit}")
    if _git(root, "cat-file", "-e", baseline + "^{commit}", check=False).returncode:
        return {"baseline_revision": baseline, "revision": current,
                "baseline_available": False, "ancestry": "unknown", "changes": []}
    ancestry = _git(root, "merge-base", "--is-ancestor", baseline, current, check=False)
    if ancestry.returncode not in {0, 1}:
        raise ValueError("cannot establish snapshot ancestry")
    raw = _git(root, "diff", "--no-ext-diff", "--no-textconv", "--name-status", "-z",
               "--find-renames", baseline, current, "--").stdout.decode("utf-8", errors="strict")
    fields = raw.split("\0")
    if fields[-1] != "":
        raise ValueError("incomplete Git diff metadata")
    changes = []
    index = 0
    while index < len(fields) - 1:
        status = fields[index]
        index += 1
        if not re.fullmatch(r"[ACDMRTUXB][0-9]*", status):
            raise ValueError("unsupported Git status")
        count = 2 if status.startswith(("R", "C")) else 1
        paths = fields[index:index + count]
        if len(paths) != count:
            raise ValueError("incomplete Git path record")
        index += count
        changes.append({"status": status, "paths": [_path(p) for p in paths]})
    return {"baseline_revision": baseline, "revision": current, "baseline_available": True,
            "ancestry": "ancestor" if ancestry.returncode == 0 else "diverged", "changes": changes}


def analyze(snapshot: dict, graph: dict) -> dict:
    """Invalidate direct changes, dependent units, unknown graphs and runtime drift."""
    _revision(snapshot["revision"])
    _revision(snapshot["baseline_revision"])
    expected = {"schema_version", "target", "revision", "baseline_revision", "graph_complete",
                "runtime_drift", "units"}
    if set(graph) != expected or graph["schema_version"] != "0.5.0":
        raise ValueError("impact graph has missing or unexpected fields")
    if not isinstance(graph["target"], str) or not graph["target"].strip():
        raise ValueError("target required")
    if (graph["revision"] != snapshot["revision"]
            or graph["baseline_revision"] != snapshot["baseline_revision"]):
        raise ValueError("impact graph revision mismatch")
    if type(graph["graph_complete"]) is not bool or graph["runtime_drift"] not in {"unknown", "changed", "unchanged"}:
        raise ValueError("invalid completeness or runtime drift")
    if not isinstance(graph["units"], list) or len(graph["units"]) > 10000:
        raise ValueError("invalid impact units")
    units = {}
    for unit in graph["units"]:
        if not isinstance(unit, dict) or set(unit) != {"id", "paths", "depends_on", "runtime_sensitive", "prior", "deferred"}:
            raise ValueError("invalid impact unit fields")
        if not isinstance(unit["id"], str) or not unit["id"].strip() or unit["id"] in units:
            raise ValueError("duplicate or missing unit ID")
        if not isinstance(unit["paths"], list) or not unit["paths"]:
            raise ValueError("unit source paths required")
        for path in unit["paths"]:
            _path(path)
        if (not isinstance(unit["depends_on"], list)
                or any(not isinstance(v, str) for v in unit["depends_on"])
                or len(set(unit["depends_on"])) != len(unit["depends_on"])):
            raise ValueError("invalid dependency IDs")
        if any(type(unit[key]) is not bool for key in ("runtime_sensitive", "prior", "deferred")):
            raise ValueError("unit flags must be booleans")
        units[unit["id"]] = unit
    if any(dep not in units for unit in units.values() for dep in unit["depends_on"]):
        raise ValueError("dangling dependency")
    paths = {_path(path) for change in snapshot["changes"] for path in change["paths"]}
    dependency_change = any(PurePosixPath(p).name in DEPENDENCY_NAMES for p in paths)
    reasons = {key: [] for key in units}
    for key, unit in units.items():
        if not snapshot["baseline_available"]:
            reasons[key].append("missing_baseline")
        if not graph["graph_complete"]:
            reasons[key].append("unknown_dependency_edges")
        if dependency_change:
            reasons[key].append("dependency_manifest_changed")
        if paths.intersection(unit["paths"]):
            reasons[key].append("source_changed")
        if unit["runtime_sensitive"] and graph["runtime_drift"] != "unchanged":
            reasons[key].append("runtime_drift_" + graph["runtime_drift"])
    changed = True
    while changed:
        changed = False
        for key, unit in units.items():
            if not reasons[key] and any(reasons[dep] for dep in unit["depends_on"]):
                reasons[key].append("security_dependency_changed")
                changed = True
    rows = []
    for key, unit in units.items():
        state = ("deferred" if unit["deferred"] else "new" if not unit["prior"]
                 else "changed" if reasons[key] else "unchanged")
        rows.append({"id": key, "change_state": state, "reasons": reasons[key],
                     "coverage_status": "deferred" if unit["deferred"] else "unassessed",
                     "revalidation_required": True})
    return {"schema_version": "0.5.0", "target": graph["target"], **snapshot, "units": rows,
            "complete_attack_surface": False,
            "limitations": ["Committed snapshots only; working-tree edits are outside this comparison.",
                "Declared impact edges are reviewer claims; missing edges can hide security impact.",
                "Unchanged is not verified. Old evidence remains bound to its old revision.",
                "Fixed status requires separate finding/remediation verification; never inferred from a diff."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--current")
    parser.add_argument("--graph", required=True, type=Path)
    args = parser.parse_args()
    try:
        from audit_artifacts import load_json
        result = analyze(git_changes(args.root, args.baseline, args.current), load_json(args.graph))
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
