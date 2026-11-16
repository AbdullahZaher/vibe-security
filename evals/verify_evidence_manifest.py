#!/usr/bin/env python3
"""Verify Git-tracked evidence artifact SHA-256 and byte counts (NOT provenance).

A developer-controlled manifest can faithfully hash fabricated claims. A PASS
here means only that the declared files match the declared digests. The script
MUST NOT issue any release authorization, attest to macOS execution, or grade
A/B/C model experiments.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_FILE = 8_000_000


def verify(manifest_path: Path, root: Path = ROOT) -> dict:
    root = root.resolve(strict=True)
    manifest_path = manifest_path.resolve(strict=True)
    if not manifest_path.is_relative_to(root):
        raise ValueError("manifest outside repository")
    obj = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("invalid manifest")
    artifacts = obj.get("artifact_digests")
    if not isinstance(artifacts, dict) or len(artifacts) < 18:
        raise ValueError("incomplete artifact manifest")
    if obj.get("stable_release_authorized") is True:
        raise ValueError("artifact hash file cannot confer release authorization")
    for name, expected in artifacts.items():
        if not isinstance(name, str) or not name or not isinstance(expected, dict):
            raise ValueError("invalid artifact entry")
        path = Path(name)
        if path.is_absolute() or ".." in path.parts or path.parts[0].startswith("."):
            raise ValueError("unsafe artifact path")
        candidate = root / path
        if not candidate.resolve(strict=True).is_relative_to(root):
            raise ValueError("artifact escapes root")
        current = root
        for component in path.parts:
            current = current / component
            if current.is_symlink():
                raise ValueError("symlink in artifact path")
        if not candidate.is_file():
            raise ValueError("not a regular file")
        size = candidate.stat().st_size
        checksum = expected.get("sha256")
        if (not isinstance(checksum, str) or SHA256.fullmatch(checksum) is None
                or type(expected.get("bytes")) is not int
                or expected["bytes"] < 0 or expected["bytes"] > MAX_FILE
                or size != expected["bytes"]):
            raise ValueError("artifact size or digest metadata mismatch: " + name)
        raw = candidate.read_bytes()
        if hashlib.sha256(raw).hexdigest() != checksum:
            raise ValueError("artifact content digest mismatch: " + name)
    return {
        "status": "PASS_CONTENT_INTEGRITY_ONLY",
        "verified_artifacts": len(artifacts),
        "independent_host_attestation": False,
        "benchmarks_independently_authenticated": False,
        "release_authorized": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "docs/evaluations/v0.5.0-evidence-manifest.json")
    args = parser.parse_args(argv)
    try:
        result = verify(args.manifest)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"EVIDENCE INTEGRITY FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
