#!/usr/bin/env python3
"""Encrypt isolated live-evaluation evidence before uploading to public-repo Actions.

Only synthetic fixture review records are allowed. GitHub receives ciphertext;
EVAL_EVIDENCE_KEY (32 random bytes, base64) must remain in a secret store.
No credential, raw reviewer output, or trace is ever printed by this program.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
from pathlib import Path
import re
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = "vibe-security-evidence-aes256gcm-v1"
AAD = VERSION.encode("ascii")
FAKE_SECRET = "DUMMY_TEST_SECRET_DO_NOT_SHARE_9AF3"
MAX_TRACE_BYTES = 2_000_000
MAX_REVIEW_BYTES = 500_000
MAX_RUNS = 3
RUN_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def load_key(value: str | None = None) -> bytes:
    encoded = value if value is not None else os.getenv("EVAL_EVIDENCE_KEY", "")
    try:
        key = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("invalid EVAL_EVIDENCE_KEY encoding") from None
    if len(key) != 32:
        raise ValueError("EVAL_EVIDENCE_KEY must decode to 32 random bytes")
    return key


def _new_private_file(path: Path, contents: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(contents)


def _validate_private_source(path: Path, size_limit: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("source is not a regular private file")
    if path.stat().st_size > size_limit:
        raise ValueError("source evidence exceeds allowed size")
    return path.read_bytes()


def collect(trace: Path, review_dir: Path) -> dict:
    if review_dir.is_symlink() or not review_dir.is_dir():
        raise ValueError("review_dir must be an existing directory, not a symlink")
    trace_bytes = _validate_private_source(trace, MAX_TRACE_BYTES)
    metadata = json.loads(trace_bytes)
    runs = metadata.get("runs")
    if not isinstance(runs, list) or not 1 <= len(runs) <= MAX_RUNS:
        raise ValueError("trace must contain one to three trials")
    seen = set()
    for run in runs:
        if not isinstance(run, dict) or not RUN_ID.fullmatch(str(run.get("run_id", ""))):
            raise ValueError("invalid run identifier")
        if run["run_id"] in seen:
            raise ValueError("duplicate run identifier")
        seen.add(run["run_id"])
        if run.get("evidence_origin") not in {"live_model_tool_calls", "live_api_attempt_unconfirmed"}:
            raise ValueError("refusing to label mock/controller data as live evidence")
    reviews = {}
    for path in review_dir.iterdir():
        if not path.is_file() or path.is_symlink() or not path.name.endswith(".txt"):
            raise ValueError("unexpected reviewer evidence file")
        run_id = path.name[:-4]
        if run_id not in seen:
            raise ValueError("review evidence does not match a run")
        review = _validate_private_source(path, MAX_REVIEW_BYTES).decode("utf-8")
        if FAKE_SECRET in review:
            raise ValueError("synthetic secret marker was not redacted")
        reviews[run_id] = review
    for run in runs:
        if run.get("status") == "response_produced" and run["run_id"] not in reviews:
            raise ValueError("missing reviewer output for a completed trial")
    return {"format": VERSION, "trace": metadata, "reviews": reviews}


def seal(trace: Path, review_dir: Path, output: Path, key: bytes) -> None:
    payload = json.dumps(collect(trace, review_dir), sort_keys=True,
                         ensure_ascii=False).encode("utf-8")
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, payload, AAD)
    envelope = json.dumps({
        "format": VERSION,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }, separators=(",", ":")).encode("utf-8")
    _new_private_file(output, envelope)


def unseal(encrypted: Path, output_dir: Path, key: bytes) -> None:
    envelope = json.loads(_validate_private_source(encrypted, 5_000_000))
    if envelope.get("format") != VERSION:
        raise ValueError("unsupported evidence format")
    try:
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
    except (KeyError, binascii.Error, ValueError):
        raise ValueError("invalid encrypted evidence envelope") from None
    if len(nonce) != 12:
        raise ValueError("invalid nonce length")
    # An incorrect key or tampered ciphertext fails with InvalidTag.
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, AAD)
    payload = json.loads(plaintext)
    if payload.get("format") != VERSION:
        raise ValueError("unexpected decrypted format")
    if output_dir.exists():
        raise ValueError("review destination must be a new directory")
    output_dir.mkdir(parents=True, mode=0o700)
    _new_private_file(output_dir / "trace.json",
                      json.dumps(payload["trace"], indent=2).encode("utf-8"))
    for run_id, review in payload["reviews"].items():
        if not RUN_ID.fullmatch(run_id) or not isinstance(review, str):
            raise ValueError("invalid reviewer record")
        _new_private_file(output_dir / (run_id + ".txt"), review.encode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    enc = sub.add_parser("seal", help="Encrypt private synthetic trace and reviewer outputs")
    enc.add_argument("--trace", type=Path, required=True)
    enc.add_argument("--review-dir", type=Path, required=True)
    enc.add_argument("--output", type=Path, required=True)
    dec = sub.add_parser("open", help="Decrypt into a new private local directory")
    dec.add_argument("--input", type=Path, required=True)
    dec.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        key = load_key()
        if args.mode == "seal":
            seal(args.trace, args.review_dir, args.output, key)
            print("Encrypted evidence bundle created; raw reviewer text was not printed.")
        else:
            unseal(args.input, args.output_dir, key)
            print("Decrypted private reviewer records; do not commit or upload plaintext.")
    except (ValueError, OSError, KeyError, TypeError) as error:
        # Do not echo filenames, command arguments, or key values.
        parser.error(type(error).__name__ + ": evidence operation did not complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
