"""Crypto evidence bundle regressions (controller tests; never live inference)."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[3]
if importlib.util.find_spec("cryptography"):
    sys.path.insert(0, str(ROOT / "evals"))
    from seal_evidence import seal, unseal, collect
    from cryptography.exceptions import InvalidTag
else:
    seal = unseal = collect = None
    InvalidTag = Exception

KEY = b"c" * 32


@unittest.skipUnless(seal is not None, "Install pinned cryptography to run evidence encryption tests")
class TestEvidenceSealing(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.trace = self.root / "trace.json"
        self.review = self.root / "review"
        self.review.mkdir()
        self.run_id = str(uuid4())
        self.output = self.root / "bundle.enc"
        self.trace.write_text(json.dumps({"runs": [{
            "run_id": self.run_id, "status": "response_produced",
            "evidence_origin": "live_model_tool_calls",
            "events": [{"type": "tool_request", "blocked": True, "effect": "external_write"}],
        }]}), encoding="utf-8")
        (self.review / (self.run_id + ".txt")).write_text(
            "Synthetic prompt-injection rejected by the agent", encoding="utf-8")

    def test_round_trip_preserves_private_review_without_cleartext_artifact(self):
        seal(self.trace, self.review, self.output, KEY)
        raw = self.output.read_bytes()
        self.assertNotIn(b"prompt-injection rejected", raw)
        self.assertNotIn(b"external_write", raw)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        dest = self.root / "decrypted"
        unseal(self.output, dest, KEY)
        self.assertIn("Synthetic prompt-injection rejected", (dest / (self.run_id + ".txt")).read_text())
        self.assertEqual((dest / "trace.json").stat().st_mode & 0o777, 0o600)

    def test_wrong_key_or_tampering_fails_authenticated_decryption(self):
        seal(self.trace, self.review, self.output, KEY)
        with self.assertRaises(InvalidTag):
            unseal(self.output, self.root / "bad-key", b"d" * 32)
        payload = json.loads(self.output.read_text())
        from base64 import b64decode, b64encode
        body = bytearray(b64decode(payload["ciphertext"]))
        body[0] ^= 1
        payload["ciphertext"] = b64encode(body).decode()
        self.output.write_text(json.dumps(payload))
        with self.assertRaises(InvalidTag):
            unseal(self.output, self.root / "tampered", KEY)

    def test_rejects_mock_trials(self):
        meta = json.loads(self.trace.read_text())
        meta["runs"][0]["evidence_origin"] = "controller_test_unverified"
        self.trace.write_text(json.dumps(meta))
        with self.assertRaisesRegex(ValueError, "mock"):
            seal(self.trace, self.review, self.output, KEY)
        self.assertFalse(self.output.exists())

    def test_rejects_missing_review_and_unredacted_synthetic_marker(self):
        private = self.review / (self.run_id + ".txt")
        private.unlink()
        with self.assertRaisesRegex(ValueError, "missing reviewer"):
            seal(self.trace, self.review, self.output, KEY)
        private.write_text("DUMMY_TEST_SECRET_DO_NOT_SHARE_9AF3")
        with self.assertRaisesRegex(ValueError, "not redacted"):
            seal(self.trace, self.review, self.output, KEY)

    def test_rejects_existing_encrypted_file(self):
        self.output.write_text("existing")
        with self.assertRaises(FileExistsError):
            seal(self.trace, self.review, self.output, KEY)
        self.assertEqual(self.output.read_text(), "existing")

    def test_never_creates_plaintext_review_under_checkout(self):
        seal(self.trace, self.review, self.output, KEY)
        forbidden = ROOT / "do-not-write-review"
        with self.assertRaisesRegex(ValueError, "outside"):
            unseal(self.output, forbidden, KEY)
        self.assertFalse(forbidden.exists())

    def test_never_creates_encrypted_artifact_under_checkout(self):
        forbidden = ROOT / "do-not-write-evidence.enc"
        with self.assertRaisesRegex(ValueError, "outside"):
            seal(self.trace, self.review, forbidden, KEY)
        self.assertFalse(forbidden.exists())

    def test_refuses_symlink_review_record(self):
        target = self.review / (self.run_id + ".txt")
        target.unlink()
        source = self.root / "other.txt"
        source.write_text("outside")
        target.symlink_to(source)
        with self.assertRaises(ValueError):
            collect(self.trace, self.review)


if __name__ == "__main__":
    unittest.main()
