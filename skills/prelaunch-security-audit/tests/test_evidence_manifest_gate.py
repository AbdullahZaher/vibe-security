"""Synthetic negative tests: SHA-256 file integrity is NOT host attestation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "evals"))
from verify_evidence_manifest import verify  # noqa: E402


class EvidenceManifestIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.manifest = self.root / "manifest.json"
        self.entries = {}
        for idx in range(18):
            name = f"evidence/file-{idx}.txt"
            path = self.root / name
            path.parent.mkdir(exist_ok=True)
            raw = f"SYNTHETIC-{idx}".encode()
            path.write_bytes(raw)
            self.entries[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
        self._save()

    def _save(self):
        self.manifest.write_text(json.dumps({"artifact_digests": self.entries}), encoding="utf-8")

    def test_matching_hashes_are_only_content_integrity(self):
        result = verify(self.manifest, root=self.root)
        self.assertEqual(result["verified_artifacts"], 18)
        self.assertFalse(result["release_authorized"])
        self.assertFalse(result["independent_host_attestation"])

    def test_modified_artifact_blocks(self):
        (self.root / "evidence/file-0.txt").write_text("TAMPERED")
        with self.assertRaisesRegex(ValueError, "mismatch"):
            verify(self.manifest, root=self.root)

    def test_symlinked_artifact_blocks_even_when_digest_matches(self):
        src = self.root / "evidence/file-1.txt"
        real = self.root / "evidence/real.txt"
        src.rename(real)
        src.symlink_to(real)
        with self.assertRaisesRegex(ValueError, "symlink"):
            verify(self.manifest, root=self.root)

    def test_path_traversal_blocks(self):
        self.entries["../escape"] = self.entries.pop("evidence/file-2.txt")
        self._save()
        with self.assertRaisesRegex(ValueError, "unsafe artifact path"):
            verify(self.manifest, root=self.root)

    def test_manifest_cannot_authorize_release(self):
        self.manifest.write_text(json.dumps({
            "artifact_digests": self.entries, "stable_release_authorized": True
        }), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "cannot confer release"):
            verify(self.manifest, root=self.root)


if __name__ == "__main__":
    unittest.main()
