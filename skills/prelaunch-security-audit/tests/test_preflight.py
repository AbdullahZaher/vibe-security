"""Offline tests for the narrow, privacy-preserving inventory."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from preflight import inventory  # noqa: E402


class TestInventory(unittest.TestCase):
    def test_only_names_and_not_values(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "package.json").write_text('{"private": true}')
            (root / ".env.local").write_text('PASSWORD=TOP_SECRET_SENTINEL')
            (root / "src").mkdir()
            (root / "src" / "a.ts").write_text('console.log("secret")')
            result = inventory(root)
            payload = json.dumps(result)
            self.assertIn("package.json", result["manifests"])
            self.assertIn(".env.local", result["possible_sensitive_filenames"])
            self.assertNotIn("TOP_SECRET_SENTINEL", payload)
            self.assertEqual(result["files_observed"], 3)

    def test_skips_dependency_dir_and_symlinks(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "node_modules").mkdir()
            (root / "node_modules" / "ignored.js").write_text("should skip")
            (root / "README.md").write_text("hello")
            (root / "link").symlink_to(root / "README.md")
            result = inventory(root)
            self.assertEqual(result["files_observed"], 1)
            self.assertEqual(result["symlinks_skipped"], 1)

    def test_bounded(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for n in range(4):
                (root / f"file{n}.txt").write_text(str(n))
            result = inventory(root, max_files=2)
            self.assertEqual(result["files_observed"], 2)
            self.assertTrue(result["truncated"])

    def test_cli(self):
        with tempfile.TemporaryDirectory() as folder:
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts/preflight.py"), "--root", folder],
                check=True, capture_output=True, text=True,
            )
            self.assertEqual(json.loads(result.stdout)["files_observed"], 0)


if __name__ == "__main__":
    unittest.main()
