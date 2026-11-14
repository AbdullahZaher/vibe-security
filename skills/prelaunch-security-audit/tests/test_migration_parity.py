"""No-network tests for optional, offline Supabase migration-ID comparison."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from migration_parity import compare_migrations  # noqa: E402


class TestMigrationParity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "repo"
        self.migrations = self.root / "supabase" / "migrations"
        self.migrations.mkdir(parents=True)
        (self.migrations / "20261111120000_first.sql").write_text("-- private SQL content", encoding="utf-8")
        (self.migrations / "20261112120000_second.sql").write_text("-- secret sentinel", encoding="utf-8")
        self.applied = Path(self.tmp.name) / "applied.txt"

    def test_matching_versions(self):
        self.applied.write_text("20261111120000\n20261112120000\n", encoding="utf-8")
        value = compare_migrations(self.root, self.applied)
        self.assertEqual(value["result"], "match")
        self.assertEqual(value["pending_in_database"], [])
        self.assertNotIn("secret sentinel", json.dumps(value))

    def test_missing_and_unexpected_version_even_with_equal_counts(self):
        self.applied.write_text("20261111120000\n20260101000000\n", encoding="utf-8")
        value = compare_migrations(self.root, self.applied)
        self.assertEqual(value["result"], "difference")
        self.assertEqual(value["pending_in_database"], ["20261112120000"])
        self.assertEqual(value["unexpected_in_database"], ["20260101000000"])
        self.assertEqual(value["repository_versions_count"], value["applied_versions_count"])

    def test_duplicates_never_pass(self):
        (self.migrations / "20261111120000_other.sql").write_text("", encoding="utf-8")
        self.applied.write_text("20261111120000\n20261112120000\n20261112120000\n", encoding="utf-8")
        value = compare_migrations(self.root, self.applied)
        self.assertEqual(value["result"], "difference")
        self.assertEqual(value["duplicate_repository_versions"], ["20261111120000"])
        self.assertEqual(value["duplicate_applied_versions"], ["20261112120000"])

    def test_invalid_or_empty_applied_list_is_not_a_pass(self):
        for content in ["", "postgresql://user:secret@host/db", "20261111120000 extra"]:
            with self.subTest(content=content):
                self.applied.write_text(content, encoding="utf-8")
                with self.assertRaises(ValueError):
                    compare_migrations(self.root, self.applied)

    def test_symlink_refused(self):
        self.applied.write_text("20261111120000\n", encoding="utf-8")
        target = Path(self.tmp.name) / "linked.txt"
        target.symlink_to(self.applied)
        with self.assertRaises(ValueError):
            compare_migrations(self.root, target)
        (self.migrations / "20261113120000_link.sql").symlink_to(self.applied)
        with self.assertRaises(ValueError):
            compare_migrations(self.root, self.applied)

    def test_malformed_sql_filename_is_not_ignored(self):
        self.applied.write_text("20261111120000\n", encoding="utf-8")
        (self.migrations / "bad_migration.sql").write_text("-- sql", encoding="utf-8")
        with self.assertRaises(ValueError):
            compare_migrations(self.root, self.applied)

    def test_cli_result_codes(self):
        self.applied.write_text("20261111120000\n20261112120000\n", encoding="utf-8")
        script = ROOT / "scripts" / "migration_parity.py"
        def call():
            return subprocess.run([sys.executable, str(script), "--root", str(self.root),
                                   "--applied-file", str(self.applied)], text=True, capture_output=True)
        self.assertEqual(call().returncode, 0)
        self.applied.write_text("20261111120000\n", encoding="utf-8")
        self.assertEqual(call().returncode, 1)
        self.applied.write_text("invalid\n", encoding="utf-8")
        self.assertEqual(call().returncode, 2)


if __name__ == "__main__":
    unittest.main()
