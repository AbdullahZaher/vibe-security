"""Host-side artifact path and bounded input/output regressions."""
import os
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from audit_artifacts import bounded_command, load_json, trusted_root, validate_schema, write_new_artifact


class ArtifactIOTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_fresh_report_is_private_and_existing_content_preserved(self):
        path = self.root / 'reports' / 'audit.md'
        write_new_artifact(path, 'synthetic report')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError): write_new_artifact(path, 'overwrite')
        self.assertEqual(path.read_text(), 'synthetic report')

    def test_output_symlink_parent_and_leaf_never_modify_target(self):
        existing = self.root / 'existing'
        existing.write_text('preserve')
        (self.root / 'link').symlink_to(existing)
        (self.root / 'parent').symlink_to(self.root, target_is_directory=True)
        for path in (self.root / 'link', self.root / 'parent' / 'new'):
            with self.assertRaises((ValueError, OSError)): write_new_artifact(path, 'bad')
        self.assertEqual(existing.read_text(), 'preserve')
        self.assertFalse((self.root / 'new').exists())

    def test_output_traversal_rejected(self):
        with self.assertRaises(ValueError):
            write_new_artifact(self.root / 'child' / '..' / 'escaped', 'bad')
        self.assertFalse((self.root / 'escaped').exists())

    def test_immutable_system_root_symlink_is_canonicalized(self):
        # macOS /var is a root-owned system symlink; user-writable links are not.
        root = Path(tempfile.gettempdir())
        self.assertEqual(trusted_root(root), root.resolve())

    def test_user_writable_symlink_root_rejected(self):
        (self.root / 'real').mkdir()
        (self.root / 'link').symlink_to(self.root / 'real', target_is_directory=True)
        with self.assertRaises(ValueError):
            trusted_root(self.root / 'link')

    def test_bounded_child_output_stops_before_unbounded_allocation(self):
        # Executes only this fixed, reviewed stdlib expression; no target code.
        with self.assertRaisesRegex(ValueError, 'exceeds limit'):
            bounded_command([sys.executable, '-c', 'print("x" * 5000)'],
                            {'PATH': os.defpath}, max_bytes=100)

    def test_non_utf8_encoding_cannot_bypass_depth_guard(self):
        path = self.root / 'encoded.json'
        # Escaped quotes in UTF-16 confuse a byte-oriented quote/depth scanner.
        body = json.dumps(['"', 0]).replace('0', '[' * 200 + '0' + ']' * 200)
        path.write_bytes(body.encode('utf-16'))
        with self.assertRaisesRegex(ValueError, 'UTF-8'): load_json(path)
        data = ['[' * 200, 'quoted " and escaped backslash \\']
        path.write_text(json.dumps(data), encoding='utf-8')
        self.assertEqual(load_json(path), data)

    def test_nonfinite_numeric_api_values_and_deep_json_fail_closed(self):
        with patch('audit_artifacts.load_json', return_value={'type': 'number'}):
            for number in (float('inf'), float('-inf'), float('nan')):
                with self.assertRaises(ValueError): validate_schema(number, 'synthetic.json')
        path = self.root / 'deep.json'
        path.write_text('[' * 2000 + ']' * 2000)
        with self.assertRaises(ValueError): load_json(path)


if __name__ == '__main__': unittest.main()
