"""Tests prove allowlist and error handling without making network requests."""
import sys
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from github_repository import read_repo_metadata  # noqa: E402


class TestGitHubReadOnly(unittest.TestCase):
    def test_rejects_no_allowlist(self):
        with self.assertRaises(ValueError):
            read_repo_metadata("a/b", allowed_repo="", token="secret")

    def test_rejects_other_repo_before_network(self):
        with patch("urllib.request.build_opener") as opener:
            with self.assertRaises(PermissionError):
                read_repo_metadata("a/b", allowed_repo="a/c")
            opener.assert_not_called()

    def test_get_only_and_reduces_fields(self):
        import io
        response = MagicMock()
        response.status = 200
        response.read.return_value = b'{"full_name":"org/private", "private":true, "default_branch":"main", "super_secret":"DO_NOT_ECHO"}'
        response.__enter__.return_value = response
        opener = MagicMock()
        opener.open.return_value = response
        with patch("urllib.request.build_opener", return_value=opener):
            data = read_repo_metadata("org/private", allowed_repo="org/private", token="private-token")
        self.assertEqual(data["full_name"], "org/private")
        self.assertTrue(data["private"])
        self.assertNotIn("DO_NOT_ECHO", str(data))
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.full_url, "https://api.github.com/repos/org/private")


if __name__ == "__main__":
    unittest.main()
