"""Report schema, conservative evidence gating, escaping and redaction."""
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from render_report import render, sanitized  # noqa: E402


class TestReport(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "assets/findings.example.json").read_text())

    def test_report_contains_all_controls(self):
        output = render(self.data)
        self.assertIn("| 01 | Authentication |", output)
        self.assertIn("| 27 | Test and report |", output)
        self.assertEqual(output.count("| not_verified |"), 27)

    def test_incomplete_pass_is_downgraded(self):
        data = copy.deepcopy(self.data)
        data["controls"][0]["status"] = "pass"
        data["launch_recommendation"] = "no blockers found in tested scope"
        output = render(data)
        self.assertIn("| 01 | Authentication | not_verified |", output)
        self.assertIn("CONDITIONAL LAUNCH", output)

    def test_pass_needs_evidence_and_method(self):
        data = copy.deepcopy(self.data)
        data["controls"][0].update({
            "status": "fixed_verified", "test_result": "pass",
            "test_method": "unit regression test", "evidence": "tests/test_auth.py::test_logout",
        })
        self.assertIn("| 01 | Authentication | fixed_verified |", render(data))

    def test_secret_redacted_and_pipes_escaped(self):
        self.assertNotIn("ghp_" + "Z" * 30, sanitized("ghp_" + "Z" * 30))
        self.assertIn("\\|", sanitized("a|b"))
        self.assertIn("&lt;script&gt;", sanitized("<script>"))

    def test_blocks_launch_for_unresolved_high_issue(self):
        self.data["controls"][4]["status"] = "failed"
        self.data["controls"][4]["severity"] = "high"
        self.assertIn("BLOCK LAUNCH", render(self.data))

    def test_detail_and_verification_sections(self):
        self.data["findings"] = [
            {"id": "F1", "title": "Example issue", "severity": "medium", "control": "05", "test_result": "fail"}
        ]
        self.data["changed_files"] = ["src/auth.py"]
        self.data["verification_log"] = [
            {"method": "pytest", "environment": "test", "expected": "rejected", "observed": "rejected", "result": "pass"}
        ]
        output = render(self.data)
        self.assertIn("### F1 — Example issue", output)
        self.assertIn("src/auth.py", output)
        self.assertIn("| pytest | test | rejected | rejected | pass |", output)

    def test_unexplained_not_applicable_is_not_verified(self):
        self.data["controls"][4].update({"status": "not_applicable", "evidence": "", "fix": ""})
        self.assertIn("| 05 | Hash passwords | not_verified |", render(self.data))

    def test_high_unverified_blocks_launch(self):
        self.data["controls"][1].update({"status": "not_verified", "severity": "high"})
        self.assertIn("**BLOCK LAUNCH**", render(self.data))

    def test_untrusted_markdown_link_is_escaped(self):
        self.assertNotIn("[click](https://evil.example)", sanitized("[click](https://evil.example)"))

    def test_rejects_missing_control(self):
        self.data["controls"].pop()
        with self.assertRaisesRegex(ValueError, "exactly 27"):
            render(self.data)


if __name__ == "__main__":
    unittest.main()
