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
        data["scope"]["revision"] = "deadbeef"
        data["controls"][0].update({
            "status": "fixed_verified", "test_result": "pass",
            "test_method": "unit regression test", "evidence": "tests/test_auth.py::test_logout",
            "evidence_revision": "deadbeef",
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
        self.assertIn("| — | — | pytest | test | rejected | rejected | pass |", output)

    def test_unexplained_not_applicable_is_not_verified(self):
        self.data["controls"][4].update({"status": "not_applicable", "evidence": "", "fix": ""})
        self.assertIn("| 05 | Hash passwords | not_verified |", render(self.data))

    def test_high_unverified_blocks_launch(self):
        self.data["controls"][1].update({"status": "not_verified", "severity": "high"})
        self.assertIn("**BLOCK LAUNCH**", render(self.data))

    def test_untrusted_markdown_link_is_escaped(self):
        self.assertNotIn("[click](https://evil.example)", sanitized("[click](https://evil.example)"))

    def test_wrong_revision_evidence_is_not_verified(self):
        self.data["scope"]["revision"] = "deadbeef"
        self.data["controls"][0].update({
            "status": "pass", "test_result": "pass", "evidence": "tests/auth.py",
            "test_method": "pytest tests/auth.py", "evidence_tier": "build",
            "evidence_revision": "old-commit"
        })
        output = render(self.data)
        self.assertIn("| 01 | Authentication | not_verified |", output)

    def test_same_revision_evidence_is_accepted_as_claim(self):
        self.data["scope"]["revision"] = "deadbeef"
        self.data["controls"][0].update({
            "status": "pass", "test_result": "pass", "evidence": "tests/auth.py",
            "test_method": "pytest tests/auth.py", "evidence_tier": "build",
            "evidence_revision": "deadbeef"
        })
        output = render(self.data)
        self.assertIn("| 01 | Authentication | pass |", output)
        self.assertIn("build @ deadbeef", output)

    def test_invalid_evidence_tier_rejected(self):
        self.data["controls"][0]["evidence_tier"] = "magic"
        with self.assertRaisesRegex(ValueError, "invalid evidence_tier"):
            render(self.data)

    def test_unresolved_high_finding_blocks_even_with_passing_test(self):
        self.data["launch_recommendation"] = "no blockers found in tested scope"
        self.data["findings"] = [{
            "id": "F-1", "severity": "high", "resolution_status": "open",
            "test_result": "pass", "evidence": "tests/payment.py",
        }]
        self.assertIn("**BLOCK LAUNCH**", render(self.data))

    def test_unproven_fix_is_downgraded_to_open(self):
        self.data["findings"] = [{
            "id": "F-2", "severity": "critical", "resolution_status": "fixed_verified",
            "test_result": "pass", "evidence": "tests/security.py", "fix": "add guard",
        }]
        report = render(self.data)
        self.assertIn("**BLOCK LAUNCH**", report)
        self.assertIn("Resolution: open", report)

    def test_matching_revision_is_required_for_fix(self):
        self.data["scope"]["revision"] = "after"
        self.data["launch_recommendation"] = "conditional launch"
        self.data["findings"] = [{
            "id": "F-3", "severity": "high", "resolution_status": "fixed_verified",
            "test_result": "pass", "verification_ref": "V-1",
            "evidence": "tests/security.py", "fix": "guard fixed",
        }]
        self.data["verification_log"] = [{
            "id": "V-1", "revision": "before", "method": "pytest tests/security.py",
            "environment": "test", "observed": "denied", "result": "pass",
        }]
        self.assertIn("**BLOCK LAUNCH**", render(self.data))
        self.data["verification_log"][0]["revision"] = "after"
        report = render(self.data)
        self.assertIn("**CONDITIONAL LAUNCH**", report)
        self.assertIn("Resolution: fixed_verified", report)

    def test_false_positive_requires_justification(self):
        self.data["findings"] = [{
            "id": "F-4", "severity": "high", "resolution_status": "false_positive_verified",
            "test_result": "pass", "evidence": "manual review",
        }]
        self.assertIn("**BLOCK LAUNCH**", render(self.data))

    def test_pass_with_unspecified_revision_is_rejected(self):
        self.data["controls"][0].update({
            "status": "pass", "test_result": "pass", "test_method": "pytest",
            "evidence": "tests/security.py",
        })
        self.assertIn("| 01 | Authentication | not_verified |", render(self.data))

    def test_fix_text_does_not_justify_not_applicable(self):
        self.data["scope"]["revision"] = "abc123"
        self.data["controls"][0].update({
            "status": "not_applicable", "fix": "delete the login system",
            "evidence": "", "test_method": "", "not_applicable_reason": "",
        })
        output = render(self.data)
        self.assertIn("| 01 | Authentication | not_verified |", output)

    def test_all_na_does_not_claim_complete_launch_assurance(self):
        self.data["scope"]["revision"] = "abc123"
        self.data["launch_recommendation"] = "no blockers found in tested scope"
        for row in self.data["controls"]:
            row.update({
                "status": "not_applicable", "evidence": "architecture/docs.md",
                "not_applicable_reason": "Feature absent from reviewed architecture",
                "test_method": "review architecture/docs.md", "evidence_tier": "source",
                "evidence_revision": "abc123",
            })
        # Even a real passing unrelated test does not prove all 27 N/As.
        self.data["verification_log"] = [{
            "id": "v", "revision": "abc123", "method": "pytest",
            "environment": "fixture", "observed": "ok", "result": "pass",
        }]
        output = render(self.data)
        self.assertIn("| 01 | Authentication | not_applicable |", output)
        self.assertIn("**CONDITIONAL LAUNCH**", output)
        self.assertNotIn("**NO BLOCKERS FOUND IN TESTED SCOPE**", output)

    def test_scoped_all_clear_requires_per_control_matching_logs(self):
        self.data["scope"]["revision"] = "abc123"
        self.data["launch_recommendation"] = "no blockers found in tested scope"
        self.data["verification_log"] = []
        for row in self.data["controls"]:
            row.update({
                "status": "pass", "test_result": "pass",
                "evidence": "tests/fixture.py", "test_method": "pytest",
                "evidence_revision": "abc123", "verification_ref": f"V-{row['id']}",
            })
            self.data["verification_log"].append({
                "id": row["verification_ref"], "control_id": row["id"],
                "revision": "abc123", "method": "pytest",
                "environment": "disposable", "observed": "pass", "result": "pass",
            })
        self.assertIn("**NO BLOCKERS FOUND IN TESTED SCOPE**", render(self.data))
        self.data["verification_log"].pop()
        self.assertIn("**CONDITIONAL LAUNCH**", render(self.data))
        self.data["verification_log"][-1]["control_id"] = "01"
        self.assertIn("**CONDITIONAL LAUNCH**", render(self.data))

    def test_rejects_missing_control(self):
        self.data["controls"].pop()
        with self.assertRaisesRegex(ValueError, "exactly 27"):
            render(self.data)


if __name__ == "__main__":
    unittest.main()
