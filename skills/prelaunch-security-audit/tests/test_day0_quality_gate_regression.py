"""v0.6 development line, unreleased: Day 0 synthetic quality-gate regression.

Roadmap reference: docs/plans/security-quality-roadmap.md (left untracked).
The owner-approved Day 0 requirement is a proposal, not an evaluator contract.
These synthetic fixtures and their reviewer labels are NOT independent evidence.
"""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "evals"))
from evaluate_trial_matrix import evaluate, fingerprint  # noqa: E402
from test_trial_matrix import protocol, trials  # noqa: E402

# placeholder proposal; final names to be set in PR-02/PR-03
EXPECTED_QUALITY_VERDICT_KEY = "quality_verdict"
EXPECTED_FAILING_QUALITY_VERDICT = "FAIL"


def trusted_authentication_test_double(kind, record):
    """Accept synthetic records for software testing; NOT independent evidence."""
    return True


class Day0QualityGateRegressionTests(unittest.TestCase):
    def setUp(self):
        self.protocol = protocol()
        self.records = trials(self.protocol)
        for record in self.records:
            record["findings"] = {
                "true_positive": 0,
                "false_positive": 10,
                "false_negative": 10,
            }
        # setUp is outside expectedFailure: fixture/evaluator errors stay visible.
        self.result = evaluate(
            self.protocol, self.records, attest=trusted_authentication_test_double
        )

    def test_a_preconditions_and_release_invariant(self):
        self.assertEqual(len(self.protocol["cases"]), 5)
        self.assertEqual(set(self.protocol["arms"]), {"A", "B", "C"})
        self.assertEqual(self.protocol["repetitions"], 3)
        self.assertEqual(len(self.records), 45)
        cases = {case["id"]: case for case in self.protocol["cases"]}
        expected_slots = {
            (case_id, arm, repetition)
            for case_id in cases
            for arm in self.protocol["arms"]
            for repetition in range(1, 4)
        }
        observed_slots = {
            (record["case_id"], record["arm"], record["repetition"])
            for record in self.records
        }
        self.assertEqual(observed_slots, expected_slots)
        for record in self.records:
            self.assertEqual(record["protocol_sha256"], fingerprint(self.protocol))
            self.assertEqual(
                record["source_revision"], cases[record["case_id"]]["source_revision"]
            )
            self.assertEqual(
                record["skill_revision"], self.protocol["arms"][record["arm"]]
            )
            self.assertEqual(record["budget"], self.protocol["budget"])
            self.assertEqual(record["status"], "completed")
            self.assertEqual(record["findings"]["true_positive"], 0)
            self.assertGreater(record["findings"]["false_positive"], 0)
            self.assertGreater(record["findings"]["false_negative"], 0)
        self.assertEqual(self.result["trials_expected"], 45)
        # This count is accepted only under our trusted TEST DOUBLE callback.
        self.assertEqual(self.result["authenticated_completed_trials"], 45)
        for arm in self.protocol["arms"]:
            metric = self.result["metrics"][arm]
            self.assertEqual(metric["recall"], 0)
            self.assertEqual(metric["precision"], 0)
            self.assertEqual(metric["counts"]["true_positive"], 0)
            self.assertGreater(metric["counts"]["false_negative"], 0)
            self.assertGreater(metric["counts"]["false_positive"], 0)
        self.assertFalse(self.result["stable_release_ready"])

    @unittest.expectedFailure
    def test_b_quality_verdict_is_explicit_failure(self):
        # Remove the decorator when the quality gate lands. unittest reports an
        # unexpected success as failure; never silently accept a stale decorator.
        self.assertEqual(
            self.result[EXPECTED_QUALITY_VERDICT_KEY], EXPECTED_FAILING_QUALITY_VERDICT
        )


if __name__ == "__main__":
    unittest.main()
