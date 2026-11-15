"""No-billing A/B/C readiness tests. Synthetic trials are NEVER real evidence."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "evals"))

from abc_trial_readiness import plan  # noqa: E402
from test_trial_matrix import protocol, trials  # noqa: E402


def authorized_test_protocol():
    p = protocol()
    p["budget"]["max_cost_usd"] = 10.0  # synthetic limit; not actual spending approval
    return p


class ABCEvaluationReadinessTests(unittest.TestCase):
    def test_empty_plan_has_45_missing_slots_and_zero_authenticated(self):
        p = authorized_test_protocol()
        result = plan(p)
        self.assertEqual(result["expected_slots"], 45)
        self.assertEqual(result["unsubmitted_slots"], 45)
        self.assertEqual(result["independently_authenticated_slots"], 0)
        self.assertEqual(result["provider_requests_executed"], 0)
        self.assertEqual(result["status"], "BLOCK_STABLE_RELEASE")
        self.assertFalse(result["release_authorized"])
        self.assertEqual(len({
            (s["case_id"], s["arm"], s["repetition"]) for s in result["slots"]
        }), 45)

    def test_all_synthetic_trial_slots_still_not_independently_authenticated(self):
        p = authorized_test_protocol()
        records = trials(p)
        result = plan(p, records)
        self.assertEqual(result["developer_submitted_slots"], 45)
        self.assertEqual(result["independently_authenticated_slots"], 0)
        self.assertEqual(result["unsubmitted_slots"], 0)
        self.assertTrue(all(s["status"] == "CLAIMED_UNVERIFIED" for s in result["slots"]))

    def test_refuse_unknown_paid_budget_even_if_samples_exist(self):
        with self.assertRaisesRegex(ValueError, "explicit numerical budget"):
            plan(protocol())

    def test_refuse_duplicate_context_or_replayed_host_log(self):
        p = authorized_test_protocol()
        for attr in ("context_id", "host_log_sha256"):
            records = trials(p)
            records[1][attr] = records[0][attr]
            with self.assertRaises(ValueError):
                plan(p, records)

    def test_refuse_claimed_trial_with_different_source_revision(self):
        p = authorized_test_protocol()
        records = trials(p)
        records[0]["source_revision"] = "f" * 40
        with self.assertRaises(ValueError):
            plan(p, records)

    def test_refuse_public_no_holdout_or_incomplete_design(self):
        p = authorized_test_protocol()
        for item in p["cases"]:
            item["holdout"] = False
        with self.assertRaises(ValueError):
            plan(p)
        p = authorized_test_protocol()
        p["repetitions"] = 2
        with self.assertRaisesRegex(ValueError, "release requires"):
            plan(p)

    def test_no_mutation_to_trial_records(self):
        p = authorized_test_protocol()
        records = trials(p)
        original = copy.deepcopy(records)
        plan(p, records)
        self.assertEqual(records, original)


if __name__ == "__main__":
    unittest.main()
