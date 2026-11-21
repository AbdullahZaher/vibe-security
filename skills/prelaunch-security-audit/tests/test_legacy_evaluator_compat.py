"""Legacy output SHAPE snapshots, not quality acceptance or independent evidence.

Only in-process evaluator calls and reads of the two legacy source files.
Synthetic reviewer/origin labels and the trusted TEST DOUBLE prove no real trust.
Never pin review readiness for poor quality or an empty blocker list.
"""
import copy
from pathlib import Path
import sys
import unittest

EVALS = Path(__file__).resolve().parents[3] / "evals"
sys.path.insert(0, str(EVALS))
from evaluate_trial_matrix import evaluate  # noqa: E402
from release_readiness_gate import evaluate_claims  # noqa: E402
from test_trial_matrix import protocol, trials  # noqa: E402

MATRIX_KEYS = {
    "protocol_sha256", "trials_expected", "authenticated_completed_trials",
    "blocked_attempts", "unsafe_executed", "metrics", "release_review_ready",
    "stable_release_ready", "blockers", "notice",
}
CLAIMS_KEYS = {
    "release_decision", "stable_release_ready", "trusted_host_attestations_supplied",
    "independent_human_signoff_verified", "protocol_minimum", "claim_only",
    "blockers", "notice",
}
COUNT_KEYS = {"true_positive", "false_positive", "false_negative"}
PROTOCOL_MINIMUM = {
    "cases": 5, "arms": 3, "repetitions_per_case_and_arm": 3,
    "expected_independent_trials": 45,
}


def trusted_authentication_test_double(kind, record):
    """Accept synthetic records only; NOT actual authentication or adjudication."""
    return True


def claims_metrics(counts=(15, 15, 15), revision="c" * 40):
    """Minimal builder matching the existing inline release-blocker fixtures."""
    return {"conditions": {
        arm: {"real_trials_completed": count,
              "source_revision": copy.deepcopy(revision) if arm == "C" else "a" * 40}
        for arm, count in zip(("A", "B", "C"), counts)
    }}


class LegacyEvaluatorCompatibilityTests(unittest.TestCase):
    def assert_string_list(self, value):
        self.assertIs(type(value), list)
        self.assertTrue(all(type(item) is str for item in value))

    def assert_matrix_snapshot(self, result):
        self.assertIs(type(result), dict)
        self.assertEqual(set(result), MATRIX_KEYS)
        self.assertIs(type(result["protocol_sha256"]), str)
        for key in ("trials_expected", "authenticated_completed_trials",
                    "blocked_attempts", "unsafe_executed"):
            self.assertIs(type(result[key]), int)
        self.assertIs(type(result["release_review_ready"]), bool)
        self.assertIs(result["stable_release_ready"], False)
        self.assert_string_list(result["blockers"])
        # evaluate_trial_matrix.evaluate, return expression: not blocked (line 187).
        # Deliberately no assertion when blockers is empty, regardless of quality.
        if result["blockers"]:
            self.assertIs(result["release_review_ready"], False)
        self.assertIs(type(result["notice"]), str)
        self.assertIs(type(result["metrics"]), dict)
        self.assertEqual(set(result["metrics"]), {"A", "B", "C"})
        for metric in result["metrics"].values():
            self.assertIs(type(metric), dict)
            self.assertEqual(set(metric), {"counts", "precision", "recall"})
            if metric["counts"] is not None:
                self.assertIs(type(metric["counts"]), dict)
                self.assertEqual(set(metric["counts"]), COUNT_KEYS)
                for count in metric["counts"].values():
                    self.assertIs(type(count), int)
            for key in ("precision", "recall"):
                self.assertTrue(metric[key] is None or type(metric[key]) is float)

    def assert_claims_snapshot(self, result, metrics):
        self.assertIs(type(result), dict)
        self.assertEqual(set(result), CLAIMS_KEYS)
        self.assertIs(type(result["release_decision"]), str)
        self.assertEqual(result["release_decision"], "BLOCK_STABLE_RELEASE")
        for key in ("stable_release_ready", "trusted_host_attestations_supplied",
                    "independent_human_signoff_verified"):
            self.assertIs(result[key], False)
        self.assertIs(type(result["protocol_minimum"]), dict)
        self.assertEqual(set(result["protocol_minimum"]), set(PROTOCOL_MINIMUM))
        for key, expected in PROTOCOL_MINIMUM.items():
            self.assertIs(type(result["protocol_minimum"][key]), int)
            self.assertEqual(result["protocol_minimum"][key], expected)
        claim = result["claim_only"]
        self.assertIs(type(claim), dict)
        self.assertEqual(set(claim), {"declared_session_count", "condition_c_source_revision",
                                     "scoring_status"})
        self.assertIs(type(claim["declared_session_count"]), int)
        self.assertEqual(claim["declared_session_count"], sum(
            metrics["conditions"][arm]["real_trials_completed"] for arm in ("A", "B", "C")))
        revision = metrics["conditions"]["C"].get("source_revision")
        self.assertIs(type(claim["condition_c_source_revision"]), type(revision))
        self.assertEqual(claim["condition_c_source_revision"], revision)
        self.assertIs(type(claim["scoring_status"]), str)
        self.assertEqual(claim["scoring_status"], "unverified_developer_assertions")
        self.assert_string_list(result["blockers"])
        self.assertTrue(result["blockers"])
        self.assertIs(type(result["notice"]), str)

    def matrix(self, frozen, records, attest=None):
        before = copy.deepcopy((frozen, records))
        result = evaluate(frozen, records, attest=attest)
        self.assert_matrix_snapshot(result)
        self.assertEqual((frozen, records), before)
        return result

    def claims(self, metrics):
        before = copy.deepcopy(metrics)
        result = evaluate_claims(metrics)
        self.assert_claims_snapshot(result, metrics)
        self.assertEqual(metrics, before)
        return result

    def assert_mutation_rejected(self, checker, result, path, value=None, *, remove=False):
        before = copy.deepcopy(result)
        changed = copy.deepcopy(result)
        parent = changed
        for key in path[:-1]:
            parent = parent[key]
        if remove:
            del parent[path[-1]]
        else:
            parent[path[-1]] = value
        with self.assertRaises(AssertionError):
            checker(changed)
        self.assertEqual(result, before)

    def test_matrix_empty_trial_list_snapshot(self):
        for callback in (None, trusted_authentication_test_double):
            result = self.matrix(protocol(), [], callback)
            self.assertTrue(result["blockers"])
            for metric in result["metrics"].values():
                self.assertIsNone(metric["counts"])
                self.assertIsNone(metric["precision"])
                self.assertIsNone(metric["recall"])

    def test_matrix_partial_trial_list_snapshot(self):
        for callback in (None, trusted_authentication_test_double):
            for end in (1, -1):
                frozen = protocol()
                result = self.matrix(frozen, trials(frozen)[:end], callback)
                self.assertTrue(result["blockers"])

    def test_matrix_complete_synthetic_test_double_snapshot(self):
        frozen = protocol()
        result = self.matrix(frozen, trials(frozen), trusted_authentication_test_double)
        for metric in result["metrics"].values():
            self.assertIs(type(metric["counts"]), dict)
            self.assertIs(type(metric["precision"]), float)
            self.assertIs(type(metric["recall"]), float)

    def test_matrix_complete_without_callback_snapshot(self):
        frozen = protocol()
        result = self.matrix(frozen, trials(frozen))
        self.assertTrue(result["blockers"])
        for metric in result["metrics"].values():
            self.assertIsNone(metric["counts"])
            self.assertIsNone(metric["precision"])
            self.assertIsNone(metric["recall"])

    def test_matrix_undefined_denominators_remain_null(self):
        for fp, fn, precision, recall in ((0, 0, None, None),
                                           (1, 0, 0.0, None), (0, 1, None, 0.0)):
            frozen = protocol()
            records = trials(frozen)
            for record in records:
                record["findings"] = {"true_positive": 0, "false_positive": fp,
                                      "false_negative": fn}
            result = self.matrix(frozen, records, trusted_authentication_test_double)
            for metric in result["metrics"].values():
                self.assertEqual(metric["precision"], precision)
                self.assertEqual(metric["recall"], recall)

    def test_matrix_unknown_finding_counts_are_nullable(self):
        frozen = protocol()
        records = trials(frozen)
        records[0]["findings"]["false_negative"] = None
        result = self.matrix(frozen, records, trusted_authentication_test_double)
        for key in ("counts", "precision", "recall"):
            self.assertIsNone(result["metrics"]["A"][key])

    def test_matrix_zero_recall_shape_without_pinning_review_verdict(self):
        frozen = protocol()
        records = trials(frozen)
        for record in records:
            record["findings"] = {"true_positive": 0, "false_positive": 1, "false_negative": 1}
        result = self.matrix(frozen, records, trusted_authentication_test_double)
        for metric in result["metrics"].values():
            self.assertEqual(metric["precision"], 0.0)
            self.assertEqual(metric["recall"], 0.0)

    def test_matrix_snapshot_checker_negative_controls(self):
        frozen = protocol()
        result = self.matrix(frozen, trials(frozen), trusted_authentication_test_double)
        checker = self.assert_matrix_snapshot
        for key in MATRIX_KEYS:
            self.assert_mutation_rejected(checker, result, (key,), remove=True)
        wrong = {"protocol_sha256": 0, "trials_expected": True,
                 "authenticated_completed_trials": True, "blocked_attempts": True,
                 "unsafe_executed": True, "metrics": [], "release_review_ready": 1,
                 "stable_release_ready": 0, "blockers": {}, "notice": None}
        for key, value in wrong.items():
            self.assert_mutation_rejected(checker, result, (key,), value)
        self.assert_mutation_rejected(checker, result, ("stable_release_ready",), True)
        self.assert_mutation_rejected(checker, result, ("unexpected",), None)
        self.assert_mutation_rejected(checker, result, ("blockers",), [1])
        for arm in ("A", "B", "C"):
            self.assert_mutation_rejected(checker, result, ("metrics", arm), remove=True)
            for key in ("counts", "precision", "recall"):
                self.assert_mutation_rejected(checker, result, ("metrics", arm, key), remove=True)
            self.assert_mutation_rejected(checker, result, ("metrics", arm, "counts"), [])
            for key in COUNT_KEYS:
                self.assert_mutation_rejected(checker, result, ("metrics", arm, "counts", key), remove=True)
                self.assert_mutation_rejected(checker, result, ("metrics", arm, "counts", key), True)
            for key in ("precision", "recall"):
                self.assert_mutation_rejected(checker, result, ("metrics", arm, key), "0.5")
        blocked = self.matrix(protocol(), [])
        self.assert_mutation_rejected(checker, blocked, ("release_review_ready",), True)

    def test_claims_count_and_missing_revision_snapshots(self):
        for counts in ((0, 0, 0), (1, 1, 1), (15, 15, 15), (2, 3, 4)):
            self.claims(claims_metrics(counts))
        missing = claims_metrics()
        del missing["conditions"]["C"]["source_revision"]
        self.assertIsNone(self.claims(missing)["claim_only"]["condition_c_source_revision"])

    def test_claims_revision_value_and_type_passthrough(self):
        for value in ("a" * 40, "b" * 64, "feature/unfrozen", "", None,
                      42, True, 1.5, [], {"declared": "revision"}):
            self.claims(claims_metrics(revision=value))

    def test_claims_snapshot_checker_negative_controls(self):
        metrics = claims_metrics()
        result = self.claims(metrics)
        checker = lambda value: self.assert_claims_snapshot(value, metrics)
        for key in CLAIMS_KEYS:
            self.assert_mutation_rejected(checker, result, (key,), remove=True)
        wrong = {"release_decision": False, "stable_release_ready": 0,
                 "trusted_host_attestations_supplied": 0, "independent_human_signoff_verified": 0,
                 "protocol_minimum": [], "claim_only": [], "blockers": {}, "notice": 0}
        for key, value in wrong.items():
            self.assert_mutation_rejected(checker, result, (key,), value)
        for key in ("stable_release_ready", "trusted_host_attestations_supplied",
                    "independent_human_signoff_verified"):
            self.assert_mutation_rejected(checker, result, (key,), True)
        self.assert_mutation_rejected(checker, result, ("release_decision",), "APPROVED")
        self.assert_mutation_rejected(checker, result, ("unexpected",), None)
        self.assert_mutation_rejected(checker, result, ("blockers",), [1])
        for key in PROTOCOL_MINIMUM:
            self.assert_mutation_rejected(checker, result, ("protocol_minimum", key), remove=True)
            self.assert_mutation_rejected(checker, result, ("protocol_minimum", key), True)
            self.assert_mutation_rejected(checker, result, ("protocol_minimum", key), 0)
        for key in ("declared_session_count", "condition_c_source_revision", "scoring_status"):
            self.assert_mutation_rejected(checker, result, ("claim_only", key), remove=True)
        self.assert_mutation_rejected(checker, result, ("claim_only", "declared_session_count"), True)
        self.assert_mutation_rejected(checker, result, ("claim_only", "declared_session_count"), 0)
        self.assert_mutation_rejected(checker, result, ("claim_only", "condition_c_source_revision"), [])
        self.assert_mutation_rejected(checker, result, ("claim_only", "scoring_status"), "verified")

    def test_legacy_source_independence_with_negative_control(self):
        for name in ("evaluate_trial_matrix.py", "release_readiness_gate.py"):
            source = (EVALS / name).read_text(encoding="utf-8")
            self.assertNotIn("assurance_contract", source)
            with self.assertRaises(AssertionError):
                self.assertNotIn("assurance_contract", copy.deepcopy(source) + "\n# assurance_contract\n")


if __name__ == "__main__":
    unittest.main()
