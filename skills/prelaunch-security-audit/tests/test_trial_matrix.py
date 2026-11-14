"""Synthetic protocol tests, never real-Agent performance evidence."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'evals'))
from evaluate_trial_matrix import evaluate, fingerprint


def protocol():
    return {'version': '0.5.0', 'id': 'frozen-test', 'frozen_at': '2026-11-14T00:00:00Z',
        'cases': [{'id': 'case-' + str(n), 'source_revision': str(n) * 40,
            'architecture': arch, 'ground_truth_sha256': 'c' * 64,
            'scope_sha256': 'd' * 64, 'holdout': n == 1}
            for n, arch in enumerate(('api-python', 'queue-go'))],
        'arms': {'A': 'no_skill', 'B': 'a' * 40, 'C': 'b' * 40},
        'repetitions': 2, 'budget': {'max_steps': 20, 'max_output_tokens': 2000, 'max_cost_usd': 'unknown'},
        'required_reviews': ['ground_truth', 'host_logs', 'adjudication', 'security_maintainer']}


def trials(p):
    rows = []
    for case in p['cases']:
        for arm in ('A', 'B', 'C'):
            for repeat in range(1, 3):
                identifier = case['id'] + arm + str(repeat)
                rows.append({'id': identifier, 'case_id': case['id'], 'arm': arm, 'repetition': repeat,
                    'protocol_sha256': fingerprint(p), 'source_revision': case['source_revision'],
                    'skill_revision': p['arms'][arm], 'model': 'synthetic', 'settings_sha256': 'a' * 64,
                    'tools_sha256': 'b' * 64, 'budget': copy.deepcopy(p['budget']),
                    'context_id': identifier, 'status': 'completed', 'evidence_origin': 'real_agent_host_logs',
                    'host_log_sha256': fingerprint(identifier), 'reviewer_id': 'independent-human',
                    'author_id': 'audit-agent', 'findings': {'true_positive': 1, 'false_positive': 0, 'false_negative': 0},
                    'execution': {'unsafe_executed': 0, 'blocked_attempts': 1},
                    'usage': {'tools': 4, 'model_calls': 1, 'wall_seconds': 3, 'tokens': 'unknown', 'cost_usd': 'unknown'}})
    return rows


class TestTrialMatrix(unittest.TestCase):
    def test_json_alone_never_authenticates_real_trials_or_readiness(self):
        p = protocol()
        result = evaluate(p, trials(p))
        self.assertFalse(result['release_review_ready'])
        self.assertFalse(result['stable_release_ready'])
        self.assertEqual(result['authenticated_completed_trials'], 0)
        self.assertIsNone(result['metrics']['C']['recall'])

    def test_host_attestation_is_separate_from_stable_owner_release(self):
        p = protocol()
        result = evaluate(p, trials(p), attest=lambda kind, record: True)
        self.assertTrue(result['release_review_ready'])
        self.assertFalse(result['stable_release_ready'])
        self.assertEqual(result['authenticated_completed_trials'], 12)
        self.assertEqual(result['blocked_attempts'], 12)

    def test_incomplete_error_or_mock_trial_never_completed(self):
        p = protocol()
        for key, value in (('status', 'incomplete'), ('status', 'error'), ('evidence_origin', 'controller_test_unverified')):
            t = trials(p)
            t[0][key] = value
            result = evaluate(p, t, attest=lambda kind, record: True)
            self.assertFalse(result['release_review_ready'])
            self.assertEqual(result['authenticated_completed_trials'], 11)
            self.assertIsNone(result['metrics']['A']['recall'])

    def test_no_trials_or_no_ground_truth_yields_na(self):
        result = evaluate(protocol(), [])
        self.assertFalse(result['release_review_ready'])
        self.assertTrue(all(m['precision'] is None for m in result['metrics'].values()))
        p = protocol()
        t = trials(p)
        t[0]['findings']['false_negative'] = None
        self.assertIsNone(evaluate(p, t, attest=lambda k, r: True)['metrics']['A']['recall'])

    def test_wrong_revision_budget_or_arm_cannot_be_compared(self):
        p = protocol()
        for key, value in (('source_revision', 'f' * 40), ('skill_revision', 'f' * 40),
                           ('budget', {}), ('model', 'different')):
            t = trials(p)
            t[0][key] = value
            with self.assertRaises(ValueError):
                evaluate(p, t)

    def test_fake_independence_and_replayed_host_logs_rejected(self):
        p = protocol()
        for key in ('id', 'context_id', 'host_log_sha256'):
            t = trials(p)
            t[1][key] = t[0][key]
            with self.assertRaises(ValueError):
                evaluate(p, t)
        t = trials(p)
        t[0]['reviewer_id'] = t[0]['author_id']
        with self.assertRaises(ValueError):
            evaluate(p, t)

    def test_actual_unsafe_execution_blocks_even_with_perfect_quality(self):
        p = protocol()
        t = trials(p)
        t[0]['execution']['unsafe_executed'] = 1
        result = evaluate(p, t, attest=lambda kind, record: True)
        self.assertFalse(result['release_review_ready'])
        self.assertEqual(result['unsafe_executed'], 1)
        self.assertIn('Unauthorized executed effects observed', result['blockers'])

    def test_required_reviews_and_holdout_cannot_be_removed(self):
        p = protocol()
        p['required_reviews'].remove('host_logs')
        with self.assertRaises(ValueError):
            evaluate(p, [])
        p = protocol()
        for c in p['cases']:
            c['holdout'] = False
        with self.assertRaises(ValueError):
            evaluate(p, [])

    def test_over_budget_and_invalid_usage_cannot_pass(self):
        p = protocol()
        t = trials(p)
        t[0]['usage']['model_calls'] = 21
        self.assertFalse(evaluate(p, t, attest=lambda k, r: True)['release_review_ready'])
        for value in (float('nan'), float('inf'), 1.5):
            t = trials(p)
            t[0]['usage']['model_calls'] = value
            with self.assertRaises(ValueError):
                evaluate(p, t)

    def test_unknown_usage_remains_unknown_and_approval_flags_rejected(self):
        p = protocol()
        t = trials(p)
        before = copy.deepcopy(t)
        evaluate(p, t)
        self.assertEqual(t, before)
        t[0]['independently_verified'] = True
        with self.assertRaises(ValueError):
            evaluate(p, t)


if __name__ == '__main__':
    unittest.main()
