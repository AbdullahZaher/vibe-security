"""Integration of real validators with synthetic report artifacts."""
import hashlib
import json
from pathlib import Path
import unittest
import test_audit_inventory_coverage as inventory_fixtures
from test_validate_findings import make_bundle
from test_validate_budget import budget
from validate_findings import digest, fingerprint
from render_report import render

ROOT = Path(__file__).resolve().parents[1]


class ReportArtifactTests(unittest.TestCase):
    def setUp(self):
        self.fixture = inventory_fixtures.ArtifactTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.data = json.loads((ROOT / 'assets/findings.example.json').read_text())
        self.data['scope'].update(project='synthetic', revision=self.fixture.rev)
        self.data['attack_surface'] = self.fixture.inventory
        self.data['coverage_ledger'] = self.fixture.ledger

    def render(self):
        return render(self.data, source_root=self.fixture.repo)

    def test_actual_inventory_and_coverage_validators_render_unknown_completeness(self):
        output = self.render()
        self.assertIn('Discovered in-scope inventory units: 1', output)
        self.assertIn('covered: 1', output)
        self.assertIn('Attack-surface completeness: unknown', output)
        self.assertIn('deployed ingress unknown', output)

    def test_real_finding_validator_propagates_high_risk_blocker(self):
        bundle = make_bundle(self.fixture.rev, self.fixture.source['sha256'])
        finding = bundle['findings'][0]
        finding['candidate']['path'] = 'app.py'
        finding['candidate']['fingerprint'] = fingerprint(finding['candidate'])
        finding['candidate_sha256'] = digest(finding['candidate'])
        finding['verifications'][0]['candidate_sha256'] = finding['candidate_sha256']
        bundle['evidence'][0]['sources'][0]['path'] = 'app.py'
        self.data['finding_bundle'] = bundle
        output = self.render()
        self.assertIn('**BLOCK LAUNCH**', output)
        self.assertIn('F1: confirmed; severity high; confidence high; tier source', output)
        self.assertIn('Rollback:', output)

    def test_invalid_coverage_never_renders(self):
        self.data['coverage_ledger']['units'][0]['evidence_ids'] = ['invented']
        with self.assertRaises(ValueError): self.render()

    def test_unavailable_source_is_not_silently_verified(self):
        with self.assertRaises(ValueError): render(self.data)

    def test_quick_ledger_without_budget_cannot_claim_launch(self):
        self.data['coverage_ledger']['mode'] = 'quick'
        with self.assertRaisesRegex(ValueError, 'Quick PR'): self.render()

    def test_budget_cannot_hide_deferred_units(self):
        b = budget()
        b.update(revision=self.fixture.rev, profile='standard')
        self.data['audit_budget'] = b
        with self.assertRaisesRegex(ValueError, 'deferred'): self.render()

    def test_legacy_all_clear_cannot_hide_blocked_ledger(self):
        self.data['launch_recommendation'] = 'no blockers found in tested scope'
        self.data['verification_log'] = []
        for row in self.data['controls']:
            row.update(status='pass',test_result='pass',test_method='targeted check',
                evidence='test.log',evidence_revision=self.fixture.rev,evidence_tier='build',
                verification_ref='V-'+row['id'])
            self.data['verification_log'].append(dict(id=row['verification_ref'],control_id=row['id'],
                revision=self.fixture.rev,result='pass',method='targeted check',environment='fixture',observed='pass'))
        self.assertIn('CONDITIONAL LAUNCH', self.render())
        self.data['coverage_ledger']['units'][0].update(status='blocked',evidence_ids=[])
        self.data['coverage_ledger']['evidence'] = []
        self.assertIn('CONDITIONAL LAUNCH', self.render())

    def test_failed_executed_coverage_check_prevents_all_clear(self):
        proof = self.fixture.ledger['evidence'][0]
        proof.update(kind='test', tier='runtime', result='fail')
        log = b'synthetic tenant isolation test: FAILED\n'
        (self.fixture.root / 'run.log').write_bytes(log)
        proof['artifact'] = {'path': 'run.log', 'sha256': hashlib.sha256(log).hexdigest()}
        self.data['launch_recommendation'] = 'no blockers found in tested scope'
        self.data['verification_log'] = []
        for row in self.data['controls']:
            row.update(status='pass', test_result='pass', test_method='targeted check',
                evidence='test.log', evidence_revision=self.fixture.rev, evidence_tier='build',
                verification_ref='V-' + row['id'])
            self.data['verification_log'].append(dict(
                id=row['verification_ref'], control_id=row['id'], revision=self.fixture.rev,
                result='pass', method='targeted check', environment='fixture', observed='pass'))
        output = render(self.data, source_root=self.fixture.repo, artifact_root=self.fixture.root)
        self.assertIn('CONDITIONAL LAUNCH', output)
        self.assertIn('Executed checks recorded as failed: 1', output)

    def test_budget_render_and_quick_has_no_launch_recommendation(self):
        b = budget()
        b.update(revision=self.fixture.rev, profile='standard', deferred_unit_ids=[])
        self.data['audit_budget'] = b
        self.assertIn('Profile: standard', self.render())
        self.data['audit_budget']['profile'] = 'quick'
        with self.assertRaisesRegex(ValueError, 'Quick PR'): self.render()


if __name__ == '__main__': unittest.main()
