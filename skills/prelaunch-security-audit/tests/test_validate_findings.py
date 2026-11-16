"""Synthetic adjudication and fix fraud cases; no real-model evaluation."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from validate_findings import digest, fingerprint, validate


def make_bundle(revision, source_hash):
    c = dict(id="F1", target="synthetic", revision=revision, component="api", path="auth.py",
             root_cause="Missing owner predicate", entry_point="GET /record", actor="tenant-a",
             resource="tenant-b-record", trust_boundary="tenant ownership", trace=["request -> query -> response"],
             defenses=["Session required but owner not checked"], prerequisites=[],
             demonstrated_impact="Reads another tenant's record", conditional_impacts=[], impact_basis="demonstrated",
             complexity=[], evidence_ids=["E1"], hunter={"identity":"agent", "context":"session"},
             invariants=[{"id":"I1","property":"Tenant reads only own records", "actors":["tenant-a","tenant-b"], "resources":["tenant-b-record"]}],
             minimal_fix="Add owner predicate", regression_plan="Assert cross-tenant denial", residual_unknowns=[])
    c["fingerprint"] = fingerprint(c)
    e = dict(id="E1", finding_id="F1", target="synthetic", revision=revision, actor="tenant-a",
             resource="tenant-b-record", kind="source_analysis", method="Trace route through database query",
             expected="Tenant predicate", observed="Query selects by record ID alone", result="observed",
             sources=[dict(path="auth.py",line_start=1,line_end=1,revision=revision,status="verified",sha256=source_hash)],
             command=None,exit_code=None,invariant_id="I1", failure_kind="none",test_definition_sha256=None,
             provenance=dict(operator="agent",timestamp="2026-11-14T00:00:00Z",environment="frozen-source",origin="source_inspection",reference="auth.py:1"))
    v = dict(id="V1",candidate_sha256=digest(c), profile="standard",verdict="confirmed",severity="high",confidence="high",verification_tier="source",
             reviewer=dict(identity="agent",context="session",independent=False),independence_ref=None,evidence_ids=["E1"],source_evidence_ids=["E1"],
             disproof_attempt="Traced middleware and query; no ownership filter",rationale="Authenticated cross-tenant path is reachable",next_check="",limitations=[])
    fix=dict(status="open",fixed_revision=None,changed_paths=[],diff_sha256=None,approval_ref=None,
             before_invariants_sha256=digest(c["invariants"]),after_invariants_sha256=digest(c["invariants"]),
             baseline_evidence_ids=[],post_evidence_ids=[],adjacent_cases=[],rollback="Revert scoped patch",residual_risk="Unpatched",high_impact=False,backup_ref=None,staging_evidence_ids=[])
    return dict(schema_version="0.5.0",target="synthetic",revision=revision,evidence=[e],findings=[dict(candidate=c,candidate_sha256=digest(c),verifications=[v],remediation=fix)])


class FindingValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(); cls.root=Path(cls.tmp.name)
        def git(*args):
            return subprocess.run(["git","-c","core.hooksPath=/dev/null","-C",str(cls.root),*args],check=True,capture_output=True,text=True).stdout.strip()
        git("init"); (cls.root/"auth.py").write_text("return database.get(record_id)\n")
        (cls.root/"link.py").symlink_to("auth.py");git("add","auth.py","link.py");git("-c","user.name=Fixture","-c","user.email=fixture@example.invalid","commit","-m","synthetic source")
        cls.rev=git("rev-parse","HEAD");cls.sha=hashlib.sha256((cls.root/"auth.py").read_bytes()).hexdigest()
        (cls.root/"auth.py").write_text("return database.get(record_id, owner=current_user)\n")
        git("add","auth.py");git("-c","user.name=Fixture","-c","user.email=fixture@example.invalid","commit","-m","synthetic fix")
        cls.fixed_rev=git("rev-parse","HEAD")
    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()
    def setUp(self): self.data=make_bundle(self.rev,self.sha)
    def check(self,**kwargs): return validate(self.data,source_root=self.root,**kwargs)
    def reseal(self):
        f=self.data['findings'][0];f['candidate']['fingerprint']=fingerprint(f['candidate']);f['candidate_sha256']=digest(f['candidate'])
        for v in f['verifications']:v['candidate_sha256']=f['candidate_sha256']
    def test_single_agent_static_confirmation(self):
        out=self.check();self.assertEqual(out['verdicts']['confirmed'],1);self.assertFalse(out['stable_release_ready']);self.assertEqual(out['unresolved_high_risk'],['F1'])
    def test_unknown_source_supports_needs_validation_only(self):
        e=self.data['evidence'][0];e['sources'][0]['status']='not_verified'
        with self.assertRaises(ValueError):self.check()
        v=self.data['findings'][0]['verifications'][0];v.update(verdict='needs_validation',next_check='Owner verifies route deployment',limitations=['Deployment unknown'])
        self.assertEqual(validate(self.data)['verdicts']['needs_validation'],1)
    def test_nonexistent_source_position_or_hash_rejected(self):
        for key,value in [('line_start',999),('sha256','f'*64),('path','missing.py')]:
            with self.subTest(key=key):
                self.setUp();self.data['evidence'][0]['sources'][0][key]=value
                with self.assertRaises(ValueError):self.check()
    def test_cross_finding_revision_target_actor_resource_evidence_rejected(self):
        for key,value in [('finding_id','F2'),('revision','f'*40),('target','foreign'),('actor','service-role'),('resource','different')]:
            with self.subTest(key=key):
                self.setUp();self.data['evidence'][0][key]=value
                with self.assertRaises(ValueError):self.check()
    def test_scanner_match_is_not_confirmation(self):
        self.data['evidence'][0]['kind']='scanner'
        with self.assertRaisesRegex(ValueError,'scanner'):self.check()
    def test_high_conditional_consequence_rejected(self):
        self.data['findings'][0]['candidate']['impact_basis']='conditional';self.reseal()
        with self.assertRaisesRegex(ValueError,'conditional'):self.check()
    def test_unknown_prerequisite_cannot_confirm(self):
        self.data['findings'][0]['candidate']['prerequisites']=[dict(claim='Publicly deployed',status='unknown',evidence_ids=[])];self.reseal()
        with self.assertRaisesRegex(ValueError,'prerequisite'):self.check()
    def test_unverified_prerequisite_source_cannot_confirm(self):
        e=copy.deepcopy(self.data['evidence'][0]);e['id']='E-prereq';e['sources'][0]['status']='not_verified';self.data['evidence'].append(e)
        self.data['findings'][0]['candidate']['prerequisites']=[dict(claim='Prerequisite exists',status='verified',evidence_ids=['E-prereq'])];self.reseal()
        with self.assertRaisesRegex(ValueError,'prerequisite lacks evidence'):self.check()
    def test_blank_provenance_or_invalid_timestamp_rejected(self):
        for key,value in [('operator','  '),('timestamp','made-up'),('timestamp','2026-11-14T00:00:00')]:
            self.setUp();self.data['evidence'][0]['provenance'][key]=value
            with self.assertRaises(ValueError):self.check()
    def test_complexity_requires_deep(self):
        self.data['findings'][0]['candidate']['complexity']=['race'];self.reseal()
        with self.assertRaisesRegex(ValueError,'deep'):self.check()
        self.data['findings'][0]['verifications'][0]['profile']='deep';self.check()
    def test_rejected_candidate_and_history_preserved(self):
        f=self.data['findings'][0];f['verifications'][0]['verdict']='rejected';f['verifications'][0]['rationale']='Effective middleware defeats hypothesis'
        previous=copy.deepcopy(self.data);v=copy.deepcopy(f['verifications'][0]);v['id']='V2';v['verdict']='confirmed';f['verifications'].append(v)
        self.assertTrue(self.check(previous=previous)['history_checked'])
        f['verifications'].pop(0)
        with self.assertRaisesRegex(ValueError,'history'):self.check(previous=previous)
    def test_candidate_or_evidence_rewrite_detected_with_checkpoint(self):
        previous=copy.deepcopy(self.data);self.data['findings'][0]['candidate']['root_cause']='Changed history';self.reseal()
        with self.assertRaisesRegex(ValueError,'overwritten'):self.check(previous=previous)
    def test_duplicate_ids_unknown_fields_and_dangling_proofs_rejected(self):
        for mutation in [lambda: self.data['evidence'].append(copy.deepcopy(self.data['evidence'][0])),lambda: self.data.update(approved=True),lambda: self.data['findings'][0]['verifications'][0]['evidence_ids'].append('nonexistent')]:
            self.setUp();mutation()
            with self.assertRaises(ValueError):self.check()
    def test_fake_independence_rejected(self):
        v=self.data['findings'][0]['verifications'][0];v['reviewer']['independent']=True
        with self.assertRaisesRegex(ValueError,'self-review'):self.check()
        v['reviewer'].update(identity='verifier',context='fresh');v['independence_ref']='host-1'
        with self.assertRaisesRegex(ValueError,'trusted host'):self.check()
    def test_independent_verifier_needs_host_source_reread(self):
        f=self.data['findings'][0];v=f['verifications'][0];v['reviewer'].update(identity='verifier',context='fresh',independent=True);v['independence_ref']='host-1'
        att=dict(kind='independent_verification',target='synthetic',revision=self.rev,finding_id='F1',candidate_sha256=f['candidate_sha256'],verification_sha256=digest(v),reviewer='verifier',context='fresh',context_separated=True,source_evidence_ids=['E1'],hunter_context='session',host_id='trusted-controller',log_ref='protected/log')
        self.check(host_attestations={'host-1':att});att['source_evidence_ids']=[]
        with self.assertRaises(ValueError):self.check(host_attestations={'host-1':att})
    def test_changed_independent_verdict_cannot_reuse_attestation(self):
        f=self.data['findings'][0];v=f['verifications'][0]
        v['reviewer'].update(identity='verifier',context='fresh',independent=True);v['independence_ref']='host-1'
        att=dict(kind='independent_verification',target='synthetic',revision=self.rev,finding_id='F1',
            candidate_sha256=f['candidate_sha256'],verification_sha256=digest(v),reviewer='verifier',
            context='fresh',context_separated=True,source_evidence_ids=['E1'],hunter_context='session',
            host_id='trusted-controller',log_ref='protected/log')
        self.check(host_attestations={'host-1':att})
        v['verdict']='rejected'
        with self.assertRaisesRegex(ValueError,'mismatched'):
            self.check(host_attestations={'host-1':att})

    def test_quality_failure_cannot_support_confirmation(self):
        self.data['evidence'][0]['failure_kind']='quality'
        with self.assertRaisesRegex(ValueError,'not security confirmation'):
            self.check()

    def test_inventory_links_cannot_dangle(self):
        self.data['findings'][0]['candidate']['inventory_ids']=['invented']
        self.reseal()
        with self.assertRaisesRegex(ValueError,'inventory'):
            self.check()

    def make_fix(self):
        f=self.data['findings'][0];fix=f['remediation'];fix.update(status='fixed_verified',fixed_revision=self.fixed_rev,changed_paths=['auth.py'],diff_sha256='a'*64,approval_ref='approval')
        base=copy.deepcopy(self.data['evidence'][0]);base.update(id='E-base',kind='runtime',result='fail',command='python -m unittest test_tenant',exit_code=1,sources=[],failure_kind='security_invariant',test_definition_sha256='c'*64);base['provenance'].update(origin='host_log',environment='disposable-fixture',reference='protected/baseline.log')
        post=copy.deepcopy(base);post.update(id='E-post',revision=self.fixed_rev,result='pass',exit_code=0,failure_kind='none')
        adj=copy.deepcopy(post);adj.update(id='E-adj',actor='tenant-b')
        self.data['evidence'] += [base,post,adj];fix.update(baseline_evidence_ids=['E-base'],post_evidence_ids=['E-post'],adjacent_cases=[dict(id='case-adj',invariant_id='I1',actor='tenant-b',resource='tenant-b-record',evidence_id='E-adj')])
        att = {'approval':dict(kind='remediation_approval',target='synthetic',finding_id='F1',candidate_sha256=f['candidate_sha256'],diff_sha256='a'*64,changed_paths=['auth.py'],high_impact=False,baseline_revision=self.rev,fixed_revision=self.fixed_rev,host_id='owner-host',log_ref='protected/approval')}
        for e in (base,post,adj):
            e['provenance']['reference']='protected/'+e['id']+'.log'
            att[e['provenance']['reference']]=dict(kind='executed_evidence',evidence_sha256=digest(e),target=e['target'],revision=e['revision'],finding_id=e['finding_id'],executed=True,authorized=True,host_id='trusted-controller',log_ref=e['provenance']['reference'])
        return att
    def refresh_execution(self, att):
        # Test helper simulates a trusted controller observing the mutated result;
        # these controller fixtures are never real runtime audit evidence.
        for e in self.data['evidence']:
            if e['result'] in {'pass','fail'}:
                att[e['provenance']['reference']].update(evidence_sha256=digest(e),revision=e['revision'],finding_id=e['finding_id'])
    def test_supported_fix_is_consistent_but_unauthenticated(self):
        att=self.make_fix();out=self.check(host_attestations=att);self.assertEqual(out['unresolved_high_risk'],[]);self.assertEqual(out['evidence_authenticity'],'not_authenticated')
    def test_fixed_without_approval_rejected(self):
        self.make_fix()
        with self.assertRaisesRegex(ValueError,'trusted host'):self.check()
    def test_adjacent_failure_or_missing_case_blocks_fix(self):
        att=self.make_fix();self.data['evidence'][-1].update(result='fail',exit_code=1,failure_kind='security_invariant')
        self.refresh_execution(att)
        with self.assertRaisesRegex(ValueError,'adjacent'):self.check(host_attestations=att)
        self.data['evidence'][-1].update(result='pass',exit_code=0,failure_kind='none');self.data['findings'][0]['remediation']['adjacent_cases']=[]
        self.refresh_execution(att)
        with self.assertRaisesRegex(ValueError,'adjacent'):self.check(host_attestations=att)
    def test_baseline_build_error_is_not_security_regression(self):
        att=self.make_fix();self.data['evidence'][1]['failure_kind']='quality'
        self.refresh_execution(att)
        with self.assertRaisesRegex(ValueError,'baseline'):self.check(host_attestations=att)
    def test_changed_assertion_or_invariant_cannot_green_fix(self):
        att=self.make_fix();self.data['evidence'][2]['test_definition_sha256']='d'*64
        self.refresh_execution(att)
        with self.assertRaisesRegex(ValueError,'must match'):self.check(host_attestations=att)
        self.data['evidence'][2]['test_definition_sha256']='c'*64;self.data['findings'][0]['remediation']['after_invariants_sha256']='f'*64
        self.refresh_execution(att)
        with self.assertRaisesRegex(ValueError,'invariants'):self.check(host_attestations=att)
    def test_cross_finding_fix_proof_and_stale_post_revision(self):
        for key,value in [('finding_id','F2'),('revision',self.rev),('actor','service-role')]:
            self.setUp();att=self.make_fix();self.data['evidence'][2][key]=value
            with self.assertRaises(ValueError):self.check(host_attestations=att)
    def test_accepted_risk_remains_blocker(self):
        self.data['findings'][0]['remediation']['status']='accepted_risk';self.assertEqual(self.check()['unresolved_high_risk'],['F1'])
    def test_path_traversal_and_symlink_rejected(self):
        for path in ['../auth.py','/auth.py','dir/../../auth.py']:
            self.setUp();self.data['findings'][0]['candidate']['path']=path;self.reseal()
            with self.assertRaises(ValueError):self.check()
        self.setUp();self.data['evidence'][0]['sources'][0]['path']='link.py'
        with self.assertRaises(ValueError):self.check()
    def test_executed_pass_with_no_command_or_nonzero_exit_rejected(self):
        att=self.make_fix();self.data['evidence'][2]['command']=None
        with self.assertRaisesRegex(ValueError,'PASS'):self.check(host_attestations=att)
    def test_forged_host_log_label_cannot_verify_fix(self):
        att=self.make_fix()
        for key in list(att):
            if key != 'approval': del att[key]
        with self.assertRaisesRegex(ValueError,'executed evidence requires trusted host'):self.check(host_attestations=att)
    def test_modified_host_result_digest_rejected(self):
        att=self.make_fix();self.data['evidence'][2]['observed']='Altered claim'
        with self.assertRaisesRegex(ValueError,'mismatched executed evidence'):self.check(host_attestations=att)
    def test_fix_approval_cannot_be_replayed_to_other_revision(self):
        att=self.make_fix();att['approval']['fixed_revision']='f'*40
        with self.assertRaisesRegex(ValueError,'mismatched remediation approval'):self.check(host_attestations=att)
    def test_execution_without_host_authorization_rejected(self):
        att=self.make_fix();att['protected/E-post.log']['authorized']=False
        with self.assertRaisesRegex(ValueError,'mismatched executed evidence'):self.check(host_attestations=att)
    def test_high_impact_fix_requires_backup_and_stage(self):
        att=self.make_fix();self.data['findings'][0]['remediation']['high_impact']=True;att['approval']['high_impact']=True
        with self.assertRaisesRegex(ValueError,'backup'):self.check(host_attestations=att)


if __name__=='__main__': unittest.main()
