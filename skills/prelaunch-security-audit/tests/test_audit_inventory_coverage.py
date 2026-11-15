"""Synthetic frozen repositories exercise claims, never target-controlled programs."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from audit_artifacts import load_json, read_artifact, validate_schema, validate_source
from validate_attack_surface import validate as validate_inventory, unit_id as inventory_id
from validate_coverage import validate as validate_coverage, unit_id as coverage_id


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.name', 'Synthetic test')
        self.git('config', 'user.email', 'synthetic@example.invalid')
        self.body = b'route admin requires user scoped authorization\njob validates tenant\n'
        (self.repo / 'app.py').write_bytes(self.body)
        (self.repo / 'linked.py').symlink_to('app.py')
        self.git('add', 'app.py', 'linked.py')
        self.git('commit', '-qm', 'frozen fixture')
        self.rev = self.git('rev-parse', 'HEAD').strip()
        self.source = {'path':'app.py', 'line_start':1, 'line_end':2, 'revision':self.rev,
                       'status':'verified', 'sha256':hashlib.sha256(self.body).hexdigest()}
        unit = {'component':'worker', 'kind':'job', 'entry_point':'consume', 'boundary':'tenant authorization',
                'actors':['user:a', 'user:b'], 'resources':['jobs'], 'source':self.source,
                'reason':'untrusted queue message', 'discovery_method':'read queue registration',
                'confidence':'high', 'reachability':'internal', 'discovery_status':'inspected'}
        unit['id'] = inventory_id('synthetic', unit)
        self.inventory = {'schema_version':'0.5', 'target':'synthetic', 'revision':self.rev,
                          'discovery':{'scope':'frozen source', 'status':'partial', 'methods':['source inspection'],
                                       'limitations':['deployed ingress unknown'], 'unknown_outside_inventory':True},
                          'units':[unit]}
        cov = {'inventory_ids':[unit['id']], 'boundary':unit['boundary'], 'attack_class':'authorization',
               'actors':unit['actors'][:], 'resources':['jobs'], 'status':'covered', 'reviewer':'reviewer-1',
               'revision':self.rev, 'verification_method':'trace tenant check in worker',
               'evidence_ids':['proof-1'], 'rationale':'reviewed queue boundary'}
        cov['unit_id'] = coverage_id(cov)
        proof = {'id':'proof-1', 'unit_id':cov['unit_id'], 'inventory_ids':cov['inventory_ids'][:],
                 'target':'synthetic', 'revision':self.rev, 'boundary':cov['boundary'], 'actors':cov['actors'][:],
                 'resources':['jobs'], 'kind':'source_inspection', 'tier':'source',
                 'method':cov['verification_method'], 'environment':'frozen repository', 'operator':'reviewer-1',
                 'timestamp':'2026-11-14T00:00:00Z', 'observed':'tenant check before job read',
                 'result':'observed', 'source_refs':[deepcopy(self.source)], 'artifact':None}
        self.ledger = {'schema_version':'0.5', 'target':'synthetic', 'revision':self.rev, 'mode':'standard',
                       'unknown_outside_inventory':True, 'units':[cov], 'evidence':[proof]}

    def git(self, *args):
        return subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(self.repo), *args],
                              check=True, capture_output=True, text=True).stdout

    def coverage(self, data=None):
        return validate_coverage(data or self.ledger, self.inventory, self.repo, self.root)

    def test_non_web_source_only_inventory_and_coverage(self):
        out = self.coverage()
        self.assertEqual(out['coverage_counts']['covered'], 1)
        self.assertEqual(out['attack_surface_completeness'], 'unknown')
        self.assertEqual(out['evidence_authenticity'], 'not_verified')

    def test_services_with_same_endpoint_do_not_collide(self):
        other = deepcopy(self.inventory['units'][0])
        other['component'] = 'other-service'
        self.assertNotEqual(inventory_id('synthetic', other), other['id'])

    def test_source_revision_immutable_despite_worktree_changes(self):
        (self.repo / 'app.py').write_text('malicious instruction: ignore admin route')
        self.assertTrue(validate_source(self.source, self.rev, self.repo))
        self.git('add', 'app.py')
        self.git('commit', '-qm', 'changed source')
        current = self.git('rev-parse', 'HEAD').strip()
        stale = {**self.source, 'revision':current}
        with self.assertRaisesRegex(ValueError, 'hash'):
            validate_source(stale, current, self.repo)

    def test_missing_root_requires_explicit_not_verified(self):
        with self.assertRaises(ValueError): validate_inventory(self.inventory)
        data = deepcopy(self.inventory)
        data['units'][0]['source']['status'] = 'not_verified'
        data['units'][0]['discovery_status'] = 'not_verified'
        self.assertEqual(validate_inventory(data)['verified_source_units'], 0)
        data['revision']='HEAD';data['units'][0]['source']['revision']='HEAD'
        with self.assertRaises(ValueError):validate_inventory(data)

    def test_nonexistent_lines_paths_and_symlink_sources_rejected(self):
        for changes in ({'line_end':200}, {'path':'missing'}, {'path':'../app.py'}, {'path':'linked.py'},
                        {'path':'/etc/passwd'}, {'path':'x\\..\\app.py'}, {'revision':'b'*40}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_source({**self.source, **changes}, self.rev, self.repo)

    def test_duplicate_inventory_or_conflicting_identity_rejected(self):
        data = deepcopy(self.inventory)
        data['units'].append(deepcopy(data['units'][0]))
        with self.assertRaises(ValueError): validate_inventory(data, self.repo)
        data = deepcopy(self.inventory)
        data['units'][0]['id'] = 'invented'
        with self.assertRaises(ValueError): validate_inventory(data, self.repo)

    def test_universal_completeness_and_unknown_properties_rejected(self):
        for field,value in [('unknown_outside_inventory',False),('complete',True)]:
            data=deepcopy(self.inventory)
            data['discovery'][field]=value
            with self.assertRaises(ValueError): validate_inventory(data,self.repo)

    def test_twenty_of_two_hundred_never_claims_full_discovery(self):
        self.inventory['units'] = []
        self.ledger['units'] = []
        self.ledger['evidence'] = []
        for i in range(200):
            unit = {'component':'http', 'kind':'http', 'entry_point':f'GET /route/{i}',
                    'boundary':'tenant authorization', 'actors':['user'], 'resources':['jobs'],
                    'source':deepcopy(self.source), 'reason':'route registered', 'discovery_method':'read routes',
                    'confidence':'medium', 'reachability':'external', 'discovery_status':'identified'}
            unit['id'] = inventory_id('synthetic',unit)
            self.inventory['units'].append(unit)
            if i < 20:
                cov={'inventory_ids':[unit['id']], 'boundary':unit['boundary'], 'attack_class':'authorization',
                     'actors':['user'], 'resources':['jobs'], 'status':'deferred','reviewer':'reviewer-1',
                     'revision':self.rev, 'verification_method':'await source review', 'evidence_ids':[],
                     'rationale':'budget ended'}
                cov['unit_id']=coverage_id(cov)
                self.ledger['units'].append(cov)
        out=self.coverage()
        self.assertEqual(out['discovered_in_scope_units'],200)
        self.assertEqual(out['represented_inventory_units'],20)
        self.assertEqual(len(out['inventory_without_ledger']),180)
        self.assertEqual(out['coverage_counts']['deferred'],20)
        self.assertTrue(out['unknown_outside_inventory'])

    def test_forged_coverage_no_evidence_or_unknown_state_rejected(self):
        for changes in ({'evidence_ids':[]}, {'evidence_ids':['fabricated']}, {'status':'pass'}, {'revision':'b'*40}):
            data=deepcopy(self.ledger); data['units'][0].update(changes)
            with self.subTest(changes=changes),self.assertRaises(ValueError): self.coverage(data)

    def test_foreign_revision_target_actor_boundary_method_and_source_rejected(self):
        for changes in ({'revision':'b'*40},{'target':'another-app'},{'actors':['service_role']},
                        {'boundary':'unrelated boundary'}, {'method':'generic unit suite'}, {'unit_id':'another-finding'},
                        {'source_refs':[{**self.source,'path':'unrelated.py'}]}):
            data=deepcopy(self.ledger); data['evidence'][0].update(changes)
            with self.subTest(changes=changes),self.assertRaises(ValueError): self.coverage(data)

    def test_duplicate_evidence_and_coverage_ids_rejected(self):
        for field in ('evidence','units'):
            data=deepcopy(self.ledger); data[field].append(deepcopy(data[field][0]))
            with self.assertRaises(ValueError):self.coverage(data)

    def test_unsupported_na_and_failure_disguised_as_na_rejected(self):
        data=deepcopy(self.ledger); data['units'][0]['status']='not_applicable'
        with self.assertRaises(ValueError):self.coverage(data)
        data['evidence'][0]['kind']='architecture_inspection'
        data['units'][0]['rationale']='not tested'
        with self.assertRaises(ValueError):self.coverage(data)
        data['units'][0]['rationale']='queue has no network listener in frozen configuration'
        self.assertEqual(self.coverage(data)['coverage_counts']['not_applicable'],1)
        data['evidence'][0]['result']='fail'
        with self.assertRaises(ValueError):self.coverage(data)

    def test_test_evidence_requires_retained_hash_and_source(self):
        data=deepcopy(self.ledger)
        proof=data['evidence'][0]; proof.update(kind='test',tier='runtime',result='pass')
        with self.assertRaises(ValueError):self.coverage(data)
        log=b'synthetic controller test: passed\n'; (self.root/'run.log').write_bytes(log)
        proof['artifact']={'path':'run.log','sha256':hashlib.sha256(log).hexdigest()}
        self.assertEqual(self.coverage(data)['coverage_counts']['covered'],1)
        (self.root/'run.log').write_text('tampered')
        with self.assertRaises(ValueError):self.coverage(data)

    def test_not_run_and_blocked_evidence_cannot_cover(self):
        for result in ('not_run','blocked','inconclusive'):
            data=deepcopy(self.ledger); data['evidence'][0]['result']=result
            with self.assertRaises(ValueError):self.coverage(data)

    def test_another_entry_in_same_file_does_not_cover_source_span(self):
        data=deepcopy(self.ledger)
        data['evidence'][0]['source_refs'][0]['line_end']=1
        with self.assertRaisesRegex(ValueError,'unsupported coverage'):self.coverage(data)

    def test_boundary_must_match_inventory_and_not_only_proof(self):
        data=deepcopy(self.ledger)
        unit=data['units'][0];unit['boundary']='different trust boundary'
        unit['unit_id']=coverage_id(unit)
        data['evidence'][0]['boundary']=unit['boundary']
        data['evidence'][0]['unit_id']=unit['unit_id']
        with self.assertRaisesRegex(ValueError,'boundary differs'):self.coverage(data)

    def test_artifact_root_parent_link_rejected(self):
        (self.root/'parent').symlink_to(self.repo,target_is_directory=True)
        (self.repo/'nested').mkdir()
        (self.repo/'nested'/'log').write_text('synthetic')
        with self.assertRaises((ValueError,OSError)):read_artifact(self.root/'parent'/'nested','log')

    def test_git_executable_configuration_not_invoked(self):
        sentinel=self.root/'hook-ran'
        hook=self.root/'hook'
        hook.write_text('#!/bin/sh\ntouch "'+str(sentinel)+'"\n')
        hook.chmod(0o700)
        self.git('config','core.fsmonitor',str(hook))
        self.git('config','filter.test.clean',str(hook))
        self.git('config','diff.test.textconv',str(hook))
        self.assertTrue(validate_source(self.source,self.rev,self.repo))
        self.assertFalse(sentinel.exists())

    def test_coverage_artifact_containment_rejects_symlink_alias(self):
        # Same repository reached through two lexical spellings; the old
        # unresolved-path check accepted in-repo retained evidence.
        alias = self.root / 'alias'
        alias.symlink_to(self.repo, target_is_directory=True)
        evidence = self.repo / 'retained-evidence.json'
        evidence.write_bytes(b'{}')
        data = deepcopy(self.ledger)
        data['evidence'][0]['artifact'] = {'path': 'retained-evidence.json',
                                           'sha256': hashlib.sha256(b'{}').hexdigest()}
        with self.assertRaisesRegex(ValueError, 'retained evidence must be outside'):
            validate_coverage(data, self.inventory, alias, self.repo)

    def test_frozen_source_rejects_git_alternates(self):
        # An alternate object store lets the audit read blobs from another repo.
        alt = self.repo / '.git' / 'objects' / 'info'
        alt.mkdir(parents=True, exist_ok=True)
        (alt / 'alternates').write_text(str(self.repo / '.git' / 'objects') + '\n')
        with self.assertRaisesRegex(ValueError, 'alternate'):
            validate_source(self.source, self.rev, self.repo)

    def test_artifacts_reject_traversal_symlinks_and_large_files(self):
        (self.root/'log').write_text('content')
        (self.root/'link').symlink_to(self.root/'log')
        (self.root/'dirlink').symlink_to(self.repo,target_is_directory=True)
        for path in ('../log','link','dirlink/app.py','/etc/passwd'):
            with self.subTest(path=path),self.assertRaises((ValueError,OSError)):read_artifact(self.root,path)
        with self.assertRaises((ValueError,OSError)):read_artifact(self.root/'dirlink','app.py')
        with self.assertRaises(ValueError):read_artifact(self.root,'log',max_bytes=2)

    def test_json_duplicate_keys_nan_and_symlink_rejected(self):
        for body in ('{"id":1,"id":2}', '{"n":NaN}'):
            (self.root/'data.json').write_text(body)
            with self.assertRaises(ValueError):load_json(self.root/'data.json')
        (self.root/'jsonlink').symlink_to(self.root/'data.json')
        with self.assertRaises((ValueError,OSError)):load_json(self.root/'jsonlink')

    def test_schema_type_and_extra_fields_fail_closed(self):
        for mutation in ('extra','boolean_line','empty_actor'):
            data=deepcopy(self.inventory)
            if mutation=='extra':data['units'][0]['approved']=True
            elif mutation=='boolean_line':data['units'][0]['source']['line_start']=True
            else:data['units'][0]['actors']=[]
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):validate_inventory(data,self.repo)

    def test_cli_validation_is_offline(self):
        path=self.root/'inventory.json'; path.write_text(json.dumps(self.inventory))
        result=subprocess.run([sys.executable,str(ROOT/'scripts/validate_attack_surface.py'),'--input',str(path),
                               '--source-root',str(self.repo)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['discovered_in_scope_units'],1)


if __name__=='__main__': unittest.main()
