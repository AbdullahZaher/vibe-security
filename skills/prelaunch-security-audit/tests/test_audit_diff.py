"""Immutable synthetic Git snapshots; never execute repository-controlled code."""
import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_diff import analyze, git_changes, _bounded_metadata

A, B = 'a' * 40, 'b' * 40


def graph():
    return {'schema_version':'0.5.0', 'target':'synthetic', 'revision':B,
        'baseline_revision':A, 'graph_complete':True, 'runtime_drift':'unchanged',
        'units':[{'id':uid, 'paths':[path], 'depends_on':deps,
                  'runtime_sensitive':False, 'prior':True, 'deferred':False}
                 for uid,path,deps in [('auth','auth.py',[]), ('route','route.py',['auth']),
                                      ('job','job.py',['route']), ('cli','cli.py',[])]]}


def snapshot(paths):
    return {'revision':B,'baseline_revision':A,'baseline_available':True,
            'ancestry':'ancestor','changes':[{'status':'M','paths':[p]} for p in paths]}


class TestImpact(unittest.TestCase):
    def test_shared_auth_invalidates_transitive_dependents(self):
        result = analyze(snapshot(['auth.py']), graph())
        units = {u['id']:u for u in result['units']}
        self.assertEqual(units['job']['change_state'], 'changed')
        self.assertEqual(units['cli']['change_state'], 'unchanged')
        self.assertTrue(all(u['revalidation_required'] for u in result['units']))
        self.assertTrue(all(u['coverage_status']=='unassessed' for u in result['units']))

    def test_manifest_change_invalidates_even_unlisted_consumers(self):
        result = analyze(snapshot(['backend/requirements.txt']), graph())
        self.assertTrue(all(u['change_state']=='changed' for u in result['units']))

    def test_missing_baseline_and_incomplete_graph_never_reuse_pass(self):
        for key in ['baseline_available','graph_complete']:
            snap, data = snapshot([]), graph()
            (snap if key=='baseline_available' else data)[key] = False
            self.assertTrue(all(u['change_state']=='changed' for u in analyze(snap,data)['units']))

    def test_unknown_runtime_and_deferred_new_states(self):
        data = graph()
        data['runtime_drift']='unknown'
        data['units'][0]['runtime_sensitive']=True
        data['units'][1]['deferred']=True
        data['units'][3]['prior']=False
        units = analyze(snapshot([]),data)['units']
        self.assertEqual([u['change_state'] for u in units],['changed','deferred','changed','new'])
        self.assertEqual(units[1]['coverage_status'],'deferred')

    def test_revision_duplicate_dangling_and_escape_rejected(self):
        mutations = [lambda d:d.update(revision=A),
            lambda d:d['units'].append(copy.deepcopy(d['units'][0])),
            lambda d:d['units'][0].update(depends_on=['missing']),
            lambda d:d['units'][0].update(paths=['../private']),
            lambda d:d.update(complete_attack_surface=True)]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                data=graph(); mutate(data)
                with self.assertRaises(ValueError): analyze(snapshot([]),data)

    def test_dependency_cycles_terminate(self):
        data=graph(); data['units'][0]['depends_on']=['job']
        self.assertEqual(analyze(snapshot(['job.py']),data)['units'][0]['change_state'],'changed')


class TestGitSnapshots(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.git('init','-q'); self.git('config','user.name','Synthetic'); self.git('config','user.email','fixture@example.invalid')
        (self.root/'auth.py').write_text('allow = False\n')
        self.git('add','.'); self.git('commit','-qm','base')
        self.base=self.git('rev-parse','HEAD').strip()

    def git(self,*args):
        return subprocess.run(['git','-C',str(self.root),*args],check=True,capture_output=True,text=True).stdout

    def test_rename_and_missing_baseline(self):
        self.git('mv','auth.py','policy.py'); self.git('commit','-qm','rename')
        result=git_changes(self.root,self.base)
        self.assertEqual(result['changes'],[{'status':'R100','paths':['auth.py','policy.py']}])
        self.assertFalse(git_changes(self.root,'1'*40)['baseline_available'])

    def test_no_external_diff_textconv_or_hooks(self):
        marker=self.root/'executed'
        hook=self.root/'hostile.sh'; hook.write_text('#!/bin/sh\ntouch '+str(marker)+'\n'); hook.chmod(0o755)
        self.git('config','diff.external',str(hook))
        self.git('config','diff.evil.textconv',str(hook))
        (self.root/'.gitattributes').write_text('*.py diff=evil\n')
        (self.root/'auth.py').write_text('allow = True\n')
        self.git('add','.'); self.git('commit','-qm','change')
        self.git('config','core.hooksPath',str(self.root))
        result=git_changes(self.root,self.base)
        self.assertTrue(result['changes']); self.assertFalse(marker.exists())

    def test_metadata_output_is_bounded_before_accumulation(self):
        # This is vetted controller code, never a target-owned executable.
        with self.assertRaisesRegex(ValueError, 'exceeds limit'):
            _bounded_metadata([sys.executable, '-c', 'print("x"*10000)'], {}, max_bytes=100)

    def test_branch_ref_and_option_injection_rejected(self):
        for baseline in ['HEAD','--output=/tmp/escape','a'*40+';touch x']:
            with self.assertRaises(ValueError): git_changes(self.root,baseline)

    def test_diverged_history_reported_without_reset_or_merge(self):
        self.git('checkout','-qb','other')
        (self.root/'new').write_text('x'); self.git('add','.'); self.git('commit','-qm','other')
        other=self.git('rev-parse','HEAD').strip()
        self.git('checkout','-q','--detach',self.base)
        (self.root/'different').write_text('y'); self.git('add','.'); self.git('commit','-qm','different')
        self.assertEqual(git_changes(self.root,other)['ancestry'],'diverged')


if __name__=='__main__': unittest.main()
