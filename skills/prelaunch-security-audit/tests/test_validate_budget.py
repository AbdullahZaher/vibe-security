"""Budget declarations never establish evidence, coverage or authorization."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from validate_budget import validate, METRICS


def budget():
    return {'schema_version':'0.5.0','target':'synthetic','revision':'a'*40,
        'profile':'quick','coverage_scope':'partial',
        'limits':{m:'unknown' for m in METRICS}, 'usage':{m:'unknown' for m in METRICS},
        'measurement_refs':{m:'unknown' for m in METRICS},'confirmation_reserve_steps':1,
        'deferred_unit_ids':['auth-other-role'],'limitations':['No token counter supplied by host.']}


class TestBudget(unittest.TestCase):
    def test_unknown_usage_stays_unknown(self):
        result=validate(budget())
        self.assertEqual(result['usage']['tokens'],'unknown')
        self.assertFalse(result['complete_attack_surface'])
        self.assertEqual(result['deferred_unit_ids'],['auth-other-role'])

    def test_quick_cannot_claim_complete_or_discovered_scope(self):
        for value in ['full','discovered_scope']:
            data=budget(); data['coverage_scope']=value
            with self.assertRaises(ValueError): validate(data)

    def test_unmeasured_and_fraudulent_usage_rejected(self):
        for value in [0, -1, True, float('nan'), 1.5]:
            data=budget(); data['usage']['tokens']=value
            with self.assertRaises(ValueError): validate(data)

    def test_measured_overrun_is_visible(self):
        data=budget(); data['usage']['steps']=4; data['limits']['steps']=3
        data['measurement_refs']['steps']='host-log:run1'
        self.assertEqual(validate(data)['budget_exceeded'],['steps'])

    def test_reserve_unknown_fields_and_duplicate_deferred_rejected(self):
        mutations=[lambda d:d.update(complete_attack_surface=True),
            lambda d:d['deferred_unit_ids'].append('auth-other-role'),
            lambda d:d['limits'].update(steps=0),
            lambda d:d['measurement_refs'].update(tokens='invented')]
        for mutate in mutations:
            data=budget(); mutate(data)
            with self.assertRaises(ValueError): validate(data)

    def test_standard_and_deep_are_not_success_labels(self):
        for profile in ['standard','deep']:
            data=budget(); data['profile']=profile; data['coverage_scope']='discovered_scope'
            self.assertFalse(validate(data)['complete_attack_surface'])


if __name__=='__main__': unittest.main()
