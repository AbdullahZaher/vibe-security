"""Synthetic GitHub ruleset tests. No admin action or live tag creation."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "evals"))
from verify_release_tag_ruleset import evaluate


def immutable():
    return {"id": 27351357, "name": "Protect Release Tags",
            "target": "tag", "enforcement": "active",
            "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
            "rules": [{"type": "update"}, {"type": "deletion"}],
            "bypass_actors": []}


def controlled_creation():
    return {"id": 12345678, "name": "Release tag creation: named publisher only",
            "target": "tag", "enforcement": "active",
            "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
            "rules": [{"type": "creation"}],
            "bypass_actors": [
                {"actor_id": 12345, "actor_type": "User", "bypass_mode": "always"}
            ]}


class TestReleaseTagRuleset(unittest.TestCase):
    def test_existing_update_delete_does_not_protect_creation(self):
        result = evaluate([immutable()])
        self.assertEqual(result["status"], "BLOCK_TAG_GOVERNANCE")
        self.assertFalse(result["creation_ruleset_ids"])
        self.assertFalse(result["stable_release_authorized"])

    def test_separate_creation_and_immutable_rulesets_shape_only(self):
        result = evaluate([immutable(), controlled_creation()])
        self.assertEqual(result["status"], "CONFIGURATION_SNAPSHOT_MATCH_ONLY")
        self.assertFalse(result["verified_live_with_github"])
        self.assertFalse(result["authorized_publisher_identity_verified"])
        self.assertFalse(result["human_approval_verified"])
        self.assertFalse(result["stable_release_authorized"])

    def test_creation_rule_with_no_publisher_cannot_be_approved(self):
        rule = controlled_creation()
        rule["bypass_actors"] = []
        self.assertEqual(evaluate([immutable(), rule])["status"], "BLOCK_TAG_GOVERNANCE")

    def test_creation_rule_broad_repo_role_is_not_an_explicit_publisher(self):
        rule = controlled_creation()
        rule["bypass_actors"] = [{"actor_id": 5, "actor_type": "RepositoryRole",
                                   "bypass_mode": "always"}]
        self.assertEqual(evaluate([immutable(), rule])["status"], "BLOCK_TAG_GOVERNANCE")

    def test_immutability_rule_with_bypass_cannot_be_approved(self):
        rule = immutable()
        rule["bypass_actors"] = copy.deepcopy(controlled_creation()["bypass_actors"])
        self.assertEqual(evaluate([rule, controlled_creation()])["status"], "BLOCK_TAG_GOVERNANCE")

    def test_combining_creation_and_update_with_bypass_is_rejected(self):
        rule = controlled_creation()
        rule["rules"].append({"type": "update"})
        self.assertEqual(evaluate([immutable(), rule])["status"], "BLOCK_TAG_GOVERNANCE")

    def test_disabled_mismatched_or_scoped_exclusion_rules_do_not_count(self):
        for mutation in ("disabled", "wrong_target", "wrong_pattern", "exclusion"):
            a, b = immutable(), controlled_creation()
            if mutation == "disabled":
                b["enforcement"] = "disabled"
            elif mutation == "wrong_target":
                b["target"] = "branch"
            elif mutation == "wrong_pattern":
                b["conditions"]["ref_name"]["include"] = ["refs/tags/release*"]
            else:
                b["conditions"]["ref_name"]["exclude"] = ["refs/tags/v0.5.0"]
            self.assertEqual(evaluate([a, b])["status"], "BLOCK_TAG_GOVERNANCE")

    def test_summary_without_rules_and_bypass_must_not_pass(self):
        self.assertEqual(evaluate([{"id": 27351357, "enforcement": "active",
                                    "target": "tag"}])["status"], "BLOCK_TAG_GOVERNANCE")

    def test_invalid_input_rejected(self):
        for bad in (None, {}, True, "not json"):
            with self.assertRaises(ValueError):
                evaluate(bad)


if __name__ == "__main__":
    unittest.main()
