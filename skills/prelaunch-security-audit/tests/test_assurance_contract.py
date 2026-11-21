"""Synthetic contract declarations only; never independently authenticated evidence."""
import copy
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "evals"))
import assurance_contract as contract  # noqa: E402


def envelope():
    data = {
        "schema_version": contract.SCHEMA_VERSION,
        "subject": {"kind": "skill_release", "revision": "a" * 40,
                    "package_sha256": "b" * 64},
        "claim_tier": "S", "authentication_basis": "none",
        "policy": {"schema_version": contract.POLICY_SCHEMA_VERSION,
                   "id": "synthetic-policy", "version": "test-only", "sha256": "d" * 64},
        "protocol": {"schema_version": contract.PROTOCOL_SCHEMA_VERSION,
                     "id": "synthetic-protocol", "version": "test-only", "sha256": "e" * 64},
        "evidence_refs": ["synthetic:trial", "synthetic:review"],
        "layer_details": {layer: {"reason_codes": ["EVIDENCE_MISSING"], "evidence_refs": []}
                          for layer in contract.LAYERS},
        "release_authorization_binding": None,
        "product_state": contract.NOT_READY,
    }
    data.update(dict.fromkeys(contract.VERDICT_FIELDS, contract.INCOMPLETE))
    return data


def owner_pending():
    data = envelope()
    data["authentication_basis"] = "owner_verified"  # Test declaration, NOT real verification.
    for layer, field in zip(contract.LAYERS[:5], contract.VERDICT_FIELDS[:5]):
        data[field] = contract.PASS
        data["layer_details"][layer] = {"reason_codes": [], "evidence_refs": ["synthetic:trial"]}
    data["layer_details"]["release_authorization"]["reason_codes"] = ["OWNER_DECISION_PENDING"]
    data["product_state"] = contract.READY_FOR_OWNER_DECISION
    return data


def authorized():
    data = owner_pending()
    data["release_authorization_verdict"] = contract.PASS
    data["layer_details"]["release_authorization"]["reason_codes"] = []
    data["release_authorization_binding"] = {
        "subject_revision": data["subject"]["revision"],
        "subject_package_sha256": data["subject"]["package_sha256"],
        "policy_sha256": data["policy"]["sha256"],
        "protocol_sha256": data["protocol"]["sha256"],
        "evidence_refs": list(data["evidence_refs"]),
        "claim_tier": data["claim_tier"],
        "assessment_sha256": contract.assessment_sha256(data),
    }
    data["product_state"] = contract.RELEASE_AUTHORIZED
    return data


def refresh_binding(data):
    """Rebind a synthetic declaration only; this is not renewed human approval."""
    binding = data["release_authorization_binding"]
    if binding is not None:
        binding["claim_tier"] = data["claim_tier"]
        binding["assessment_sha256"] = contract.assessment_sha256(data)


class AssuranceContractTests(unittest.TestCase):
    def assert_valid(self, data):
        self.assertIsNone(contract.validate_envelope(data))
        self.assertEqual(contract.derive_product_state(data), data["product_state"])

    def assert_invalid(self, data):
        with self.assertRaises(contract.AssuranceContractError):
            contract.validate_envelope(data)

    def test_structure_pass_never_implies_quality_or_owner_readiness(self):
        data = envelope()
        data["structure_verdict"] = contract.PASS
        data["layer_details"]["structure"]["reason_codes"] = []
        self.assert_valid(data)
        self.assertEqual(data["detection_quality_verdict"], contract.INCOMPLETE)
        self.assertEqual(contract.derive_product_state(data), contract.NOT_READY)
        data["product_state"] = contract.READY_FOR_OWNER_DECISION
        self.assert_invalid(data)

    def test_five_pass_layers_leave_owner_decision_pending(self):
        data = owner_pending()
        self.assert_valid(data)
        self.assertNotEqual(contract.derive_product_state(data), contract.RELEASE_AUTHORIZED)
        data["product_state"] = contract.RELEASE_AUTHORIZED
        self.assert_invalid(data)

    def test_any_first_five_nonpass_prevents_readiness_even_with_approval(self):
        for factory in (owner_pending, authorized):
            self.assert_valid(factory())
            for layer, field in zip(contract.LAYERS[:5], contract.VERDICT_FIELDS[:5]):
                for state in (contract.FAIL, contract.INCOMPLETE, contract.NOT_APPLICABLE):
                    with self.subTest(factory=factory.__name__, field=field, state=state):
                        data = factory()
                        data[field] = state
                        reason = {contract.FAIL: "REQUIREMENT_FAILED",
                                  contract.INCOMPLETE: "EVIDENCE_MISSING",
                                  contract.NOT_APPLICABLE: "POLICY_NOT_APPLICABLE"}[state]
                        data["layer_details"][layer]["reason_codes"] = [reason]
                        data["product_state"] = contract.NOT_READY
                        if factory is authorized:
                            self.assert_invalid(data)  # The original assessment binding is stale.
                            refresh_binding(data)
                        # Even an exact otherwise-authorized binding cannot make N/A ready.
                        self.assert_valid(data)
                        data["product_state"] = contract.READY_FOR_OWNER_DECISION
                        self.assert_invalid(data)

    def test_owner_pending_must_be_the_only_release_reason(self):
        self.assert_valid(owner_pending())
        missing_reason = owner_pending()
        missing_reason["layer_details"]["release_authorization"]["reason_codes"] = []
        self.assert_invalid(missing_reason)
        for state, reasons in (
            (contract.INCOMPLETE, ["EVIDENCE_MISSING"]),
            (contract.INCOMPLETE, ["OWNER_DECISION_PENDING", "RELEASE_PREREQUISITES_INCOMPLETE"]),
            (contract.FAIL, ["REQUIREMENT_FAILED"]),
            (contract.NOT_APPLICABLE, ["POLICY_NOT_APPLICABLE"]),
        ):
            with self.subTest(state=state, reasons=reasons):
                data = owner_pending()
                data["release_authorization_verdict"] = state
                data["layer_details"]["release_authorization"]["reason_codes"] = reasons
                data["product_state"] = contract.NOT_READY
                self.assert_valid(data)
                data["product_state"] = contract.READY_FOR_OWNER_DECISION
                self.assert_invalid(data)

    def test_product_state_is_derived_not_trusted(self):
        for factory in (envelope, owner_pending, authorized):
            data = factory()
            expected = data["product_state"]
            self.assert_valid(data)
            for wrong in contract.PRODUCT_STATES - {expected}:
                data["product_state"] = wrong
                self.assertEqual(contract.derive_product_state(data), expected)
                self.assert_invalid(data)

    def test_authorization_binding_matches_every_identity_exactly(self):
        self.assert_valid(authorized())
        for field in contract.BINDING_FIELDS:
            with self.subTest(field=field):
                data = authorized()
                data["release_authorization_binding"][field] = (
                    list(reversed(data["evidence_refs"])) if field == "evidence_refs"
                    else "I" if field == "claim_tier"
                    else "f" * (40 if field == "subject_revision" else 64))
                self.assert_invalid(data)
        for section, field in (("subject", "revision"), ("subject", "package_sha256"),
                               ("policy", "sha256"), ("protocol", "sha256")):
            data = authorized()
            data[section][field] = "f" * (40 if field == "revision" else 64)
            self.assert_invalid(data)
        data = authorized()
        data["evidence_refs"].append("synthetic:extra")
        self.assert_invalid(data)

    def test_authorization_requires_binding_and_nonempty_evidence(self):
        self.assert_valid(authorized())
        data = authorized()
        data["release_authorization_binding"] = None
        self.assert_invalid(data)
        data = authorized()
        data["evidence_refs"] = []
        data["release_authorization_binding"]["evidence_refs"] = []
        for detail in data["layer_details"].values():
            detail["evidence_refs"] = []
        self.assert_invalid(data)
        data = authorized()
        data["policy"] = None
        self.assert_invalid(data)

    def test_none_and_test_double_cannot_pass_authentication(self):
        self.assert_valid(owner_pending())
        for basis in ("none", "test_double"):
            data = owner_pending()
            data["authentication_basis"] = basis
            self.assert_invalid(data)
            data["authentication_verdict"] = contract.INCOMPLETE
            data["layer_details"]["authentication"]["reason_codes"] = ["AUTHENTICATION_UNVERIFIED"]
            data["product_state"] = contract.NOT_READY
            self.assert_valid(data)

    def test_tier_i_pass_requires_independently_reviewed_basis(self):
        data = owner_pending()
        data["claim_tier"] = "I"
        self.assert_invalid(data)
        data["authentication_basis"] = "independently_reviewed"
        self.assert_valid(data)
        for tier in ("P", "S"):
            for basis in ("independently_reviewed", "owner_verified"):
                data = owner_pending()
                data["claim_tier"] = tier
                data["authentication_basis"] = basis
                if tier == "P":
                    data["product_state"] = contract.NOT_READY
                self.assert_valid(data)

    def test_not_applicable_requires_policy_and_reason(self):
        data = envelope()
        data["completeness_verdict"] = contract.NOT_APPLICABLE
        data["layer_details"]["completeness"]["reason_codes"] = ["POLICY_NOT_APPLICABLE"]
        self.assert_valid(data)
        data["policy"] = None
        self.assert_invalid(data)
        data = envelope()
        data["completeness_verdict"] = contract.NOT_APPLICABLE
        data["layer_details"]["completeness"]["reason_codes"] = []
        self.assert_invalid(data)

    def test_reason_codes_are_closed_unique_string_arrays(self):
        self.assert_valid(envelope())
        for reasons in (["UNKNOWN_REASON"], ["EVIDENCE_MISSING", "EVIDENCE_MISSING"],
                        [True], "EVIDENCE_MISSING", None):
            data = envelope()
            data["layer_details"]["structure"]["reason_codes"] = reasons
            self.assert_invalid(data)

    def test_unknown_schema_and_reference_format_versions_rejected(self):
        self.assert_valid(owner_pending())
        data = owner_pending()
        data["schema_version"] = "assurance-result/v2"
        self.assert_invalid(data)
        with self.assertRaises(contract.AssuranceContractError):
            contract.derive_product_state(data)
        for key in ("policy", "protocol"):
            data = owner_pending()
            data[key]["schema_version"] = "unknown/v99"
            self.assert_invalid(data)

    def test_unknown_keys_rejected_at_every_record_boundary(self):
        self.assert_valid(envelope())
        for path in ((), ("subject",), ("policy",), ("protocol",), ("layer_details",),
                     *(("layer_details", layer) for layer in contract.LAYERS)):
            data = envelope()
            target = data
            for key in path:
                target = target[key]
            target["unknown"] = "not permitted"
            self.assert_invalid(data)
        for field in ("audit_mode", "legacy_result"):
            data = envelope()
            data[field] = None
            self.assert_invalid(data)
        data = authorized()
        data["release_authorization_binding"]["unknown"] = None
        self.assert_invalid(data)

    def test_wrong_types_rejected_without_coercion(self):
        self.assert_valid(envelope())
        for key, value in (("subject", []), ("policy", []), ("protocol", "none"),
                           ("claim_tier", ["S"]), ("authentication_basis", True),
                           ("evidence_refs", ("synthetic:trial",)), ("layer_details", []),
                           ("product_state", False), ("release_authorization_binding", False)):
            data = envelope()
            data[key] = value
            self.assert_invalid(data)
        for value in (None, [], "envelope", 1, True):
            self.assert_invalid(value)

    def test_malformed_hashes_rejected(self):
        self.assert_valid(owner_pending())
        for section, field in (("subject", "revision"), ("subject", "package_sha256"),
                               ("policy", "sha256"), ("protocol", "sha256")):
            for value in ("", "a" * 39, "a" * 63, "A" * 64, "g" * 64,
                          "a" * 64 + "\n", 0, True):
                data = owner_pending()
                data[section][field] = value
                self.assert_invalid(data)
        data = owner_pending()
        data["subject"]["revision"] = "a" * 64
        self.assert_valid(data)

    def test_unknown_states_tiers_subjects_and_bases_rejected(self):
        self.assert_valid(envelope())
        for field in contract.VERDICT_FIELDS:
            for value in ("pass", "UNKNOWN", False):
                data = envelope()
                data[field] = value
                self.assert_invalid(data)
        for key, value in (("claim_tier", "X"), ("authentication_basis", "claimed"),
                           ("product_state", "APPROVED")):
            data = envelope()
            data[key] = value
            self.assert_invalid(data)
        data = envelope()
        data["subject"]["kind"] = "target_review"
        self.assert_invalid(data)

    def test_canonical_hash_is_stable_and_sensitive_to_content(self):
        data = {"b": [2, 1], "a": "é"}
        expected = hashlib.sha256(b'{"a":"\\u00e9","b":[2,1]}').hexdigest()
        self.assertEqual(contract.canonical_json_sha256(data), expected)
        self.assertEqual(contract.canonical_json_sha256({"a": "é", "b": [2, 1]}), expected)
        self.assertNotEqual(contract.canonical_json_sha256({"a": "é", "b": [1, 2]}), expected)

    def test_nonfinite_numbers_fail_closed(self):
        self.assertEqual(len(contract.canonical_json_sha256({"finite": 1.25})), 64)
        for number in (float("nan"), float("inf"), -float("inf")):
            with self.assertRaises(contract.AssuranceContractError):
                contract.canonical_json_sha256({"nested": [number]})
            data = envelope()
            data["evidence_refs"] = [number]
            self.assert_invalid(data)

    def test_non_json_values_and_cycles_use_contract_exception(self):
        self.assertEqual(len(contract.canonical_json_sha256({"valid": [None, True, 1]})), 64)
        cycle = []
        cycle.append(cycle)
        for value in ((1,), {1: "integer key"}, b"bytes", {1}, object(), cycle):
            with self.assertRaises(contract.AssuranceContractError):
                contract.canonical_json_sha256(value)
        self.assert_invalid(cycle)

    def test_inputs_never_mutated_on_success_or_rejection(self):
        for factory in (envelope, owner_pending, authorized):
            data = factory()
            before = copy.deepcopy(data)
            self.assert_valid(data)
            contract.canonical_json_sha256(data)
            contract.assessment_sha256(data)
            self.assertEqual(data, before)
            partial = copy.deepcopy(data)
            del partial["product_state"]
            saved = copy.deepcopy(partial)
            self.assertEqual(contract.derive_product_state(partial), data["product_state"])
            self.assertEqual(partial, saved)
            data["product_state"] = "wrong"
            invalid_before = copy.deepcopy(data)
            self.assert_invalid(data)
            contract.assessment_sha256(data)
            self.assertEqual(data, invalid_before)
            self.assertNotEqual(data, before)

    def test_missing_policy_or_protocol_cannot_be_owner_ready(self):
        self.assert_valid(owner_pending())
        for key in ("policy", "protocol"):
            data = owner_pending()
            data[key] = None
            data["product_state"] = contract.NOT_READY
            self.assert_valid(data)
            data["product_state"] = contract.READY_FOR_OWNER_DECISION
            self.assert_invalid(data)

    def test_evidence_references_are_unique_linked_nonempty_strings(self):
        data = envelope()
        data["layer_details"]["structure"]["evidence_refs"] = ["synthetic:trial"]
        self.assert_valid(data)
        for refs in (["foreign"], ["synthetic:trial", "synthetic:trial"], [""], [False]):
            data["layer_details"]["structure"]["evidence_refs"] = refs
            self.assert_invalid(data)
        data = envelope()
        data["evidence_refs"].append(data["evidence_refs"][0])
        self.assert_invalid(data)

    def test_required_fields_and_nonempty_reference_identities(self):
        self.assert_valid(envelope())
        for field in contract.ENVELOPE_FIELDS:
            data = envelope()
            del data[field]
            self.assert_invalid(data)
        for section in ("policy", "protocol"):
            for field in ("id", "version"):
                for value in ("", " ", 1):
                    data = envelope()
                    data[section][field] = value
                    self.assert_invalid(data)


    def test_authorization_binds_all_earlier_assessment_fields(self):
        original = authorized()
        original["authentication_basis"] = "independently_reviewed"
        refresh_binding(original)
        self.assert_valid(original)
        changes = [(layer, kind) for layer in contract.LAYERS[:5]
                   for kind in ("verdict", "reason_codes", "evidence_refs")]
        changes += [(None, "authentication_basis"), (None, "claim_tier")]
        for layer, kind in changes:
            with self.subTest(layer=layer, kind=kind):
                data = copy.deepcopy(original)
                if kind == "verdict":
                    data[layer + "_verdict"] = contract.FAIL
                    data["layer_details"][layer]["reason_codes"] = ["REQUIREMENT_FAILED"]
                    data["product_state"] = contract.NOT_READY
                elif kind == "reason_codes":
                    data["layer_details"][layer]["reason_codes"] = ["REQUIREMENT_FAILED"]
                elif kind == "evidence_refs":
                    data["layer_details"][layer]["evidence_refs"] = ["synthetic:review"]
                elif kind == "authentication_basis":
                    data["authentication_basis"] = "owner_verified"
                else:
                    data["claim_tier"] = "I"
                self.assertNotEqual(contract.assessment_sha256(data),
                                    original["release_authorization_binding"]["assessment_sha256"])
                self.assert_invalid(data)
                refresh_binding(data)
                if kind == "reason_codes":
                    self.assert_invalid(data)  # Rebinding cannot excuse reasons on PASS.
                else:
                    self.assert_valid(data)
        self.assert_valid(original)

    def test_binding_tier_must_match_even_when_other_identities_match(self):
        data = authorized()
        self.assert_valid(data)
        data["release_authorization_binding"]["claim_tier"] = "I"
        self.assert_invalid(data)

    def test_assessment_hash_excludes_only_authorization_and_product_fields(self):
        data = authorized()
        before = copy.deepcopy(data)
        payload = copy.deepcopy(data)
        for field in ("release_authorization_verdict", "release_authorization_binding", "product_state"):
            del payload[field]
        del payload["layer_details"]["release_authorization"]
        expected = contract.canonical_json_sha256(payload)
        self.assertEqual(contract.assessment_sha256(data), expected)
        for key, value in (("release_authorization_verdict", contract.FAIL),
                           ("release_authorization_binding", None),
                           ("product_state", contract.NOT_READY)):
            changed = copy.deepcopy(data)
            changed[key] = value
            self.assertEqual(contract.assessment_sha256(changed), expected)
        changed = copy.deepcopy(data)
        changed["layer_details"]["release_authorization"] = {
            "reason_codes": ["REQUIREMENT_FAILED"], "evidence_refs": ["synthetic:review"]}
        self.assertEqual(contract.assessment_sha256(changed), expected)
        changed["structure_verdict"] = contract.FAIL
        self.assertNotEqual(contract.assessment_sha256(changed), expected)
        self.assertEqual(data, before)
        for invalid in (None, [], {"layer_details": []}):
            with self.assertRaises(contract.AssuranceContractError):
                contract.assessment_sha256(invalid)

    def test_reason_codes_match_each_layer_verdict(self):
        for layer, field in zip(contract.LAYERS, contract.VERDICT_FIELDS):
            data = authorized()
            self.assert_valid(data)
            data["layer_details"][layer]["reason_codes"] = ["REQUIREMENT_FAILED"]
            refresh_binding(data)
            self.assert_invalid(data)
            for state in (contract.FAIL, contract.INCOMPLETE):
                data = authorized()
                data[field] = state
                data["layer_details"][layer]["reason_codes"] = ["REQUIREMENT_FAILED"]
                data["product_state"] = contract.NOT_READY
                refresh_binding(data)
                self.assert_valid(data)
                data["layer_details"][layer]["reason_codes"] = []
                refresh_binding(data)
                self.assert_invalid(data)

    def test_tier_p_never_reaches_owner_ready_or_authorized_in_v1(self):
        for factory in (owner_pending, authorized):
            data = factory()
            data["claim_tier"] = "P"
            data["product_state"] = contract.NOT_READY
            refresh_binding(data)
            self.assert_valid(data)
            for wrong in (contract.READY_FOR_OWNER_DECISION, contract.RELEASE_AUTHORIZED):
                data["product_state"] = wrong
                self.assertEqual(contract.derive_product_state(data), contract.NOT_READY)
                self.assert_invalid(data)

    def test_python_json_digest_distinguishes_integer_and_float(self):
        integer = contract.canonical_json_sha256(1)
        floating = contract.canonical_json_sha256(1.0)
        self.assertEqual(integer, hashlib.sha256(b"1").hexdigest())
        self.assertEqual(floating, hashlib.sha256(b"1.0").hexdigest())
        self.assertNotEqual(integer, floating)


if __name__ == "__main__":
    unittest.main()
