"""Deterministic assurance declarations; not evidence or release authentication.

No evaluator, policy thresholds, corpus rules or verifier interfaces are defined.
All six verdicts are supplied declarations. A matching authorization binding is
structural consistency, not proof of genuine consent, execution or independence.
validate_envelope returns None on success and raises AssuranceContractError on
invalid input. derive_product_state accepts the same envelope with product_state
optionally omitted; an existing state is never used to derive the result.

NOT_APPLICABLE never contributes to owner readiness or release authorization in
v1. Per-tier applicability is an undecided owner decision; no tier-to-layer
applicability is encoded. Tier P cannot reach owner-ready or authorized in v1.
The digest convention uses Python json.dumps, not RFC 8785; 1 and 1.0 hash
differently. Evidence references are free strings in v1, not content bindings;
content digests must be required when the evaluator is integrated.
"""
import copy
import hashlib
import json
import math
import re

PASS = "PASS"
FAIL = "FAIL"
INCOMPLETE = "INCOMPLETE"
NOT_APPLICABLE = "NOT_APPLICABLE"
STATES = frozenset((PASS, FAIL, INCOMPLETE, NOT_APPLICABLE))
LAYERS = ("structure", "source_identity", "authentication", "completeness",
          "detection_quality", "release_authorization")
VERDICT_FIELDS = tuple(layer + "_verdict" for layer in LAYERS)
NOT_READY = "NOT_READY"
READY_FOR_OWNER_DECISION = "READY_FOR_OWNER_DECISION"
RELEASE_AUTHORIZED = "RELEASE_AUTHORIZED"
PRODUCT_STATES = frozenset((NOT_READY, READY_FOR_OWNER_DECISION, RELEASE_AUTHORIZED))
AUTHENTICATION_BASES = frozenset(("none", "test_double", "owner_verified",
                                "independently_reviewed"))
CLAIM_TIERS = frozenset(("P", "S", "I"))
SCHEMA_VERSION = "assurance-result/v1"
POLICY_SCHEMA_VERSION = "acceptance-policy/v1"
PROTOCOL_SCHEMA_VERSION = "evaluation-protocol/v1"
REASON_CODES = frozenset((
    "EVIDENCE_MISSING", "REQUIREMENT_FAILED", "IDENTITY_MISMATCH",
    "AUTHENTICATION_UNVERIFIED", "REPLAY_DETECTED", "POLICY_NOT_APPLICABLE",
    "OWNER_DECISION_PENDING", "RELEASE_PREREQUISITES_INCOMPLETE",
    "QUALITY_NOT_EVALUATED",
))
ENVELOPE_FIELDS = frozenset((
    "schema_version", "subject", "claim_tier", "policy", "protocol",
    "authentication_basis", "evidence_refs", "layer_details",
    "release_authorization_binding", "product_state", *VERDICT_FIELDS,
))
BINDING_FIELDS = frozenset((
    "subject_revision", "subject_package_sha256", "policy_sha256",
    "protocol_sha256", "evidence_refs", "claim_tier", "assessment_sha256",
))


class AssuranceContractError(ValueError):
    """The supplied value does not satisfy this contract."""


def _require(condition, message):
    if not condition:
        raise AssuranceContractError(message)


def _json_value(value, ancestors):
    kind = type(value)
    if value is None or kind in (str, bool, int):
        return
    if kind is float:
        _require(math.isfinite(value), "non-finite number")
        return
    _require(kind in (dict, list), "only plain JSON types are supported")
    _require(id(value) not in ancestors, "cyclic JSON value")
    ancestors.add(id(value))
    try:
        if kind is dict:
            _require(all(type(key) is str for key in value), "JSON keys must be strings")
            children = value.values()
        else:
            children = value
        for child in children:
            _json_value(child, ancestors)
    finally:
        ancestors.remove(id(value))


def canonical_json_sha256(value):
    """Hash strict JSON: UTF-8, sorted keys, compact separators, ASCII escaping."""
    try:
        _json_value(value, set())
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()
    except AssuranceContractError:
        raise
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError) as exc:
        raise AssuranceContractError("cannot canonicalize JSON") from exc


def assessment_sha256(envelope):
    """Hash a deep copy excluding authorization decisions, binding and product state.

    The entire release_authorization layer detail is also excluded. This digest
    binds declarations and reference strings, not referenced evidence contents.
    """
    canonical_json_sha256(envelope)
    _require(type(envelope) is dict, "assessment envelope must be an object")
    try:
        assessment = copy.deepcopy(envelope)
    except RecursionError as exc:
        raise AssuranceContractError("assessment is too deeply nested") from exc
    for field in ("release_authorization_verdict", "release_authorization_binding", "product_state"):
        assessment.pop(field, None)
    details = assessment.get("layer_details")
    _require(type(details) is dict, "assessment needs layer_details object")
    details.pop("release_authorization", None)
    return canonical_json_sha256(assessment)


def _record(value, fields, label):
    _require(type(value) is dict and set(value) == set(fields),
             label + ": missing or unknown keys")


def _choice(value, choices, label):
    _require(type(value) is str and value in choices, label + ": unknown value or type")


def _text(value, label):
    _require(type(value) is str and bool(value.strip()), label + ": non-empty string required")


def _hash(value, label, revision=False):
    pattern = r"(?:[0-9a-f]{40}|[0-9a-f]{64})" if revision else r"[0-9a-f]{64}"
    _require(type(value) is str and re.fullmatch(pattern, value) is not None,
             label + ": malformed hash")


def _strings(value, label, choices=None):
    _require(type(value) is list, label + ": array required")
    for item in value:
        _text(item, label)
        if choices is not None:
            _choice(item, choices, label)
    _require(len(value) == len(set(value)), label + ": duplicate entries")


def _reference(value, version, label):
    if value is not None:
        _record(value, ("schema_version", "id", "version", "sha256"), label)
        _choice(value["schema_version"], (version,), label + ".schema_version")
        _text(value["id"], label + ".id")
        _text(value["version"], label + ".version")
        _hash(value["sha256"], label + ".sha256")


def _validate_shape(envelope, require_state):
    canonical_json_sha256(envelope)
    fields = ENVELOPE_FIELDS
    if not require_state and type(envelope) is dict and "product_state" not in envelope:
        fields = fields - {"product_state"}
    _record(envelope, fields, "envelope")
    _choice(envelope["schema_version"], (SCHEMA_VERSION,), "schema_version")
    _choice(envelope["claim_tier"], CLAIM_TIERS, "claim_tier")
    _choice(envelope["authentication_basis"], AUTHENTICATION_BASES, "authentication_basis")
    if "product_state" in envelope:
        _choice(envelope["product_state"], PRODUCT_STATES, "product_state")
    subject = envelope["subject"]
    _record(subject, ("kind", "revision", "package_sha256"), "subject")
    _choice(subject["kind"], ("skill_release",), "subject.kind")
    _hash(subject["revision"], "subject.revision", revision=True)
    _hash(subject["package_sha256"], "subject.package_sha256")
    _reference(envelope["policy"], POLICY_SCHEMA_VERSION, "policy")
    _reference(envelope["protocol"], PROTOCOL_SCHEMA_VERSION, "protocol")
    _strings(envelope["evidence_refs"], "evidence_refs")
    _record(envelope["layer_details"], LAYERS, "layer_details")
    for layer, field in zip(LAYERS, VERDICT_FIELDS):
        _choice(envelope[field], STATES, field)
        detail = envelope["layer_details"][layer]
        _record(detail, ("reason_codes", "evidence_refs"), layer)
        _strings(detail["reason_codes"], layer + ".reason_codes", REASON_CODES)
        _strings(detail["evidence_refs"], layer + ".evidence_refs")
        _require(set(detail["evidence_refs"]) <= set(envelope["evidence_refs"]),
                 layer + ": foreign evidence reference")
        if envelope[field] == PASS:
            _require(not detail["reason_codes"], layer + ": PASS must have no reason codes")
        elif envelope[field] in (FAIL, INCOMPLETE):
            _require(bool(detail["reason_codes"]), layer + ": FAIL/INCOMPLETE needs a reason")
        if envelope[field] == NOT_APPLICABLE:
            _require(envelope["policy"] is not None and bool(detail["reason_codes"]),
                     layer + ": NOT_APPLICABLE needs policy and reason")
    if envelope["authentication_verdict"] == PASS:
        _require(envelope["authentication_basis"] in {"owner_verified", "independently_reviewed"},
                 "authentication PASS cannot use none or test_double")
        if envelope["claim_tier"] == "I":
            _require(envelope["authentication_basis"] == "independently_reviewed",
                     "Tier I authentication PASS needs independent review")
    binding = envelope["release_authorization_binding"]
    if binding is not None:
        _record(binding, BINDING_FIELDS, "release_authorization_binding")
        _hash(binding["subject_revision"], "binding.subject_revision", revision=True)
        _choice(binding["claim_tier"], CLAIM_TIERS, "binding.claim_tier")
        for field in ("subject_package_sha256", "policy_sha256", "protocol_sha256", "assessment_sha256"):
            _hash(binding[field], "binding." + field)
        _strings(binding["evidence_refs"], "binding.evidence_refs")
        _require(envelope["policy"] is not None and envelope["protocol"] is not None,
                 "authorization binding needs policy and protocol")
        expected = {
            "subject_revision": subject["revision"],
            "subject_package_sha256": subject["package_sha256"],
            "policy_sha256": envelope["policy"]["sha256"],
            "protocol_sha256": envelope["protocol"]["sha256"],
            "evidence_refs": envelope["evidence_refs"],
            "claim_tier": envelope["claim_tier"],
            "assessment_sha256": assessment_sha256(envelope),
        }
        _require(bool(binding["evidence_refs"]) and binding == expected,
                 "authorization binding differs from envelope identities")
    _require(envelope["release_authorization_verdict"] != PASS or binding is not None,
             "authorization PASS needs an exact binding")


def _derive(envelope):
    if (envelope["claim_tier"] == "P"
            or envelope["policy"] is None or envelope["protocol"] is None
            or any(envelope[field] != PASS for field in VERDICT_FIELDS[:5])):
        return NOT_READY
    if envelope["release_authorization_verdict"] == PASS:
        return RELEASE_AUTHORIZED
    reasons = envelope["layer_details"]["release_authorization"]["reason_codes"]
    if (envelope["release_authorization_verdict"] == INCOMPLETE
            and reasons == ["OWNER_DECISION_PENDING"]):
        return READY_FOR_OWNER_DECISION
    return NOT_READY


def derive_product_state(envelope):
    """Derive only from validated declarations; perform no authentication."""
    _validate_shape(envelope, require_state=False)
    return _derive(envelope)


def validate_envelope(envelope):
    """Reject invalid declarations using AssuranceContractError; never mutate input."""
    _validate_shape(envelope, require_state=True)
    _require(envelope["product_state"] == _derive(envelope),
             "product_state differs from derived state")
