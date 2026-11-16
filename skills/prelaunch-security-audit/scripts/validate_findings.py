#!/usr/bin/env python3
"""Validate v0.5 finding histories and remediation claims, offline and read-only.

Input consistency and frozen source checks do not authenticate execution logs.
Trusted host attestations are optional API inputs, never taken from the bundle.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path

from audit_artifacts import (load_json, require, safe_relative_path, unique_index,
                             validate_schema, validate_source)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


def _nonblank(value, key=""):
    if isinstance(value, dict):
        for name, item in value.items():
            _nonblank(item, name)
    elif isinstance(value, list):
        for item in value:
            _nonblank(item, key)
    elif isinstance(value, str) and key not in {"next_check", "sha256"}:
        require(bool(value.strip()), f"blank {key} is not meaningful evidence")


def fingerprint(candidate):
    """Stable across revisions; a changed root cause is a new candidate."""
    return digest([candidate[k] for k in
                   ("target", "component", "path", "entry_point", "root_cause")])


def _proofs(ids, evidence, candidate, revision=None, actor=None, resource=None):
    result = []
    for ident in ids:
        require(ident in evidence, f"dangling evidence reference: {ident}")
        e = evidence[ident]
        require(e["finding_id"] == candidate["id"], "cross-finding evidence")
        require(e["target"] == candidate["target"], "foreign target evidence")
        require(e["revision"] == (revision or candidate["revision"]), "cross-revision evidence")
        require(e["actor"] == (actor or candidate["actor"]), "wrong actor / service-role evidence")
        require(e["resource"] == (resource or candidate["resource"]), "wrong resource evidence")
        result.append(e)
    return result


def _executed(e, result):
    return (e["result"] == result and e["kind"] in {"build", "runtime", "deployment"}
            and e["provenance"]["origin"] == "host_log"
            and bool(e["command"] and e["command"].strip())
            and bool(e["test_definition_sha256"])
            and type(e["exit_code"]) is int
            and ((e["exit_code"] == 0) == (result == "pass")))


def _attestation(ref, trusted, expected, kind):
    require(bool(ref) and ref in trusted, f"{kind} requires trusted host attestation")
    proof = trusted[ref]
    require(isinstance(proof, dict), f"invalid {kind} attestation")
    require(all(proof.get(k) == v for k, v in expected.items()),
            f"mismatched {kind} host attestation")
    require(bool(proof.get("host_id")) and bool(proof.get("log_ref")),
            f"{kind} requires host identity and retained log")
    return proof


def _validate_remediation(f, evidence, trusted):
    c, fix = f["candidate"], f["remediation"]
    invariants = unique_index(c["invariants"])
    expected = digest(c["invariants"])
    require(fix["before_invariants_sha256"] == expected
            and fix["after_invariants_sha256"] == expected,
            "security invariants changed or weakened")
    for path in fix["changed_paths"]:
        safe_relative_path(path)
    unique_index(fix["adjacent_cases"])
    before = _proofs(fix["baseline_evidence_ids"], evidence, c)
    after = _proofs(fix["post_evidence_ids"], evidence, c, fix["fixed_revision"])
    stage = _proofs(fix["staging_evidence_ids"], evidence, c, fix["fixed_revision"])
    adjacent = []
    for case in fix["adjacent_cases"]:
        require(case["invariant_id"] in invariants, "unknown adjacent invariant")
        e = _proofs([case["evidence_id"]], evidence, c, fix["fixed_revision"],
                    case["actor"], case["resource"])[0]
        require(e["invariant_id"] == case["invariant_id"], "wrong adjacent invariant proof")
        adjacent.append(e)
    if fix["status"] != "fixed_verified":
        return
    require(f["verifications"][-1]["verdict"] == "confirmed", "fix needs confirmed vulnerability")
    require(fix["fixed_revision"] and fix["fixed_revision"] != c["revision"]
            and fix["changed_paths"] and fix["diff_sha256"], "fix needs exact changed revision and diff")
    _attestation(fix["approval_ref"], trusted, {
        "kind": "remediation_approval", "target": c["target"], "finding_id": c["id"],
        "candidate_sha256": f["candidate_sha256"], "diff_sha256": fix["diff_sha256"],
        "changed_paths": fix["changed_paths"], "high_impact": fix["high_impact"],
        "baseline_revision": c["revision"], "fixed_revision": fix["fixed_revision"],
    }, "remediation approval")
    require(before and after and adjacent, "fix needs baseline, post-fix and adjacent evidence")
    require(all(_executed(e, "fail") and e["failure_kind"] == "security_invariant" for e in before), "baseline must fail for security invariant")
    require(all(_executed(e, "pass") for e in after + adjacent), "post-fix or adjacent check failed/unrun")
    for ident, invariant in invariants.items():
        pre = [e for e in before if e["invariant_id"] == ident]
        post = [e for e in after if e["invariant_id"] == ident]
        require(pre and post, "every invariant needs baseline and post-fix proof")
        require(all(any((e["method"], e["expected"], e["actor"], e["resource"],
                         e["provenance"]["environment"], e["test_definition_sha256"]) ==
                        (p["method"], p["expected"], p["actor"], p["resource"],
                         p["provenance"]["environment"], p["test_definition_sha256"]) for p in pre) for e in post),
                "baseline and post-fix test/environment must match")
        # Require every declared adjacent role/resource pair. Invariants are frozen
        # before patching, so dropping a failing case cannot make a fix green.
        required = {(a, r) for a in invariant["actors"] for r in invariant["resources"]}
        covered = {(e["actor"], e["resource"]) for e in after + adjacent
                   if e["invariant_id"] == ident}
        require(required <= covered, "missing adjacent role/resource invariant checks")
    if fix["high_impact"]:
        _attestation(fix["backup_ref"], trusted, {
            "kind": "backup_snapshot", "target": c["target"], "finding_id": c["id"],
            "baseline_revision": c["revision"], "restore_verified": True,
        }, "backup")
        require(fix["backup_ref"] and stage and all(
            _executed(e, "pass") and e["kind"] == "deployment" for e in stage),
            "high-impact fix needs backup and authorized staging verification")


def validate(data, *, previous=None, host_attestations=None, source_root=None, inventory=None):
    """Validate a bundle; trusted inputs must be host-owned, outside the target.

    previous is a retained original snapshot. Without it a digest detects internal
    inconsistency, not deletion or rewriting of historical records. host_attestations
    must not be loaded from model/repository data; the CLI intentionally cannot
    import alleged approvals. API callers own authentication of this channel.
    """
    validate_schema(data, "findings-v0.5.schema.json")
    _nonblank(data)
    if inventory is not None:
        from validate_attack_surface import validate as validate_inventory
        validate_inventory(inventory, source_root)
        require(inventory["target"] == data["target"] and inventory["revision"] == data["revision"],
                "finding inventory scope/revision mismatch")
    inventory_ids = {u["id"] for u in inventory["units"]} if inventory is not None else set()
    trusted = host_attestations or {}
    evidence = unique_index(data["evidence"])
    candidates = unique_index([f["candidate"] for f in data["findings"]])
    unique_index([{"id": c["fingerprint"]} for c in candidates.values()])
    unique_index([v for f in data["findings"] for v in f["verifications"]])
    verified_sources = set()
    for e in evidence.values():
        require(e["finding_id"] in candidates, "orphan evidence finding")
        require(e["target"] == data["target"], "foreign evidence target")
        try:
            timestamp = datetime.fromisoformat(e["provenance"]["timestamp"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("invalid provenance timestamp") from exc
        require(timestamp.tzinfo is not None, "provenance timestamp needs timezone")
        checked = [validate_source(s, e["revision"], source_root) for s in e["sources"]]
        if checked and all(checked):
            verified_sources.add(e["id"])
        if e["kind"] == "source_analysis":
            require(e["provenance"]["origin"] == "source_inspection"
                    and e["result"] == "observed" and e["command"] is None
                    and e["exit_code"] is None and e["sources"], "invalid source analysis evidence")
        if e["result"] in {"pass", "fail"}:
            require(_executed(e, e["result"]), "unsupported executed PASS/FAIL")
            # Model-written origin labels, commands and exit codes are not host
            # execution proof. The protected controller must bind the entire
            # retained record, including revision, actor, invariant and result.
            _attestation(e["provenance"]["reference"], trusted, {
                "kind": "executed_evidence", "evidence_sha256": digest(e),
                "target": e["target"], "revision": e["revision"],
                "finding_id": e["finding_id"], "executed": True, "authorized": True,
            }, "executed evidence")
        if e["result"] in {"not_run", "blocked", "observed"}:
            require(e["exit_code"] is None, "unrun evidence has exit code")
    counts = {k: 0 for k in ("confirmed", "needs_validation", "rejected")}
    blockers = []
    for f in data["findings"]:
        c = f["candidate"]
        require(c["target"] == data["target"] and c["revision"] == data["revision"],
                "candidate scope/revision mismatch")
        safe_relative_path(c["path"])
        if "inventory_ids" in c:
            require(inventory is not None and set(c["inventory_ids"]) <= inventory_ids,
                    "finding has dangling inventory references or no inventory context")
        require(c["fingerprint"] == fingerprint(c), "unstable finding fingerprint")
        require(f["candidate_sha256"] == digest(c), "candidate digest mismatch")
        _proofs(c["evidence_ids"], evidence, c)
        for p in c["prerequisites"]:
            linked = _proofs(p["evidence_ids"], evidence, c)
            if p["status"] == "verified":
                require(linked and all(e["result"] in {"observed", "pass", "fail"}
                                      and e["kind"] != "scanner"
                                      and (e["kind"] != "source_analysis" or e["id"] in verified_sources)
                                      and e["failure_kind"] not in {"quality", "environment"}
                                      for e in linked),
                        "verified prerequisite lacks evidence")
        for v in f["verifications"]:
            require(v["candidate_sha256"] == f["candidate_sha256"], "verifier changed original candidate")
            proofs = _proofs(v["evidence_ids"], evidence, c)
            source_proofs = _proofs(v["source_evidence_ids"], evidence, c)
            require(set(v["source_evidence_ids"]) <= set(v["evidence_ids"]),
                    "source review references unrelated evidence")
            if c["complexity"]:
                require(v["profile"] == "deep", "complex/contradictory finding requires deep verification")
            if v["verdict"] in {"confirmed", "rejected"}:
                require(source_proofs and all(e["id"] in verified_sources for e in source_proofs),
                        "adjudication requires reread frozen source")
                require(any(any(s["path"] == c["path"] for s in e["sources"])
                            for e in source_proofs), "candidate path not examined")
                require(all(e["kind"] != "scanner" and e["result"] not in {"blocked", "not_run"}
                            for e in proofs), "scanner/raw or unrun evidence cannot adjudicate")
                require(v["verification_tier"] != "not_verified", "adjudication has no verification tier")
            if v["verdict"] == "confirmed":
                require(all(e["failure_kind"] not in {"quality", "environment"} for e in proofs),
                        "build/environment failure is not security confirmation evidence")
                require(all(p["status"] == "verified" for p in c["prerequisites"]),
                        "confirmation has unknown/impossible prerequisite")
                require(c["impact_basis"] == "demonstrated", "conditional impact cannot confirm severity")
                require(v["severity"] != "none", "confirmed finding needs justified severity")
            if v["severity"] in {"critical", "high"}:
                require(c["impact_basis"] == "demonstrated", "high severity relies on conditional impact")
            if v["verdict"] == "needs_validation":
                require(v["next_check"].strip() and v["limitations"], "needs_validation needs decisive next check and limits")
            if v["verification_tier"] in {"build", "runtime", "deployment"}:
                require(any(e["kind"] == v["verification_tier"] and e["result"] in {"pass", "fail"}
                            for e in proofs), "verification tier unsupported by executed evidence")
            if v["verification_tier"] == "source":
                require(source_proofs, "source verification tier needs source references")
            reviewer = v["reviewer"]
            if reviewer["independent"]:
                require(reviewer["identity"] != c["hunter"]["identity"]
                        and reviewer["context"] != c["hunter"]["context"], "self-review is not independent")
                proof = _attestation(v["independence_ref"], trusted, {
                    "kind": "independent_verification", "target": c["target"],
                    "revision": c["revision"], "finding_id": c["id"],
                    "candidate_sha256": f["candidate_sha256"], "verification_sha256": digest(v),
                    "reviewer": reviewer["identity"], "context": reviewer["context"],
                    "context_separated": True, "source_evidence_ids": v["source_evidence_ids"],
                }, "independent verification")
                require(proof.get("hunter_context") == c["hunter"]["context"], "wrong hunter context attestation")
            else:
                require(v["independence_ref"] is None, "self-review cannot claim independent reference")
        _validate_remediation(f, evidence, trusted)
        last = f["verifications"][-1]
        counts[last["verdict"]] += 1
        if last["severity"] in {"high", "critical"} and last["verdict"] != "rejected" and f["remediation"]["status"] != "fixed_verified":
            blockers.append(c["id"])
    if previous is not None:
        # Validate the retained snapshot schema, then require append-only history.
        validate_schema(previous, "findings-v0.5.schema.json")
        require(previous["target"] == data["target"] and previous["revision"] == data["revision"],
                "history must be from the same audit revision")
        current = {f["candidate"]["id"]: f for f in data["findings"]}
        for old in previous["findings"]:
            ident = old["candidate"]["id"]
            require(ident in current, "finding history deleted")
            new = current[ident]
            require(old["candidate"] == new["candidate"], "original candidate overwritten")
            require(new["verifications"][:len(old["verifications"])] == old["verifications"],
                    "verification history overwritten or rejection hidden")
        for old in previous["evidence"]:
            require(evidence.get(old["id"]) == old, "original evidence overwritten")
    return {"verdicts": counts, "unresolved_high_risk": blockers,
            "history_checked": previous is not None,
            "evidence_authenticity": "not_authenticated", "stable_release_ready": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--inventory", type=Path, help="Optional linked attack-surface artifact")
    args = parser.parse_args()
    try:
        result = validate(load_json(args.input), source_root=args.source_root,
                          previous=load_json(args.previous) if args.previous else None,
                          inventory=load_json(args.inventory) if args.inventory else None)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
