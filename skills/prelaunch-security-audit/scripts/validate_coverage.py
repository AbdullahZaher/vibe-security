#!/usr/bin/env python3
"""Validate coverage evidence linkage; no artifact can authenticate its own claims."""
import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
from audit_artifacts import load_json, read_artifact, require, stable_id, unique_index, validate_schema, validate_source
from validate_attack_surface import validate as validate_inventory

STATES = ("covered", "partially_covered", "blocked", "deferred", "not_applicable", "unassessed")


def unit_id(unit):
    return stable_id("cov-", sorted(unit["inventory_ids"]), unit["boundary"], unit["attack_class"],
                     sorted(unit["actors"]), sorted(unit["resources"]))


def validate(data, inventory, source_root=None, artifact_root=None):
    discovery = validate_inventory(inventory, source_root)
    validate_schema(data, "coverage-ledger.schema.json")
    require(data["target"] == inventory["target"] and data["revision"] == inventory["revision"],
            "coverage target/revision differs from inventory")
    inv = unique_index(inventory["units"])
    units = unique_index(data["units"], "unit_id")
    evidence = unique_index(data["evidence"])
    verified_evidence = {}
    for proof in evidence.values():
        require(proof["unit_id"] in units, "evidence has foreign coverage unit")
        require(proof["target"] == data["target"] and proof["revision"] == data["revision"],
                "evidence target/revision mismatch")
        unit = units[proof["unit_id"]]
        try:
            recorded = datetime.fromisoformat(proof["timestamp"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("invalid evidence timestamp") from exc
        require(recorded.tzinfo is not None, "evidence timestamp needs timezone")
        require(proof["operator"] == unit["reviewer"], "evidence operator differs from assigned reviewer")
        require(proof["id"] in unit["evidence_ids"], "unlinked evidence")
        require(set(proof["inventory_ids"]) <= set(unit["inventory_ids"]) and
                set(proof["inventory_ids"]) <= inv.keys(), "foreign evidence inventory")
        require(proof["boundary"] == unit["boundary"], "evidence boundary mismatch")
        require(set(proof["actors"]) == set(unit["actors"]) and
                set(proof["resources"]) == set(unit["resources"]), "evidence actor/resource mismatch")
        require(proof["method"] == unit["verification_method"], "evidence method mismatch")
        checked_sources = []
        for source in proof["source_refs"]:
            require(any(source["path"] == inv[i]["source"]["path"] for i in proof["inventory_ids"]),
                    "evidence cites unrelated source")
            if validate_source(source, data["revision"], source_root):
                checked_sources.append(source)
        if proof["kind"] in {"source_inspection", "architecture_inspection"}:
            require(proof["tier"] == "source" and proof["result"] in {"observed", "inconclusive", "not_run", "blocked"},
                    "source inspection cannot claim executed PASS")
            checked = bool(checked_sources) and proof["result"] == "observed"
        else:
            require(proof["tier"] != "source" and proof["result"] != "observed", "invalid test evidence tier/result")
            checked = proof["result"] in {"pass", "fail"} and bool(checked_sources)
            if checked:
                require(proof["artifact"] is not None and artifact_root is not None,
                        "executed test evidence requires retained artifact and trusted artifact root")
        if proof["artifact"] is not None:
            require(artifact_root is not None, "artifact root required to verify evidence hash")
            require(source_root is not None, "source root required to verify evidence containment")
            source_root_resolved = Path(source_root).resolve()
            artifact_root_resolved = Path(artifact_root).resolve()
            require(source_root_resolved.is_dir() and artifact_root_resolved.is_dir(),
                    "source and artifact roots must be existing directories")
            retained = artifact_root_resolved / proof["artifact"]["path"]
            require(not retained.is_relative_to(source_root_resolved),
                    "retained evidence must be outside the target repository")
            raw = read_artifact(artifact_root, proof["artifact"]["path"])
            require(hashlib.sha256(raw).hexdigest() == proof["artifact"]["sha256"], "evidence artifact hash mismatch")
        # Require a concrete source trace for each referenced entry. One generic
        # suite or another endpoint's log cannot silently cover every route.
        verified_evidence[proof["id"]] = checked and all(
            any(source["path"] == inv[i]["source"]["path"] and
                source["line_start"] <= inv[i]["source"]["line_start"] and
                source["line_end"] >= inv[i]["source"]["line_end"] for source in checked_sources)
            for i in proof["inventory_ids"])
    represented = set()
    assessed = set()
    for unit in units.values():
        require(unit["unit_id"] == unit_id(unit), "coverage ID does not match stable identity")
        require(unit["revision"] == data["revision"], "coverage unit revision mismatch")
        require(set(unit["inventory_ids"]) <= inv.keys(), "dangling inventory reference")
        require(set(unit["evidence_ids"]) <= evidence.keys(), "dangling evidence reference")
        for entry in unit["inventory_ids"]:
            require(unit["boundary"] == inv[entry]["boundary"], "coverage boundary differs from inventory")
            require(set(unit["actors"]) <= set(inv[entry]["actors"]) and
                    set(unit["resources"]) <= set(inv[entry]["resources"]), "coverage actor/resource outside inventory")
        proofs = [evidence[e] for e in unit["evidence_ids"]]
        require(all(p["unit_id"] == unit["unit_id"] for p in proofs), "cross-unit evidence reuse")
        represented.update(unit["inventory_ids"])
        if unit["status"] in {"covered", "not_applicable"}:
            require(proofs and all(verified_evidence[p["id"]] for p in proofs), "unsupported coverage claim")
            linked = {i for p in proofs for i in p["inventory_ids"]}
            require(linked == set(unit["inventory_ids"]), "not all inventory entries have evidence")
            if unit["status"] == "not_applicable":
                require(all(p["kind"] == "architecture_inspection" for p in proofs), "N/A requires architecture inspection")
                require(unit["rationale"].strip().lower() not in {"not tested", "not run", "unknown", "n/a", "not applicable"},
                        "N/A requires project-specific architectural rationale")
            assessed.update(unit["inventory_ids"])
        if unit["status"] in {"blocked", "deferred", "unassessed"}:
            require(not any(verified_evidence[p["id"]] for p in proofs), "contradictory unassessed/blocked coverage")
    counts = Counter(u["status"] for u in units.values())
    return {"target": data["target"], "revision": data["revision"], "mode": data["mode"],
            "coverage_counts": {state: counts[state] for state in STATES},
            "discovered_in_scope_units": len(inv), "represented_inventory_units": len(represented),
            "inventory_with_assessment": len(assessed), "inventory_without_ledger": sorted(inv.keys() - represented),
            "unknown_outside_inventory": True, "attack_surface_completeness": "unknown",
            "discovery": discovery, "evidence_authenticity": "not_verified"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--artifact-root", type=Path, help="Protected retained evidence outside target")
    args = parser.parse_args()
    try:
        print(json.dumps(validate(load_json(args.input), load_json(args.inventory), args.source_root, args.artifact_root), indent=2))
    except (ValueError, OSError, KeyError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
