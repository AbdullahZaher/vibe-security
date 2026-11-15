#!/usr/bin/env python3
"""Validate a revision-bound, explicitly non-exhaustive attack-surface inventory."""
import argparse
from collections import Counter
import json
from pathlib import Path
from audit_artifacts import load_json, require, stable_id, unique_index, validate_schema, validate_source


def unit_id(target, unit):
    """Identity deliberately excludes revision, line numbers and discovery confidence."""
    return stable_id("inv-", target, unit["component"], unit["kind"], unit["entry_point"],
                     unit["source"]["path"], unit["boundary"])


def validate(data, source_root=None):
    validate_schema(data, "attack-surface.schema.json")
    unique_index(data["units"])
    verified = 0
    for unit in data["units"]:
        require(unit["id"] == unit_id(data["target"], unit), "inventory ID does not match stable identity")
        checked = validate_source(unit["source"], data["revision"], source_root)
        verified += checked
        require(unit["discovery_status"] != "inspected" or checked,
                "inspected inventory requires verified frozen source")
        require(unit["source"]["status"] != "not_verified" or unit["discovery_status"] == "not_verified",
                "unverified source must be explicit in discovery status")
    return {"target": data["target"], "revision": data["revision"],
            "discovered_in_scope_units": len(data["units"]), "verified_source_units": verified,
            "discovery_status": data["discovery"]["status"],
            "unit_discovery_counts": dict(Counter(u["discovery_status"] for u in data["units"])),
            "unknown_outside_inventory": True, "attack_surface_completeness": "unknown",
            "limitations": data["discovery"]["limitations"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--source-root", type=Path, help="Read immutable Git blobs, never execute target code")
    args = parser.parse_args()
    try:
        print(json.dumps(validate(load_json(args.input), args.source_root), indent=2))
    except (ValueError, OSError, KeyError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
