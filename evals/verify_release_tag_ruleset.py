#!/usr/bin/env python3
"""Read-only checks for a GitHub release-tag ruleset JSON snapshot.

Rejects the common mistake "update + deletion rules means tag creation is
restricted". The file supplied must contain FULL GitHub REST ruleset details,
not the abbreviated list response. It does not authenticate origin, identity,
API permissions, live state, human release authorization, or tag creation rights.

Use only independently fetched live details from GitHub (not self-authored
manifests) to inform a human release decision. Always fail closed on unknown.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

EXACT_TAG_SCOPE = "refs/tags/v*"
ALLOWED_PUBLISHERS = frozenset({"User", "Integration"})


def _scope(rule: dict) -> bool:
    if rule.get("target") != "tag" or rule.get("enforcement") != "active":
        return False
    conditions = rule.get("conditions")
    if not isinstance(conditions, dict):
        return False
    ref = conditions.get("ref_name")
    return (isinstance(ref, dict) and ref.get("include") == [EXACT_TAG_SCOPE]
            and ref.get("exclude") == [])


def _types(rule: dict) -> set[str]:
    rules = rule.get("rules")
    if not isinstance(rules, list) or not all(isinstance(r, dict) for r in rules):
        return set()
    return {r.get("type") for r in rules if isinstance(r.get("type"), str)}


def evaluate(rulesets: object) -> dict:
    if not isinstance(rulesets, list):
        raise ValueError("expected a list of full GitHub ruleset details")
    immutable = []
    controlled_create = []
    for rule in rulesets:
        if not isinstance(rule, dict) or not _scope(rule):
            continue
        kinds = _types(rule)
        bypass = rule.get("bypass_actors")
        # Abbreviated list responses omit bypass_actors and rules; never pass.
        if not isinstance(bypass, list):
            continue
        if {"update", "deletion"}.issubset(kinds) and not bypass:
            immutable.append(rule.get("id"))
        # Creation-only ruleset: an authorized named publisher may CREATE,
        # but must NOT gain permission to mutate existing immutable tags.
        if kinds == {"creation"} and bypass:
            allowed = True
            for actor in bypass:
                if (not isinstance(actor, dict)
                    or actor.get("actor_type") not in ALLOWED_PUBLISHERS
                    or type(actor.get("actor_id")) is not int
                    or actor["actor_id"] <= 0
                    or actor.get("bypass_mode") != "always"):
                    allowed = False
            if allowed:
                controlled_create.append(rule.get("id"))
    blocked = []
    if not immutable:
        blocked.append("No active immutable v* tag update+deletion ruleset with zero bypass actors")
    if not controlled_create:
        blocked.append("No active v* tag CREATION-only ruleset with an explicitly named release publisher bypass")
    return {
        "status": "CONFIGURATION_SNAPSHOT_MATCH_ONLY" if not blocked else "BLOCK_TAG_GOVERNANCE",
        "tags_scope": EXACT_TAG_SCOPE,
        "immutable_ruleset_ids": immutable,
        "creation_ruleset_ids": controlled_create,
        "verified_live_with_github": False,
        "authorized_publisher_identity_verified": False,
        "human_approval_verified": False,
        "stable_release_authorized": False,
        "blockers": blocked,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--details", type=Path, required=True,
                        help="JSON list of full REST GET /repos/.../rulesets/{id} results")
    args = parser.parse_args()
    try:
        if args.details.stat().st_size > 1_000_000:
            raise ValueError("snapshot file too large")
        result = evaluate(json.loads(args.details.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError) as exc:
        print("TAG GOVERNANCE UNVERIFIED: " + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 2 if result["blockers"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
