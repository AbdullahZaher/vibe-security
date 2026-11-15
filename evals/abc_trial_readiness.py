#!/usr/bin/env python3
"""Offline 45-slot A/B/C evidence readiness inventory: NO inference, NO approval.

This tool inventories case × arm × repetition slots. It never runs a model,
reads private host traces, authenticates a reviewer or certifies a release.
For authenticated trial review use evaluate_trial_matrix.evaluate() with a
trusted host-owned attestation provider. Model-supplied flags are NOT authority.

Exit code 2 means mandatory release evidence is incomplete. Exit code 0 means
the *structural inventory* is present, never that stable release is approved.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from evaluate_trial_matrix import validate_protocol, evaluate, fingerprint

ARMS = ("A", "B", "C")
SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
MAX_INPUT_BYTES = 2_000_000


def load_bounded(path: Path) -> object:
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("input too large")
    return json.loads(path.read_text(encoding="utf-8"))


def plan(protocol: dict, trials: list | None = None) -> dict:
    cases = validate_protocol(protocol)
    if len(cases) < 5 or protocol["repetitions"] < 3:
        raise ValueError("release requires >=5 cases and >=3 repetitions")
    if any(protocol["budget"][k] == "unknown" for k in
           ("max_steps", "max_output_tokens", "max_cost_usd")):
        raise ValueError("paid evaluation requires explicit numerical budget before scheduling")
    if not isinstance(trials, list) and trials is not None:
        raise ValueError("trials must be an array")
    trials = [] if trials is None else trials
    # Existing evaluator performs strict schema, repetition, distinct-context,
    # source-identity, common settings, log hash and numeric usage validation.
    result = evaluate(protocol, trials)  # trusted host callback deliberately absent
    known = {(t["case_id"], t["arm"], t["repetition"]): t for t in trials}
    slots = []
    for case in sorted(cases):
        for arm in ARMS:
            for repetition in range(1, protocol["repetitions"] + 1):
                row = known.get((case, arm, repetition))
                slots.append({
                    "case_id": case, "arm": arm, "repetition": repetition,
                    "source_revision": cases[case]["source_revision"],
                    "skill_revision": protocol["arms"][arm],
                    "status": "CLAIMED_UNVERIFIED" if row else "NOT_SUBMITTED",
                    "trial_id": row["id"] if row else None,
                    "accepted_as_independent_trial": False,
                })
    submitted = sum(x["status"] == "CLAIMED_UNVERIFIED" for x in slots)
    return {
        "protocol_sha256": fingerprint(protocol),
        "status": "BLOCK_STABLE_RELEASE",
        "plan_only": True,
        "provider_requests_executed": 0,
        "expected_slots": len(slots),
        "developer_submitted_slots": submitted,
        "independently_authenticated_slots": 0,
        "unsubmitted_slots": len(slots) - submitted,
        "test_evaluator_blockers": result["blockers"][:7],
        "release_authorized": False,
        "independent_host_and_human_verification_required": True,
        "slots": slots,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, required=True,
                        help="Private frozen protocol (not public ground truth)")
    parser.add_argument("--trials", type=Path, help="Optional untrusted candidate trial array")
    args = parser.parse_args()
    try:
        protocol = load_bounded(args.protocol)
        trials = load_bounded(args.trials) if args.trials is not None else None
        result = plan(protocol, trials)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.error("invalid trial evidence: " + str(exc))
    print(json.dumps(result, indent=2))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
