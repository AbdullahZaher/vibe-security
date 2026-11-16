#!/usr/bin/env python3
"""Fail-closed v0.5 stable-release evidence gate.

This CLI audits the *shape* and completeness of developer assertions. It does
not authenticate provider traces, Seatbelt tests, human identity or permissions,
so it deliberately cannot issue APPROVE_FOR_STABLE_RELEASE. Trusted release
controllers must authenticate those records out-of-band and reuse
evaluate_trial_matrix.evaluate(..., attest=host_callback).

Exit 2 = release blocked; exit 1 = malformed evidence/usage; never exits 0.
No model calls, network activity, shell execution, or write access.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
REQUIRED_CASES = 5
ARMS = ("A", "B", "C")
REPETITIONS = 3
REQUIRED_TRIALS = REQUIRED_CASES * len(ARMS) * REPETITIONS


def evaluate_claims(metrics: dict) -> dict:
    """Return *untrusted* claim consistency observations, not an attestation."""
    if not isinstance(metrics, dict) or not isinstance(metrics.get("conditions"), dict):
        raise ValueError("metrics needs conditions object")
    conditions = metrics["conditions"]
    blockers = [
        "No authenticated host-side A/B/C trial matrix and independent adjudication was provided",
        "No independent source/target revision and ground-truth attestations were provided",
        "No final-revision runtime negative evidence with signed host provenance was provided",
        "No named human security reviewer and release-owner sign-off was provided",
    ]
    if set(conditions) != set(ARMS):
        raise ValueError("three conditions A/B/C are required")
    for arm in ARMS:
        c = conditions[arm]
        if not isinstance(c, dict) or type(c.get("real_trials_completed")) is not int:
            raise ValueError("invalid real_trials_completed for condition " + arm)
        if c["real_trials_completed"] < REQUIRED_CASES * REPETITIONS:
            blockers.append(
                f"Condition {arm}: fewer than {REQUIRED_CASES * REPETITIONS} declared independent trials"
            )
    c_revision = conditions["C"].get("source_revision")
    if not isinstance(c_revision, str) or not SHA.fullmatch(c_revision):
        blockers.append("Condition C revision is mutable or missing (must be a full Git SHA)")
    for arm in ("B", "C"):
        if not isinstance(conditions[arm].get("source_revision"), str):
            blockers.append("Condition " + arm + " source revision missing")
    return {
        "release_decision": "BLOCK_STABLE_RELEASE",
        "stable_release_ready": False,
        "trusted_host_attestations_supplied": False,
        "independent_human_signoff_verified": False,
        "protocol_minimum": {"cases": REQUIRED_CASES, "arms": 3,
                             "repetitions_per_case_and_arm": REPETITIONS,
                             "expected_independent_trials": REQUIRED_TRIALS},
        "claim_only": {"declared_session_count": sum(
            int(conditions[arm]["real_trials_completed"]) for arm in ARMS),
            "condition_c_source_revision": c_revision,
            "scoring_status": "unverified_developer_assertions"},
        "blockers": blockers,
        "notice": "PASS in unit CI or plausible precision/recall JSON is not a stable-release attestation.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metrics", type=Path, required=True)
    args = parser.parse_args()
    try:
        # Existing developer report is public data, never a trusted credential.
        if args.metrics.stat().st_size > 1_000_000:
            raise ValueError("metrics file over size limit")
        metrics = json.loads(args.metrics.read_text(encoding="utf-8"))
        result = evaluate_claims(metrics)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.error(type(exc).__name__ + ": invalid metrics (no release decision granted)")
    print(json.dumps(result, indent=2))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
