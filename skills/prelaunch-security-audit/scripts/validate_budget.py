#!/usr/bin/env python3
"""Validate declared resource accounting; does not meter usage or authorize costs."""
import argparse
import json
import math
from pathlib import Path

from audit_artifacts import load_json, validate_schema

METRICS = ("tool_calls", "steps", "tokens", "cost_usd", "wall_seconds")


def validate(data):
    validate_schema(data, "audit-budget.schema.json")
    if data["profile"] == "quick" and data["coverage_scope"] != "partial":
        raise ValueError("quick profile must report partial coverage")
    if len(data["deferred_unit_ids"]) != len(set(data["deferred_unit_ids"])):
        raise ValueError("duplicate deferred unit IDs")
    if not data["target"].strip():
        raise ValueError("target required")
    exceeded = []
    for metric in METRICS:
        actual, reference = data["usage"][metric], data["measurement_refs"][metric]
        for value in (actual, data["limits"][metric]):
            if value != "unknown" and not math.isfinite(value):
                raise ValueError("usage and limits must be finite")
        if not reference.strip():
            raise ValueError("measurement references cannot be blank")
        if (actual == "unknown") != (reference == "unknown"):
            raise ValueError("measured usage requires a measurement reference; absent usage is unknown")
        if metric in {"tool_calls", "steps", "tokens"}:
            for value in (actual, data["limits"][metric]):
                if value != "unknown" and (type(value) is not int or value < 0):
                    raise ValueError("count metrics must be nonnegative integers or unknown")
        if actual != "unknown" and data["limits"][metric] != "unknown" and actual > data["limits"][metric]:
            exceeded.append(metric)
    if (data["limits"]["steps"] != "unknown"
            and data["confirmation_reserve_steps"] > data["limits"]["steps"]):
        raise ValueError("confirmation reserve exceeds total step limit")
    return {"profile": data["profile"], "coverage_scope": data["coverage_scope"],
            "budget_exceeded": exceeded, "deferred_unit_ids": data["deferred_unit_ids"],
            "usage": data["usage"], "complete_attack_surface": False,
            "notice": "Structural accounting only; references are not authenticated measurements or spending approval."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = validate(load_json(args.input))
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    return 1 if result["budget_exceeded"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
