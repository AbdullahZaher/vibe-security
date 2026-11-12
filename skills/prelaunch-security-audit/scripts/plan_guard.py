#!/usr/bin/env python3
"""Advisory classifier for proposed security-audit actions. DOES NOT execute."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / "policy/action-policy.json").read_text(encoding="utf-8"))
VALID = set(POLICY["actions"])
SHELL_META = re.compile(r"[;&|`\n\r]|\$\(|<\(|>\(")


def evaluate(plan: dict) -> dict:
    if not isinstance(plan, dict) or not isinstance(plan.get("actions"), list):
        raise ValueError("plan must contain an actions array")
    actions = plan["actions"]
    if len(actions) > POLICY["max_actions"]:
        raise ValueError("too many actions")
    decisions = []
    for i, item in enumerate(actions, 1):
        if not isinstance(item, dict):
            raise ValueError(f"action {i} must be an object")
        kind = item.get("class")
        if kind not in VALID:
            decisions.append({"index": i, "decision": "deny", "reason": "unknown action class"})
            continue
        command = item.get("command", "")
        if not isinstance(command, str) or len(command) > 2000:
            decisions.append({"index": i, "decision": "deny", "reason": "invalid command"})
            continue
        lower = " ".join(command.lower().split())
        forbidden = any(x in lower for x in POLICY["forbidden_commands"])
        if forbidden or SHELL_META.search(command):
            decisions.append({"index": i, "decision": "deny", "reason": "dangerous or shell-composed command"})
            continue
        decision = POLICY["actions"][kind]
        reason = "policy default: requires host/user action-specific approval" if decision == "ask" else "policy default"
        if kind == "observe" and command and lower not in POLICY["allowed_observe_commands"]:
            decision, reason = "ask", "observation command is not on narrow allowlist"
        if command and kind == "observe" and any(
            re.search(r"(?<![A-Za-z0-9_-])" + re.escape(x) + r"(?![A-Za-z0-9_-])", lower)
            for x in POLICY["high_risk_tools"]
        ):
            decision, reason = "ask", "potentially executable operation disguised as observation"
        if kind in {"network_read", "external_write"} and not item.get("destination"):
            decision, reason = "deny", "missing explicit remote destination"
        if kind in {"modify_local", "external_write"} and not item.get("target"):
            decision, reason = "deny", "missing specific target"
        decisions.append({"index": i, "decision": decision, "reason": reason})
    summary = {d: sum(x["decision"] == d for x in decisions) for d in ("allow", "ask", "deny")}
    return {"policy": "advisory-only", "decisions": decisions, "summary": summary,
            "notice": "This classifier does not grant tool permissions or execute actions."}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.plan.stat().st_size > 200_000:
            raise ValueError("plan too large")
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
        result = evaluate(plan)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    if result["summary"]["deny"]:
        return 2
    if result["summary"]["ask"]:
        return 3
    return 0

if __name__ == "__main__":
    sys.exit(main())
