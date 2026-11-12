#!/usr/bin/env python3
"""Render a 27-control, evidence-aware markdown report from structured JSON.

Input is owned/trusted by the reviewer; obvious credential-like text is
redacted, but no automated redaction can guarantee removal of every secret.
Review the generated report before publishing or sharing it.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import html
import json
from pathlib import Path
import re
from typing import Any

CONTROLS = [
    "Authentication", "Protect API keys", "Secure database access",
    "Enforce HTTPS", "Hash passwords", "Server-side validation",
    "Protect against XSS", "Logging and monitoring", "Restrict admin routes",
    "Parameterized queries", "Check environment variables", "Rate limiting",
    "Restrict CORS", "Security headers", "Secure cookies", "CSRF protection",
    "Expiring password reset links", "Restrict file uploads",
    "Verify prices and payments", "Disable debug in production",
    "Update vulnerable dependencies", "Remove unused packages",
    "Check for exposed files", "Scan Git history", "Revoke and replace keys",
    "Integrated security review", "Test and report",
]
STATUS = {"pass", "fixed_verified", "failed", "needs_approval", "not_applicable", "not_verified"}
SEVERITY = {"critical", "high", "medium", "low", "informational", "none"}
TEST_RESULT = {"pass", "fail", "blocked", "not_run"}
EVIDENCE_TIER = {"source", "build", "runtime", "deployment", "unspecified"}
SECRET_PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.S),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b(?:password|api[_-]?key|secret|access[_-]?token)\s*[:=]\s*[^\s,;]+", re.I),
]


def sanitized(value: Any) -> str:
    text = str(value) if value is not None else "—"
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    text = re.sub(r"[\x00-\x1f\x7f]", " ", text)
    # Escape Markdown formatting and links as well as raw HTML.
    text = html.escape(text, quote=False)
    for char in ("\\", "|", "[", "]", "`", "*"):
        text = text.replace(char, "\\" + char)
    return text.strip() or "—"


def _validate_control(row: Any, index: int, revision: str = "not provided") -> dict[str, Any]:
    if not isinstance(row, dict):
        raise ValueError(f"control #{index} must be an object")
    result = dict(row)
    expected_id = f"{index:02d}"
    if str(result.get("id", "")) != expected_id:
        raise ValueError(f"control #{index} must have id {expected_id}")
    for field, valid, default in (
        ("status", STATUS, "not_verified"),
        ("severity", SEVERITY, "none"),
        ("test_result", TEST_RESULT, "not_run"),
    ):
        result.setdefault(field, default)
        if result[field] not in valid:
            raise ValueError(f"invalid {field} on control {expected_id}: {result[field]!r}")
    result.setdefault("evidence_tier", "unspecified")
    if result["evidence_tier"] not in EVIDENCE_TIER:
        raise ValueError(f"invalid evidence_tier on control {expected_id}")
    if result["status"] == "not_applicable" and not (
        result.get("evidence") or result.get("fix")
    ):
        result["status"] = "not_verified"
        result["owner_action"] = "Non-applicability was not justified; record architecture-specific evidence."
    if result["status"] in {"pass", "fixed_verified"}:
        current_revision = revision not in {"", "not provided", "unspecified", None}
        wrong_revision = current_revision and result.get("evidence_revision") != revision
        if (result["test_result"] != "pass" or not result.get("test_method")
                or not result.get("evidence") or wrong_revision):
            result["status"] = "not_verified"
            result["test_result"] = "not_run"
            result["owner_action"] = (
                "Original claimed pass lacked a passing test, test method, "
                "or evidence on the evaluated revision; verify before approval."
            )
    return result


def render(data: dict[str, Any]) -> str:
    if not isinstance(data, dict) or not isinstance(data.get("controls"), list):
        raise ValueError("input must be an object with a 'controls' array")
    provided = data["controls"]
    if len(provided) != 27:
        raise ValueError("provide exactly 27 controls in order, including unverified ones")
    scope = data.get("scope", {})
    if not isinstance(scope, dict):
        raise ValueError("scope must be an object")
    rows = [_validate_control(row, i, scope.get("revision", "not provided"))
            for i, row in enumerate(provided, 1)]
    recommendation = data.get("launch_recommendation", "conditional launch")
    if recommendation not in {"block launch", "conditional launch", "no blockers found in tested scope"}:
        raise ValueError("invalid launch_recommendation")
    # Recommendations are conservative regardless of the input's requested label.
    # A high-severity unresolved/untested control is not safe to clear.
    unresolved_high_risk = any(
        row["severity"] in {"critical", "high"}
        and row["status"] in {"failed", "needs_approval", "not_verified"}
        for row in rows
    )
    # The renderer cannot authenticate claims in the input. Conservatively
    # require a verification log before accepting even a scoped all-clear.
    has_verification_log = bool(data.get("verification_log"))
    if unresolved_high_risk:
        recommendation = "block launch"
    elif recommendation == "no blockers found in tested scope" and (
        not has_verification_log
        or any(row["status"] in {"failed", "needs_approval", "not_verified"}
               for row in rows)
    ):
        recommendation = "conditional launch"
    result = [
        "# Prelaunch Security Review", "",
        "> Evidence-based project review, not a security certification or penetration test.", "",
        "## Scope", "",
        f"- Project: {sanitized(scope.get('project', 'not specified'))}",
        f"- Revision: {sanitized(scope.get('revision', 'not specified'))}",
        f"- Environment: {sanitized(scope.get('environment', 'not specified'))}",
        f"- Generated (UTC): {datetime.now(timezone.utc).isoformat()}",
        f"- Limitations: {sanitized(scope.get('limitations', 'not specified'))}",
        "", "## Launch recommendation", "",
        f"**{sanitized(recommendation).upper()}**", "",
        "## 27-point control matrix", "",
        "| ID | Control | Status | Severity | Evidence | Provenance | Fix | Test | Owner action |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for i, row in enumerate(rows):
        cells = [f"{i+1:02d}", CONTROLS[i], row["status"], row["severity"],
                 row.get("evidence", "—"),
                 f"{row['evidence_tier']} @ {row.get('evidence_revision', 'not specified')}",
                 row.get("fix", "—"),
                 f"{row['test_result']} ({row.get('test_method', 'not provided')})",
                 row.get("owner_action", "—")]
        result.append("| " + " | ".join(sanitized(x) for x in cells) + " |")
    result += ["", "## Open issues and approvals", ""]
    issues = [r for r in rows if r["status"] in {"failed", "needs_approval", "not_verified"}]
    if issues:
        for row in issues:
            result.append(f"- **Control {sanitized(row['id'])}** "
                          f"({sanitized(row['status'])}, {sanitized(row['severity'])}): "
                          f"{sanitized(row.get('owner_action', 'Review the evidence and test coverage.'))}")
    else:
        result.append("- No unresolved controls recorded in the provided data; assess evidence quality separately.")
    result += ["", "## Findings by severity", ""]
    findings = data.get("findings", [])
    if not isinstance(findings, list):
        raise ValueError("findings must be an array")
    weight = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "none": 5}
    for finding in findings:
        if not isinstance(finding, dict) or finding.get("severity", "none") not in SEVERITY:
            raise ValueError("each finding must be an object with a valid severity")
    if recommendation != "block launch" and any(
        finding.get("severity") in {"critical", "high"}
        and finding.get("test_result", "not_run") != "pass"
        for finding in findings
    ):
        # Heading is already added above; fail closed rather than silently
        # contradicting the detailed findings.
        new_heading = "**BLOCK LAUNCH**"
        heading_index = result.index("## Launch recommendation") + 2
        result[heading_index] = new_heading
    for finding in sorted(findings, key=lambda f: weight[f.get("severity", "none")]):
        result.extend([
            f"### {sanitized(finding.get('id', 'Unnumbered'))} — {sanitized(finding.get('title', 'Untitled'))}", "",
            f"- Control: {sanitized(finding.get('control', 'not specified'))}",
            f"- Severity: {sanitized(finding.get('severity', 'none'))}",
            f"- Evidence: {sanitized(finding.get('evidence', 'not provided'))}",
            f"- Mitigation/fix: {sanitized(finding.get('fix', 'not provided'))}",
            f"- Verification: {sanitized(finding.get('test_result', 'not_run'))}"
            f" ({sanitized(finding.get('test_method', 'not specified'))})",
            f"- Residual risk: {sanitized(finding.get('residual_risk', 'not assessed'))}",
            "",
        ])
    if not findings:
        result.append("- No detailed findings supplied; a blank example is not evidence of safety.")
    result += ["", "## Changed files", ""]
    changes = data.get("changed_files", [])
    if not isinstance(changes, list):
        raise ValueError("changed_files must be an array")
    result.extend(f"- {sanitized(path)}" for path in changes)
    if not changes:
        result.append("- No changed files recorded.")
    result += ["", "## Verification log", ""]
    logs = data.get("verification_log", [])
    if not isinstance(logs, list):
        raise ValueError("verification_log must be an array")
    result.extend([
        "| Method / command | Environment | Expected | Observed | Result |",
        "|---|---|---|---|---|",
    ])
    for log in logs:
        if not isinstance(log, dict) or log.get("result", "not_run") not in TEST_RESULT:
            raise ValueError("each verification_log row must have a valid result")
        result.append("| " + " | ".join(sanitized(log.get(k, "—"))
             for k in ("method", "environment", "expected", "observed", "result")) + " |")
    if not logs:
        result.append("| — | — | — | No tests recorded | not_run |")
    result += ["", "## Test details / limitations", "",
               "- A PASS requires actual execution evidence on the evaluated revision; this renderer does not run tests.",
               "- Evidence provenance values in the input are claims, not authenticated attestations.",
               "- Review redactions, scope and all test evidence before distributing.",
               "- Check untested environments and independent security review needs before launch.", ""]
    return "\n".join(result)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.input.stat().st_size > 2_000_000:
            raise ValueError("input too large (max 2 MB)")
        data = json.loads(args.input.read_text(encoding="utf-8"))
        content = render(data)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(content, encoding="utf-8")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(f"Generated report: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
