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
RESOLUTION_STATUS = {"open", "in_progress", "needs_approval", "fixed_verified", "false_positive_verified", "accepted_risk"}
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
    if result["status"] == "not_applicable":
        # A proposed fix is NOT proof that a control is irrelevant.
        # N/A must cite architecture-specific evidence at the reviewed revision
        # and a repeatable method (static inspection is allowed).
        applicable_proof = (
            revision not in {"", "not provided", "unspecified", None}
            and result.get("evidence_revision") == revision
            and result["evidence_tier"] in {"source", "build", "runtime", "deployment"}
            and all(isinstance(result.get(field), str) and result[field].strip()
                    for field in ("evidence", "not_applicable_reason", "test_method"))
        )
        if not applicable_proof:
            result["status"] = "not_verified"
            result["owner_action"] = (
                "N/A lacked architecture-specific evidence, a non-applicability "
                "rationale, a method and a matching revision."
            )
    if result["status"] in {"pass", "fixed_verified"}:
        current_revision = revision not in {"", "not provided", "unspecified", None}
        wrong_revision = not current_revision or result.get("evidence_revision") != revision
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
    # A report is not an attestation: all supplied evidence is a claim.
    revision = scope.get("revision", "not provided")
    logs = data.get("verification_log", [])
    findings = data.get("findings", [])
    if not isinstance(logs, list) or not isinstance(findings, list):
        raise ValueError("findings and verification_log must be arrays")
    if any(not isinstance(log, dict) or log.get("result", "not_run") not in TEST_RESULT
           for log in logs):
        raise ValueError("each verification_log row must have a valid result")
    log_by_id = {log.get("id"): log for log in logs
                 if isinstance(log.get("id"), str) and log.get("id")}
    checked_findings = []
    for issue in findings:
        if not isinstance(issue, dict) or issue.get("severity", "none") not in SEVERITY:
            raise ValueError("each finding must be an object with a valid severity")
        finding = dict(issue)
        state = finding.get("resolution_status", "open")
        if state not in RESOLUTION_STATUS:
            raise ValueError("invalid resolution_status on finding")
        if state in {"fixed_verified", "false_positive_verified"}:
            proof = log_by_id.get(finding.get("verification_ref"))
            valid = (
                revision not in {"", "not provided", "unspecified", None}
                and isinstance(proof, dict)
                and proof.get("revision") == revision
                and proof.get("result") == "pass"
                and proof.get("method") and proof.get("environment")
                and proof.get("observed")
                and finding.get("test_result") == "pass"
                and finding.get("evidence")
                and (finding.get("fix") if state == "fixed_verified"
                     else finding.get("disposition_justification"))
            )
            if not valid:
                state = "open"
                finding["verification_note"] = "Unsupported resolution downgraded to open."
        finding["resolution_status"] = state
        checked_findings.append(finding)

    unresolved_high_risk = any(
        row["severity"] in {"critical", "high"}
        and row["status"] in {"failed", "needs_approval", "not_verified"}
        for row in rows
    ) or any(
        finding["severity"] in {"critical", "high"}
        and finding["resolution_status"] not in {"fixed_verified", "false_positive_verified"}
        for finding in checked_findings
    )
    # A single successful test cannot clear 27 controls. Every claimed
    # PASS/fixed_verified must point to its own matching verification record.
    # This is a consistency check, not independent authentication.
    passed_controls = [row for row in rows if row["status"] in {"pass", "fixed_verified"}]
    verified_control_coverage = bool(passed_controls) and all(
        isinstance(row.get("verification_ref"), str)
        and bool(row["verification_ref"].strip())
        and any(
            log.get("id") == row["verification_ref"]
            and log.get("control_id") == row["id"]
            and log.get("revision") == revision
            and revision not in {"", "not provided", "unspecified", None}
            and log.get("result") == "pass"
            and all(isinstance(log.get(field), str) and log[field].strip()
                    for field in ("method", "environment", "observed"))
            for log in logs
        )
        for row in passed_controls
    )
    if unresolved_high_risk:
        recommendation = "block launch"
    elif recommendation == "no blockers found in tested scope" and (
        not verified_control_coverage
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
    weight = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "none": 5}
    for finding in sorted(checked_findings, key=lambda f: weight[f.get("severity", "none")]):
        result.extend([
            f"### {sanitized(finding.get('id', 'Unnumbered'))} — {sanitized(finding.get('title', 'Untitled'))}", "",
            f"- Control: {sanitized(finding.get('control', 'not specified'))}",
            f"- Severity: {sanitized(finding.get('severity', 'none'))}",
            f"- Resolution: {sanitized(finding.get('resolution_status', 'open'))}",
            f"- Verification reference: {sanitized(finding.get('verification_ref', 'not provided'))}",
            f"- Verification note: {sanitized(finding.get('verification_note', 'none'))}",
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
    result.extend([
        "| ID | Revision | Method / command | Environment | Expected | Observed | Result |",
        "|---|---|---|---|---|---|---|",
    ])
    for log in logs:
        if not isinstance(log, dict) or log.get("result", "not_run") not in TEST_RESULT:
            raise ValueError("each verification_log row must have a valid result")
        result.append("| " + " | ".join(sanitized(log.get(k, "—"))
             for k in ("id", "revision", "method", "environment", "expected", "observed", "result")) + " |")
    if not logs:
        result.append("| — | — | — | — | — | No tests recorded | not_run |")
    result += ["", "## Test details / limitations", "",
               "- A PASS requires actual execution evidence on the evaluated revision; this renderer does not run tests.",
               "- Evidence provenance values in the input are claims, not authenticated attestations.",
               "- High/critical issues are independent launch gates; a PASS alone is never a verified fix.",
               "- A scoped all-clear requires matching-revision evidence for every applicable PASS control; a single test cannot clear the matrix.",
               "- N/A requires documented architecture evidence and method at the reviewed revision; a proposed fix is not evidence.",
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
