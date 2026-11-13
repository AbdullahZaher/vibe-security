# Prelaunch Security Review

> **This is a template, not a certification.** Never insert PASS for unrun tests.

## Scope
- Project / revision:
- Owner-approved repositories and environments:
- Date:
- Framework / auth / database / deployment:
- Tools actually used:
- Limitations:

## Executive Summary
- Launch recommendation: **BLOCK LAUNCH / CONDITIONAL LAUNCH / NO BLOCKERS FOUND IN TESTED SCOPE**
- Verified critical/high issues:
- Fixed and verified:
- Open approvals:
- Unverified areas:

## 27-Point Control Matrix
| ID | Control | Status | Severity | Evidence | Fix | Test result | Owner action |
|---|---|---|---|---|---|---|---|
| 01 | Authentication | not_verified | none | — | — | not_run | — |
<!-- Complete every row 01–27; never silently omit checks. -->

## Findings by Severity
### F-001 — <title>
- Control:
- Severity / rationale:
- Evidence (redacted):
- Root cause:
- Changes made or proposed:
- Resolution status: open / in_progress / needs_approval / fixed_verified / false_positive_verified / accepted_risk
- Verification reference: matching verification_log[].id + revision + successful observed result (still a claim)
- Test command / expected / observed:
- Residual risk:
- Approval required:

## Changed Files
- (exact paths and rationale)

## Verification Log
| Command or method | Environment | Exit / observed | Result | Notes |
|---|---|---|---|---|

## Approvals and Manual Actions
- [ ] Owner decision / provider action / rollback plan

## Limitations and Residual Risk
- (unavailable tests, third-party dependencies, manual pentest advisability)

## Evidence consistency before a scoped all-clear

For each `not_applicable` control, supply `not_applicable_reason`, architecture
`evidence`, `test_method`, `evidence_tier` and matching `evidence_revision`.
For each `pass` or `fixed_verified` control, supply `verification_ref` to a
specific `verification_log[].id` with matching `control_id`, revision,
method/environment/observed and PASS. For resolved findings, logs must also
specify the matching `finding_id`. A single generic PASS or all-N/A report
cannot establish an all-clear; these remain reviewable claims, not attestations.
