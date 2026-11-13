## v0.4.0-rc1 — proposed, unmerged

- Tighten 27-control release gating: reject unsupported N/A, unrelated test logs,
  duplicate verification IDs and findings verified against another finding's log.
- Correct the Agent evaluator's N/A denominators: independently reviewed
  non-exercised capabilities remain N/A, can be non-blocking only when case
  expectations explicitly exclude them, and do not become fictitious 100%.
- Upgrade the MCP CI SDK from vulnerable 2.1.0 to patched 2.2.0
  (GHSA-rwrf-2pqf-9j8j / CVE-2026-116686).
- Encrypt synthetic private reviewer evidence with AES-256-GCM using a
  separately stored `EVAL_EVIDENCE_KEY` before a 24-hour GitHub artifact
  upload; added tamper, redaction and permission tests. Manual paid dispatch
  remains unavailable until the workflow exists on the default branch; do not
  merge this Draft PR without explicit approval.

- Fix release gating for unresolved high/critical detailed findings and enforce revision-consistent report evidence.
- Add negative regression tests for forged PASS and unverified fix claims.
- Add offline agent telemetry scoring and synthetic regression fixtures (not real agent performance scores).
- Add 20 isolated synthetic scenario fixtures, a guarded real-model Responses tool-loop, optional private reviewer artifacts, and explicit manual-only billable GitHub Actions dispatch. No actual model run has been recorded.
- Add optional real SDK v2 MCP stdio smoke test, quick PR mode and stack-specific playbooks.

# Changelog

## 0.3.0 — proposed (2026-11-13)

- Added action classification and advisory plan guard with deny/ask/allow decisions.
- Documented evidence tiers, revision binding, and report-honesty guidance.
- Added OWASP ASVS, NIST SSDF, OpenSSF and SLSA reference mapping.
- Expanded agent-in-the-loop evaluation corpus from 8 to 20 scenarios.
- Hardened GitHub Actions to pinned action commits and disabled checkout credential persistence.
- Expanded prompt-injection and MCP confused-deputy / token-audience threat model.
- Added tests for the new guard. See `docs/research-implementation-v0.3.0.md`.

## 0.2.0

- Initial public 27-control skill with offline preflight, report generation and optional read-only MCP adapter.
