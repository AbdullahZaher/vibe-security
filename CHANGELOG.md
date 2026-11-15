## v0.5.0-rc1 — engineering candidate (2026-11-14, feature branch)

- Add strict, revision-bound inventory and coverage schemas/validators with
  deterministic IDs, explicit discovery limits, source-blob integrity and
  evidence scope/actor/resource linkage; reject misleading completeness claims.
- Add Standard/Deep finding adjudication with separate verdict, severity,
  confidence and tier, retained history comparison and optional trusted-host
  independence checks. Static proof remains supported.
- Add remediation invariant preservation, exact scoped approval, baseline,
  post-fix and adjacent role/resource verification requirements.
- Separate authorization from execution isolation; provide a capability-limited
  static host and host-observed denial regressions. No arbitrary-code OS sandbox
  is supplied or claimed; plan_guard remains advisory.
- Add conservative revision/dependency impact analysis, budget accounting and
  explicit unknown/deferred work; add focused optional AI/tool-boundary guidance.
- Bound artifact sizes/nesting, require UTF-8 JSON, reject symlink/traversal
  escapes, and create reports privately without overwriting existing files.
- Integrate optional artifacts into legacy 27-control reports. Unsupported PASS
  rows now downgrade individually; duplicate finding IDs are rejected. Existing
  report shape remains accepted; see migration guide for evidence additions.
- Add A/B/C protocol and release-gate infrastructure; synthetic/controller tests
  cannot satisfy stable release. Actual model trials and independent maintainer
  review remain pending. No vulnerability-detection performance claim is made.

## v0.4.0-rc2 — general-purpose audit hardening (proposed, unmerged)

- Add adaptive, hypothesis-driven attack-surface discovery before the 27 controls,
  covering host/container listener exposure without claiming that a wildcard
  binding alone proves remote exploitability.
- Tighten CSP evaluation to effective response policies, nonce/hash/fallback
  semantics, and architecture-aware risk instead of blanket pass/fail guesses.
- Add optional **offline** Supabase migration ID parity comparison with bounded,
  non-symlink inputs, drift/duplicate detection and seven unit tests. The
  filename-only preflight remains unchanged; no database connection or
  migrations are performed.
- Improve limited-evidence handoff with explicitly unexecuted, authorized next
  commands and differentiate security vulnerabilities from build/test issues.
- Changes are generalized from a single case study; no new real-world Agent
  benchmark or deployment verification is claimed.

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
