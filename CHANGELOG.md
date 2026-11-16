## v0.5.0-rc1 — independent release assurance corrections (PR #3, not a stable release)

- Verified GitHub Actions run `43760303379` totals: **299 tests, 267 passed, 32 skipped, 0 failed** in unit/contract on Linux (277 passed, 22 skipped on macOS); separate MCP integration passed and live model job skipped.
- Verified candidate commit `cd83271a604ffeb5ed38cd403c7b82b289243fe1`; Git root tree `b3f29ccf15340b5a15e7c4c5d832d730e7ce40be`; Skill subtree `77585b64825659a5b2198c3701ea2e2aeeb1f53c`.
- Enforced active GitHub branch protections on `main` and `feat/prelaunch-security-audit-v0.5.0-plan-20261114` (PR requirement, 1 human approval, dismiss stale, signed commits, linear history, status checks `unit-and-contract` and `mcp-stdio-integration`, enforce_admins). Created active tag ruleset 27351357 (`Protect Release Tags` targeting `refs/tags/v*`).
- Re-executed macOS 10 negative security tests on macOS 15.7.3 arm64 at candidate commit `cd83271a604ffeb5ed38cd403c7b82b289243fe1`; 10/10 tests passed (100% pass rate).
- Preserved original independent security finding IDs `IR-001`..`IR-015` with canonical classifications in `docs/security/v0.5.0-original-findings-crosswalk.json`.
- Implemented zero-cost 45-slot trial readiness inventory in `evals/abc_trial_readiness.py`; 0/45 real trials authenticated; execution gate marked `BLOCKED_PENDING_AUTHORIZATION`.
- Fix release rollback command syntax; prohibit removing the durable approval consumption ledger to revoke authorizations.
- Stable remains **NO-GO**; no merge, tag or publication authorized.

## v0.5.0-rc1 — developer-remediation and release-evidence draft (2026-11-15, PR #3)

- **Fail-Closed Runtime Isolation (IR-002, IR-003, IR-005):** Disabled untrusted subprocess execution in `IsolatedHostAdapter.dispatch()`. Empirically verified POSIX `setsid()` escape limitation on macOS Seatbelt; documented that Darwin `sandbox-exec` lacks cgroup resource quotas and process group containment. Narrowed capability scope strictly to allowlisted static reads via `StaticHost`.
- **Durable Atomic ApprovalStore (IR-001):** Hardened single-use approval persistence against TOCTOU and symlinks using directory file descriptor pinning (`dir_fd`, `O_NOFOLLOW`), permissions `0o700`/`0o600`, cross-process `fcntl.flock(LOCK_EX)`, atomic replacement via `O_EXCL`, and fail-closed corruption detection. Prohibited unauthorized approval history resets (`clear()` raises `PermissionError`).
- **Mandatory ExecutionSpec Binding (IR-004):** Enforced mandatory cryptographic binding of commands, targets, revisions, timeouts, and sanitized environment keys to `spec_sha256`. Rejected observe and staging requests from subprocess dispatch.
- **Reporting Trust Boundary & Gate Enforcement (IR-010):** Enforced that unauthenticated JSON PASS logs cannot produce a positive "no blockers found in tested scope" all-clear in `render_report.py` (capped at "conditional launch"). Implemented `evals/release_readiness_gate.py` returning exit 2 (fail-closed) against developer claims.
- **Telemetry & Evidence Privacy (IR-009):** Scrubbed cleartext query tokens, raw file paths, and command arguments from host events, retaining SHA256 digests and counts.
- **macOS Host Verification Suite:** Added `evals/macos_host_verifier.py` executing 10 mandatory negative security tests on macOS 15.7.3 arm64; all 10 tests passed (100% pass rate). Generated `docs/security/v0.5.0-macos-host-verification.md` and `docs/security/v0.5.0-remediation-verification-matrix.json`.
- **Benchmark Integrity & Evidence Manifest:** Documented developer-reported Ground Truth audit for 5 target repositories (8 vulnerabilities, 12 negative controls, 20 entry points). Recorded a proposed explanation for the historical runtime matrix timestamp discrepancy and authored `docs/evaluations/v0.5.0-evidence-manifest.json` binding 18 historical artifacts (new corrected manifest will supersede this scope) with cryptographic digests.
- **Definitive Release Decision: NO-GO:** Formally recorded `NO-GO` verdict in `docs/security/v0.5.0-final-security-certification.md` and `docs/release/v0.5.0-release-readiness-checklist.md`. Stable release remains blocked pending independent human maintainer approval and completion of the full 45-trial evaluation matrix.

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
