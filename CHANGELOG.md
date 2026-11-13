## v0.4.0-rc1 — proposed, unmerged

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
