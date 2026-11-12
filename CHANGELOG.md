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
