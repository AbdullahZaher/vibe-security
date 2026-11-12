# Reference frameworks (non-certification mapping)

This 27-item onboarding checklist is **not** an exhaustive security standard.
Use the linked primary sources and record project-specific coverage gaps.

| Reference | What it helps verify | Important limit |
|---|---|---|
| [OWASP ASVS 5.0](https://asvs.owasp.org/) | Authentication, access control, input handling, configuration and app requirements | Map to exact requirements for the actual app; do not claim ASVS conformance from a checklist |
| [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) | Reproducible web security test methods | Active testing requires owned/authorized targets and explicit scope |
| [OWASP Top 10:2025](https://owasp.org/Top10/) | Risk awareness and taxonomy | Not a test plan or compliance badge |
| [NIST SSDF SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final) | Secure development and release practices | Process guidance, not vulnerability proof |
| [OpenSSF Scorecard](https://securityscorecards.dev/) | Source repository and CI supply-chain posture | Does not prove app behavior is secure |
| [SLSA](https://slsa.dev/spec/v1.2/) | Artifact provenance and build integrity | Relevant where build artifacts are distributed |
| [MCP authorization security](https://modelcontextprotocol.io/specification/) | Tools, tokens, grants and cross-server boundaries | Host/provider enforcement is required |
| [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) | MCP prompt injection, tool poisoning, confused-deputy threats | Guidance must become tool policies and evaluations |

Control 26 should review missed categories, especially tenant isolation,
authorization, business logic, webhook replay, observability, recovery,
third-party supply chain and agent tool permissions. Record explicit gaps
rather than adding speculative vulnerabilities to the report.
