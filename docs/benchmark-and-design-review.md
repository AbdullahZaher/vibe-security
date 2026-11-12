# Benchmark-informed design review

Reviewed against the **publicly available designs**, not formally certified, tested, or endorsed by the projects below. Source snapshots are time-sensitive; review date 2026-11-12.

| Source | Useful design pattern | Application in this project |
|---|---|---|
| [Agent Skills official specification](https://agentskills.io/specification) | Valid YAML metadata, compact activation instructions, relative resource links and progressive disclosure | One `SKILL.md` in a name-matching directory; separate references and scripts |
| [Anthropic skill-creator](https://github.com/anthropics/skills/tree/main/skills/skill-creator) | Test prompts, negative evaluation, iterative quality improvement | `evals/cases.json` has scenario triggers and observable expected behaviors; no runtime agent evaluation has been claimed |
| [Trail of Bits semgrep skill](https://github.com/trailofbits/skills/tree/main/plugins/static-analysis/skills/semgrep) | Plan first, explicit approval gate, scanner telemetry awareness and partial coverage reporting | Read `references/tooling-and-privacy.md`; do not auto-install or run third-party rule sets |
| [Trail of Bits post-patch-validation](https://github.com/trailofbits/skills/tree/main/plugins/post-patch-validation/skills/post-patch-validation) | Verify security invariants and regressions, not simply that code builds | Baseline failing exploit-regression test when feasible; passing test after fix; record unresolved variants |
| [Trail of Bits agentic-actions-auditor](https://github.com/trailofbits/skills/tree/main/plugins/agentic-actions-auditor/skills/agentic-actions-auditor) | Treat agent CI/workflows as untrusted, avoid prompt injection across tool boundaries | No execution of repository prose; permission gates enforced by host tools, not words in prompt |
| [Vercel react-best-practices](https://github.com/vercel-labs/agent-skills/tree/main/skills/react-best-practices) | Small discoverable skill plus categorized, focused references | Numbered controls with `Inspect`/`Fix`/`Verify` and short main skill |

## Review findings and actions

1. **HIGH — Repository naming mismatch:** A skill called `prelaunch-security-audit` at the root of a repository named `vibe-security` is not reliably portable. **Fix:** place it in `skills/prelaunch-security-audit/SKILL.md`.
2. **HIGH — Evidence laundering:** A renderer cannot prove a user-supplied test claim ran. **Fix:** distinguish *asserted* from *confirmed by the evaluator*; refuse to turn empty or partial evidence into a broad release clearance. Do not equate 27 checklist rows with 27 verified protections.
3. **HIGH — Secret-report leakage:** Regex redaction is not exhaustive, especially for vendor-specific and user-defined credentials. **Fix:** report references to secret locations and provider names only; use private results storage; review generated output before sharing. Never publish findings from customer projects automatically.
4. **MEDIUM — Evaluation gap:** Unit tests of utilities cannot establish skill effectiveness on real applications. **Fix:** benchmark cases in `evals/cases.json`; future agent-in-the-loop evaluation against vulnerable fixtures is required before claiming detection metrics.
5. **MEDIUM — Tool risk:** Security tools can execute package scripts, transmit telemetry or fetch third-party rules. **Fix:** require scan plan, scanner/version provenance, safe local scope, telemetry review, and network permission before running.
6. **HIGH — Python module shadowing:** An adapter in `mcp/server.py` can mask the real `mcp` package during direct execution. **Fix:** rename the folder to `mcp_adapter/`; test package imports in an environment with the official SDK installed. The live MCP interoperability test is still pending.
7. **MEDIUM — Optional MCP/SDK compatibility:** The MCP server is optional, fixed-root, read-only, and not a sandbox boundary. **Fix:** document host permissions; test MCP separately before recommending production deployment.
8. **MEDIUM — RLS, CORS, payment and session advice can be oversimplified:** Controls must adapt to actual technology and business logic. **Fix:** document provider-specific considerations, negative authorization tests and staged high-impact changes.
9. **LOW — Reporting semantics:** `not_applicable` needs a reason; `not_verified` must not be translated into `pass`. **Fix:** explicit report states and conservative launch guidance.

## Claims this project does **not** make

- No comparison source endorses this skill.
- No measured detection rate, false-positive rate or cross-agent behavioral score is asserted.
- Local library tests are not penetration tests or proof of a website's security.
- ASVS/WSTG references guide reviews; they do not imply official OWASP verification or certification.
