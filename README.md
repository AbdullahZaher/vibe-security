# Vibe Security

A portable, evidence-driven **Agent Skill** for owner-authorized prelaunch web application security reviews, controlled remediation, and verification.

**Skill:** [`prelaunch-security-audit`](skills/prelaunch-security-audit/SKILL.md) · **27 sequential controls** · **Safe by default** · **Optional read-only MCP**

## Install

```bash
npx skills add AbdullahZaher/vibe-security --skill prelaunch-security-audit
```

For hosts that do not support the installer, copy `skills/prelaunch-security-audit/` to an Agent Skills directory recognized by that host. The skill name must remain `prelaunch-security-audit`.

## Ask your agent

> Use the `prelaunch-security-audit` skill to review this authorized website repository before launch. Assess controls 01–27 in order, collect verifiable evidence, propose narrowly scoped fixes, ask before major changes or any external write, and report exact tests and limitations. Do not claim security certification or mark unexecuted tests as passed.

## What this can and cannot do

- **Can:** guide code/config reviews, plan scans, run locally available approved checks, propose small safe fixes where authorized, and produce an evidence-based report.
- **Cannot on its own:** guarantee security, access production, perform a penetration test, revoke secrets, or execute actions without host-granted tools and user permission.
- **Optional utilities:** read-only repository inventory, constrained read-only GitHub metadata, deterministic report renderer, and local unit tests. The Python MCP integration is optional and must not be exposed publicly.
- **Privacy:** never paste real credentials or raw secret matches into chat, logs, reports, or public issues. Run agents in isolated workspaces and review third-party scanner privacy/telemetry behavior.

Read the [skill README](skills/prelaunch-security-audit/README.md), [comparison and design review](docs/benchmark-and-design-review.md), and [evaluation scenarios](evals/cases.json).

## Local checks

```bash
cd skills/prelaunch-security-audit
python3 -m unittest discover -s tests -v
python3 scripts/preflight.py --root /path/to/authorized/website
python3 scripts/render_report.py --input assets/findings.example.json --output /tmp/example-security-review.md
```

The example report is **not a real audit**. The preflight enumerates names, not vulnerabilities. The 27-control review requires project-specific evidence and often a human security reviewer.

## Standards

- [Agent Skills specification](https://agentskills.io/specification)
- [OWASP ASVS 5.0](https://asvs.owasp.org/)
- [OWASP WSTG 4.2](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

MIT licensed. This is a community project; no affiliation with or endorsement by any named reference organization.
