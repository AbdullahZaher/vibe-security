# Prelaunch Security Audit — Agent Skill

An English, vendor-neutral Agent Skill for an authorized owner's **27-point**
prelaunch web application security review, minimally invasive fixes, approval-
gated remediation, and evidence-based testing/reporting.

## 0.3.0 execution governance

Actions are classified into six side-effect classes using
`references/execution-policy.md`. The optional `scripts/plan_guard.py`
classifies structured plans but does not execute them or authorize tools.
Consult `references/evidence-model.md` for source/build/runtime/deployment
evidence, and `references/standards-map.md` for OWASP/SSDF/SLSA context.

## What it does (and does not)

- Follows the 27 controls in `references/security-controls.md` sequentially.
- Uses OWASP ASVS 5.0 / WSTG as frameworks, not as a certification claim.
- Examines code/config, suggests fixes, applies low-risk fixes **only when the
  owner requests remediation**, and asks before major changes.
- Supports local tools and separately provisioned GitHub, provider APIs, and
  MCP tools; tools remain permission-gated by the agent/provider.
- Bundles a read-only preflight scanner (files/metadata only), deterministic
  report renderer, tests, and optional fixed-root read-only MCP server and GitHub metadata tool.
- It is **not** a magic scanner, a penetration test, a guarantee of security,
  nor permission to attack third-party systems.

## Install

From the parent `vibe-security` public GitHub repository:

```bash
npx skills add AbdullahZaher/vibe-security --skill prelaunch-security-audit
```

Or add the `prelaunch-security-audit` directory directly to the appropriate
skills directory supported by the host. See https://agentskills.io/specification
and https://www.skills.sh/docs.

## Request to the agent

> Use the prelaunch-security-audit skill on this authorized repository. Review
> every control 01–27 in order. Fix small reversible local issues, ask before
> any major or external change, run permitted tests, and produce a redacted
> SECURITY-REVIEW.md with evidence and results. Do not claim unrun checks pass.

## Manual local preflight

Python 3.11+ recommended; no third-party packages needed for local scripts:

```bash
python3 scripts/preflight.py --root /path/to/authorized/project
python3 scripts/preflight.py --root /path/to/authorized/project --out reports/preflight.json
python3 -m unittest discover -s tests -v
```

The preflight checks metadata and filenames only. It does **not** inspect
secret values, execute the application, or establish that a protection works.

## Report generation

`assets/findings.example.json` is a **blank structural example**, not actual
findings. Its optional JSON Schema is `assets/findings.schema.json`. Populate it from evidence gathered during a real review.

```bash
python3 scripts/render_report.py --input assets/findings.example.json --output reports/SECURITY-REVIEW.md
```

## Optional MCP server

The included Python MCP SDK v2 server exports **read-only** repository
preflight and allowlisted GitHub repository metadata tools. MCP is optional.
Configure it only for an owner-authorized local root:

```bash
python3 -m pip install 'mcp>=2,<3'
export SECURITY_AUDIT_REPO_ROOT='/absolute/path/to/authorized/project'
# Optional: enable read-only GitHub metadata (never sends a token to chat)
export SECURITY_AUDIT_GITHUB_REPO='YOUR-ORG/YOUR-REPO'
# GITHUB_TOKEN should be provided through a secure host secret store if needed
python3 mcp_adapter/server.py
```

To use the GitHub REST API without MCP, the equivalent read-only command is:

```bash
SECURITY_AUDIT_GITHUB_REPO='YOUR-ORG/YOUR-REPO' \
  python3 scripts/github_repository.py --repo YOUR-ORG/YOUR-REPO
```

The API call is a real network GET to `api.github.com` and will fail without
network access or appropriate permissions. It is **not** an audit of GitHub
branch-protection rules or repository code.

For write operations on GitHub and provider APIs, connect your agent to those tools
and use the `references/approval-policy.md` guardrails. **This bundle does not
include GitHub or payments write operations.** Never expose the
demo MCP server publicly.

## Contribution policy

Do not add prompt-injection instructions, credential collectors, active exploit
payloads, or destructive defaults. New checks need evidence of safe execution,
clear authorization requirements, and false-positive discussion.

## References

- Agent Skills format: https://agentskills.io/specification
- OWASP ASVS: https://asvs.owasp.org/
- OWASP WSTG: https://wstg.owasp.org/v4.2/
- MCP Python SDK: https://py.sdk.modelcontextprotocol.io/v2/

Run agents in a sandbox or disposable development environment with restricted
network access and without production credentials. Instructions are not a
substitute for technical tool permissions and provider approval gates.

Licensed under MIT (see repository root `LICENSE`). Security audits should be independently reviewed before
sensitive or regulated production launches.

For benchmark-informed design decisions, see `../../docs/benchmark-and-design-review.md`; to evaluate agent behavior, see `../../evals/cases.json`. These scenarios have not been executed against agent hosts.

## Release checklist

- [ ] Validate `SKILL.md` against Agent Skills (`skills-ref validate .`).
- [ ] Run offline tests and review script permissions.
- [ ] Verify MCP v2 behavior in MCP Inspector in a sandbox environment.
- [ ] Test in at least two supported host agents; tool permissions vary.
- [ ] Check examples and README contain no real credentials.
- [ ] Publish a public GitHub repository and tag a versioned release.
- [ ] Confirm `npx skills add AbdullahZaher/vibe-security --skill prelaunch-security-audit` installs correctly.
- [ ] Do not publish sensitive findings from customers as public issues.

## Review modes (v0.4.0 release candidate)

- **Quick PR review:** analyze the changed files and adjacent auth/data boundaries, run only approved targeted tests, and report what was not covered. Never describe it as a complete 27-control audit.
- **Full prelaunch audit:** retain the original sequential 27-control evidence workflow and release recommendation.

See [review-modes.md](references/review-modes.md) and [stack-playbooks.md](references/stack-playbooks.md). The report now links high/critical finding resolution to a matching-revision verification log. It does **not** authenticate log contents.

Agent evaluation: use [evals/README.md](../../evals/README.md) for the offline host-trace scoring format. The 20 cases are specifications; no real agent behavior benchmark is claimed.
