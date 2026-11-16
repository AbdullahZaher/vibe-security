# Vibe Security

**A beginner-friendly security review skill for AI coding agents.**

Vibe Security helps you check a website or app for common security problems **before you launch it**. It guides an AI agent through a structured review, asks for evidence, suggests safer fixes, and explains what still needs attention.

You do **not** need to be a security expert to get started. You do need access to a project you own or are explicitly authorized to assess.

> **Release status:** The bundled `prelaunch-security-audit` skill is **v0.5.0-rc1 (release candidate)**, **not an independently certified Stable release**. It currently supports **static-only** review: executing untrusted project code through the bundled host adapter is disabled. [See release blockers](docs/security/v0.5.0-release-readiness-blockers.md).

## What is an Agent Skill?

An **Agent Skill** is a set of instructions and supporting files that helps a compatible AI coding assistant perform a specific job. In this case, the job is reviewing the security of a website or application.

Vibe Security is **not** a website hosting service or a one-click vulnerability scanner. Your AI agent needs permission to access your project, and any tools or commands it uses must be available in your own environment.

## Quick start: three steps

### 1. Install the skill

In a terminal, run:

```bash
npx skills add AbdullahZaher/vibe-security --skill prelaunch-security-audit
```

This uses the [Skills CLI](https://skills.sh/docs). You need Node.js/npm with `npx`, and an AI agent that supports Agent Skills. Follow the installer's prompts and reload your agent if its host requires it.

**Alternative:** If your agent does not support this installer, copy the [`skills/prelaunch-security-audit/`](skills/prelaunch-security-audit/) folder into the skills directory supported by your agent. Keep the folder name `prelaunch-security-audit` and the included `SKILL.md` file intact. See the [Agent Skills specification](https://agentskills.io/specification).

### 2. Open your own project in your AI agent

Open the folder containing your website or application's source code. Start with a local checkout or disposable workspace, **without production secrets**. Your agent must actually be able to read that folder.

### 3. Copy this first prompt

> Use the `prelaunch-security-audit` skill to perform a **read-only security review** of this project. I own or am authorized to review it. Start by identifying the application and its important security boundaries, then assess the relevant controls with evidence. Explain findings in beginner-friendly language, prioritize serious risks, and show what you could not verify. **Do not modify files, install tools, access production, run untrusted project code, or send data to external services without my specific permission.**

The agent should explain what it discovered, what looks risky, and what still needs verification. It should **not** automatically declare your project secure.

## What can it help you check?

The full prelaunch review follows **27 numbered controls**, covering areas such as:

| Area | In simple terms |
| --- | --- |
| Login and permissions | Can only the right people access accounts, admin pages, and private data? |
| Passwords, sessions, and recovery | Are sign-in and password-reset processes protected? |
| API keys and secrets | Are sensitive keys kept away from public code and responses? |
| Input and web security | Are user inputs checked, and are common attacks such as XSS and injection addressed? |
| Database and tenant access | Can a user access data belonging to another user or organization? |
| Uploads, payments, and integrations | Are files, prices, webhooks, and third-party services handled safely when present? |
| Deployment and monitoring | Are production settings, HTTPS, logging, and error handling appropriate? |
| Testing and release readiness | Which protections were actually verified, and what might block launch? |

A missing feature is not automatically a vulnerability. For example, a site with no payment system does not need payment-specific checks.

For the precise list and required evidence, read [the 27 security controls](skills/prelaunch-security-audit/references/security-controls.md).

## Choose the right review mode

| Mode | Best for | What the agent does |
| --- | --- | --- |
| **Audit only** (recommended first) | A first look at your project | Inspects authorized code/configuration and reports findings; does not edit your files. |
| **Quick PR review** | A small code change | Reviews changed files **and affected security boundaries**; does not claim a complete website audit. |
| **Full prelaunch audit** | Preparing a website/app for launch | Works through all 27 controls in order and records evidence, gaps, risks, and a release recommendation. |
| **Audit + safe fixes** | After reviewing the findings | Suggests and, **only with authorization**, applies small reversible fixes; major changes still require separate approval. |

**Example prompt for safe fixes:**

> Review the findings from the previous audit. Propose a prioritized remediation plan. For each change, explain which files would change, why, how to test it, and how to roll it back. Apply **only** the specific low-risk changes I authorize. Ask before changing production settings, authentication, databases, payments, credentials, or infrastructure. Report actual test results and anything not tested.

## What should the results look like?

A useful review distinguishes **evidence from assumptions**. For example:

| Example finding | Status | Meaning |
| --- | --- | --- |
| Admin route checks the user's role on the server | `pass` **only when verified** | The relevant protection was checked using matching evidence. |
| API key appears in a public configuration | `failed` | A problem was found; it needs investigation and remediation. |
| Authorization fix was applied and re-tested | `fixed_verified` | The fix passed specific verification; other risks may remain. |
| Payment checks on a site with no payments | `not_applicable` | This check does not apply, with a documented reason. |
| Production session settings cannot be inspected | `not_verified` | There is not enough evidence to say it passed. |

*These are illustrative examples, not results from an actual website.*

For a full review, the agent can prepare a `SECURITY-REVIEW.md` report with findings, severity, evidence, affected files, recommended fixes, test outcomes, remaining risks, and a launch recommendation. **A report is not a security certificate.**

## Optional: run local helper commands

You can use the skill **without** running the bundled helper scripts. If you want to explore the tools yourself, Python **3.11+** is recommended.

From a cloned copy of this repository:

```bash
cd skills/prelaunch-security-audit

# List relevant project filenames/configuration (does NOT scan for vulnerabilities).
python3 scripts/preflight.py --root /absolute/path/to/your-project

# Test the skill's own Python components, not your website.
python3 -m unittest discover -s tests -v

# Render a demonstration report from sample data, not real audit findings.
python3 scripts/render_report.py \
  --input assets/findings.example.json \
  --output /tmp/vibe-security-example-report.md
```

Use a **new output path** if you run the report command again; the renderer may refuse to overwrite an existing file. The preflight inspects filenames and configuration inventory only: it does **not** read secret values, test a live site, or prove that the application is safe.

For evidence schemas, advanced validation, and existing JSON compatibility, see the [v0.5 artifact guide](docs/v0.5.0-artifact-guide.md).

## Safety and privacy: read this first

- **Only review projects you own or are authorized to test.** Do not point the skill at another person's website without permission.
- **Never share private keys, passwords, API tokens, customer records, or raw secret findings** in chat, public issues, or reports.
- **Start read-only.** Running an application, installing packages, invoking third-party scanners, or making network calls may have side effects and needs appropriate authorization.
- **Keep high-impact changes behind explicit approval.** This includes production deployment, credential rotation, payment settings, data deletion, and major database changes.
- **Treat AI output as advice supported by evidence, not as a guarantee.** A passing test or green CI job does not prove an entire application is secure.
- **Keep sensitive reports private.** Do not automatically commit real audit findings or upload them to public services.

### Important limitation: Static-Only runtime

In **v0.5.0-rc1**, the bundled `IsolatedHostAdapter` **does not run untrusted subprocesses**. This is an intentional safety restriction while stronger independent host-isolation evidence is pending.

The skill can still guide source and configuration reviews, propose tests, and help organize results. Any test that did **not** run must be reported as **not run**, never as a pass. An agent may use separately available tools only where their permissions and isolation have actually been established.

See the [skill instructions](skills/prelaunch-security-audit/SKILL.md) and [release-readiness blockers](docs/security/v0.5.0-release-readiness-blockers.md) for details.

## Common questions

<details>
<summary>Do I need to know programming or cybersecurity?</summary>

No specialist knowledge is needed to read the guided explanations. You will still need an authorized project and an AI coding agent that can inspect its files. Serious findings and release decisions may need a qualified security professional.

</details>

<details>
<summary>Will installing the skill automatically fix my website?</summary>

No. Installing it supplies instructions and optional helpers. The agent must have the right tools and permissions. It should request approval before changing files and report what it actually did.

</details>

<details>
<summary>Can I use it with Next.js, WordPress, Django, or another stack?</summary>

The 27-control approach is framework-neutral. What can be verified depends on the project's architecture, the files available, and any separately approved test tools. Some checks may not apply.

</details>

<details>
<summary>Does a green report mean my website is safe to publish?</summary>

No. Evidence can be incomplete or limited to a particular revision or environment. Fix high-risk findings, review remaining gaps, and obtain appropriate independent verification before sensitive production launches.

</details>

<details>
<summary>Is v0.5.0 Stable available?</summary>

Not yet certified in this repository. The code is a **release candidate**, and the Stable release remains gated on independent evaluation, host evidence, reviewer approval, and explicit release authorization. See the [release checklist](docs/release/v0.5.0-release-readiness-checklist.md).

</details>

## Documentation map

| Where to go | What you will find |
| --- | --- |
| [Skill instructions](skills/prelaunch-security-audit/SKILL.md) | The agent's full workflow and safety boundaries. |
| [Detailed skill README](skills/prelaunch-security-audit/README.md) | Local utilities, optional MCP integration, and advanced setup. |
| [27 security controls](skills/prelaunch-security-audit/references/security-controls.md) | The checklist used during full audits. |
| [Artifact guide](docs/v0.5.0-artifact-guide.md) | Evidence files, validators, and report formats. |
| [Evaluation guide](evals/README.md) | Advanced, opt-in evaluation procedures; some require paid APIs and separate approval. |
| [Release blocker register](docs/security/v0.5.0-release-readiness-blockers.md) | What remains before this skill can be called Stable. |
| [Security policy](SECURITY.md) | How to handle vulnerability reports privately. |
| [Contributing](CONTRIBUTING.md) | How to propose improvements. |

## Standards and attribution

This project draws on established guidance, including [OWASP ASVS 5.0](https://asvs.owasp.org/), the [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/), and the [Agent Skills specification](https://agentskills.io/specification).

Using those references **does not mean OWASP or any other organization has certified, endorsed, or audited this project**.

**License:** [MIT](LICENSE). Community-maintained; not affiliated with or endorsed by OWASP, GitHub, or any named AI-agent vendor.
