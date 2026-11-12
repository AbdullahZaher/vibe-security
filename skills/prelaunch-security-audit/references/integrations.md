# API, CLI and MCP Integration Guide

## Portable by design

Agent Skills provide instructions, not automatically granted tools. The host
agent determines which filesystem, shell, browser, MCP servers, or external API
connections are available. The skill must inspect capabilities and degrade
gracefully rather than inventing access or executing untrusted commands.

## Capability mapping

| Capability | Suggested integration | Default authorization |
|---|---|---|
| Read project files / Git status | Host filesystem + Git tool | Local, read-only |
| Build and unit/integration tests | Host approved command runner | Inspect for side effects first |
| SAST / dependency audit | Installed vetted scanners | Local, read-only |
| Git history secret detection | Gitleaks (`git` mode) or equivalent | Local, redact output |
| Review GitHub issues/PRs | Host GitHub MCP/API | Read-only |
| Create issue/PR or modify CI | GitHub MCP/API tool | Explicit per-action approval |
| Observe HTTP headers | Authorized staging browser/HTTP tool | Restricted by scope |
| Update production secrets/CDN/payment | Provider-specific MCP/API | Never automatic; explicit approval and least privilege |

For Gitleaks versions that support it, `gitleaks git <repo-path>` is a
history scanner. Avoid verbose/plain findings that might expose matched
secrets, and do not store raw results in a public workspace. Confirm the
installed tool's CLI help and exit codes before use.

## Optional bundled MCP adapter

`mcp_adapter/server.py` exposes a **read-only** preflight inventory, with a fixed root
supplied through `SECURITY_AUDIT_REPO_ROOT`; no tool argument can request
arbitrary filesystem locations. It also exposes GitHub metadata via the
read-only GET API, restricted to the single repository configured by
`SECURITY_AUDIT_GITHUB_REPO`. Credentials come from the host environment only. It
requires the official Python MCP SDK v2 and is not needed to use the skill.

```bash
python3 -m pip install 'mcp>=2,<3'
export SECURITY_AUDIT_REPO_ROOT='/absolute/path/to/authorized/project'
export SECURITY_AUDIT_GITHUB_REPO='YOUR-ORG/YOUR-REPO'  # optional
python3 mcp_adapter/server.py
```

Connect the process as a stdio MCP server using your agent's supported MCP
configuration. For a remote MCP server, add strong authentication,
authorization, transport security, request validation and audit logging;
**do not expose this demo server directly to the internet**.

## External write operations

Use provider-managed identity / tokens via secure host configuration rather
than passing tokens in chat or tool arguments. Before creating issues, PRs or
config changes, request the owner's explicit approval. Verify the exact target
repo/environment, minimize scopes, and remove secret values from payloads.
The host's native approval UI and provider-side permissions must enforce the
gate; wording in SKILL.md cannot substitute for technical enforcement.

## Workflow fallback

If an MCP tool is unavailable, perform local evidence gathering only, then
provide exact proposed actions and mark that control `not_verified` or
`needs_approval`. Never claim that a tool action occurred if it did not.

## Production deployment caution

This example MCP server intentionally does not expose an arbitrary command runner, credential rotation, package upgrades or broad repository write tools. For production tools, implement service-side permission enforcement, per-target ACLs, sanitized audit logs and scoped authorization separate from any prompt.
