# Testing Playbook

## Levels of evidence

1. **Static observation:** source/config present. Does not prove behavior.
2. **Unit/integration test:** a repeatable assertion for a control.
3. **Staging behavior:** an authorized test of the deployed stage environment.
4. **Production observation:** only with explicit owner approval and a safe plan.

Mark `pass` or `fixed_verified` only when appropriate evidence and actual
executed tests support the claim. Never mark blocked/unrun as passed.

## Baseline and regression

- Check Git status and the existing test setup before running commands.
- Inspect test scripts for destructive side effects before running.
- Prefer focused unit and integration tests over broad active scans.
- Run framework-native typecheck/lint/unit/integration/build as supported.
- Verify negative cases as well as expected success cases.
- Preserve test output summaries and exit codes (redacted).
- Re-run relevant checks after each fix; report regressions separately.
- A successful build does not establish that any security control works.
- Failed unit tests, build incompatibilities and migration-history mismatches
  are meaningful release/verification findings; do not mislabel them as
  exploitable application vulnerabilities without a security-impact path.

## Recommended negative tests by domain

- **Auth/session:** unauthenticated requests rejected; expired/revoked session
  rejected; logout denies continued use; account A cannot access account B.
- **Access control/RLS:** unauthorized and cross-tenant reads/writes denied,
  including via direct API calls; privileged operations require server role.
- **Input/XSS/SQL:** invalid types and lengths rejected; untrusted output is
  encoded; malicious-looking test strings remain data; query input is bound.
- **Transport/headers/cookies/CSRF:** expected response headers/cookie
  attributes; permitted clients work; cross-origin state-changing requests
  without valid protections are rejected when applicable.
- **Rate limiting:** bounded local or staging tests with safe fixtures; return
  429 and recover gracefully; don't cause account lockouts or traffic spikes.
- **Reset flow:** short expiry, one-time use, replay failure and invalidation
  after reset; do not use live users' accounts.
- **Uploads:** benign disallowed extension/MIME/size tests; test storage
  boundaries without uploading malicious payloads to public sites.
- **Payments:** provider sandbox only; server-side recomputation; invalid
  webhook signature rejected; duplicates idempotent; no real charges.
- **Debug/files:** generic production-like errors; no sensitive static files
  exposed from the generated build; only safe authorized stage checks.
- **Dependencies/history:** use established audit and secret detection tools,
  redact matched values; verify package build/test post-change.

## Limited-evidence handoff

If executable checks are blocked, show **Authorized next checks (not executed)**
with a small number of technology-relevant, copy-ready examples and the target
environment/permissions needed. Review package scripts before recommending
`pnpm test`/`npm test` or any command capable of side effects. A read-only
`git status --short` or offline `preflight.py` may be suitable; active scans,
network checks, database queries and Docker daemon access still require their
own authorization and isolation. Mark outcomes `not_run`/`not_verified`.
Never imply the suggested commands were actually executed.

## Evidence format

For each case record `command_or_method`, `environment`, `expected`,
`observed`, `result` (`pass`, `fail`, `blocked`, `not_run`), `date`, and a
sanitized reference to output. Avoid screenshots/logs with credentials.

## Go/no-go rules

`block launch` for unresolved critical/high exploitable issues involving
credentials, unauthorized data access, admin access or money movement, unless
the owner documents a sound mitigating control and risk acceptance. Never
invent a numerical security score or certification from a checklist alone.

## Security regression proof

For a confirmed fix, prefer a safe negative test that fails on the vulnerable baseline for the expected security reason, then passes after remediation. Include adjacent authorization/tenant/role variants and record when baseline replay is unsafe or unavailable. See `verification-and-coverage.md`.

## Scan privacy

Scanners are not free of side effects; inspect telemetry, third-party rules, data egress, generated files, execution permissions and source scopes. Present a scan plan and use a host-enforced approval gate. See `tooling-and-privacy.md`.
