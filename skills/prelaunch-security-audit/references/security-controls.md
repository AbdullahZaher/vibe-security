# Security Control-by-Control Playbook

Evaluate controls **01 through 25 in order**, then complete 26 (integrated
review) and 27 (test/report). For each control record applicability, proof,
severity, fix/approval, and a concrete verification outcome. Prefer OWASP ASVS
5.0 and WSTG 4.2 guidance; adapt to the actual technology and threat model.

## 01 — Authentication
**Inspect:** Providers, session creation/rotation, logout invalidation, server-
side checks on protected API/page handlers, MFA where appropriate. **Fix:**
Use supported auth provider/library and server validation; avoid custom auth.
**Verify:** anonymous and invalid/expired sessions denied; logout invalidates
sessions, including server-side revocation where supported. Auth migrations need
approval.

## 02 — Protect API keys
**Inspect:** Browser bundle, frontend env prefixes, logs, hard-coded code,
public assets, and proxy flows. **Fix:** move *server-only* secrets into secure
server/provider storage; route privileged API operations through a backend.
**Verify:** built frontend lacks private keys; external calls authenticate on
the backend. Never print secret values; exposure requires rotation (25).

## 03 — Secure database access
**Inspect:** tenant/user object authorization on every data path, service roles,
RLS where available, server-side filtering and least-privilege DB accounts.
**Fix:** deny-by-default ownership checks; appropriate RLS/policies in systems
that support them. **Verify:** user A cannot read/write B's records, including
by directly changing identifiers. RLS/policy changes require approval.

## 04 — Enforce HTTPS
**Inspect:** host/CDN TLS, HTTP redirect, mixed content, HSTS readiness across
subdomains. **Fix:** TLS and redirect with staged HSTS rollout. **Verify:**
authorized staging endpoints redirect safely, assets load securely and
headers are as expected. Production or preload changes require approval.

## 05 — Hash passwords
**Inspect:** only if the app stores passwords itself. Check Argon2id or a
properly tuned bcrypt implementation, per-password salt, upgrade strategy and
no password logging. For managed auth, verify provider settings. **Fix:**
use vetted implementation; migrate legacy hashes with explicit plan.
**Verify:** no plaintext storage and controlled authentication regression tests.

## 06 — Server-side validation
**Inspect:** form actions, REST/GraphQL/edge routes, type/size/bounds and
schema checks. **Fix:** validated parse and normalization at server trust
boundaries. **Verify:** invalid and overlong payloads receive expected 4xx
responses without exposing internals; UI checks alone are insufficient.

## 07 — Cross-site scripting
**Inspect:** HTML rendering, rich text, templates, URL sinks, dynamic DOM and
unsafe `innerHTML`/`dangerouslySetInnerHTML`. **Fix:** contextual output
encoding, safe rendering and vetted sanitization where HTML is required;
consider CSP defense in depth. **Verify:** controlled strings are displayed as
data, not executed. Do not test public users with malicious payloads.

## 08 — Logging and monitoring
**Inspect:** authentication/admin activity, alert routing, telemetry and PII/
secret logging. **Fix:** redacted structured security events, safe retention,
alert rules, actionable runbooks. **Verify:** representative test event appears
in the intended sink without secret values; do not create real security noise.

## 09 — Restrict admin routes
**Inspect:** every admin API/action and server endpoint, not just UI links.
**Fix:** explicit server-side RBAC/ABAC and deny-by-default enforcement.
**Verify:** anonymous and non-admin users cannot access admin actions; a
hidden navigation element is not an authorization control.

## 10 — Parameterized queries
**Inspect:** SQL concatenation and dynamic query builders. **Fix:** bind
values via parameters/ORM; allowlist dynamic table/column identifiers.
**Verify:** crafted *local test inputs* are handled as data and do not change
query structure. ORM usage itself does not prove every query is safe.

## 11 — Environment variables
**Inspect:** browser-exposed prefixes (`NEXT_PUBLIC_`, `VITE_`, etc.), bundled
build values, .gitignore, secret provider configuration and Git tracking.
**Fix:** server-only credentials and safe env examples. **Verify:** private
config stays outside client assets and commits. `.gitignore` does not untrack
previously committed secrets; see 24–25.

## 12 — Rate limiting
**Inspect:** auth, reset, signup, expensive APIs, password spraying and shared
load-balancer/proxy trust configuration. **Fix:** bounded per-account and
per-IP throttles (distributed if needed) with 429 responses and monitoring.
**Verify:** limited synthetic tests, not aggressive traffic or real lockouts.

## 13 — Restrict CORS
**Inspect:** credentialed origins, reflection of arbitrary Origin, wildcard
headers, preflights. **Fix:** a least-privilege origin allowlist matching real
clients. **Verify:** authorized browser origins function; untrusted origins do
not receive inappropriate CORS permissions. CORS is not auth or a general
server-to-server request blocker; keep server authorization and CSRF.

## 14 — Security headers
**Inspect:** CSP, `frame-ancestors`/X-Frame-Options, HSTS, nosniff, Referrer-
Policy, and framework/CDN precedence. **Fix:** tailored headers, start CSP in
report-only where appropriate, avoid breaking integrations. **Verify:** headers
and key application flows in staging; strict deployment requires approval.

## 15 — Secure cookies
**Inspect:** session cookie `Secure`, `HttpOnly`, appropriate `SameSite`, path,
domain, TTL/rotation, prefixes where useful. **Fix:** secure attributes and
session expiration. **Verify:** local/staging Set-Cookie behavior, logout and
cross-site user flows; `SameSite` does not eliminate all CSRF threats.

## 16 — CSRF
**Inspect:** cookie-authenticated state-changing endpoints and unsafe GET
routes. **Fix:** antiforgery tokens, verified Origin/Referer or appropriately
chosen double-submit mechanisms, with SameSite defense in depth. **Verify:**
unauthorized cross-site state changes fail while legitimate flows work.

## 17 — Password reset links
**Inspect:** provider/owned flows, token randomness, hash-at-rest as relevant,
short expiry, replay prevention and reset audit events. **Fix:** 15–30-minute
single-use links where applicable, invalidate after use, handle session rules.
**Verify:** expired/reused/reset-invalidated tokens rejected with test users.

## 18 — File uploads
**Inspect:** allowed formats, magic bytes, limits, storage, URL access and
malware handling depending on risk. **Fix:** allowlist, file inspection,
quotas and non-executable storage outside source/web roots. **Verify:** benign
invalid-type and over-limit tests are rejected; valid files remain usable.

## 19 — Prices and payments
**Inspect:** trusted price calculation, authorization, currency, coupons,
webhook signature verification, replay/idempotency and fulfillment timing.
**Fix:** server-side authoritative prices; verify provider signatures with its
SDK; idempotency and reconciliation. **Verify:** payment provider sandbox
only. Never process real charges or alter billing without approval.

## 20 — Disable debug in production
**Inspect:** prod flags, verbose error responses, stack traces, source maps,
admin debug routes and debug logging. **Fix:** safe error handling and internal
logging. **Verify:** production-like environment reveals no internals while
operators retain actionable diagnostics.

## 21 — Vulnerable dependencies
**Inspect:** lockfile, advisories, transitive packages, runtime relevance.
**Fix:** minimal compatible patched releases. Avoid blind major upgrades,
force-audit fixes and arbitrary package install scripts. **Verify:** audit
and build/unit/integration after upgrades; breaking upgrades need approval.

## 22 — Unused packages
**Inspect:** manifests, imports, scripts, dynamic imports, plugin runtime use
and build tooling. **Fix:** remove only verified-unused dependencies, preserving
lockfile integrity. **Verify:** build and functional tests. Treat dynamic
loading as a false-positive risk; questionable removals need approval.

## 23 — Exposed files
**Inspect:** public/static roots, deployment output, backups, DB dumps,
`.env*`, `.git`, source maps and misconfigured web servers. **Fix:** block
exposure and remove unnecessary deployed copies. **Verify:** local build
artifact inspection; authorized low-impact stage checks if approved.

## 24 — Git history secrets
**Inspect:** all available branches/history with vetted secret detection
(Gitleaks or equivalent); scope and tool version matter. **Fix:** do not echo
matches, record only provider/type/location and exposure window. **Verify:**
confirm history scan completed; its absence or no findings is not proof no
secret exists. History rewriting requires explicit owner approval and does
not replace revocation.

## 25 — Revoke and replace exposed keys
**Inspect:** confirmed exposed credentials and account scope. **Fix:** present
provider-specific owner rotation instructions; arrange secure replacement in
secret manager; update dependent systems and monitor. **Verify:** owner/provider
confirms old key revoked, new key works, no leaks in logs/bundles/history.
**Never** automatically revoke/reissue secrets or ask for the value in chat.

## 26 — Integrated security review
**Inspect:** revisit trust boundaries, privilege escalation, BOLA/IDOR,
account recovery, admin workflows, business logic, third-party access,
supply-chain, incident response and deployment exposures. Cross-check with
OWASP ASVS 5.0 and WSTG. **Verify:** consolidate findings, rank risk from
actual exposure, document uncovered boundaries and scope limitations.

## 27 — Test and report
**Inspect:** targeted tests per control, regression suite, build and CI,
remaining high-severity gaps and owner decisions. **Fix:** report validated
remediations and unresolved issues separately. **Verify:** summarize executed
commands and exits, report all 27 statuses, and issue release recommendation
without inventing certification.

## Standards

- https://agentskills.io/specification
- https://asvs.owasp.org/ (OWASP ASVS 5.0)
- https://wstg.owasp.org/v4.2/
- https://cheatsheetseries.owasp.org/
