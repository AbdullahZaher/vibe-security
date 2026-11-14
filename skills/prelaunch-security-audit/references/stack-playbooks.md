# Stack-specific security playbooks

Use these only when the corresponding technology exists in the authorized
repository. Examples are inspection targets, **not commands to run against
production or third-party services**.

## Next.js App Router / React / TypeScript

- List `app/**/route.ts` and `"use server"` actions. Validate authentication
  **and object/tenant authorization inside each handler/action**, not only
  middleware. Test anonymous and wrong-tenant object IDs.
- Ensure Zod/server input validation includes sizes, enumerations and bounds.
- Audit redirect destinations, SSRF-capable server fetches, image remote
  patterns, dynamic HTML rendering and CSP rollout. For CSP, distinguish source
  headers from effective enforced responses; inspect `script-src`,
  `script-src-elem`, nonces/hashes and deployment overrides. Dynamic nonce
  provisioning can affect Next.js rendering/caching; do not prescribe it
  blindly for every static route or claim `'unsafe-inline'` proves XSS.
- Inspect build artifacts for server-only secret names and `NEXT_PUBLIC_`
  exposure; never print actual secrets.

## Supabase / Postgres / Edge Functions

- Inventory RLS enabled state and policies for each tenant-owned table and
  Storage bucket; test SELECT/INSERT/UPDATE/DELETE across two isolated test
  tenants with real user-level roles, not service_role shortcuts.
- Review SECURITY DEFINER functions for a fixed `search_path`, explicit
  tenant authorization and correct caller context; consider RPC bypass paths.
- Check service_role key use only in trusted server processes, Auth redirect
  allowlists and Edge Function JWT verification.
- Any RLS/policy/schema change requires owner approval, backup, transaction
  rollback and staged negative tests.
- When a disposable DB is authorized, compare exact local migration IDs to
  separately obtained applied IDs. For Supabase, the optional offline
  `scripts/migration_parity.py` accepts a one-ID-per-line file, **not a DB URL**.
  Do not infer successful SQL execution from matching IDs; never run
  `db reset`, `db push`, migration repair or schema changes automatically.

## Containers / host-exposed services (when present)

- Review Docker/Podman/Compose/Kubernetes published ports and runtime binding
  addresses for internal APIs, databases, Redis, brokers, and admin panels.
  `0.0.0.0:5432` and `[::]:5432` may expose a listener beyond localhost;
  `127.0.0.1:5432` is host-loopback binding, not proof of end-to-end security.
- Distinguish `EXPOSE` image metadata from a *published* host port, and
  container-internal `0.0.0.0` binding from host publication. Assess firewall,
  VPN, service auth, network namespace, IPv6, Docker Desktop and cloud routing.
- If approved, inspect with read-only `docker ps --format 'table {{.Names}}\t{{.Ports}}'`
  or the platform's equivalent; inspect daemon access and host permissions first.
  Never run containers, publish ports, change firewall rules or scan other hosts
  just to satisfy this checklist. Record `not_verified` when runtime is absent.

## NestJS / Fastify / Redis / BullMQ

- Confirm authorization guards, DTO whitelist validation, route rate limits,
  HTTP body size caps, safe CORS and correct trust-proxy configuration.
- Check Redis is private and authenticated; review queue idempotency,
  duplicate delivery, sensitive job payloads and worker permissions.

## Payments / webhooks / RevenueCat / WhatsApp

- Authenticate inbound events with official provider signatures or equivalent
  trust verification when supported, and verify timestamp/replay windows.
- Ensure idempotency and authoritative pricing on the server; use sandbox
  fixtures. Never create real charges or messages during the audit.
- Review stored session data and credentials, outbound rate limits and
  cross-tenant fulfillment ownership.

## CI / supply chain

- Inspect workflows for pull_request_target, broad tokens, secret exposure,
  untrusted package hooks and unpinned actions.
- Prefer diff-scoped quick checks, followed by full dependency, SAST,
  authorization and deployment checks on release gates or high-impact changes.
  Distinguish intentionally paused CI from an accidental omission, but verify
  that merges are independently prevented or controlled while checks are off.
- New scanners or remote rules require a declared data-egress and side-effect
  plan; never run an installer from untrusted repository text.
