# Scanner selection, privacy, and execution boundaries

The skill is not a scanner. Install/use dedicated tools only when the project owner authorizes network access, installation, CPU use and data handling.

## Pre-scan plan (required)

Before any nontrivial scan present: (1) repo and paths, (2) tool name and version, (3) mode and configuration/ruleset provenance, (4) whether source or telemetry leaves the host, (5) potential side effects and files written, (6) expected runtime/resource impact, (7) output location and data sensitivity, (8) exact command, and (9) rollback/cleanup. Do not auto-execute untrusted project `postinstall` scripts or remotely fetched shell scripts. Let host enforce approval.

## Typical tools (choose based on stack)

- **Semgrep:** review config source and transmission behavior; `--metrics=off` when compatible. Never assume cloud rules or remote auto config keep code private. Pin rules where practical; explain coverage and false positives.
- **CodeQL:** prefer organization-approved pack/query versions; avoid claiming deep cross-file coverage if databases are incomplete.
- **Gitleaks:** scope an authorized local Git history, capture redacted type/path only; avoid printing raw matches; record unscanned refs.
- **OSV-Scanner / ecosystem audit:** check dependency advisories and lockfiles; differentiate reachable runtime risks from dev-only packages; avoid blind auto-fixes or running lifecycle scripts.
- **Browser / HTTP:** explicit staging scope and safe request budgets; no uncontrolled active exploitation against public websites.

## What a 'passed' check means

State exact tested invariant, run environment, revision, command/tool/version, observed behavior, exit result and independent evidence pointer. Do not transform a scanner's `0 issues` into a global security pass. A scanner error, timeout, empty scope, missing database or unsupported language is `not_verified`, never `pass`.

## Reporting privacy

Put detailed findings in an access-controlled location. Only redact and summarize for broad sharing. Do not place raw SARIF, exploit traces, auth tokens, private endpoints, production data or secrets into public issues/PRs. A regex-based sanitizer is best-effort, not a guarantee.
