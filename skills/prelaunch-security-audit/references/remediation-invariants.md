# Remediation invariants and regression proof

Audit-only remains the default. An audit request authorizes no patch, commit,
push, production change or credential rotation. Use existing, specifically
scoped user authorization when supplied; new actions outside it need approval.
For high-impact auth, permissions, RLS, migrations, firewall/SSH and production
changes, require action-specific owner approval, tested recovery and staging
verification. The validator does not execute any change.

Before patching, freeze the candidate and its security invariants: exact
properties, IDs and all relevant actors/resources. Include alternate roles,
tenants, endpoints, states and concurrency/replay conditions where relevant.
Record a minimal proposed diff, changed paths, rollback and residual risk.

For `fixed_verified`, the new bundle validator requires:

- A confirmed finding, distinct exact baseline/fixed revisions, changed paths
  and diff SHA-256; approval bound to that candidate, diff, revisions and scope.
- Unchanged before/after invariant hashes. Dropping an invariant to make a test
  pass fails validation. Retain the original snapshot outside target control.
- Baseline negatives that fail specifically for `security_invariant`; quality
  failures, missing dependencies or environment errors are not baseline proof.
- Passing post-fix replay with the same method, expected result, actor/resource,
  environment and test-definition hash. Changing an assertion cannot certify
  the old invariant. Retain the test definition the host actually executed.
- Passing adjacent checks covering every declared invariant actor/resource pair.
  A failed, unrun, missing or unrelated role/tenant check blocks the claim.
- Controller-owned execution evidence for each actual test, never a JSON PASS
  alone. Every proof binds the finding, actor, resource, revision and invariant.
- High-impact changes additionally need a host-confirmed recoverable snapshot
  and passing authorized staging deployment evidence.

Use `proposed_fix_not_executed`, `needs_approval`, `not_verified`, `open` or
`accepted_risk` where appropriate. Accepted risk is not a fix. If baseline replay
is unsafe or the host cannot attest execution, document the limitation and keep
`not_verified`; a useful patch proposal does not require a false fix claim.

The trusted API mapping uses `approval_ref` for a `remediation_approval` record
with exact target, finding ID, candidate SHA-256, diff SHA-256, changed paths,
baseline revision, fixed revision, high-impact flag, host ID and retained log
reference. The controller derives approval from real owner authorization,
never from a repository or model field. For `backup_ref`, require
`kind: backup_snapshot`, target, finding ID, baseline revision,
`restore_verified: true`, host ID and retained log reference. These are input
contracts for a trusted host; they do not grant approval or certify isolation.
The CLI intentionally cannot import purported approval JSON.

A report must distinguish production-security blockers from release/build
issues and environment limitations. List executed/blocked checks, changes,
rollback, unverified conditions and residual risk. A fixed case is narrow proof,
not an assurance that all roles or every deployed path are safe. The Skill
remains an RC until real Agent evaluations, maintainer review and explicit owner
release approval satisfy the saved plan.
