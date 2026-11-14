# Evidence provenance and report honesty

A control's evidence must identify **what was tested**, **where**, **when**,
**against which revision**, and **the observed result**, without leaking data.

## Evidence tiers

- `source`: code/config/dependency inspection; proves only that text exists.
- `build`: a reproducible test/build/scan from a named source revision.
- `runtime`: observed behavior under test in a named local/staging environment.
- `deployment`: verified deployed configuration/behavior of an authorized target.

These are *types*, not a guaranteed hierarchy. A runtime XSS test cannot prove
that a production proxy adds HSTS, and a successful build cannot prove an
authorization boundary is secure. Use the narrowest claim supported by each
piece of evidence. Link raw logs privately, record commands and exit codes,
redact identifiers/secrets, and explain missing prerequisites.

## Required provenance for confidence

- Source/revision (Git SHA or immutable artifact reference), environment,
  subject, method, expected result, observed result, timestamp, and operator.
- For a regression fix, reproduce the failing behavior before the patch when
  safe, then test the same security invariant after it. Add negative tests,
  cross-tenant/role variants and normal-use regressions as applicable.
- Re-run checks on the final revision. CI on an older commit or screenshots
  from a different deployment never proves the new revision passed.
- `not_run`, `blocked`, and `inconclusive` cannot become `pass`.
- Keep findings separate from test logs; a markdown report or JSON entry is a
  claim and is not independently authenticated evidence.
- Mark any ASVS requirement outside scope as `not_verified` or explicitly
  `not_applicable` with rationale. No checklist equals ASVS certification.

The bundled renderer conservatively downgrades unsupported PASS claims when
metadata contradicts the evaluated revision; it cannot verify arbitrary input
logs are truthful. Human review is essential before launch decisions.

## Report release gate (v0.4.0-rc1)

- A control marked `not_applicable` requires a substantive
  `not_applicable_reason`, a nonempty `evidence` location, a repeatable
  `test_method`, a concrete `evidence_tier` and `evidence_revision` matching
  the reviewed scope. Proposed `fix` text does **not** establish N/A.
  A failed/blocked check cannot be labeled N/A.
- A scoped all-clear cannot come from one unrelated passing test. Every
  applicable `pass`/`fixed_verified` control needs a `verification_ref`
  pointing to a distinct, matching `verification_log[].id`, `control_id`,
  revision, method, environment, observed result and PASS. At least one
  applicable control must actually be verified; 27 N/A claims cannot produce
  an all-clear.
- For a high/critical finding, any claimed verified resolution needs an
  entry with matching `finding_id`, not only a shared log from another issue.
  Verification IDs cannot be duplicated.
- These checks enforce **structural consistency**, not the authenticity of
  submitted test logs. A human security reviewer must independently examine
  command output, environment and target revision before launch approval.
