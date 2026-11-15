# Coverage ledger and evidence linkage

Maintain `coverage-ledger.json` alongside the inventory in every review mode,
including Quick PR. Coverage describes assessment of a named security boundary
for specific inventory entries, actors and resources. It is separate from
inventory discovery, the 27-control status matrix, finding adjudication and
remediation. A covered boundary may have a confirmed vulnerability.

Use `assets/coverage-ledger.schema.json` and the offline validator:

```bash
python3 scripts/validate_coverage.py --input /private/coverage-ledger.json --inventory /private/attack-surface.json --source-root /approved/repository --artifact-root /protected/evidence
```

No tool installation, model API, MCP, Docker, target execution or network is
required. `--artifact-root` is needed only for retained evidence artifacts.
Source-only assessment is fully supported. Source paths are checked against
frozen Git blobs by the inventory validator. Without verified source input,
retain partial/unassessed coverage rather than manufacture evidence.

Coverage states:

- `covered`: relevant inspection or completed verification of the stated boundary.
- `partially_covered`: only some decisive checks or actors are assessed.
- `blocked`: a required capability, isolation or authorization is unavailable.
- `deferred`: deliberately postponed, for example after the configured budget.
- `not_applicable`: project-specific architecture evidence shows this boundary
  check does not apply; “not tested” is never a reason.
- `unassessed`: planned but not yet investigated.

Each unit records `unit_id`, `inventory_ids`, boundary, attack class, actors,
resources, status, reviewer, revision, method, evidence IDs and rationale. Generate
IDs with `validate_coverage.unit_id(unit)`: `cov-` plus 24 SHA-256 hex characters
of compact ASCII JSON encoding of `[sorted(inventory_ids), boundary, attack_class,
sorted(actors), sorted(resources)]`. Revision is excluded so stale results can be
identified, but each assessment and evidence record must match the current
inventory revision. A renamed entry or changed boundary requires a new ID.

Evidence records bind to exactly one coverage unit and target/revision, with
inventory IDs, boundary, actors/resources, kind, tier, method, environment,
operator, timezone-qualified timestamp, observed outcome, source references and
optional retained artifact hash/path. All proof actors/resources must exactly
match the coverage unit. A service-role test cannot certify ordinary tenant
access. Each verified source span must cover the cited inventory span; a test
from a different endpoint in the same file is insufficient. Units and evidence
must match the inventory boundary. Split mixed-boundary assessments.

Source/architecture inspection uses tier `source` and result `observed`, never
executed PASS. Test evidence uses `build`, `runtime` or `deployment` and a
recorded result. Completed tests require retained, hash-checked logs outside the
target repository. N/A requires architecture inspection, not a passing unrelated
suite. `not_run`, `blocked`, `inconclusive`, dangling IDs, duplicate IDs, unknown
properties, revision mismatches and contradictory states cannot establish
covered/N/A. Failed executed tests can establish *assessment* while showing a
control failed; coverage is not security success.

The summary always includes counts of every coverage state, discovered in-scope
inventory denominator, units represented in the ledger, inventory entries with
some assessment, and inventory IDs absent from the ledger. “Inventory with
assessment” does not imply every actor/resource combination was tested. Unknown
outside-inventory units and discovery limitations remain explicit; no percentage
or universal all-clear is generated. Quick budgets cannot turn partial scope into
complete coverage, and 27 completed control rows never equal full attack surface.

Hashes detect changed bytes, not authentic execution. `evidence_authenticity`
remains `not_verified`; a dishonest author can fabricate plausible text. A
trusted host must retain real command/effect logs, and a reviewer must inspect
relevance before making runtime or release claims. Evidence paths reject
traversal, symlinks (including root ancestors), non-regular files and oversized
content. On hosts without safe descriptor-relative reads, artifact reading fails
closed; manually inspect source and report unverified limitations.
