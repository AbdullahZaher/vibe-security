# Incremental security audits

Bind the baseline and current assessment to full Git commit IDs. Keep prior
findings and test logs at their original revisions. A code diff is a review
input; unchanged text does not establish unchanged security behavior.

1. Compare immutable baseline/current snapshots. Include both old and new
   paths for renames and deletions. If the baseline was rebased away or is
   absent locally, record missing history; do not fetch or invent it.
2. Build a reviewer-inspected impact graph from callers, routes, authorization
   policies, data flows, deployment boundaries and dependency consumers. Edges
   point from a consumer to the security property/component it depends on.
   Include unchanged callers of changed authorization code.
3. Mark `graph_complete: false` when dependency enumeration is incomplete.
   Treat unknown runtime/deployment drift explicitly. Do not claim that source
   equality verifies production configuration or externally hosted components.
4. Reassess affected properties and adjacent actors/tenants. Preserve deferred
   units. Reuse prior evidence only after explicit current-revision review,
   retaining its original provenance and recording new revalidation evidence.
   Never relabel an old log with the new revision.

The optional `scripts/audit_diff.py` reads Git metadata without hooks, external
filters, textconv, target executables, network access or working-tree changes:

```bash
python3 scripts/audit_diff.py --root /authorized/checkout \
  --baseline <full-baseline-sha> --current <full-current-sha> \
  --graph /private/impact-graph.json
```

Omit `--current` to resolve current HEAD. Inputs must be full immutable SHA-1 or
SHA-256 commit IDs, not branch names, shell strings or revision expressions.
A missing baseline returns `baseline_available: false`; diverged history is
reported without merge, reset or checkout. The command compares committed
snapshots only. Inspect local modifications separately and do not claim this
output covers them.

A minimal declared graph has this shape (replace illustrative IDs/revisions):

```json
{
  "schema_version": "0.5.0",
  "target": "owner-service",
  "baseline_revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "revision": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "graph_complete": false,
  "runtime_drift": "unknown",
  "units": [
    {"id": "shared-auth", "paths": ["src/auth.py"], "depends_on": [],
     "runtime_sensitive": true, "prior": true, "deferred": false},
    {"id": "route", "paths": ["src/route.py"], "depends_on": ["shared-auth"],
     "runtime_sensitive": false, "prior": true, "deferred": false}
  ]
}
```

Direct changes invalidate their units and transitively dependent units. A
security-sensitive dependency-manifest change conservatively invalidates all
listed units. Missing baselines and incomplete graphs also invalidate all
listed units; unknown/changed runtime state invalidates runtime-sensitive units
and their dependents. Cycles terminate safely. This is a declared dependency
analysis, not an automatic cross-language call-graph scanner. Review omissions
and generated/dynamic behavior explicitly.

Output distinguishes `new`, `changed`, `unchanged`, and `deferred`. Every unit
still has `revalidation_required: true`; coverage is `unassessed` or `deferred`,
never inferred PASS. A diff cannot prove a fix, so `fixed_verified` is available
only through the separate findings/remediation validator with regression
proof. Deleted paths still invalidate prior dependent properties; deletion is
not automatically remediation. No output claims exhaustive discovery.
