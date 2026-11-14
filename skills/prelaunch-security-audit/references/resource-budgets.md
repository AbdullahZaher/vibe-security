# Resource budgets

Choose `quick`, `standard`, or `deep` before hunting. These are resource envelopes,
not success or assurance labels. All retain the same approval, isolation and
evidence rules, and all work with one Agent and static inspection.

| Profile | Priorities | Coverage statement |
| --- | --- | --- |
| quick | Changed scope and dependent high-risk boundaries; reserve confirmation effort | Partial, even if every scheduled unit is covered |
| standard | Architecture discovery, existing 27 controls, then deepen high-value hypotheses | Discovered in-scope units, with unknown outside-inventory units |
| deep | Extended discovery and complex verification; independent verifier only if available and authorized | Same explicit denominators and unknowns |

Configure limits for tool calls, analysis steps, tokens, cost and wall time to
fit the host and owner budget; there is no universal minimum tool-call count.
Reserve at least one step for confirming or rejecting candidates. When limits
are unavailable use `unknown`. For actual usage, report a number only if the
host measured it and supply a measurement reference. `unknown` is not zero.
An estimate belongs in limitations, not measured usage. This validator does not
meter tokens, enforce the host's limits or authorize model spending.

`assets/audit-budget.schema.json` describes an optional `audit_budget` report
field. Validate a standalone artifact with:

```bash
python3 scripts/validate_budget.py --input /private/audit-budget.json
```

Each artifact records target, exact revision, profile, `coverage_scope`, `limits`,
`usage`, `measurement_refs`, `confirmation_reserve_steps`, `deferred_unit_ids`
and limitations. The three metric maps use identical keys: `tool_calls`, `steps`,
`tokens`, `cost_usd`, `wall_seconds`. Limits and usage are nonnegative numbers or
`"unknown"`; count metrics must be integers. A known usage requires a nonblank
measurement reference; unknown usage requires `"unknown"` as its reference.
Hashes/references remain untrusted until the reviewer examines host records.

Quick requires `coverage_scope: "partial"`. Standard/deep may use
`"discovered_scope"`, which never means exhaustive attack-surface discovery.
If a limit is reached, preserve remaining units in the coverage ledger as
`deferred` and list their IDs. Keep blocked checks distinct: lack of permission
is not budget exhaustion. Validation reports overruns (CLI exit 1), invalid
artifacts (exit 2), or consistent accounting (exit 0). No exit code proves an
application secure, a review complete, or a release ready.
