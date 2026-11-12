# Coverage and evidence-quality rules

## Before remediation

- Establish base revision and branch. Preserve local changes and document the actual test environment.
- Confirm a vulnerability with safe evidence; if the user approves a local test, write a minimal regression assertion for the vulnerable behavior when feasible.
- Before making a fix, run the regression test on the vulnerable baseline; it should **fail for the expected security reason**. If impossible, disclose the limitation instead of inventing a baseline.

## After remediation

- Re-run the same assertion against the patch and ensure it **passes for the expected security invariant**; note that only one checked input path is covered.
- Test adjacent paths: alternate roles, tenants, API methods, object IDs, failure paths, replay, concurrency, serialization, and caching where applicable.
- Run authorized build/typecheck/unit/integration and report exact commands and exit codes.
- Track which control, asset and environment the evidence supports. A passing unit test never proves an entire live deployment is secure.

## Coverage labels

- `pass`: Applicable control successfully verified for the documented scope using executed evidence.
- `fixed_verified`: A defect was fixed and its regression evidence executed successfully.
- `failed`: Issue reproducible, unresolved, or executed protection test failed.
- `needs_approval`: Remediation or validation cannot proceed without owner decision.
- `not_applicable`: Excluded by architecture with a specific rationale.
- `not_verified`: Missing tools, evidence, permissions, or inconclusive result.

`not_applicable` needs a written rationale. `not_verified` may coexist with serious unknown risk; do not present as low risk. Do not claim a broad all-clear from a generated JSON template.
