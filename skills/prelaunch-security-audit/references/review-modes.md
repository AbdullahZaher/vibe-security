# Review modes — minimize unnecessary tests

## Quick PR security review

Use for a small, authorized pull request or change request, **not** a
production launch or a request for full assurance. Default to read-only unless
the owner explicitly requests code fixes.

1. Inspect the exact base/head diff, changed routes, database policies,
   secrets names, package scripts, CI, and callers of modified code.
2. Trace adjacent trust boundaries (authentication, authorization, tenant IDs,
   payment/webhook signatures, file storage, outbound fetches).
3. Prioritize targeted negative-security regression tests. Do not rerun
   unrelated suites just because the 27-control full checklist exists.
4. State the tested revision, test commands/exits, findings and unreviewed
   surfaces. Never present a 27/27 PASS or a release recommendation from this mode.
5. Promote to full prelaunch mode for broad auth/RLS changes, secrets exposed,
   payment logic or production infrastructure changes, or when requested.

For source-only reviews without a shell, mark behavioral tests not verified;
do not fabricate passing outcomes. Missing a vulnerable code path in the diff
does not prove the deployed environment is safe.

## Full prelaunch audit

Apply controls 01–27 sequentially, assess deployment and runtime boundaries
when authorized, generate the evidence-based 27-row report and perform a
manual release decision. `not_verified` is not a passing status.
