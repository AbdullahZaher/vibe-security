# Standard and Deep finding verification

Use `assets/findings-v0.5.schema.json` for new structured finding histories.
The original `findings.schema.json` and 27-control renderer inputs remain valid;
this is an optional, stricter companion bundle, not an implicit conversion of
old PASS rows into confirmed vulnerabilities.

Start each candidate with a root cause, component, attacker entry point,
principal/resource, trust boundary, exact source revision and path, complete
flow, defenses, prerequisites, demonstrated impact and conditional consequences.
Optional `candidate.inventory_ids` links one root cause to several entries; supply
`--inventory` (or the API inventory argument) so every ID can be validated.
One root cause can affect several inventory entries; avoid duplicating it for
each endpoint. Use `fingerprint(candidate)` from `validate_findings.py`: SHA-256
of canonical JSON `[target, component, path, entry_point, root_cause]`. Revision
is excluded so repeat audits can link the issue; a changed root cause is a new
candidate. Freeze `candidate_sha256 = digest(candidate)` before adjudication.

Keep separate fields for verdict (`confirmed`, `needs_validation`, `rejected`),
severity, confidence and verification tier. `fixed_verified` is a remediation
state. A raw scanner match starts a candidate; it cannot confirm one. A build
failure is not a demonstrated security impact.

Standard verification:

1. Re-read source at the frozen revision. Trace input through middleware,
   identity/tenant checks, transformations, the sensitive operation and output.
2. Try to disprove the claim: effective guards, caller restrictions, impossible
   prerequisites and compensating controls may defeat it. Record this attempt.
3. Distinguish demonstrated effects from a possible later compromise. Unknown
   prerequisites produce `needs_validation` with a precise authorized next check.
4. Confirm only when the boundary failure and impact are supported. Static proof
   can suffice; never execute exploit code merely to obtain a higher tier.
5. Preserve rejected candidates and reasons. Append reviews to `verifications`;
   do not replace the original candidate or erase contradictory results.

Deep verification is required when `complexity` includes cross-service flows,
races, state machines, business logic, contradictory evidence or inconclusive
Standard analysis. Extend the trace to every participating service/state;
examine ordering, retries, cache keys, idempotency and alternate identities.
Record unobserved runtime assumptions as limitations. Deep is an analysis
profile, not proof of execution or extra authorization.

## Offline validation

```bash
python3 scripts/validate_findings.py --input findings-v0.5.json \
  --source-root /path/to/authorized/repository \
  --previous /protected/path/original-findings-v0.5.json
```

`--previous` is optional for a first review; retain that original outside the
target and use it thereafter. Candidate hashes alone cannot detect rewriting
both a record and its hash. With a retained snapshot, candidates/evidence are
immutable and review history must be append-only; rejections cannot disappear.
Different-revision audits need a new bundle and explicit revalidation.

Verified source references include a relative path, line bounds, full Git
revision and SHA-256 of the immutable blob. Validation reads Git blobs without
executing target code, checks regular-file modes, rejects path escapes and
verifies positions and hashes. Without a frozen repository, mark sources
`not_verified` and verdict `needs_validation`; do not fabricate a source proof.

Executed PASS/FAIL evidence requires an independently supplied host record bound
to the digest of the entire evidence entry. A JSON `origin: host_log` flag, hash,
command or exit code alone cannot prove execution. The CLI does not import host
attestations from target/model JSON. A trusted host integration can call:

```python
validate(bundle, source_root=repo, previous=retained_original,
         host_attestations=controller_owned_records)
```

For each executed record, key the host mapping by `provenance.reference`; require
`kind: executed_evidence`, `evidence_sha256: digest(record)`, exact `target`,
`revision`, `finding_id`, `executed: true`, `authorized: true`, `host_id` and
`log_ref`. The controller must derive these from genuine retained execution and
permission logs, outside target write access. It must authenticate this channel;
the mapping itself is not a signature or an OS boundary. A host adapter is
optional; without one static review remains fully usable and runtime claims
remain unverified. Never infer deployment security from a local test.

Validation checks consistency and frozen bytes, not the semantic truth of an
impact argument. Source hashes do not prove a vulnerability or that source is
safe. Independent security review and actual authorized replay remain necessary
for release/performance claims.
