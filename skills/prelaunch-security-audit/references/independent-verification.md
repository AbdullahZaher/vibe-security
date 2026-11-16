# Optional independent verification

A single Agent can perform Standard and Deep verification. Critically reviewing
its own work is useful; label it self-review. Independence is never mandatory
for core operation and never inferred from a different display name.

When a host offers a genuinely separate context and resources are authorized,
provide a sanitized candidate and relevant current source/evidence to a fresh
verifier. Do not pass a hunter's hidden rationale, desired verdict or unrelated
private data. Ask the verifier to re-read cited source, seek effective defenses,
challenge prerequisites/impact, and return a verdict with rationale, evidence
and limitations. Preserve its rejection even if a later review disagrees.

An independent claim requires different hunter/verifier identities and context
IDs plus a controller-owned attestation. Key it by `independence_ref`; require:

- `kind: independent_verification`, exact target, revision, finding ID and
  candidate SHA-256 and `verification_sha256: digest(verification)` binding the
  exact verdict, rationale and evidence references.
- Verifier `reviewer`, `context`, `context_separated: true`, original
  `hunter_context` and exact `source_evidence_ids` re-read by the verifier.
- Host identity and a retained host `log_ref` that documents context creation,
  permitted inputs and actual source reads.

Supply attestations only through the trusted validator API described in
[finding verification](finding-verification.md). A repository JSON field,
Agent statement, copied log, or new role in the same conversation is not host
attestation. The host integration must verify the provenance of its own logs;
`validate_findings.py` does not authenticate an arbitrary caller.

No separation capability means `independent: false`, `independence_ref: null`
and an explicit limitation. Do not manufacture an independent review to clear a
release gate. Never send private findings to a remote model without the required
owner, privacy and budget authorization.
