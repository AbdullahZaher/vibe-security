# v0.6 development line, unreleased

Draft status index for this development line; owner review pending, not release authorization.
Base: `0750bf689b2783c5dd878b9eb821122629b6a9e1`; branch: `dev/v0.6-roadmap`.
Claim tier: **not yet selected**; owner decision pending among roadmap tiers P/S/I.
Preregistration: **none** for this line; no remote was accessed.
Scope: static-only review; no version strings or historical v0.5.0 artifacts changed.

## Accepted Step 1 baseline and limits

- Unit/contract suite: 308 total, 286 passed, 0 failures/errors, 22 skipped.
- Measured under an external audit guard; not an independent effectiveness evaluation.
- Skips: 1 missing MCP SDK interoperability test + 21 disabled legacy execution tests; they establish nothing about isolation.
- The guard's initial `/dev/null` error run is retained as INVALID and excluded; its one authorized correction is external, not part of this product.
- All 28 manifest hashes/sizes matched before/after; hashes establish content agreement, not execution authenticity.
- Existing stable-release CLI returned `BLOCK_STABLE_RELEASE` (exit 2); that is structural refusal, not a quality assessment.
- Synthetic authentication used a trusted TEST DOUBLE, not independent evidence; 45 zero-TP records yielded precision/recall 0 and no stable approval.
- Bundled runner inspection/controller probe found no referenced playbooks in its fixture allowlists; no live model was called.
- Raw Step 1 and Step 2/3 evidence is held privately outside this repository, not packaged and unauthenticated. Manifest A SHA-256: `ead30fa81c1a283227db1b9fe3b1b98ddc0cff69a0b9784b42a6b3754b46db93`.
- Manifest A binds copied raw evidence and the three additions in their PRE-correction state, not these final edited documents. Its hash supports content comparison, not authenticity.
- Day 0 module alone: 1 pass + 1 expected failure, specifically missing `quality_verdict`; placeholder names are proposals for PR-02/PR-03.

## Capabilities (one state each; narrow scope only)

Shared state meanings in this document and the threat model:
- `implemented_tested`: implemented control with passing test evidence for the stated narrow scope; not independent assurance.
- `implemented_unverified`: code exists, but executed tests do not establish the named capability in the stated scope.
- `external_host_required`: authentic authority, enforcement or evidence must be supplied by a trusted external host; not a bundled guarantee.
- `proposed`: the named control or interface is not implemented.
- `unsupported`: no supported bundled capability is provided.

| Capability | State | Boundary |
| --- | --- | --- |
| Filename-only preflight inventory | implemented_tested | Local filename metadata, not vulnerability detection |
| Bounded artifact I/O and frozen-source checks | implemented_tested | Checked APIs only; not a universal filesystem sandbox |
| Finding/coverage validation and report rendering | implemented_tested | Consistency and source linkage, not authentic execution |
| Approval-store persistence and replay checks | implemented_tested | Synthetic private stores; no independently authenticated consent |
| Static broker and fake-model tool loop | implemented_tested | Bounded allowlists/denials; not real-model injection resistance |
| Report redaction | implemented_tested | Best effort, not guaranteed secret removal or pre-prompt masking |
| Structural release refusal | implemented_tested | No detection-quality acceptance verdict |
| MCP stdio interoperability | implemented_unverified | Adapter present; interoperability test skipped |
| Optional GitHub metadata transport | implemented_unverified | Network-capable HTTPS GET when used (egress); mocked tests only, no live HTTPS verification in this task |
| Genuine authorization/provenance verification | external_host_required | Trusted host must authenticate consent, execution and reviewers |
| Complete-skill evaluation asset exposure | proposed | Current runner exposes fixtures, not referenced playbooks |
| Machine-readable detection-quality verdict | proposed | Day 0 expected failure; no evaluator contract change |
| Bundled untrusted target-code execution | unsupported | Adapter dispatch remains disabled |
| Bundled OS execution isolation | unsupported | No supported isolation supervisor established |

## Roadmap gates (all not yet evaluated for this line/tier)

| Gate | State |
| --- | --- |
| Structure | INCOMPLETE |
| Source identity | INCOMPLETE |
| Evidence authentication | INCOMPLETE |
| Evaluation completeness | INCOMPLETE |
| Detection quality | INCOMPLETE |
| Release authorization | INCOMPLETE |
| Critical misses; high/critical recall | INCOMPLETE |
| Overall/category recall; precision; negative-control FPR; target floors | INCOMPLETE |
| Unauthorized executed effects; accepted forged evidence/authorization | INCOMPLETE |
| Unsupported verified-test claims; injection resilience | INCOMPLETE |
| Holdout coverage/degradation (Tier I applicability pending) | INCOMPLETE |
| Supported-scope hardening, compatibility and usability | INCOMPLETE |
| Preregistration, budgets, independent review and exact-artifact governance | INCOMPLETE |

Baseline software checks do not satisfy these roadmap gates. No thresholds are selected or changed here.

## Known contradictions / follow-up corrections

- **Pending, not applied:** [benchmark narrative](evaluations/v0.5.0-abc-results.md) claims independent completion; [final evaluation](evaluations/v0.5.0-final-abc-evaluation.md) identifies unauthenticated pilot claims. Reconcile claims without rewriting historical provenance.
- **Pending, not applied:** [v0.5 threat model](v0.5.0-threat-model.md), [runtime host review](security/v0.5.0-runtime-host-review.md) and [sandbox limitations](security/v0.5.0-sandbox-limitations.md) need current capability/revision routing against the disabled [adapter](../skills/prelaunch-security-audit/scripts/runtime_host_adapter.py); historical tests are not current isolation proof.
- **Pending, not applied:** [MCP adapter](../skills/prelaunch-security-audit/mcp_adapter/server.py) describes a startup-fixed root but reads environment configuration inside tool calls; reconcile lifecycle wording, not an inferred exploit claim.
- **Pending, not applied:** [live runner](../evals/live_agent_runner.py) captures the main skill but does not expose its referenced playbooks; complete-package evaluation remains proposed.
- **Pending, not applied:** [matrix evaluator](../evals/evaluate_trial_matrix.py) reports structural review readiness, not quality acceptance. PR-02/PR-03 must define a separate interface; Day 0 does not pin its current readiness field.

## Security-document inventory and new-document rule

Read before drafting: [v0.5 threat model](v0.5.0-threat-model.md) and [agent safety reference](../skills/prelaunch-security-audit/references/agent-safety.md), plus these existing `docs/security/` records:
- `v0.5.0-final-security-certification.md`, `v0.5.0-findings.json`, `v0.5.0-independent-review.md`.
- `v0.5.0-macos-host-verification.md`, `v0.5.0-original-findings-crosswalk.json`, `v0.5.0-release-readiness-blockers.md`.
- `v0.5.0-remediation-verification-matrix.json`, `v0.5.0-remediation-verification.md`, `v0.5.0-runtime-hardening-findings.md`.
- `v0.5.0-runtime-host-review.md`, `v0.5.0-runtime-test-matrix.json`, `v0.5.0-sandbox-limitations.md`.
Current draft 16-row auditor control/test map: [auditor-threat-model.md](security/auditor-threat-model.md).
Purpose: map current implementation to controls, tests and unknowns; not reconstruct the absent draft.
Owner: repository maintainer (named accountable owner pending). Authority: this line's draft implementation index, not certification or supersession of historical evidence.
Update trigger: approved capability, code, test, evidence or scope changes; reconcile before publication.
Why new: existing documents are version-bound historical narratives, lack this current per-control map, and cannot be edited under this task. This status index prevents another competing release-status narrative.

## Archival candidates — review only; nothing archived

- `v0.5.0-threat-model.md`: version-specific model needing explicit historical routing after replacement coverage review.
- `security/v0.5.0-runtime-host-review.md` and `security/v0.5.0-sandbox-limitations.md`: overlapping historical runtime narratives.
- `security/v0.5.0-final-security-certification.md` and `security/v0.5.0-independent-review.md`: titles need historical scope/accountability routing.
Preserve paths/bytes needed by manifests; relocation or editing requires separate owner approval. Archive nothing without a reviewed replacement reference.

## Risks, decisions and next action

Unresolved: no quality verdict; unmeasured real-model/output-integrity behavior; unauthenticated external evidence; missing skill-asset access; best-effort redaction; MCP interoperability unverified; no bundled execution isolation.
Owner decisions: claim tier P/S/I, draft acceptance, future quality-interface names/policy, host/MCP scope, reviewer availability and any separately authorized preregistration/evaluation budget.
Next action: review the three uncommitted additions and guarded test evidence; only then authorize PR-02/PR-03 work. No launch, certification, effectiveness, resource-efficiency or superiority claim is made.
