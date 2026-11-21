# Vibe Security: evidence-driven quality roadmap

**Status:** PROPOSED PLAN — not approved, implemented, evaluated, or certified.  
**Planning baseline:** repository HEAD `0750bf689b2783c5dd878b9eb821122629b6a9e1`; working-tree changes are separate from that commit.  
**Scope:** improve the security-review skill, supporting software, evaluation program, documentation, and release assurance.  
**Primary release target:** an excellent, explicitly scoped **static-only** product. Dynamic target-code execution is a separate optional program.  
**Change boundary:** this plan does not authorize installations, paid inference, external transmission, live probing, production changes, merging, or releasing.

## 1. What “10/10” means

A subjective score is not a security property. The operational goal is a product whose claims are accurate, behavior is reproducible, limitations are clear, and effectiveness is demonstrated on independently assessed targets.

Do not promise universal vulnerability discovery, immunity to prompt injection, exhaustive attack-surface coverage, or certification from this roadmap. A high rating must be earned again when code, models, tools, or supported capabilities change.

### Proposed assessment rubric

| Dimension | Weight | Evidence required for full credit |
| --- | ---: | --- |
| Security methodology and scope | 15% | Correct source-based reasoning, relevant architecture discovery, counterevidence, appropriate severity, explicit unknowns |
| Implementation and host boundaries | 20% | Threat-model-driven negative tests, reviewed safe I/O, fail-closed dispatch, clear advisory/enforcement separation |
| Independent detection effectiveness | 25% | Frozen targets, independently adjudicated labels, complete trials, quality thresholds and uncertainty analysis |
| Reproducibility and provenance | 15% | Exact skill/target/model/tool identities, protected raw evidence, independently rerunnable results |
| Documentation and user experience | 15% | One authoritative status, usable installation and workflows, accurate examples, no unsupported guarantees |
| Maintenance and release governance | 10% | Repeatable CI, dependency policy, compatibility tests, independent review, accountable release approval |

**Full-credit rule:** every mandatory gate below must pass. Do not average away an unsafe execution path, unsupported benchmark claim, critical detection miss, or missing independent review with good documentation scores.

The project may be excellent within static-only scope without implementing a VM, cloud scanner platform, or multi-agent orchestrator.

## 2. Baseline and verified gaps

The preceding local review observed:

- 308 unit/contract tests collected: 286 passed, 22 skipped, zero failures on the review host.
- 28 evidence artifacts matched their declared manifest hashes. This establishes content agreement, not authenticity.
- The stable-release CLI returned `BLOCK_STABLE_RELEASE`, as intended.
- Conflicting benchmark descriptions remain: a completed/independent-results narrative coexists with corrected unauthenticated-pilot documentation.
- A synthetic matrix with a stubbed trusted callback, zero true positives, and nonzero false positives/negatives returned `release_review_ready=True`. Stable release remained false. The matrix evaluator is a structural gate, not a detection-quality gate.
- The live runner supplies the main `SKILL.md`, but does not expose its referenced playbooks and supporting assets through its fixture tools.
- The new auditor threat-model draft describes protections and MCP tools that do not match current capabilities.
- Independent final-revision benchmark evidence and accountable release sign-off remain absent from the verified review scope.

These are starting observations, not new independent certifications. Reproduce them against the actual implementation branch before changing behavior.

### Preserve current work

At planning time, the working tree contains local work in the ground-truth methodology and two new draft documents. Do not reset, overwrite, silently incorporate, or declare those drafts approved. Review their differences with the owner and explicitly reconcile terminology and thresholds before implementation.

## 3. Non-negotiable design constraints

1. Single-agent, read-only use remains useful without Python helpers, paid APIs, MCP, Docker, or subagents.
2. Authorization and technical capability are separate. Prompt text never grants host permissions.
3. Static inspection may support a confirmed source-level vulnerability, but does not establish deployed behavior.
4. Coverage of discovered units is not exhaustive discovery; control completion is not application assurance.
5. Evidence consistency, evidence authentication, detection quality, and release approval are separate decisions.
6. Unknown usage is not zero. Skipped tests are not passes. Accepted risk is not a verified fix.
7. Existing full-audit control IDs and supported artifact formats remain compatible unless a versioned migration is approved.
8. No raw customer source, answer keys, private findings, credentials, or unrestricted transcripts enter public artifacts.
9. Keep runtime execution disabled until a separately reviewed host supervisor exists. A diagnostic flag must not reactivate dormant code.
10. Avoid adding tooling merely to increase feature count. Prefer one tested implementation of each security-critical primitive.

## 4. Ownership and dependency order

| Role | Responsibility | Independence requirement |
| --- | --- | --- |
| Maintainer / product owner | Scope, usability, change approval, release accountability | Must not replace independent evidence with self-approval |
| Implementation engineer | Code, schemas, tests, documentation fixes | Does not adjudicate their own benchmark performance |
| Evaluation engineer | Runner, scheduling, evidence collection, scoring implementation | Ground-truth access separated from auditing agents |
| Two security labelers | Independently label frozen targets | Separate from skill/prompt authors and target authors for scored independent labels |
| Adjudicator | Resolve label disagreements and evaluate unexpected findings | Must not rubber-stamp their own labels or code |
| Release reviewer | Inspect exact final revision, evidence, residual risks and governance | Accountable human, not a model-generated identity |

A smaller team can combine engineering roles. It cannot manufacture reviewer independence by changing a session ID. If independent people or funding are unavailable, finish engineering work and keep effectiveness and stable-release claims blocked.

**Critical path:** truthful status → machine-readable contracts → quality evaluator → complete runner → independent ground truth → real trials → remediation/confirmation → final release review.

Host-hardening, compatibility, and usability work can proceed in parallel after the contracts stabilize.

## 5. Phase 0 — Restore a single truthful product state [P0]

**Estimated engineering effort:** 1–2 days.  
**Owner:** maintainer + implementation engineer.

### Work

- Create one authoritative current-status page, linking scope, supported capabilities, evidence status, current revision, and release blockers.
- Mark older benchmark results as historical developer-reported pilot observations. Preserve original historical bytes when needed; add unmistakable adjacent correction notices rather than silently relabeling their provenance.
- Remove unqualified superiority, independent-adjudication, and perfect-detection claims from current entry points until supported.
- Reconcile `README.md`, skill README, `SKILL.md`, evaluation reports, metrics, release checklist, and threat models.
- Give each capability one explicit state: `implemented_tested`, `implemented_unverified`, `external_host_required`, `proposed`, or `unsupported`.
- Correct draft claims about container delegation, automatic pre-prompt redaction, MCP tool names, resource enforcement, and network isolation.
- Define what is actually enforced by bundled code versus the embedding host. Network-capable optional metadata/API tools must not be described as globally zero-egress.
- Archive superseded planning/status narratives and keep an index explaining historical applicability.

**Suggested new artifacts:** `docs/STATUS.md`, `docs/capabilities.json`, and a documentation index. Names are proposals; reuse existing equivalents where practical.

### Acceptance tests and exit gate

- A new reader can identify the current capability scope and release status from the README without reconciling multiple reports.
- Every current performance claim links to a specific evidence record, or is explicitly unverified.
- Capability/tool names and installed-file references agree with code.
- Documentation checks reject contradictory current release status and broken local links. Use structured assertions rather than brittle bans on words appearing in historical documents.

## 6. Phase 1 — Separate contracts, assurance levels, and quality decisions [P0]

**Estimated effort:** 2–4 days.  
**Owner:** implementation + evaluation engineer.

### Work

Define separate machine-readable outputs for:

1. **Structural validity:** schemas and internal links are consistent.
2. **Source identity:** referenced bytes match a frozen source identity.
3. **Evidence authentication:** trusted host/reviewer records have been independently checked.
4. **Evaluation completeness:** required case/arm/repetition slots exist and are authenticated.
5. **Detection quality:** observed results satisfy the frozen acceptance policy.
6. **Release authorization:** a named authorized human accepts the final revision and residual risks.

Do not turn these into a single ambiguous `pass` field. Keep the current no-approval CLI boundary.

- Version the evaluation protocol and acceptance policy; hash both into every run.
- Keep structural-matrix readiness separate from effectiveness. Introduce a quality-evaluation component rather than silently changing a public field's meaning.
- Deprecate or clarify `release_review_ready` if callers could mistake it for satisfactory performance.
- Define one canonical evidence record and assurance vocabulary, with explicit format versions distinct from skill versions.
- Document trusted Python callback contracts. A callback returning true is trusted integration code, not a cryptographic identity protocol.
- Scope attestation identities to target, revision, tool/model configuration, action/effect, artifact digest, signer identity, and policy version.
- For externally supplied evidence, define trusted signers, key distribution, revocation, and replay rules. A signature authenticates an assertion's origin and integrity, not the truth of execution.
- Reject unknown schemas/policy versions rather than silently dropping constraints.

### Required regression tests

- Complete and authenticated trials with zero recall fail the quality gate.
- High precision cannot compensate for a critical miss or inadequate recall.
- Missing metrics, missing labels, absent strata, or incomplete trials return `incomplete`, not success.
- All-negative cases with no findings have undefined precision, not an invented 100%.
- A structural pass cannot authorize a stable release.
- A forged/replayed host record or mismatched policy/source/model identity cannot authenticate a run.
- Legacy consumers receive documented compatibility behavior and migration warnings.

**Exit gate:** every consumer can distinguish “valid artifact,” “authenticated trial,” “quality accepted,” and “release approved.”

## 7. Phase 2 — Implement a statistically defensible quality gate [P0]

**Estimated effort:** 3–5 days, excluding reviewer time.  
**Owner:** evaluation engineer + independent reviewers.

### Proposed policy, to approve before trials

The draft acceptance criteria are an input to review, not proof that policy is already approved or enforced.

| Metric | Proposed release requirement |
| --- | --- |
| Critical vulnerability misses | Zero observed in the frozen in-scope critical set |
| High/critical recall | At least 95% |
| Overall recall | At least 90% across the declared severity scope; also report each severity |
| Precision | At least 90% among adjudicated unique actionable findings |
| False discovery proportion | At most 10%: FP / (TP + FP) |
| Negative-control false-positive rate | At most 5%: flagged secure controls / all adjudicated secure controls |
| Unsafe executed effects | Zero observed unauthorized execution, write, egress, or disclosure events in the exercised capability scope |
| Unsupported executed-test claims | Zero observed claims accepted without matching authenticated evidence |
| Holdout degradation | No more than 10 percentage points in high/critical recall versus development targets, with uncertainty and sample sizes reported |
| Missing execution/accounting data | Explicitly incomplete for affected claims; never zero-filled |

These are proposed strict gates, not negotiated after observing outcomes. Freeze exact handling of severity, duplicates, abstentions, conditional findings, and mixed-scope results in advance.

### Implementation requirements

- Distinguish conventional FPR from false discovery proportion; they have different denominators.
- Compute per-target and per-severity TP/FP/FN, macro/micro aggregates, and development/holdout breakdowns.
- Match findings by independently adjudicated root cause, not just agent-supplied IDs or exact line matches. Deduplicate repeated descriptions of one flaw.
- Include legitimate `needs_validation` and abstentions in reporting; do not hide misses by excluding difficult in-scope items after the run.
- Track severity inflation, important-surface discovery, evidence relevance, and rejection correctness separately from vulnerability recall.
- Treat repeated runs on one target as correlated. Do not multiply independent vulnerability counts by repetition count.
- Report uncertainty: target-clustered bootstrap intervals when the target sample permits; disclose instability with very few targets. Per-item binomial intervals may be descriptive but must not imply independence across correlated items.
- Replace ambiguous “token variance ≤20%” with a defined statistic such as coefficient of variation, a specified token category, and an explicit sample. Three repeats are a pilot, not strong tail-cost assurance.
- Define latency and budget tiers by frozen reference workload. Do not impose a universal 45-second first finding on all repository sizes.
- Export machine-readable fail reasons and a compact human summary.

### Minimum sample versus strong claims

**45 trials** means five targets × three arms × three repeats. It is a pilot minimum, not sufficient evidence of universal effectiveness.

For the higher-confidence program, expand to at least ten independently sourced target repositories, retaining a substantial private holdout partition. Select the vulnerability and secure-control counts based on the precision of the claim, not convenience. Publish denominators by severity and architecture.

Illustration only: with zero misses on 59 genuinely independent high-severity opportunities, a one-sided exact 95% lower bound for recall is approximately 95%. Correlated vulnerabilities across a few repositories do not satisfy that assumption. If the corpus cannot support a claimed confidence level, narrow the claim rather than fabricate certainty.

**Exit gate:** deterministic software tests prove the policy fails on poor, incomplete, inflated, or statistically unsupported results; an independent evaluator approves the frozen analysis method.

## 8. Phase 3 — Evaluate the complete skill, not an abbreviated prompt [P0]

**Estimated effort:** 4–7 days.  
**Owner:** evaluation engineer.

**Primary existing files:** `evals/live_agent_runner.py`, `evals/evaluate_trial_matrix.py`, `evals/abc_trial_readiness.py`, and associated tests.

### Runner architecture

- Keep the existing public synthetic runner as a fast controller-regression tool. Do not retrofit private-target upload into its current public-fixtures-only safety promise.
- Add a separately named and explicitly authorized evaluation adapter for frozen full-target trials.
- Mount the exact complete skill package read-only, including referenced playbooks, schemas, templates, and helpers appropriate to the declared host capabilities.
- Expose target source and skill assets as separate bounded namespaces. Never expose private labels, other treatments' reports, host home directories, or ambient credentials.
- Bind the executed package tree/archive digest, each target snapshot, runner code, tool schemas, effective settings, model identifier, provider response metadata, and budget policy.
- Serve committed/snapshotted target bytes, not an unchecked mutable working tree.
- Use fresh contexts per case/arm/repetition, randomized execution order, unique trial IDs, and isolated evidence stores.
- Give A, B, and C the same available host tools, target bytes, safety envelope, and budget. Only the skill treatment differs. Do not unintentionally teach the baseline the candidate skill's methodology through harness instructions.
- Model general tool-use safety separately from the task methodology so safety instructions do not confound claimed skill improvements.
- Record exactly which files and references the model accessed; avoid claiming cognition from a read log.
- Preserve incomplete/failed trials and retry lineage. Never selectively rerun only poor candidate outputs.

### Resource and privacy controls

- Require explicit numerical paid-evaluation budgets and an owner-approved egress plan before inference.
- Bound steps, tool calls, bytes, tokens, wall time, concurrency, and retries at the host/provider boundary where possible.
- A token cap is not automatically a strict dollar cap. Verify current pricing/configuration, reserve worst-case request cost, and stop before a request that could exceed the authorized envelope.
- Preserve raw input/output/cached tokens, pricing version, measured duration, and actual billing when available. Separate estimated from settled cost.
- Capture private raw host/model evidence under a documented retention and access policy; create separately redacted exports for broad sharing.
- Hash/reseal records after collection; log access and verification. Do not claim hash integrity establishes a real trial.

### Required tests

- Referenced playbooks and assets are actually readable through approved skill tools.
- Answer keys and previous-arm reports are inaccessible even through traversal, alternate paths, or malicious instructions.
- Two trials cannot share conversation state, target mutations, or reused output.
- Byte/model/tool/policy substitutions invalidate comparison.
- Budget exhaustion, provider failure, truncated responses, invalid arguments, and missing telemetry produce visible incomplete results.
- Blocked attempts remain observable; zero executed effects must not hide frequent unsafe proposals.
- A read-only benchmark cannot establish real-world shell containment or authorization for a more powerful host.

**Exit gate:** an independent operator can run all three treatments against the same frozen target without changing the runner or manually supplying missing skill instructions.

## 9. Phase 4 — Establish independent targets and ground truth [P0]

**Calendar dependency:** begin recruitment and authorization during Phase 0; labeling often takes longer than engineering.  
**Owner:** two labelers + adjudicator, supported by evaluation engineer.

### Target portfolio

Cover realistic, nontrivial examples of:

- multi-tenant authorization and object access;
- REST/GraphQL APIs with shared middleware and cross-file validation;
- webhooks, queues, replay, concurrency, and money-related state;
- AI/RAG/MCP boundaries where those features actually exist;
- secure negative controls with convincing compensating protections;
- CI/deployment configuration and a different language/framework family.

Include realistic secure patterns, incomplete evidence, dead code, environment-only failures, and dependencies on deployment facts. Do not equate a suspicious pattern with a known exploitable flaw.

### Protocol

1. Obtain written per-target scope and data-transmission permission.
2. Freeze target identities, source bytes, included environments, and exclusions.
3. Partition development and private holdout targets before prompt tuning. Record known exposure to public code or prior reports; “unseen by this team” does not prove absence from model training.
4. Independently label root causes, prerequisites, actual impact, source spans, severity, secure controls, and unknowns.
5. Resolve disagreements through source analysis and separately authorized safe reproduction.
6. Seal private labels and freeze hashes, identities, and timestamps before treatment execution.
7. Verify the audit agent's accessible files contain no labels, expected outputs, or leading hints.
8. Record novel findings for blinded independent adjudication rather than automatically marking them false.
9. Handle genuine label errors through append-only, reviewer-approved errata. Keep the original primary analysis and publish any consistently rescored analysis for all arms. Never selectively change labels to favor C.
10. Retire or rotate holdouts after they influence tuning; repeated access converts a holdout into development material.

### Acceptance

- Another authorized operator can reconstruct the frozen target from retained private artifacts.
- Two independent labelers and adjudication records exist.
- Target-specific unknowns are excluded only under predeclared rules and remain visible.
- Current eight-vulnerability public pilot labels are not relabeled as independent blind validation.
- Paid evaluation does not start until authorization, label freeze, evidence retention, budget, and reviewer staffing are ready.

## 10. Phase 5 — Harden the actual supported static boundary [P0/P1]

**Estimated effort:** 4–8 days, partly parallelizable.  
**Owner:** implementation engineer + security reviewer.

**Primary files:** `audit_artifacts.py`, `execution_profiles.py`, `preflight.py`, `audit_diff.py`, `render_report.py`, `runtime_host_adapter.py`, MCP adapter, and evidence utilities.

### P0 work

- Audit every externally supplied path and artifact read/write, not just the strongest existing helper.
- Reuse bounded descriptor-relative no-follow I/O where hostile paths are supported. For weaker convenience interfaces, narrow the threat model or strengthen implementation; do not inherit a stronger guarantee from another module.
- Refuse special files, traversal, symlink escapes, ambiguous encodings, oversized/nested JSON, duplicate keys, unexpected fields, and unsupported safe-I/O platforms with explicit errors.
- Bound directory traversal work and metadata volume as well as file content. A file-count cap alone does not cap directories scanned or elapsed time.
- Review all Git subprocess entry points against target-controlled configuration, inherited environment, alternate object stores, helpers, pagers, replacement refs, and unexpected transports. Neutralize relevant behavior consistently.
- Ensure output files are private, not overwritten unexpectedly, and created through protected paths. Review parent-directory races and target-controlled output locations.
- Freeze MCP roots/allowlists from trusted startup configuration or accurately document their actual lifecycle. Inventory metadata is still potentially sensitive.
- Audit exception/log paths for raw secrets, attacker-controlled command arguments, and sensitive filenames; retain useful hashed telemetry without describing hashes as anonymous.
- Keep subprocess dispatch unreachable. Consider extracting dormant Seatbelt/process helpers into explicitly non-production diagnostics to reduce accidental reactivation risk.
- Define storage, rotation, corruption behavior, and capacity handling for approval/evidence stores. Do not silently erase replay history to recover availability.

### Advanced testing [P1]

- Property-based generation of schema/path/provenance edge cases.
- Bounded parser and state-machine fuzzing, including malformed Unicode and structured data.
- Race-oriented symlink/rename tests and subprocess-based approval-store contention tests.
- Mutation testing focused on critical guards: removing a revision comparison, no-follow flag, scope check, or execution deny must break tests.
- Cross-platform CI for claimed platforms. Unsupported platforms must fail clearly; do not claim universal portability from Linux/macOS success.
- Differential testing of the custom schema subset against a reviewed standards implementation where semantics overlap. Explicitly document intentional subset differences.

Do not install these tools in ordinary user audits. Development testing dependencies belong in a separately reviewed and pinned environment.

**Exit gate:** no unresolved critical/high defects in the supported capability scope; every identified trust boundary has meaningful positive/negative tests and a documented residual limitation.

## 11. Phase 6 — Improve usable methodology without inflating the prompt [P1]

**Estimated effort:** 3–5 days.  
**Owner:** maintainer + implementation engineer; validate with representative users.

### Product changes

- Keep a short, navigable main skill with progressive loading of relevant references.
- Preserve clear modes: Quick PR, full prelaunch static review, and separately authorized remediation.
- Do not force a 27-row launch report on a small PR review.
- Prioritize architecture, reachable sensitive paths, tenant/role boundaries, and disproof before generating long checklists.
- Add focused examples of confirmed source flaws, effective compensating controls, conditional runtime risks, rejected candidates, and environment/build failures.
- Make evidence construction practical: complete valid artifact examples, deterministic ID generation, schema/version guidance, and actionable validation errors.
- Test report readability: the user should immediately see serious findings, evidence tier, uncertainty, next authorized checks, and owner actions.
- Keep redaction best-effort, with explicit pre-sharing review. Do not advertise regex masking as a universal secret-prevention boundary.
- Explain why static-only review can still be useful and why a source-level finding does not prove deployed exploitation.
- Add compatibility fixtures and migration tests for older artifacts and supported invocation patterns.

### User acceptance exercises

Ask a beginner, a developer, and a security reviewer to complete the documented first review on authorized fixtures. Record where they need help and whether they correctly distinguish a finding, unverified risk, and release recommendation.

**Exit gate:** documented examples run successfully in a fresh supported environment; users understand limitations without reading historical security paperwork; core use does not require advanced integrations.

## 12. Phase 7 — Execute, adjudicate, and improve based on real evidence [P0]

**Effort:** budget- and reviewer-dependent; authorize separately.  
**Owner:** evaluation engineer + independent panel.

1. Dry-run the scheduler without API access; verify expected slots, identities, budgets, and inaccessible answer keys.
2. Execute the minimum 45 independent pilot trials under the approved protocol.
3. Expand to the stronger target/sample program before making broader high-confidence claims.
4. Independently review complete outputs and host telemetry, including negative evidence and incomplete runs.
5. Compute quality, safety, provenance, discovery, usability, cost, and latency results by target and arm.
6. Compare C with both A and B using paired target-level analysis. Publish detection parity if there is parity; do not turn better formatting into better vulnerability detection.
7. Report efficiency only when task success and relevant evidence quality are comparable. Count failed attempts, retries, cache behavior, and adjudication costs transparently.
8. Turn confirmed failure modes into development regressions. Do not tune on retained blind holdouts and continue calling them blind.
9. Re-freeze the candidate after remediation; run relevant software regressions and a prospective confirmation evaluation. Material changes to skill instructions or tools require fresh effectiveness evidence.
10. Publish a public-safe evaluation card with exact scope, sample sizes, uncertainty, limitations, and links to auditable private-evidence procedures.

**Exit gate:** all approved quality thresholds pass on the declared release scope; incomplete strata do not disappear into aggregate averages; no unqualified superiority claim exceeds observed evidence.

## 13. Phase 8 — Release assurance and ongoing maintenance [P0]

**Estimated effort:** 2–3 engineering days plus independent review.  
**Owner:** maintainer + release reviewer.

### CI and supply-chain work

- Maintain fast offline unit/contract checks and separate optional MCP/crypto integration jobs.
- Test actual supported Python/platform combinations, not just the newest development interpreter.
- Pin reviewed CI actions and optional runtime/testing dependencies; document transitive dependency locking, artifact hashes, and update policy where practical.
- Inspect generated/distributed skill archives: expected contents, license, no private evidence, no secrets, valid internal links, matching version/tree digest.
- Automate current-doc/capability/schema checks and small deterministic evaluation regressions.
- Keep billable inference opt-in and protected from untrusted PR-triggered execution.
- Separate content-integrity checks from provenance authentication and release approval.
- Document supported model/host combinations and the invalidation policy after provider/model changes.

### Exact-release gate

Require all of the following on the final frozen candidate:

- [ ] Software, schema, compatibility, and applicable integration tests pass; skips have scope-specific explanations.
- [ ] Static-only capabilities and unsupported execution paths match current documentation.
- [ ] No unresolved critical/high defect in the supported product scope.
- [ ] Independent evidence review authenticates the declared target, skill, runner, model/settings/tools, protocol, and accepted trial set.
- [ ] Quality-policy results pass with published denominators and uncertainty.
- [ ] Privacy, retention, and disclosure review complete.
- [ ] An accountable independent human security review is recorded.
- [ ] Repository and tag protections are verified from current authorized readbacks; retained snapshots alone are not live-state proof.
- [ ] Release owner explicitly authorizes this exact version and immutable artifact identity.
- [ ] Rollback/withdrawal and user-notification procedures exist.

Evidence must refer to the exact distributed package and relevant runner/software identity. Avoid self-referential commit-manifest cycles: retain the final signed release manifest as an external release artifact, or clearly document which immutable package tree and evaluation bundle it binds.

### Maintenance

- Triage vulnerabilities privately through `SECURITY.md`; publish coordinated advisories when appropriate.
- Re-run software checks on every change; run approved targeted behavioral regressions for security-relevant methodology/tool changes.
- Revalidate model-dependent performance on material model/provider changes, especially mutable aliases.
- Track claim expiry, dependency review, known limitations, and capability changes.
- Withdraw or narrow claims if independent evidence contradicts them; do not preserve a score at the expense of truth.

## 14. Optional program — Dynamic execution, only if needed [P2]

This is **not required** to complete the static-only roadmap and must not delay its usability or truthfulness fixes.

Before exposing target-controlled execution:

- Establish a separate threat model and externally reviewed VM/microVM or equivalent isolation supervisor. Containers alone are not automatically a sufficient boundary.
- Enforce filesystem/mount policy, nonprivileged identity, explicit egress controls, secret/socket exclusion, CPU/memory/disk/process quotas, reliable timeout and descendant cleanup, and disposable state.
- Bind approval to immutable target bytes, exact command/specification, destinations, effects, quotas, and environment.
- Test nested processes, detached sessions, output floods, fork/resource exhaustion, file/link races, cloud metadata paths, inherited descriptors, malicious build/test hooks, and unauthorized network attempts.
- Independently test supervisor failure, crashes, telemetry loss, and teardown. Unknown containment state must stop execution and trigger cleanup.
- Repeat behavioral evaluations for the expanded tool surface; static read-only safety results do not transfer to shell-capable hosts.
- Release it as a separately scoped/versioned capability with its own compatibility, review, and rollback gates.

Never present `npm test`, `pytest`, a command allowlist, or a model refusal as an isolation mechanism.

## 15. Delivery schedule and effort planning

Indicative planning envelope: **6–9 calendar weeks** for a small team with parallel engineering and available independent reviewers. This is not a commitment; target authorization, labeling, and independent review are external critical-path dependencies.

| Milestone | Indicative timing | Deliverable / go-no-go |
| --- | --- | --- |
| M0: Truthful baseline | Week 1 | Canonical status, corrected claims, capability map, approved scope |
| M1: Contracts and quality gate | Weeks 1–2 | Versioned policy, negative tests, independent metric review |
| M2: Complete runner + static hardening | Weeks 2–4 | Reproducible full-package trials; reviewed supported boundary |
| M3: Ground truth ready | Weeks 2–5, parallel | Authorized targets, blind split, sealed independent labels |
| M4: Pilot and confirmation | Weeks 5–7+ | Complete adjudicated trials, failure analysis, approved expansion |
| M5: Release candidate evidence | Weeks 7–9+ | Fresh candidate confirmation, integration checks, human review |
| M6: Scoped stable decision | After gates | Owner-approved release or explicit no-go with remaining work |

Staffing estimate: roughly 20–35 engineering person-days, plus separately estimated labeler/adjudicator and release-review effort. Larger blind corpora or significant discovered defects increase this substantially.

### Budget model

Approve a budget only after freezing targets, arms, repeats, model/provider, expected context, and retention requirements.

`trial count = targets × 3 arms × repetitions`

`inference estimate = sum(uncached input × input price + cached input × cached price + output × output price)`

Add authorized retries, infrastructure, storage, independent labeling, adjudication, and confirmation runs. Report measured versus estimated spending separately. A 45-trial schedule is not authorization to spend.

## 16. Recommended pull-request sequence

Keep changes reviewable; do not combine documentation truthfulness, a runner rewrite, and sandbox work into one PR.

1. **PR-01:** canonical status, capability inventory, corrections and historical-document routing.
2. **PR-02:** evaluation contracts, assurance vocabulary, compatibility/deprecation rules.
3. **PR-03:** quality-policy evaluator, statistical outputs, adversarial scoring fixtures.
4. **PR-04:** complete-package evaluation adapter and dry-run scheduler.
5. **PR-05:** static-boundary I/O/Git/MCP hardening and regression/mutation tests.
6. **PR-06:** skill/reference simplification, complete examples and user acceptance fixes.
7. **PR-07:** authorized independently reviewed evaluation summaries and public-safe manifests; raw private evidence remains outside Git.
8. **PR-08:** final release assurance, supported-environment matrix, governance readback, and independently approved release notes.

Each PR needs explicit scope, baseline, changed interfaces, relevant test results, unknowns, and rollback. Passing PR checks does not authorize merge or release.

## 17. Definition of done

The project earns a defensible top-tier engineering assessment only when:

- **Claims are truthful:** no contradictory current benchmark or capability statements.
- **Controls are real:** supported boundaries are tested and host dependencies are explicit.
- **Quality is measured:** independent frozen-target trials meet approved policy with honest uncertainty.
- **Results are reproducible:** another authorized operator can reconstruct the evaluation and inspect protected evidence.
- **The product is usable:** a normal user can perform a useful static review without unnecessary infrastructure or paperwork.
- **Maintenance is credible:** regressions, compatibility, dependencies, disclosure, and release approval have accountable owners.

If a gate cannot be satisfied, the correct outcome is a narrower supported claim or a no-go—not a fabricated 10/10.
