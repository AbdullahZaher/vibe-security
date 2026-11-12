# Research implementation review — v0.3.0 (proposed)

This changeset implements the prioritized issues found in the Deep Research
review of the existing 0.2.0 release. It is not a certification.

## Findings and changes

| Prior issue | Change | Remaining limitation |
|---|---|---|
| Approval text is not enforceable | `policy/action-policy.json` + `scripts/plan_guard.py` classify actions; destructive commands denied by advisory guard | The host and provider must enforce real permissions; plan JSON is untrusted |
| Weak provenance | `references/evidence-model.md` and revision mismatch checks in renderer | Renderer cannot authenticate arbitrary execution claims |
| Threat-model gaps | Expanded MCP poisoning, tool-output injection and token-audience guidance | No live cross-host adversarial benchmark yet |
| 8 hand-authored evals | 20 attack/benign scenarios and measurable metrics | No completed agent-in-the-loop results |
| Mutable CI action tags | Full verified SHAs and checkout `persist-credentials: false` | Branch protection and reviews must be configured in GitHub separately |
| ASVS conflated with a checklist | Mapped reference frameworks by purpose | No ASVS audit or certification completed |

## Release acceptance criteria (targets, not achieved results)

- Run the 20-case corpus at least 3 times per target host and record tool calls.
- Zero unauthorized external writes, unapproved destructive actions or secret disclosures.
- 100% action-specific approvals for sensitive operations.
- 100% unsupported/wrong-revision PASS claims rejected or downgraded.
- >=95% benign completion and <=5% false-positive rate on independent fixtures.
- Real MCP smoke/integration testing on at least two supported hosts.
- CI checks and review pass on the exact release commit; no claims based solely on static scan output.

## Scope and limitations

The unit suite tests local utilities and contracts, not the security of arbitrary
web applications. The optional MCP adapter is read-only by design and cannot
perform remediation. The advisory plan guard must never be placed in charge of
actual permissions without a separate host-side enforcement mechanism.

## Primary sources

- [Agent Skills specification](https://agentskills.io/specification)
- [Anthropic Skill Creator](https://github.com/anthropics/skills/tree/main/skills/skill-creator)
- [Trail of Bits Post-Patch Validation](https://github.com/trailofbits/skills/tree/main/plugins/post-patch-validation)
- [OWASP ASVS](https://asvs.owasp.org/)
- [NIST SSDF](https://csrc.nist.gov/pubs/sp/800/218/final)
- [OpenSSF Scorecard](https://securityscorecards.dev/)
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
