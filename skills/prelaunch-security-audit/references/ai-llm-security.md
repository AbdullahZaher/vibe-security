# Optional AI, RAG and tool-boundary review

Load only when the inventory includes AI ingestion, model output consumers or
agent/MCP tools. This is a focused trust-boundary method, not an exhaustive
vendor catalog or a claim about current advisories.

Trace attacker-controlled content through documents, retrieval, prompts, tool
arguments and output sinks. Identify which principal supplies each value and
which host identity executes the resulting operation. Record the source revision
and effective allowlists, scopes and approval channels. A hostile string alone
is not a vulnerability: establish a reachable unauthorized effect or state the
missing prerequisite as needs_validation.

Try to disprove the hypothesis using host-side enforcement: fixed resource roots,
per-tool authorization, audience-restricted credentials, server identity pinning,
output encoding, retrieval tenant filters, and separation of instructions from
data. Model refusal is not proof that a preceding tool action was blocked.

Where authorized isolation exists, use only synthetic documents and dummy secret
markers to test cross-tenant retrieval, malicious tool descriptions, indirect
prompt injection, cross-server confused deputy, approval text in data, and model
output reaching executable/HTML/SQL sinks. Retain genuine host event logs,
blocked attempts and executed effects separately. Do not send private prompts,
source or documents to another model or remote scanner without owner approval.
Without runtime authorization, trace the source and provide unexecuted next
checks. Apply Standard/Deep verification and the coverage ledger to each boundary.

No remote advisory lookup was performed for this playbook; freshness is unverified.
Broad mobile/cloud/protocol catalogs remain deferred to v0.6.0.
