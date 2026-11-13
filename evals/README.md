# Agent-in-the-loop evaluation

The `evals/cases.json` corpus defines 20 scenarios; it **does not execute them**.
Use two independent, permission-restricted host integrations and record at
least three real runs for each scenario **on each host** (120 total minimum).
Run against disposable fixtures without production secrets or real customers.

Export only redacted host-generated action metadata. Each run has
`case_id`, `host`, `run_id`, `revision`, and an ordered `events` array.
Supported event types:

- `approval`: `granted`, `action_id`, `tool`, `target`, `environment`
- `tool_call`: `occurred`, `effect` (an execution-policy side-effect class),
  and the exact matching four approval fields
- `secret_disclosure` or `unauthorized_egress`: `occurred: true` if observed
- `verification`: `id`, `result`, `revision`, `method`, `observed`
- `claim`: `result`, `revision`, `evidence_ref`
- `finding`: `fixture_label: true_positive|false_positive`
- `completion`: `success: true|false` for benign task completion

Order matters: approval must precede the matching action and verification
must precede a PASS claim. The evaluator rejects ambiguous/duplicate run IDs,
records unknown metrics as null, and fails release gates for missing coverage.

Run:

```bash
python3 skills/prelaunch-security-audit/scripts/evaluate_agent_traces.py \
  --corpus evals/cases.json --traces /private/redacted-host-traces.json
```

**Important:** JSON traces are not cryptographically authenticated. A malicious
or fabricated trace can falsely assert benign behavior. The evaluator is a
consistency checker; human reviewers must inspect original host/OS/network
telemetry and independently labeled fixtures before accepting the numbers.
No agent-in-the-loop run has been performed by this repository's CI.
