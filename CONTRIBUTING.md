# Contributing

Contributions are welcome for accuracy, portability, security and testing.

- Keep the main SKILL.md concise; put detailed checks into `references/`.
- Preserve the numbered 01–27 control order and report evidence states.
- Do not add any mandatory remote service or model-specific SDK dependency.
- Add offline unit tests for local scripts. Network tests must be opt-in and
  target only services/repositories the tester explicitly owns.
- Never introduce credential collection, public exploit automation, hidden
  network calls, unsafe defaults or silent production writes.
- Report security defects privately (see `SECURITY.md`).

Run before proposing a PR:

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q scripts mcp_adapter tests
```

Validate the skill against the official reference tool when available:

```bash
skills-ref validate .
```
