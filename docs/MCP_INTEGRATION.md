# MCP integration

The protocol details, call contract and overlay format are in [`references/mcp-integration.md`](../skills/re-super-intelligence/references/mcp-integration.md). This page is the operator's guide.

## Register RESI with an agent

1. Install the runtime: `skills/re-super-intelligence/scripts/install.sh --target <skills dir> --with-runtime`.
2. Add an MCP server entry pointing at the venv's `resi` with args `["mcp"]` and `RESI_HOME` in env — template in [`examples/mcp-config.json`](../skills/re-super-intelligence/examples/mcp-config.json).
3. Restart the agent and confirm the `resi_*` tools are listed.
4. Smoke test from a shell:

   ```bash
   printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | resi mcp | head -c 200
   ```

## Feed RESI the tools your agent can call

RESI can't see another server's tools by itself; the agent tells it. Either:

- the agent calls `resi_refresh_registry` with the names of the tools announced in its session, or
- a human saves those names to a file and runs `resi registry refresh --announced tools.txt [--overlay overlay.json]`.

Re-run after installing or removing tools. Verified status is preserved across refreshes.

## Tools exposed to agents

| Tool | Writes state | Purpose |
|---|---|---|
| `resi_classify` | no | Classify by content |
| `resi_plan` | no | Authorized, learned plan |
| `resi_security_check` | no | Dry-run guardrail verdict |
| `resi_record_execution` | yes | Record an agent-made call (guarded, learned from) |
| `resi_record_claim` | yes | Record a claim |
| `resi_validate_evidence` | yes | Evidence Validator |
| `resi_security_audit` | no | Security Auditor |
| `resi_cleanroom_check` | no | Clean-room gate |
| `resi_remember` / `resi_recall` | yes / no | Memory and RAG |
| `resi_learning_report` / `resi_refresh_lessons` | no / yes | Learning engine |
| `resi_registry` / `resi_refresh_registry` | no / yes | Registry (no overlays) |
| `resi_propose_hypothesis` / `resi_plan_experiment` / `resi_record_outcome` | yes | Hypothesis loop |
| `resi_report` | no | Markdown report |

Deliberately absent: project creation, artifact/target authorization, approvals, overlays.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Agent shows no `resi_*` tools | Wrong command path or Python | Use the absolute path to the venv's `resi`; check `resi --version` |
| `invalid arguments - missing/unknown` | Schema mismatch | Arguments must match `tools/list` exactly; extra keys are rejected |
| Every plan is unauthorized | Artifact not in scope | A human runs `resi project authorize` |
| A REA tool is always `missing` | Registry never refreshed with announced names | `resi_refresh_registry` |
| Dynamic call rejected | No approval, or it was single-use and consumed | Human runs `resi project approve` |
| Output to stdout corrupts the session | Something printed to stdout | RESI logs only to stderr; check wrappers |
