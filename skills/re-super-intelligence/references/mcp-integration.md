# MCP integration

RESI speaks MCP in both directions.

## Inbound: any agent connects to RESI

`resi mcp` is an MCP server over stdio (JSON-RPC 2.0, newline-delimited; protocol versions 2025-06-18, 2025-03-26, 2024-11-05). Register it in your agent's MCP configuration:

```json
{
  "mcpServers": {
    "resi": {
      "command": "resi",
      "args": ["mcp"],
      "env": { "RESI_HOME": "/path/to/.resi" }
    }
  }
}
```

The same block works for any client that reads the common `mcpServers` format; clients that use TOML or YAML take the same command, args and env. If `resi` is not on the client's PATH, use the absolute path of the virtualenv's `resi` script or `python -m resi mcp`.

**Security boundary.** The MCP surface exposes research, memory, guardrail checks and validation. It never exposes project creation, scope authorization, approvals or registry overlays — an autonomous agent cannot widen its own permissions.

## Outbound: RESI routes to any MCP server's tools

RESI does not need its own MCP client: the host agent already has one. The agent:

1. Gives RESI the tool names announced in its session — `resi_refresh_registry` with `announced: [...]`, or `resi registry refresh --announced file`.
2. Plans with `resi_plan`, checks with `resi_security_check`.
3. Calls the tool through its own client.
4. Records the call with `resi_record_execution` (guardrails re-applied; unapproved or out-of-scope calls are recorded as rejected and audited).

Programmatic hosts can instead pass a transport to the container, and RESI drives the call itself:

```python
from resi.adapters.outbound.infrastructure import CallableTransport
from resi.bootstrap import build_container

container = build_container(transport=CallableTransport(my_mcp_client.call_tool))
container.execution.execute(project_id, ExecutionRequest("rea.list_strings", sha256))
```

## Classifying tools from other MCP servers

Uncatalogued tools are registered as `uncatalogued`, class **D** — they need approval until classified. A human classifies them with an overlay:

```json
{
  "ghidra.decompile_function": {
    "module": "binary", "security_class": "R",
    "input_types": ["elf", "pe", "macho"], "operations": ["decompile"]
  },
  "ghidra.rename_function": { "module": "binary", "security_class": "L" }
}
```

```bash
resi registry refresh --announced announced.txt --overlay overlay.json
```

Classify honestly: anything that executes, attaches, emulates or touches a live device is `D`; anything that changes a device is `M`.

## Call contract (enforced by the execution service)

| Step | Behaviour |
|---|---|
| Allowlist | Tool must be in the registry with status `discovered` or `verified` |
| Scope | Target must be authorized; class D/M needs a matching, unconsumed human approval |
| Command filter | Free-form tools (`execute_rizin_command`, `cutter_command`, `rizin_debug_command`, `gdb_console`) reject shell escapes, pipes/redirection, file writes, and — for static tools — execution |
| Timeout | 120 s default; 600 s for `batch_decompile`, `extract_firmware`, `extract_artifact` |
| Retry | Once on error/timeout for class R/L; never automatically for D/M |
| Output | Secrets redacted, prompt injection flagged, truncated at 200 000 chars, digest recorded |
| Audit | One JSON line per call in `audit.log` |
| Learning | Every call becomes an episode for the tool-outcome model |

## Error handling

| Situation | What to do |
|---|---|
| Tool not announced | Status `unverified`; `resi_plan` lists it under `missing` and offers fallbacks |
| Server not running | Report the server's actual state; do not guess |
| Timeout | Narrow the request (one function, smaller range). Repeated timeouts become a stored lesson |
| Unexpected output shape | Do not interpret partial output as evidence; record `succeeded: false` |
| Truncated output | Re-query a narrower range before drawing conclusions |
