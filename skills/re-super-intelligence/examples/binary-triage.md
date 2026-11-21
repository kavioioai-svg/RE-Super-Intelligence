# Worked example: triaging an ELF you own

Goal: find how a firmware update daemon you built builds its update URL, with evidence.

## 1. Human sets scope (CLI, once)

```bash
resi project init --name update-daemon --profile firmware \
  --statement "Our own updated binary, v2.3 build 118; static analysis approved by the product owner"
resi project authorize --project prj-1a2b3c updated
resi registry refresh --announced announced-tools.txt     # tool names from the agent session
```

## 2. Agent plans (MCP)

```text
resi_recall {"query": "update URL ELF aarch64"}
  → lesson: "rea.batch_decompile frequently times out — narrow the request"
resi_plan {"project_id": "prj-1a2b3c", "path": "updated"}
  → steps: binary_overview, list_strings, list_procedures, get_call_graph, procedure_pseudo_code
    missing: []   needs_approval: []
```

## 3. Execute and record

```text
(call rea.list_strings through the agent's MCP client)
resi_record_execution {"project_id": "prj-1a2b3c", "tool_id": "rea.list_strings",
  "target": "<sha256>", "artifact_id": "art-…", "latency_ms": 640,
  "output": {"strings": ["https://%s/fw/%s/manifest.json", "X-Device-Token: %s"]}}
  → exe-0007, flags: []
resi_record_claim {"kind": "observed", "execution_id": "exe-0007",
  "observation": "format string 'https://%s/fw/%s/manifest.json' at 0x41c2a0",
  "interpretation": "update manifest URL is host + version path",
  "confidence": "high", "subject": "proto:update-manifest-url", ...}
```

A second tool (decompiling the function that references 0x41c2a0) records a `tool_derived` claim with the same `subject`.

## 4. Hypothesis with a falsification condition

```text
resi_propose_hypothesis {"statement": "sub_40a110 fills the URL host from /etc/update.conf",
  "prediction": "a read of /etc/update.conf precedes the sprintf call",
  "falsified_if": "no reference to update.conf in sub_40a110 or its callers"}
resi_plan_experiment {"security_class": "R", "information_gain": 4, "relevance": 5, "cost": 1, ...}
```

## 5. Validate, audit, report

```text
resi_validate_evidence → corroborated: ["proto:update-manifest-url"], ingested: 2
resi_security_audit    → passed: true
resi_report            → Markdown with observed / tool-derived / hypothesis sections
resi_refresh_lessons
```

The next engagement on a similar binary recalls the corroborated finding and starts from it.
