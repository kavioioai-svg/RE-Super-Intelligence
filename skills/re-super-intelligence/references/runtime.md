# Runtime reference

## Install

```bash
pip install -e ./orchestrator            # core: standard library only
pip install -e './orchestrator[vision]'  # + numpy for the 3D track
resi --version
```

Python 3.11+. State lives in `$RESI_HOME` (default `~/.resi`).

## Human-only CLI commands

These widen permissions, so they are **not** exposed over MCP.

| Command | Purpose |
|---|---|
| `resi project init --name N --profile P --statement "..."` | Create a project; the statement records who owns the target and what is authorized |
| `resi project authorize --project ID <file>` | Add an artifact (by SHA-256) to scope |
| `resi project target --project ID <url\|package\|process\|serial>` | Add a non-file target |
| `resi project approve --project ID --tool 'rea.*frida*' --target <t> --by NAME --statement "..." [--single-use]` | Approve class D/M work |
| `resi registry refresh --announced tools.txt [--overlay overlay.json]` | Rebuild the registry; the overlay classifies tools from other MCP servers |
| `resi playbooks import <file-or-folder>...` | Import Markdown playbooks (also available to agents) |

## Shared commands

| CLI | MCP tool | Purpose |
|---|---|---|
| `resi classify <file>` | `resi_classify` | Content-based classification |
| `resi plan --project ID <file>` | `resi_plan` | Authorized, learned plan with per-step guardrail verdicts and `target` |
| — | `resi_security_check` | Dry-run guardrail verdict |
| `resi run --project ID --tool cli.rizin --target <file> --arg command=ij` | `resi_run_local` | RESI-run second engine, recorded as evidence |
| `resi score --project ID <original> <rebuilt>` | `resi_reconstruction_score` | Byte-level reconstruction scorecard |
| — | `resi_record_execution` | Record an agent-made tool call (guarded) |
| — | `resi_record_claim` | Record an evidence claim |
| `resi validate --project ID` | `resi_validate_evidence` | Evidence Validator |
| `resi audit --project ID` | `resi_security_audit` | Security Auditor (exit 3 on critical/high) |
| `resi cleanroom <spec>` | `resi_cleanroom_check` | Decompiler-artefact gate (exit 3 on leak) |
| `resi remember --title T --text X` | `resi_remember` | Store knowledge (guarded) |
| `resi recall "<query>"` | `resi_recall` | Hybrid memory search |
| `resi learn [--refresh-lessons]` | `resi_learning_report`, `resi_refresh_lessons` | Learning report, lessons |
| `resi playbooks import <paths>` | `resi_import_playbooks` | Expert procedures into memory |
| `resi registry show` | `resi_registry`, `resi_refresh_registry` | Inspect / rebuild registry (no overlay over MCP) |
| `resi registry verify --execution exe-…` | `resi_verify_tool` | Mark a tool verified from its own successful run |
| — | `resi_propose_hypothesis`, `resi_plan_experiment`, `resi_record_outcome` | Hypothesis loop |
| `resi report --project ID` | `resi_report` | Markdown report |
| `resi vision-demo [--seed N]` | — | Reproducible synthetic 3D run |
| `resi mcp` | — | Serve the MCP interface on stdio |

## Typical agent session (MCP)

```text
resi_recall            {"query": "aarch64 ELF update daemon"}
resi_import_playbooks  {"paths": ["~/.agents/skills/re-super-intelligence",
                                   "~/.agents/skills/reverse-engineer-anything"]}
resi_plan              {"project_id": "prj-…", "path": "/samples/updated"}
                       → use plan.target (the SHA-256) as target below
resi_security_check    {"project_id": "prj-…", "tool_id": "rea.list_strings", "target": "<sha256>"}
  → call mcp rea list_strings yourself
resi_record_execution  {"project_id": "prj-…", "tool_id": "rea.list_strings", "target": "<sha256>",
                        "output": {...}, "latency_ms": 820, "artifact_id": "art-…"}
resi_record_claim      {..., "execution_id": "exe-…", "kind": "observed",
                        "subject": "proto:update-url", "confidence": "high"}
resi_run_local         {"project_id": "prj-…", "tool_id": "cli.rizin", "target": "<sha256>",
                        "args": {"command": "izj"}}       → second engine, same subject
resi_verify_tool       {"execution_id": "exe-…", "version": "6.7.0"}
resi_validate_evidence {"project_id": "prj-…"}
resi_security_audit    {"project_id": "prj-…"}
resi_report            {"project_id": "prj-…"}
```

## Exit codes

`0` success · `1` error · `3` audit or clean-room check failed.
