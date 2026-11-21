# Evidence schema

Rules and semantics: [`references/evidence-model.md`](../skills/re-super-intelligence/references/evidence-model.md). This page documents storage.

## Location

`$RESI_HOME/resi.db` (SQLite, WAL mode). Each table stores a JSON `body` plus indexed key columns; bodies are the serialised domain objects.

| Table | Key columns | Body |
|---|---|---|
| `projects` | `id` | `Project` |
| `scopes` | `id` (project) | authorized artifacts/targets, approvals, consumed approvals |
| `artifacts` | `id`, `project_id` | `Artifact` (incl. parsed header details) |
| `executions` | `id`, `project_id`, `seq` | `ExecutionRecord` |
| `claims` | `id`, `project_id`, `kind`, `seq` | `Claim` |
| `hypotheses` | `id`, `project_id`, `seq` | `Hypothesis` |
| `experiments` | `id`, `hypothesis_id`, `seq` | `Experiment` |
| `documents` | `id`, `project_id`, `kind`, `source_ref`, `trusted`, `seq` | `KnowledgeDocument` (with optional vector) |
| `episodes` | `id`, `tool_id`, `seq` | `Episode` |
| `calibration` | autoincrement | `CalibrationPoint` |

`seq` preserves insertion order across process restarts; replacing a claim keeps its original position.

Also in `$RESI_HOME`: `registry.json` (capability registry, atomic writes) and `audit.log` (append-only JSON lines).

## Records

```json
// executions.body
{
  "execution_id": "exe-4f1c2a9b0d3e", "project_id": "prj-…", "artifact_id": "art-36293c12f22a",
  "tool_id": "rea.list_strings", "tool_version": "discovered-2026-11-21",
  "target": "36293c12f22a…", "args_hash": "…", "started_at": "…", "finished_at": "…",
  "status": "ok", "output": {"strings": ["password=[REDACTED]"]}, "output_digest": "…",
  "truncated": false, "attempts": 1, "latency_ms": 420.0, "error": "",
  "flags": ["secret:credential-assignment"]
}

// claims.body
{
  "claim_id": "clm-…", "project_id": "prj-…", "artifact_id": "art-…",
  "source_hash": "36293c12f22a…", "tool_id": "rea.list_strings", "tool_version": "…",
  "execution_id": "exe-…", "kind": "observed",
  "observation": "format string 'https://%s/fw/%s/manifest.json' at 0x41c2a0",
  "interpretation": "update manifest URL is host + version path",
  "confidence": "high", "verification": "supported",
  "reproduction": "rea.list_strings on art-…, filter 'manifest'",
  "limitations": "", "subject": "proto:update-manifest-url", "created_at": "…"
}

// audit.log line
{"event": "execution", "at": "…", "project_id": "prj-…", "execution_id": "exe-…",
 "tool": "rea.start_frida_session", "target": "…", "status": "rejected", "class": null,
 "decision": null, "attempts": 0, "latency_ms": 0.0, "flags": [],
 "error": "rea.start_frida_session: class D needs explicit per-target approval"}
```

## Querying

```bash
sqlite3 ~/.resi/resi.db "SELECT json_extract(body,'$.observation') FROM claims
                         WHERE project_id='prj-…' AND kind='observed'"
jq -c 'select(.status=="rejected")' ~/.resi/audit.log
```

## Migration path

The schema is portable: `TEXT` → PostgreSQL `TEXT`, `body` → `JSONB`, same indexes. Implement the repository Protocols against PostgreSQL and swap it in `bootstrap.py`. Do this for multi-user or cross-machine access — not before.
