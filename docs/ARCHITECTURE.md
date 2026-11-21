# Architecture

RESI uses a hexagonal (ports and adapters) architecture. The agent-facing summary is in [`skills/re-super-intelligence/references/architecture.md`](../skills/re-super-intelligence/references/architecture.md); this document is the engineering map.

## Layers and modules

| Layer | Module | Responsibility |
|---|---|---|
| Domain | `models.py` | Entities and value objects: `Artifact`, `ToolDescriptor`, `Scope` (aggregate), `Approval`, `ExecutionRecord`, `Claim`, `Hypothesis`, `Experiment`, `ResearchPlan`, `KnowledgeDocument`, `Episode`, `CalibrationPoint` |
| | `enums.py`, `errors.py` | Closed vocabularies (security class, status, claim kind…) and typed failures |
| | `classification.py` | Content-based classification; ELF and pcap header parsers |
| | `catalog.py`, `registry.py` | Tool catalogue; `CapabilityRegistry` aggregate; name normalisation; overlays |
| | `routing.py` | Route tables, fallbacks, learned re-ranking (`plan_research`) |
| | `guardrails.py` | Redaction, injection/PII/clean-room detection, command filter, memory admission |
| | `evidence_rules.py` | Claim validation, hypothesis status, experiment priority, corroboration |
| | `learning.py` | Tool bandit, calibration, lesson extraction |
| | `retrieval.py` | BM25, cosine, reciprocal rank fusion |
| | `profiles.py`, `geometry.py` | Research profiles; ellipse perimeter |
| Application | `ports.py` | Protocols: `Clock`, `IdGenerator`, `ArtifactReader`, `ToolTransport`, `EnvironmentProbe`, `Embedder`, `PointCloudAnalyzer`, `AuditLog`, and the repositories |
| | `projects.py` | Project lifecycle, scope, approvals (human-only operations) |
| | `registry_service.py`, `research.py` | Discovery; classification and planning |
| | `execution.py` | Guarded execution: authorize → filter → execute → guard output → persist → audit → learn |
| | `evidence.py` | Claims, Evidence Validator, hypothesis loop |
| | `knowledge.py`, `learning.py` | Memory admission and RAG; learning reports and lessons |
| | `security_audit.py`, `reporting.py`, `vision.py` | Security Auditor; Markdown report; 3D use case |
| Inbound adapters | `cli.py`, `mcp_server.py`, `presenters.py` | Human CLI; MCP stdio server; JSON presentation |
| Outbound adapters | `sqlite_store.py`, `memory_store.py` | Repositories (same contract) |
| | `infrastructure.py` | Clock, ids, file reader, JSON registry, JSONL audit log, environment probe, callable transport, hashing embedder |
| | `vision_numpy.py`, `serialization.py` | numpy point-cloud analyzer; domain ↔ JSON mapping |
| Composition root | `bootstrap.py` | Builds the `Container`; manages resource lifetime |

## Execution sequence

```
agent ──resi_record_execution──► MCP server ──► ToolExecutionService.record_external
                                                  │ registry.require_usable(tool)
                                                  │ scope.check(tool, target)      ── deny → REJECTED record + audit
                                                  │ check_command(...) (free-form) ── deny → REJECTED record + audit
                                                  │ guard_output(raw): redact, scan, truncate
                                                  │ evidence.save_execution(record)
                                                  │ episodes.add_episode(...)       ── learning signal
                                                  └ audit.append(event)
```

## Design decisions

| Decision | Rationale |
|---|---|
| Standard-library core | Runs inside any agent's environment; no supply-chain surface. numpy only for the optional vision extra. |
| Roles, not processes | One evidence store, no inter-agent state drift. Revisit with benchmarks. |
| Human-only permission changes | The MCP surface cannot create projects, authorize, approve or overlay. |
| Re-derived audit | The auditor trusts stored facts, not past decisions, so bypassed guardrails surface. |
| Rejections ≠ tool failures | Learning measures tool reliability, not scope mistakes. |
| JSON-in-SQLite | Portable to PostgreSQL `JSONB`; schema changes don't need migrations for new optional fields. |
| Deterministic learning | Seeded exploration, idempotent feedback; results reproduce exactly. |

## Extension points

| To add | Implement | Wire in |
|---|---|---|
| PostgreSQL | The four repository Protocols (copy `SqliteStore`'s JSON approach) | `bootstrap.build_container` |
| Neural embeddings | `Embedder.embed(text) -> tuple[float, ...]` | `build_container(embedder=...)` |
| Direct MCP/CLI driving | `ToolTransport.invoke(tool_id, args, timeout_s)` | `build_container(transport=...)` |
| A new tool family | `CatalogGroup` entries in `catalog.py` (or an overlay at runtime) | — |
| A new artifact kind | A branch in `classification.classify` + a route in `routing.ROUTES` | — |
| A new guardrail | A pure detector in `guardrails.py` + a call site + an auditor check | — |

The architecture test (`tests/architecture/test_dependency_rule.py`) fails the build if a change breaks the dependency rule.
