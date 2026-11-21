# RE Super Intelligence (RESI)

**Evidence-driven reverse engineering research for any coding agent** — with a learning engine, long-term memory with RAG, security guardrails, an evidence validator and a security auditor.

RESI is not another disassembler. It is the layer that decides **what** to run, **in what order**, and **what the result proves**, then drives the tools you already have (primarily the [REA](#tooling) MCP server, plus Ghidra, Rizin, Frida, binwalk, JADX, TShark, Open3D and others). Every claim is traced to the tool execution that produced it; every unsafe action is stopped before it runs; every engagement makes the next one smarter.

```
skill (what agents read)  ─┐
                           ├─►  resi runtime  ──►  your RE tools (MCP, CLI, Python)
MCP server (any agent)  ───┘    classify · authorize · plan · guard · record ·
CLI (humans)  ─────────────┘    validate · audit · remember · learn · report
```

## Highlights

| | |
|---|---|
| **Agent-neutral skill** | `skills/re-super-intelligence/` — a standard `SKILL.md` with references and ten specialist roles. Works with any agent that loads skills. |
| **MCP server, both ways** | `resi mcp` exposes 18 tools to any MCP client; RESI also routes to any other MCP server's tools through the registry. |
| **Learning engine** | Beta-Bernoulli tool bandit, confidence calibration (Brier score), automatic lessons. Explainable, offline, deterministic. |
| **Memory + RAG** | Findings and lessons stored with provenance; hybrid BM25 + vector retrieval with reciprocal rank fusion. |
| **Guardrails** | Scope and approval gates, command filtering, secret redaction, prompt-injection and personal-data detection, clean-room leak detection. |
| **Validator + auditor** | Unsupported claims downgraded, corroborated claims promoted; an independent audit re-derives every security verdict. |
| **Hexagonal core** | Pure domain, ports, adapters; the dependency rule is enforced by tests. Standard library only (numpy optional). |

## Quick start

```bash
git clone https://github.com/kavioioai-svg/RE-Super-Intelligence.git
cd RE-Super-Intelligence

# 1. Install the skill into your agent's skills folder (+ the runtime in a venv)
skills/re-super-intelligence/scripts/install.sh --target ~/.agents/skills --with-runtime

# 2. See what this machine can do (read-only)
python3 skills/re-super-intelligence/scripts/discover_environment.py

# 3. Register the MCP server with your agent (see examples/mcp-config.json)
~/.resi/venv/bin/resi mcp

# 4. A human authorizes the work
resi project init --name demo --profile general --statement "Sample we own; static analysis only"
resi project authorize --project <id> ./sample.bin
```

Then ask your agent to analyse `./sample.bin` — it will recall, plan, check, execute, record, validate, audit and report. See [`docs/RESEARCH_WORKFLOWS.md`](docs/RESEARCH_WORKFLOWS.md).

## Repository layout

```
skills/re-super-intelligence/   the skill: SKILL.md, references/, agents/, scripts/, examples/, tests/
orchestrator/resi/
  domain/                       pure rules: models, classification, registry, routing,
                                guardrails, evidence rules, learning, retrieval, profiles
  application/                  use cases + ports (Protocols)
  adapters/inbound/             CLI, MCP server
  adapters/outbound/            SQLite & in-memory stores, registry file, audit log,
                                filesystem reader, transport, probe, embedder, numpy vision
  bootstrap.py                  composition root
orchestrator/tests/             unit · integration · architecture · acceptance
docs/                           architecture, security, deployment, workflows, …
```

## Quality gates

```bash
cd orchestrator
pip install -e '.[dev]'
ruff check resi tests && mypy --strict resi && pytest --cov=resi
pytest ../skills/re-super-intelligence/tests
```

292 tests (290 pass; 2 live-tool checks skip explicitly until run on a machine with Ghidra/REA), 92 % branch coverage, strict typing, zero lint or type suppressions. CI runs on Ubuntu and macOS, Python 3.11–3.13. Details: [`docs/TESTING.md`](docs/TESTING.md).

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| 1 | Environment discovery | Done — `discover_environment.py` |
| 2 | Skill, capability registry, evidence model | Done |
| 3 | REA and Ghidra integration | Routing and recording done; live verification runs on the target machine |
| 4 | Firmware, protocol, file formats | Routing done; binwalk/unblob/QEMU/Kaitai adapters next |
| 5 | Authorized runtime and mobile | Approval gates done; device workflows next |
| 6 | 3D vision research | Synthetic pipeline done; Open3D/trimesh/FreeCAD adapters next |
| 7 | Evidence correlation, hypothesis validation | Done |
| 8 | Reporting, regression tests, observability | Reporting + tests done; metrics export next |
| + | Learning engine, memory/RAG, MCP server, guardrails, auditor | Done |

No integration is reported as working until an execution has verified it ([acceptance test 10](docs/TESTING.md#acceptance-tests)).

## Documentation

[Architecture](docs/ARCHITECTURE.md) · [Capability matrix](docs/CAPABILITY_MATRIX.md) · [MCP integration](docs/MCP_INTEGRATION.md) · [Security](docs/SECURITY.md) · [Research workflows](docs/RESEARCH_WORKFLOWS.md) · [Evidence schema](docs/EVIDENCE_SCHEMA.md) · [Learning engine](docs/LEARNING_ENGINE.md) · [Testing](docs/TESTING.md) · [Deployment](docs/DEPLOYMENT.md)

## Responsible use

RESI is for authorized research on software, firmware, devices and data you own or have explicit permission to analyse. It enforces scope and approvals, but the authorization itself is your responsibility. Reverse engineering rights vary by jurisdiction and licence — this is not legal advice. Medical outputs are research only until clinically validated.

## Tooling

REA (Reverse Engineering Assistant) is an MCP server exposing static, dynamic, mobile, firmware, protocol and web analysis tools. RESI catalogues its tools but works without it: any tool from any MCP server, CLI or Python library can be registered.
