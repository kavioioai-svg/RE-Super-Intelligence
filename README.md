# RE Super Intelligence (RESI)

[![ci](https://github.com/kavioioai-svg/RE-Super-Intelligence/actions/workflows/ci.yml/badge.svg)](https://github.com/kavioioai-svg/RE-Super-Intelligence/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![MCP](https://img.shields.io/badge/MCP-server-6f42c1.svg)

**Reverse engineering intelligence for coding agents.** RESI turns any agent into a disciplined reverse engineer: it plans the investigation, drives the right analysis engines, cross-checks their answers, proves or rejects its own hypotheses, measures rebuilds byte by byte, remembers what it learned, and won't let an unsupported claim or an unauthorized action through.

Disassemblers and decompilers produce output. RESI produces **conclusions you can trust**, each traced to the tool run that produced it.

```
                ┌───────────────────────── RESI ──────────────────────────┐
 your agent ──► │ classify → authorize → plan → guard → execute → corroborate │ ──► REA (207 tools: Ghidra,
 (any MCP       │ claim → hypothesis → experiment → validate → audit → learn │      Hopper, Frida, ADB, pcap…)
  client)       │   memory · playbooks · reconstruction scorecard · reports   │ ──► Rizin (RESI-run 2nd engine)
                └─────────────────────────────────────────────────────────────┘ ──► any MCP server, CLI, Python lib
```

## What makes it super

| Capability | What you get |
|---|---|
| **Expert playbooks** | Built-in procedures for triage, finding the code that matters, fingerprinting languages and runtimes, identifying algorithms by their constants (AES, SHA-2, ChaCha, CRC, Murmur…), hidden strings, packing and obfuscation signs, protocol and format inference, firmware, mobile frameworks (Flutter, React Native/Hermes, Unity IL2CPP, MAUI), web bundles and patch diffing. Import any other skill's procedures too. |
| **Two engines, one verdict** | RESI runs Rizin itself as an independent second engine. When two tools agree on the same fact, the validator promotes it to *supported*; one tool alone is never enough for high confidence. |
| **Byte-level reconstruction scoring** | Score a rebuild against the original for Mach-O (thin and fat), ELF and PE: *identical*, *identical-except-volatile*, *near*, *partial* or *different*, per section and per function, with build ids, UUIDs, timestamps, checksums and signatures excluded. |
| **Scientific method built in** | Falsifiable hypotheses, experiments ranked by information gain over cost and risk, one contradiction rejects, two supports verify. |
| **Evidence model** | Observed facts, tool interpretations, hypotheses and verified conclusions are always kept apart. Every claim cites an execution, a source hash and reproduction steps. |
| **Learns from every run** | A Bayesian tool-reliability model re-ranks plans and demotes failing tools; confidence calibration flags overconfidence; recurring failures become stored lessons. Explainable and deterministic. |
| **Memory + RAG** | Findings, lessons and playbooks persist across projects, with hybrid keyword and vector retrieval and provenance on every hit. |
| **Guardrails an agent can't talk its way past** | Only a human can grant scope or approvals. Dynamic and device actions need explicit approval. Secrets are redacted, prompt injection hidden in binaries is flagged and quarantined, and local engines only ever touch the authorized file. |
| **Independent security audit** | The auditor re-derives every verdict from stored records, so a bypassed guardrail shows up as a critical finding. |
| **Works with any agent** | A standard skill folder plus an MCP server with 22 tools. No vendor lock-in. |

## Proven, not promised

- **Live end-to-end run** on a test binary with REA 6.7.0. RESI refreshed its registry from all 207 announced REA tools, planned the right Mach-O steps, recorded each REA call as evidence (including a decompiler failure, reported honestly instead of guessed around), kept facts and hypotheses in separate report sections, and passed its own security audit. Bugs that run exposed were fixed, each with a regression test.
- **Reconstruction scorecard on real compiler output:** the same source built twice scores *identical*. Changing one constant (`return 42` → `return 43`) scores *near* and pinpoints the differing byte in `.text`. A 51 MB comparison takes about 0.3 s.
- **359 tests, 92 % branch coverage, strict typing, zero lint or type suppressions**, with CI on macOS and Ubuntu for Python 3.11–3.13. Includes the specification's ten acceptance tests; the two that need live Ghidra or REA skip explicitly rather than pretend.

## Quick start

```bash
git clone https://github.com/kavioioai-svg/RE-Super-Intelligence.git
cd RE-Super-Intelligence

# 1. Skill + runtime. Needs Python 3.11+; the installer finds python3.13/3.12/3.11 itself.
skills/re-super-intelligence/scripts/install.sh --target <your agent's skills folder> --with-runtime

# 2. What can this machine do? (read-only)
python3 skills/re-super-intelligence/scripts/discover_environment.py

# 3. Register the MCP server in your agent: command ~/.resi/venv/bin/resi, args ["mcp"]
#    (template: skills/re-super-intelligence/examples/mcp-config.json)

# 4. A human authorizes the work
resi project init --name demo --statement "Sample we own; static analysis only"
resi project authorize --project <project_id> ./sample.bin
```

Then ask your agent: *"Use re-super-intelligence. Import the playbooks, refresh the registry with your rea tools, and analyse ./sample.bin in project <project_id>: plan, run, corroborate with Rizin, record every claim, validate, audit and report."*

**Recommended engines:** [REA](https://github.com/morluto/rea) (`npx rea-agents setup`), Ghidra 12.1 for REA's decompiler (`GHIDRA_INSTALL_DIR`), Rizin (`brew install rizin` or your package manager). RESI tells you what's missing: `resi_plan` lists `missing` and `recommended` tools.

## Example: what an agent does with RESI

```text
resi_import_playbooks  ~/.agents/skills/re-super-intelligence, ~/.agents/skills/reverse-engineer-anything
resi_recall            "aarch64 ELF update daemon"          → playbooks, past findings, lessons
resi_plan              project, ./updated                  → steps with guardrail verdicts, target = sha256
rea.list_strings       → resi_record_execution             → exe-0007 (secrets redacted, injection flagged)
resi_record_claim      observed: "format string https://%s/fw/%s/manifest.json at 0x41c2a0"
resi_run_local         cli.rizin "izj"                     → second engine agrees, same subject
resi_propose_hypothesis "sub_40a110 reads the host from /etc/update.conf", falsified if no reference
resi_validate_evidence → corroborated: proto:update-manifest-url → supported, stored in memory
resi_security_audit    → passed
resi_report            → observed / tool-derived / hypotheses / failures / unresolved questions
```

## How it's built

A hexagonal (ports and adapters) core in Python with **zero third-party runtime dependencies**:

```
orchestrator/resi/
  domain/        pure rules: classification, binary layouts, reconstruction, registry, routing,
                 guardrails, evidence rules, learning, retrieval, playbooks, profiles
  application/   use cases + ports: projects, research, guarded execution, evidence & validator,
                 hypotheses, knowledge, playbooks, learning, security audit, reporting
  adapters/      inbound: CLI (humans), MCP server (agents)
                 outbound: SQLite & in-memory stores, Rizin + scorecard runner, registry file,
                 audit log, filesystem, embedder, numpy vision
  bootstrap.py   composition root
skills/re-super-intelligence/   SKILL.md, 11 references, 10 specialist roles, scripts, examples
```

The dependency rule is enforced by tests, so the architecture can't drift. Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Responsible use

RESI is for authorized research on software, firmware, devices and data you own or have explicit permission to analyse. It enforces scope and approvals, but the authorization itself is your responsibility. It recognises protections and reports them; it does not bypass them. Byte-matching reconstruction is for your own binaries, open source and lost-source recovery with permission, never input to a clean-room reimplementation. Reverse engineering rights vary by jurisdiction and licence; this is not legal advice.

## Documentation

[Architecture](docs/ARCHITECTURE.md) · [Capability matrix](docs/CAPABILITY_MATRIX.md) · [MCP integration](docs/MCP_INTEGRATION.md) · [Security](docs/SECURITY.md) · [Research workflows](docs/RESEARCH_WORKFLOWS.md) · [Evidence schema](docs/EVIDENCE_SCHEMA.md) · [Learning engine](docs/LEARNING_ENGINE.md) · [Learning contributions](docs/LEARNING_CONTRIBUTIONS.md) · [Testing](docs/TESTING.md) · [Deployment](docs/DEPLOYMENT.md) · [Changelog](CHANGELOG.md)

Skill references: [playbooks](skills/re-super-intelligence/references/playbooks.md) · [reconstruction](skills/re-super-intelligence/references/reconstruction.md) · [all references](skills/re-super-intelligence/references/)

## Tooling

RESI builds on existing tools rather than replacing them. [REA (Reverse Engineer Anything)](https://github.com/morluto/rea) is an MIT-licensed MCP server whose 207 tools RESI catalogues (REA 6.7.0). RESI works without any of them: classification, planning, guardrails, evidence, memory, scoring and reporting run on the standard library, and any tool from any MCP server, CLI or Python library can be registered. RESI does not bundle or redistribute third-party tools; each keeps its own licence.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and the [code of conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Copyright 2026 Kavio Pte Ltd. Licensed under the [Apache License, Version 2.0](LICENSE); see [NOTICE](NOTICE).
