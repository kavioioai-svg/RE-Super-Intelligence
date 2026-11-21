# Architecture

RESI follows a hexagonal (ports and adapters) architecture. Business rules sit in the middle with no knowledge of storage, transport or user interface; everything else plugs in through ports.

```
            ┌──────────────── inbound adapters ────────────────┐
            │  CLI (humans)            MCP server (any agent)   │
            └──────────────────────┬───────────────────────────┘
                                   │ calls use cases
            ┌──────────────────────▼───────────────────────────┐
            │ APPLICATION  projects · research · execution ·    │
            │              evidence · hypotheses · knowledge ·  │
            │              learning · security audit · reports  │
            │              ports.py  (Protocols)                │
            └──────────────────────┬───────────────────────────┘
                                   │ uses
            ┌──────────────────────▼───────────────────────────┐
            │ DOMAIN  models · classification · registry ·      │
            │         routing · guardrails · evidence rules ·   │
            │         learning · retrieval · profiles           │
            │         (pure Python, no I/O, no third party)     │
            └──────────────────────────────────────────────────┘
                                   ▲ implements ports
            ┌──────────────────────┴───────────────────────────┐
            │ outbound adapters: SQLite / in-memory stores,     │
            │ JSON registry, JSONL audit log, filesystem reader,│
            │ tool transport, environment probe, embedder,      │
            │ numpy point-cloud analyzer                        │
            └──────────────────────────────────────────────────┘
       bootstrap.py — composition root: the only place adapters are wired
```

## Dependency rule (enforced by `tests/architecture`)

| Layer | May import |
|---|---|
| domain | standard library + domain. No I/O modules (`os`, `sqlite3`, `subprocess`, `socket`, `pathlib`...). |
| application | domain + application |
| outbound adapters | domain + application ports — never inbound adapters or bootstrap |
| inbound adapters | application, domain, bootstrap |
| bootstrap | everything (it wires the graph) |

A violation fails the test suite, so the architecture cannot erode silently.

## Why this shape

- **Swappable infrastructure.** SQLite and in-memory stores pass the same repository contract tests. PostgreSQL, a vector database or a neural embedder is a new adapter, not a rewrite.
- **Testable core.** Domain and application are tested without a filesystem, network or MCP server.
- **One rule set, many front doors.** The CLI and the MCP server call the same use cases, so guardrails cannot differ between them.
- **Roles, not processes.** Specialist agents are roles over one shared evidence store. Persistent multi-process agents are only worth adding if benchmarks show a gain.
- **Wrap, don't rebuild.** REA already exposes ~200 analysis tools plus an unknowns ledger and evidence bundles. RESI adds classification, scope enforcement, correlation, hypothesis tracking, learning, memory and reporting.

## Classification

By content, never extension (`domain/classification.py`):

| Signature | Kind | Module |
|---|---|---|
| `7F 45 4C 46` | ELF (header parsed: bits, endianness, machine, entry) | binary |
| `MZ` + `PE\0\0` at `e_lfanew` | PE | binary |
| `FEEDFACE/CF`, `CEFAEDFE/CF` | Mach-O | binary |
| `CAFEBABE` + small arch count | Mach-O fat (else Java class) | binary / mobile |
| `00 61 73 6D` | WASM | binary |
| `PK 03 04` + member names | APK / AAB / IPA / JAR / ZIP | mobile / binary |
| pcap magics / `0A0D0D0A` | PCAP (header parsed) / PCAPNG | protocol |
| `27051956`, `hsqs`, `1F 8B` | uImage, SquashFS, gzip | firmware |
| `SQLite format 3\0` | SQLite | protocol |
| PLY / STL / PCD / OFF headers, binary STL size check | point cloud / mesh | vision |
| no magic, entropy > 7.5 bits/byte | packed / encrypted blob | firmware |

## Storage

`$RESI_HOME` (default `~/.resi`): `resi.db` (SQLite, WAL), `registry.json`, `audit.log` (append-only JSONL). Rows hold JSON documents keyed by indexed columns, so the schema ports to PostgreSQL `JSONB` unchanged. Move to PostgreSQL only for multi-user or cross-machine access.

## Isolation

Artifacts are opened read-only; the reader hashes and reads the first 4 KiB only. Extraction writes to an isolated work directory. Dynamic analysis targets a VM, emulator or dedicated test device — never the analyst's host processes.
