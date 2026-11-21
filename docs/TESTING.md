# Testing

## Run everything

```bash
cd orchestrator
pip install -e '.[dev]'
ruff check resi tests                     # lint (strict rule set, zero suppressions)
mypy --strict resi                        # types
pytest --cov=resi --cov-report=term       # 339 tests
pytest ../skills/re-super-intelligence/tests   # 20 skill-package tests
```

Treat resource leaks as errors with `pytest -W error::ResourceWarning`.

## Test pyramid

| Suite | Path | What it proves | Speed |
|---|---|---|---|
| Domain unit | `tests/unit/domain` | Classification and parsers, section layouts and reconstruction scoring (synthetic Mach-O/fat/PE and real compiler builds), registry and scope, guardrails, evidence rules, learning maths, retrieval, routing | ms, no I/O |
| Application unit | `tests/unit/application` | Use cases through ports with in-memory adapters: execution guardrails, plan/guardrail parity, local-engine confinement, retries, validator, hypothesis loop, memory admission, playbook import, learning loop, auditor, reports | ms |
| Integration | `tests/integration` | One repository contract run against SQLite and in-memory stores; CLI and MCP server end to end (incl. a real subprocess); numpy vision | < 1 s |
| Architecture | `tests/architecture` | Hexagonal dependency rule; domain is pure Python with no I/O | ms |
| Acceptance | `tests/acceptance` | The specification's ten acceptance tests | < 1 s |
| Skill package | `skills/…/tests` | Frontmatter, resolvable references, roles, agent neutrality, discovery script, safe installer and Python detection | < 1 s |

## Acceptance tests

| # | Requirement | Test | State here |
|---|---|---|---|
| 1 | Discovery of installed tools | `test_01_discovers_installed_tools` | Pass |
| 2 | Correct routing per artifact type | `test_02_routes_artifact_types_correctly` (ELF, pcap, uImage, PLY) | Pass |
| 3 | Verified Ghidra analysis of an approved sample | `test_03_…` + mechanism `test_03b_…` | Mechanism passes; live run **skipped** — Ghidra not installed in CI |
| 4 | Verified REA integration where available | `test_04_…` | **Skipped** unless `RESI_REA_LIVE=1` on a machine with REA |
| 5 | Parsing a documented binary format | `test_05_…` (ELF, pcap both endiannesses) | Pass |
| 6 | Reproducible synthetic 3D analysis | `test_06_…` | Pass |
| 7 | Evidence-backed reporting | `test_07_…` | Pass |
| 8 | Missing tools handled | `test_08_…` | Pass |
| 9 | Authorization boundaries enforced | `test_09_…` | Pass |
| 10 | No unsupported integration claims | `test_10_…` | Pass |

Skips are explicit on purpose: claiming tests 3 and 4 without a real Ghidra or REA run would violate test 10.

## Running the live integrations (target machine)

```bash
# Ghidra: put analyzeHeadless on PATH, then
pytest tests/acceptance -k test_03 -rs
# REA: in an agent session with the rea MCP server announced
RESI_REA_LIVE=1 pytest tests/acceptance -k test_04 -rs
```

Both are placeholders that fail until the live assertions are written for your sample — enable them deliberately.

## Writing tests

- Domain tests: construct value objects directly; no fixtures with I/O.
- Application tests: `tests/support.build_app()` gives deterministic clock and ids, a scripted transport and in-memory stores.
- Persistence: add cases to `test_repository_contract.py` so every store must satisfy them.
- Use synthetic samples only (`tests/support.elf_bytes()` builds a valid ELF header).
