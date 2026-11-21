# Contributing to RESI

Thanks for helping make reverse engineering research more rigorous. Bug reports, tool adapters, catalogue updates, docs and test samples are all welcome.

## Ground rules

- **Authorized research only.** Contributions must not add credential interception, stealth instrumentation, access-control bypass, malware functionality or third-party traffic capture. See [`docs/SECURITY.md`](docs/SECURITY.md).
- **Agent-neutral.** The skill must work with any coding agent. Don't name a specific agent vendor in `skills/`; a test enforces this.
- **Evidence over assertion.** Never mark a tool or integration as working without an execution that proves it.
- **Synthetic samples.** Tests use generated or publicly licensed samples only — never proprietary binaries, captures or personal data.

## Development setup

```bash
git clone https://github.com/kavioioai-svg/RE-Super-Intelligence.git
cd RE-Super-Intelligence/orchestrator
python3.12 -m venv .venv && source .venv/bin/activate     # any Python 3.11+
pip install -e '.[dev]'
```

## Quality gates (CI runs exactly these)

```bash
cd orchestrator
ruff check resi tests ../skills
mypy --strict resi
pytest -W error::ResourceWarning --cov=resi --cov-fail-under=90
pytest ../skills/re-super-intelligence/tests
```

No `# type: ignore` or `# noqa` without a written justification in the same line.

## Architecture rules

RESI is hexagonal; `tests/architecture` fails the build if these break:

- `resi/domain` is pure Python: standard library only, no I/O.
- `resi/application` depends only on the domain and its own ports.
- Adapters implement ports; only `resi/bootstrap.py` wires concrete adapters.
- The core runtime keeps **zero third-party dependencies**. Optional extras (like `vision`) are fine.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the extension points (new tool families, artifact kinds, guardrails, stores, embedders, transports).

## Common contributions

| Change | Where | Also update |
|---|---|---|
| New tool from an MCP server | `domain/catalog.py` (or document an overlay) | `references/tool-registry.md` |
| New artifact type | `domain/classification.py`, `domain/routing.py` | classification + routing tests |
| New guardrail | `domain/guardrails.py`, call site, `application/security_audit.py` | guardrail + auditor tests, `references/security.md` |
| New persistence store | an outbound adapter implementing the repository ports | add it to `tests/integration/test_repository_contract.py` |
| Skill wording | `skills/re-super-intelligence/` | keep `SKILL.md` under 150 lines |

## Pull requests

1. Open an issue first for anything larger than a small fix.
2. One logical change per pull request, with tests.
3. Run all quality gates locally.
4. Add an entry under **Unreleased** in [`CHANGELOG.md`](CHANGELOG.md).

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE), the same license as the project.
