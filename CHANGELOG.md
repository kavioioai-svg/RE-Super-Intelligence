# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- Learning engine: a setup failure (no analysis provider, a program not installed, a tool not configured) stops counting against a tool once that tool succeeds later; it measured the environment, not the tool. Unresolved setup failures still count, so a broken tool is still demoted. Tool explanations show how many resolved setup failures were excluded.
- Reports list a tool failure under "Unresolved questions" only until the same tool succeeds in the project; the full failure history stays in "Tool failures".

### Added
- Lesson extraction groups recurring setup failures across one server's tools (for example every `rea` tool failing because no decompiler provider is available) and says whether the setup has since been fixed.
- The Evidence Validator closes hypothesis claims that a verified claim explicitly settles: "settles/confirms/supports clm-..." marks them supported and "refutes/rejects/contradicts/falsifies clm-..." marks them rejected (negated statements settle nothing; rejection wins). Each settlement feeds calibration, and `resi_validate_evidence` returns them as `settled`.

## [0.3.0] - 2026-11-21

### Added
- Reconstruction scorecard (`resi_reconstruction_score`, `resi score`): byte-level comparison of a rebuild against the original for Mach-O (thin and fat), ELF and PE, per section and per function, with build ids, UUIDs, timestamps, checksums and signatures excluded.
- RESI-run second engine (`resi_run_local`, `resi run`): Rizin runs on the authorized artifact only, re-hashed before every run, recorded as evidence; plans add it for corroboration or list it as `recommended`.
- Expert playbooks (`references/playbooks.md`) and playbook import (`resi_import_playbooks`, `resi playbooks import`) from any skill folder, attributed and refreshable.
- Evidence-gated tool verification (`resi_verify_tool`, `resi registry verify`).
- Plans expose `target` (the SHA-256 to use) and each step's guardrail verdict (`allowed`, `gate`).
- Reports list tool failures and untested hypotheses.
- Apache License 2.0, NOTICE (copyright Kavio Pte Ltd), contributing guide, security policy, code of conduct, issue and pull request templates.
- Installer finds a Python 3.11+ interpreter automatically (`$PYTHON`, `python3.13`, `python3.12`, `python3.11`, `python3`) and explains how to fix an old one.
- Installer `--runtime-only` mode to install the runtime without touching an installed skill.
- Package metadata: licence expression, author, classifiers, project URLs, `py.typed`.

### Fixed
- `resi_plan` could report a plan as authorized while the guardrail refused every step when the target was passed as a file path. Paths now resolve to the artifact's SHA-256 everywhere, and a regression test checks that plan and guardrail verdicts agree.
- Guardrail false positives: hex constants were detected as phone numbers, prose about medical records as a record number, and backticked pattern names as secrets.
- Playbook headings at the same level no longer nest under each other.

## [0.2.0] - 2026-11-21

### Added
- Agent-neutral `re-super-intelligence` skill: operating loop, routing, references, ten specialist roles, read-only environment discovery and a safe installer.
- Orchestration runtime with a hexagonal architecture and a standard-library-only core.
- Content-based artifact classification with ELF and pcap header parsing.
- Capability registry cataloguing 207 REA tools plus external CLIs and libraries, with overlays for any MCP server.
- Guarded execution: scope and approval gates, command filtering, secret redaction, prompt-injection detection, audit log.
- Evidence model, Evidence Validator with cross-tool corroboration, hypothesis and experiment loop.
- Learning engine (tool-outcome bandit, confidence calibration, lessons), long-term memory and hybrid RAG retrieval.
- Security Auditor and clean-room leak gate.
- MCP stdio server (18 tools) and human-only CLI for permission changes.
- Reproducible synthetic 3D measurement pipeline.
- Test suite (unit, integration, architecture, acceptance, skill) and CI on Ubuntu and macOS for Python 3.11–3.13.
