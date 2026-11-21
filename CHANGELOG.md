# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Apache License 2.0, NOTICE (copyright Kavio Pte Ltd), contributing guide, security policy, code of conduct, issue and pull request templates.
- Installer finds a Python 3.11+ interpreter automatically (`$PYTHON`, `python3.13`, `python3.12`, `python3.11`, `python3`) and explains how to fix an old one.
- Installer `--runtime-only` mode to install the runtime without touching an installed skill.
- Package metadata: licence expression, author, classifiers, project URLs, `py.typed`.

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
