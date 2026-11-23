"""Command-line adapter. The only interface that can widen permissions.

Scope-changing commands (project init, authorize, target, approve, registry
overlay) live here because they must come from a human, never from an agent.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ... import __version__
from ...bootstrap import Container, build_container, build_ingestion
from ...domain.contributions import (
    MIN_CALIBRATION_POINTS,
    MIN_CONTRIBUTIONS,
    MIN_SAMPLES,
    PRIOR_STRENGTH,
    RankingParameters,
    render,
)
from ...domain.enums import Module, SecurityClass
from ...domain.errors import ResiError
from ...domain.models import ExecutionRequest
from ...domain.registry import OverlayEntry
from .presenters import present

EXIT_OK, EXIT_ERROR, EXIT_AUDIT_FAILED = 0, 1, 3


def _emit(value: Any) -> None:
    data = present(value)
    print(data if isinstance(data, str) else json.dumps(data, indent=2, default=str))


def _load_overlay(path: str) -> dict[str, OverlayEntry]:
    raw = json.loads(Path(path).read_text())
    return {
        tool_id: OverlayEntry(Module(e["module"]), SecurityClass(e["security_class"]),
                              tuple(e.get("input_types", ("any",))),
                              tuple(e.get("operations", ("external",))))
        for tool_id, e in raw.items()
    }


def _read_lines(path: str) -> list[str]:
    text = sys.stdin.read() if path == "-" else Path(path).read_text()
    return [line.strip() for line in text.splitlines() if line.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="resi", description="RE Super Intelligence")
    parser.add_argument("--version", action="version", version=f"resi {__version__}")
    parser.add_argument("--home", type=Path, help="state directory (default: $RESI_HOME or ~/.resi)")
    sub = parser.add_subparsers(dest="command", required=True)

    project = sub.add_parser("project", help="projects and authorization scope (human only)")
    psub = project.add_subparsers(dest="action", required=True)
    p = psub.add_parser("init")
    p.add_argument("--name", required=True)
    p.add_argument("--profile", default="general")
    p.add_argument("--statement", required=True, help="who owns the target, what is authorized")
    p = psub.add_parser("authorize", help="add an artifact file to scope")
    p.add_argument("--project", required=True)
    p.add_argument("path")
    p = psub.add_parser("target", help="add a URL, package, process or device to scope")
    p.add_argument("--project", required=True)
    p.add_argument("target")
    p = psub.add_parser("approve", help="approve dynamic / device-mutating work")
    p.add_argument("--project", required=True)
    p.add_argument("--tool", required=True, help="tool id or glob, e.g. 'rea.*frida*'")
    p.add_argument("--target", required=True, help="sha256, package, process, URL or serial")
    p.add_argument("--by", required=True)
    p.add_argument("--statement", required=True, help="the approver's words, verbatim")
    p.add_argument("--single-use", action="store_true")
    p = psub.add_parser("show")
    p.add_argument("--project", required=True)

    p = sub.add_parser("classify", help="classify an artifact by content")
    p.add_argument("path")

    registry = sub.add_parser("registry", help="capability registry")
    rsub = registry.add_subparsers(dest="action", required=True)
    p = rsub.add_parser("refresh", help="rebuild from announced MCP tool names")
    p.add_argument("--announced", default=None, help="file with one tool name per line, or -")
    p.add_argument("--overlay", default=None, help="JSON classifying uncatalogued tools (human only)")
    p = rsub.add_parser("verify", help="mark a tool verified from a successful execution")
    p.add_argument("--execution", required=True)
    p.add_argument("--version", default="")
    p = rsub.add_parser("show")
    p.add_argument("--module")
    p.add_argument("--status")
    p.add_argument("--summary", action="store_true")

    p = sub.add_parser("plan", help="plan research for an authorized artifact")
    p.add_argument("--project", required=True)
    p.add_argument("path")
    p.add_argument("--no-adaptive", action="store_true")
    p.add_argument("--explore", action="store_true")
    p.add_argument("--seed", type=int, default=0)

    p = sub.add_parser("run", help="run a local tool (cli.rizin, resi.*) through the guardrails")
    p.add_argument("--project", required=True)
    p.add_argument("--tool", required=True, help="e.g. cli.rizin")
    p.add_argument("--target", required=True, help="artifact path or SHA-256")
    p.add_argument("--arg", action="append", default=[], metavar="KEY=VALUE",
                   help="tool argument, e.g. --arg command=ij")
    p = sub.add_parser("score", help="reconstruction scorecard: rebuilt vs authorized original")
    p.add_argument("--project", required=True)
    p.add_argument("original", help="authorized original binary (path or SHA-256)")
    p.add_argument("rebuilt", help="your rebuilt binary")

    p = sub.add_parser("validate", help="run the Evidence Validator")
    p.add_argument("--project", required=True)
    p = sub.add_parser("audit", help="run the Security Auditor (exit 3 on critical/high)")
    p.add_argument("--project", required=True)
    p = sub.add_parser("cleanroom", help="check a spec for decompiler artefacts (exit 3 on leak)")
    p.add_argument("path")

    p = sub.add_parser("remember", help="store knowledge in memory")
    p.add_argument("--title", required=True)
    p.add_argument("--text", required=True)
    p.add_argument("--kind", default="note")
    p.add_argument("--project")
    p.add_argument("--tag", action="append", default=[])
    p = sub.add_parser("recall", help="search memory")
    p.add_argument("query")
    p.add_argument("-k", type=int, default=5)
    p.add_argument("--project")

    playbooks = sub.add_parser("playbooks", help="expert procedures in memory")
    pbsub = playbooks.add_subparsers(dest="action", required=True)
    p = pbsub.add_parser("import", help="import Markdown playbooks from files or skill folders")
    p.add_argument("paths", nargs="+")

    p = sub.add_parser("learn", help="learning report and lesson refresh")
    p.add_argument("--context")
    p.add_argument("--refresh-lessons", action="store_true")

    p = sub.add_parser("report", help="render the Markdown research report")
    p.add_argument("--project", required=True)
    p = sub.add_parser("vision-demo", help="reproducible synthetic 3D analysis (needs numpy)")
    p.add_argument("--seed", type=int, default=7)
    sub.add_parser("mcp", help="serve RESI as an MCP server over stdio")

    contribute = sub.add_parser(
        "contribute", help="opt-in learning contributions: see and export what you would share")
    csub = contribute.add_subparsers(dest="action", required=True)
    csub.add_parser("preview", help="print the exact JSON that export would write (offline)")
    p = csub.add_parser("export", help="write the contribution JSON to a file (offline)")
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--force", action="store_true", help="overwrite an existing file")

    ingest = sub.add_parser(
        "ingest", help="private contribution ingestion and ranking (Kavio infrastructure)")
    isub = ingest.add_subparsers(dest="action", required=True)
    isub.add_parser("serve", help="run the authenticated HTTPS endpoint (config from env)")
    p = isub.add_parser("accept", help="validate and store contribution files received offline")
    p.add_argument("--db", required=True, type=Path)
    p.add_argument("files", nargs="+", type=Path)
    p = isub.add_parser("rank", help="run the deterministic ranking job")
    p.add_argument("--db", required=True, type=Path)
    p.add_argument("--out", type=Path, help="write the ranking artifact here (default: stdout)")
    p.add_argument("--min-samples", type=int, default=MIN_SAMPLES)
    p.add_argument("--min-contributions", type=int, default=MIN_CONTRIBUTIONS)
    p.add_argument("--prior-strength", type=float, default=PRIOR_STRENGTH)
    p.add_argument("--min-calibration-points", type=int, default=MIN_CALIBRATION_POINTS)
    return parser


def _write_new(path: Path, text: str, force: bool) -> None:
    if path.exists() and not force:
        raise ValueError(f"{path} exists; pass --force to overwrite")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text)
    tmp.replace(path)


def run_ingest(args: argparse.Namespace) -> int:
    """Private-side commands: they never open a user's RESI state."""
    if args.action == "serve":  # pragma: no cover - long-running; covered by the demo
        import logging

        from .ingest_server import IngestConfig, serve

        # Request lines are method, path and status only (see ingest_server).
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
        config = IngestConfig.from_env(os.environ)
        serve(config, build_ingestion(config.db_path, config.max_bytes).ingestion)
        return EXIT_OK
    container = build_ingestion(args.db)
    if args.action == "accept":
        results: list[dict[str, Any]] = []
        failed = False
        for path in args.files:
            try:
                result = container.ingestion.accept(path.read_bytes())
                results.append({"file": str(path), "status": result.status,
                                "contribution_id": result.contribution_id})
            except ResiError as exc:
                failed = True
                results.append({"file": str(path), "status": "rejected", "error": str(exc)})
        _emit(results)
        return EXIT_ERROR if failed else EXIT_OK
    params = RankingParameters(args.min_samples, args.min_contributions, args.prior_strength,
                               args.min_calibration_points)
    text = render(container.ranking.rank(params))
    if args.out:
        _write_new(args.out, text, force=True)
        _emit({"written": str(args.out), "bytes": len(text.encode("utf-8"))})
    else:
        print(text, end="")
    return EXIT_OK


def run(args: argparse.Namespace, container: Container) -> int:
    c = container
    if args.command == "project":
        if args.action == "init":
            _emit(c.projects.init_project(args.name, args.profile, args.statement))
        elif args.action == "authorize":
            _emit(c.projects.authorize_artifact(args.project, args.path))
        elif args.action == "target":
            c.projects.authorize_target(args.project, args.target)
            _emit({"authorized_target": args.target})
        elif args.action == "approve":
            _emit(c.projects.approve(args.project, args.tool, args.target, args.by,
                                     args.statement, args.single_use))
        else:
            _emit({"project": c.projects.project(args.project),
                   "scope": c.projects.scope(args.project)})
    elif args.command == "classify":
        _emit(c.research.classify(args.path))
    elif args.command == "registry":
        if args.action == "refresh":
            announced = _read_lines(args.announced) if args.announced else []
            overlay = _load_overlay(args.overlay) if args.overlay else None
            _emit(c.registry.refresh(announced, overlay).summary())
        elif args.action == "verify":
            _emit(c.execution.verify_tool(args.execution, args.version))
        else:
            registry = c.registry.current()
            if args.summary:
                _emit(registry.summary())
            else:
                _emit([t for t in registry
                       if (not args.module or t.module.value == args.module)
                       and (not args.status or t.status.value == args.status)])
    elif args.command == "plan":
        _emit(c.research.plan(args.project, args.path, not args.no_adaptive, args.explore, args.seed))
    elif args.command == "run":
        tool_args = dict(item.split("=", 1) for item in args.arg if "=" in item)
        _emit(c.execution.execute(args.project, ExecutionRequest(args.tool, args.target, tool_args)))
    elif args.command == "score":
        record = c.execution.execute(args.project, ExecutionRequest(
            "resi.reconstruction_score", args.original, {"rebuilt": args.rebuilt}))
        _emit(record)
        return EXIT_OK if record.succeeded else EXIT_ERROR
    elif args.command == "validate":
        _emit(c.evidence.validate(args.project))
    elif args.command == "audit":
        result = c.auditor.audit(args.project)
        _emit({"passed": result.passed, "counts": result.counts(), "findings": result.findings})
        return EXIT_OK if result.passed else EXIT_AUDIT_FAILED
    elif args.command == "cleanroom":
        findings = c.auditor.check_cleanroom(Path(args.path).read_text(), args.path)
        _emit({"clean": not findings, "findings": findings})
        return EXIT_AUDIT_FAILED if findings else EXIT_OK
    elif args.command == "remember":
        _emit(c.knowledge.remember(args.title, args.text, args.kind, args.project, args.tag))
    elif args.command == "recall":
        _emit(c.knowledge.recall(args.query, args.k, args.project))
    elif args.command == "playbooks":
        _emit(c.playbooks.import_paths(args.paths))
    elif args.command == "learn":
        if args.refresh_lessons:
            _emit({"lessons": c.learning.refresh_lessons()})
        _emit(c.learning.report(args.context))
    elif args.command == "report":
        print(c.reports.render(args.project), end="")
    elif args.command == "vision-demo":
        _emit(Container.vision().analyse_synthetic(args.seed))
    elif args.command == "mcp":
        from .mcp_server import serve

        serve(c)
    elif args.command == "contribute":
        if args.action == "preview":
            print(c.contributions.preview(), end="")
        else:
            export = c.contributions.prepare_export()
            _write_new(args.out, export.text, args.force)
            c.contributions.complete_export(export.contribution_id)
            print(json.dumps({"written": str(args.out), "contribution_id": export.contribution_id,
                              "groups": export.groups,
                              "bytes": len(export.text.encode("utf-8"))}, indent=2),
                  file=sys.stderr)
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "ingest":
            return run_ingest(args)
        with build_container(args.home) as container:
            return run(args, container)
    except (ResiError, ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
