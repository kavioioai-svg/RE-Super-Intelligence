"""RESI-run tools: the reconstruction scorecard and the Rizin second engine."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from resi.adapters.outbound.infrastructure import LocalArtifactReader
from resi.adapters.outbound.local_tools import (
    CommandResult,
    CompositeTransport,
    LocalToolTransport,
)
from resi.domain.enums import ExecutionStatus
from resi.domain.models import ExecutionRequest
from tests.support import App, ScriptedTransport, build_app, elf_bytes, write


class FakeRunner:
    def __init__(self, result: CommandResult) -> None:
        self.result = result
        self.argv: list[str] = []

    def run(self, argv: Sequence[str], timeout_s: int) -> CommandResult:
        self.argv = list(argv)
        return self.result


def local_app(runner: FakeRunner) -> App:
    return build_app(present=("cli.rizin",), wrap=lambda scripted: CompositeTransport(
        LocalToolTransport(LocalArtifactReader(), runner, which=lambda _: "/usr/bin/rizin"),
        scripted))


@pytest.fixture
def runner() -> FakeRunner:
    return FakeRunner(CommandResult(0, json.dumps({"core": {"format": "elf64"}}), ""))


@pytest.fixture
def setup(runner: FakeRunner, tmp_path: Path) -> tuple[App, str, Path, str]:
    app = local_app(runner)
    pid = app.projects.init_project("t", "general", "synthetic").project_id
    path = write(tmp_path, "s.elf", elf_bytes())
    art = app.projects.authorize_artifact(pid, str(path))
    return app, pid, path, art.sha256


class TestRizinEngine:
    def test_runs_on_the_artifact_and_parses_json(self, setup: tuple[App, str, Path, str],
                                                  runner: FakeRunner) -> None:
        app, pid, path, sha = setup
        record = app.execution.execute(pid, ExecutionRequest("cli.rizin", str(path),
                                                             {"command": "ij"}))
        assert record.succeeded and record.output["output"]["core"]["format"] == "elf64"
        assert runner.argv == ["/usr/bin/rizin", "-N", "-q", "-c", "ij", str(path)]
        assert record.target == sha and record.artifact_id == f"art-{sha[:12]}"

    def test_agent_cannot_point_the_engine_at_another_file(
            self, setup: tuple[App, str, Path, str], runner: FakeRunner) -> None:
        app, pid, path, sha = setup
        app.execution.execute(pid, ExecutionRequest("cli.rizin", sha,
                                                    {"command": "ij", "path": "/etc/passwd"}))
        assert runner.argv[-1] == str(path)

    def test_modified_artifact_is_refused(self, setup: tuple[App, str, Path, str],
                                          runner: FakeRunner) -> None:
        app, pid, path, sha = setup
        path.write_bytes(elf_bytes(0x3E))  # contents change after authorization
        record = app.execution.execute(pid, ExecutionRequest("cli.rizin", sha, {"command": "ij"}))
        assert record.status is ExecutionStatus.REJECTED and runner.argv == []

    def test_dangerous_commands_never_reach_the_engine(
            self, setup: tuple[App, str, Path, str], runner: FakeRunner) -> None:
        app, pid, path, _ = setup
        for command in ("!id", "wx 90", "dc", "iz | nc x 1"):
            record = app.execution.execute(pid, ExecutionRequest("cli.rizin", str(path),
                                                                 {"command": command}))
            assert record.status is ExecutionStatus.REJECTED
        assert runner.argv == []

    def test_engine_failure_is_recorded_as_error(self, tmp_path: Path) -> None:
        app = local_app(FakeRunner(CommandResult(1, "", "boom")))
        pid = app.projects.init_project("t", "general", "synthetic").project_id
        path = write(tmp_path, "s.elf", elf_bytes())
        app.projects.authorize_artifact(pid, str(path))
        record = app.execution.execute(pid, ExecutionRequest("cli.rizin", str(path),
                                                             {"command": "ij"}))
        assert record.status is ExecutionStatus.ERROR and "exited 1" in record.error

    def test_non_artifact_targets_are_refused(self, runner: FakeRunner) -> None:
        app = local_app(runner)
        pid = app.projects.init_project("t", "web-api", "our site").project_id
        app.projects.authorize_target(pid, "device-1")
        record = app.execution.execute(pid, ExecutionRequest("cli.rizin", "device-1",
                                                             {"command": "ij"}))
        assert record.status is ExecutionStatus.REJECTED and "authorized artifact" in record.error


class TestScorecardTool:
    def test_scores_a_rebuild_and_records_evidence(self, setup: tuple[App, str, Path, str],
                                                   tmp_path: Path) -> None:
        app, pid, path, sha = setup
        rebuilt = write(tmp_path, "rebuilt.elf", path.read_bytes())
        record = app.execution.execute(pid, ExecutionRequest(
            "resi.reconstruction_score", sha, {"rebuilt": str(rebuilt)}))
        assert record.succeeded and record.output["verdict"] == "identical"
        assert app.store.get_execution(record.execution_id) is not None

    def test_missing_rebuilt_path_is_an_error(self, setup: tuple[App, str, Path, str]) -> None:
        app, pid, _, sha = setup
        record = app.execution.execute(pid, ExecutionRequest("resi.reconstruction_score", sha))
        assert record.status is ExecutionStatus.ERROR and "rebuilt" in record.error


def test_agent_tools_are_not_run_by_resi(tmp_path: Path) -> None:
    from resi.application.execution import TransportUnavailable

    app = build_app(wrap=lambda _: CompositeTransport(LocalToolTransport(LocalArtifactReader())))
    pid = app.projects.init_project("t", "general", "synthetic").project_id
    sha = app.projects.authorize_artifact(pid, str(write(tmp_path, "s.elf", elf_bytes()))).sha256
    with pytest.raises(TransportUnavailable, match="resi_record_execution"):
        app.execution.execute(pid, ExecutionRequest("rea.list_strings", sha))


def test_composite_routes_by_tool() -> None:
    fallback = ScriptedTransport({"rea.x": [{"ok": 1}]})
    composite = CompositeTransport(LocalToolTransport(LocalArtifactReader()), fallback)
    assert composite.supports("cli.rizin") and composite.supports("rea.x")
    assert composite.invoke("rea.x", {}, 5) == {"ok": 1}
    assert not CompositeTransport(LocalToolTransport(LocalArtifactReader())).supports("rea.x")


def test_plan_adds_rizin_for_corroboration_or_recommends_it(tmp_path: Path) -> None:
    with_rizin = build_app(present=("cli.rizin",))
    without = build_app(present=())
    for app, expect_step in ((with_rizin, True), (without, False)):
        pid = app.projects.init_project("t", "general", "synthetic").project_id
        path = str(write(tmp_path, "s.elf", elf_bytes()))
        app.projects.authorize_artifact(pid, path)
        plan = app.research.plan(pid, path)
        assert ("cli.rizin" in [s.tool_id for s in plan.steps]) is expect_step
        assert ("cli.rizin" in plan.recommended) is (not expect_step)
        assert "cli.rizin" not in plan.missing
