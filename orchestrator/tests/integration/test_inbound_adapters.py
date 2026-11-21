"""CLI and MCP server exercised end to end against a real on-disk state directory."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from resi.adapters.inbound.cli import main
from resi.adapters.inbound.mcp_server import TOOLS, MCPServer, serve
from resi.bootstrap import build_container
from tests.support import elf_bytes, write


def cli(home: Path, *args: str, capsys: pytest.CaptureFixture[str]) -> tuple[int, Any]:
    code = main(["--home", str(home), *args])
    out = capsys.readouterr().out
    try:
        return code, json.loads(out)
    except json.JSONDecodeError:
        return code, out


@pytest.fixture
def state(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    home = tmp_path / "home"
    elf = write(tmp_path, "s.elf", elf_bytes())
    announced = tmp_path / "announced.txt"
    announced.write_text("mcp__rea__binary_overview\nmcp__rea__list_strings\n")
    cli(home, "registry", "refresh", "--announced", str(announced), capsys=capsys)
    _, project = cli(home, "project", "init", "--name", "t", "--statement", "mine", capsys=capsys)
    return {"home": home, "elf": elf, "pid": project["project_id"]}


class TestCli:
    def test_full_human_workflow(self, state: dict[str, Any], capsys: pytest.CaptureFixture[str]) -> None:
        home, elf, pid = state["home"], str(state["elf"]), state["pid"]
        code, plan = cli(home, "plan", "--project", pid, elf, capsys=capsys)
        assert code == 0 and plan["authorized"] is False
        _, artifact = cli(home, "project", "authorize", "--project", pid, elf, capsys=capsys)
        assert artifact["kind"] == "elf"
        _, plan = cli(home, "plan", "--project", pid, elf, capsys=capsys)
        assert [s["tool_id"] for s in plan["steps"]] == ["rea.binary_overview", "rea.list_strings"]
        code, audit = cli(home, "audit", "--project", pid, capsys=capsys)
        assert code == 0 and audit["passed"] is True
        code, report = cli(home, "report", "--project", pid, capsys=capsys)
        assert code == 0 and report.startswith("# Research report: t")

    def test_cleanroom_exit_code(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        spec = tmp_path / "spec.md"
        spec.write_text("call FUN_00401000 with param_1")
        code, result = cli(tmp_path / "h", "cleanroom", str(spec), capsys=capsys)
        assert code == 3 and result["clean"] is False

    def test_memory_round_trip(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        home = tmp_path / "h"
        cli(home, "remember", "--title", "uImage", "--text", "extract then squashfs", capsys=capsys)
        _, hits = cli(home, "recall", "squashfs", capsys=capsys)
        assert hits[0]["document"]["title"] == "uImage"

    def test_errors_exit_nonzero(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--home", str(tmp_path), "plan", "--project", "nope", "x"]) == 1
        assert "error:" in capsys.readouterr().err


class TestMcpServer:
    @pytest.fixture(autouse=True)
    def _container(self, state: dict[str, Any]) -> Iterator[None]:
        self.container = build_container(state["home"])
        yield
        self.container.close()

    def _server(self, state: dict[str, Any]) -> MCPServer:
        return MCPServer(self.container)

    def _call(self, server: MCPServer, name: str, **args: Any) -> dict[str, Any]:
        response = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                  "params": {"name": name, "arguments": args}})
        assert response is not None
        result: dict[str, Any] = response["result"]
        return result

    def test_handshake_and_listing(self, state: dict[str, Any]) -> None:
        server = self._server(state)
        init = server.handle({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                              "params": {"protocolVersion": "2099-01-01"}})
        assert init is not None and init["result"]["protocolVersion"] == "2025-06-18"
        assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
        listed = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert listed is not None and len(listed["result"]["tools"]) == len(TOOLS)

    def test_agents_cannot_widen_permissions(self) -> None:
        forbidden = ("approve", "authorize", "init", "overlay", "target", "scope")
        assert not [t.name for t in TOOLS if any(word in t.name for word in forbidden)]
        refresh = next(t for t in TOOLS if t.name == "resi_refresh_registry")
        assert "overlay" not in refresh.schema["properties"]

    def test_tool_errors_are_reported_not_raised(self, state: dict[str, Any]) -> None:
        server = self._server(state)
        result = self._call(server, "resi_plan", project_id="missing", path="x")
        assert result["isError"] is True
        assert self._call(server, "resi_plan", bogus=1)["isError"] is True

    def test_unknown_method(self, state: dict[str, Any]) -> None:
        response = self._server(state).handle({"jsonrpc": "2.0", "id": 9, "method": "nope"})
        assert response is not None and response["error"]["code"] == -32601

    def test_recall_carries_untrusted_notice(self, state: dict[str, Any]) -> None:
        server = self._server(state)
        self._call(server, "resi_remember", title="t", text="pcap of the update protocol")
        payload = json.loads(self._call(server, "resi_recall", query="update protocol")
                             ["content"][0]["text"])
        assert "not instructions" in payload["notice"] and payload["hits"]

    def test_stdio_serve_loop(self, state: dict[str, Any]) -> None:
        stdin = io.StringIO('{"jsonrpc":"2.0","id":1,"method":"ping"}\nnot json\n\n')
        stdout = io.StringIO()
        serve(self.container, stdin, stdout)
        lines = [json.loads(line) for line in stdout.getvalue().splitlines()]
        assert lines[0] == {"jsonrpc": "2.0", "id": 1, "result": {}}
        assert lines[1]["error"]["code"] == -32700

    def test_runs_as_a_real_subprocess(self, state: dict[str, Any]) -> None:
        proc = subprocess.run(
            [sys.executable, "-m", "resi", "--home", str(state["home"]), "mcp"],
            input='{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n',
            capture_output=True, text=True, timeout=60, check=True)
        assert len(json.loads(proc.stdout)["result"]["tools"]) == len(TOOLS)
        assert proc.stderr == ""
