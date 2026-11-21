"""The specification's acceptance tests, numbered as in the spec (section 16).

Tests that need real third-party tools on the target machine are skipped with
an explicit reason rather than faked - acceptance test 10 forbids claiming an
integration that was not exercised.
"""

from __future__ import annotations

import os
import shutil
import struct
from pathlib import Path

import pytest

from resi.adapters.outbound.infrastructure import SystemEnvironmentProbe
from resi.application.evidence import ClaimInput
from resi.domain.catalog import EXTERNAL_TOOLS
from resi.domain.classification import parse_elf_header, parse_pcap_header
from resi.domain.enums import ClaimKind, Confidence, ExecutionStatus, ToolStatus
from resi.domain.errors import ToolNotCallable
from resi.domain.models import ExecutionRequest
from resi.domain.registry import build_registry
from tests.support import build_app, elf_bytes, require, write


def test_01_discovers_installed_tools() -> None:
    status = SystemEnvironmentProbe().probe(EXTERNAL_TOOLS)
    assert set(status) == {t.id for t in EXTERNAL_TOOLS}
    if shutil.which("gdb"):
        assert status["cli.gdb"] is ToolStatus.DISCOVERED
    registry = build_registry(["mcp__remote-devices__rea__binary_overview"], status)
    assert require(registry.get("rea.binary_overview")).status is ToolStatus.DISCOVERED


@pytest.mark.parametrize(("name", "data", "first_tool"), [
    ("a.elf", elf_bytes(), "rea.binary_overview"),
    ("a.pcap", struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1), "rea.inspect_pcap_capture"),
    ("a.bin", b"\x27\x05\x19\x56" + b"\x00" * 64, "rea.inspect_artifact"),
    ("a.ply", b"ply\nformat ascii 1.0\nelement vertex 1\nend_header\n0 0 0\n", "py.numpy"),
])
def test_02_routes_artifact_types_correctly(tmp_path: Path, name: str, data: bytes,
                                            first_tool: str) -> None:
    app = build_app(announced=["mcp__rea__binary_overview", "mcp__rea__inspect_pcap_capture",
                               "mcp__rea__inspect_artifact"], present=["py.numpy"])
    pid = app.projects.init_project("t", "general", "synthetic").project_id
    path = str(write(tmp_path, name, data))
    app.projects.authorize_artifact(pid, path)
    assert app.research.plan(pid, path).steps[0].tool_id == first_tool


@pytest.mark.skipif(not shutil.which("analyzeHeadless"),
                    reason="Ghidra is not installed here; run on the target machine (Phase 3)")
def test_03_verified_ghidra_analysis_of_approved_sample() -> None:  # pragma: no cover
    pytest.fail("wire the Ghidra headless adapter and assert on its output before enabling")


def test_03b_a_tool_is_only_verified_through_recorded_evidence(tmp_path: Path) -> None:
    app = build_app(present=["cli.ghidra"])
    pid = app.projects.init_project("t", "general", "synthetic").project_id
    art = app.projects.authorize_artifact(pid, str(write(tmp_path, "s.elf", elf_bytes())))
    record = app.execution.execute(pid, ExecutionRequest("cli.ghidra", art.sha256))
    assert record.status is ExecutionStatus.OK
    app.registry.verify("cli.ghidra", "11.x", record.execution_id)
    assert require(app.registry.current().get("cli.ghidra")).status is ToolStatus.VERIFIED


@pytest.mark.skipif(not os.environ.get("RESI_REA_LIVE"),
                    reason="needs a live REA MCP session; set RESI_REA_LIVE=1 on the target machine")
def test_04_verified_rea_integration() -> None:  # pragma: no cover
    pytest.fail("record a real rea.binary_overview call via resi_record_execution, then verify")


def test_05_parses_documented_binary_formats() -> None:
    assert parse_elf_header(elf_bytes(0x3E))["machine"] == "x86_64"
    pcap = parse_pcap_header(struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 105))
    assert (pcap["endianness"], pcap["linktype"], pcap["snaplen"]) == ("big", 105, 262144)


def test_06_reproducible_synthetic_3d_analysis() -> None:
    pytest.importorskip("numpy")
    from resi.adapters.outbound.vision_numpy import NumpyPointCloudAnalyzer

    analyzer = NumpyPointCloudAnalyzer()
    assert analyzer.analyse_synthetic(3)["result_sha256"] == analyzer.analyse_synthetic(3)["result_sha256"]


def test_07_evidence_backed_technical_report(tmp_path: Path) -> None:
    app = build_app()
    pid = app.projects.init_project("demo", "general", "synthetic").project_id
    art = app.projects.authorize_artifact(pid, str(write(tmp_path, "s.elf", elf_bytes())))
    exe = app.execution.execute(pid, ExecutionRequest("rea.list_strings", art.sha256))
    app.evidence.record_claim(ClaimInput(pid, art.artifact_id, art.sha256, "rea.list_strings",
                                         exe.execution_id, ClaimKind.OBSERVED, "string 'AES'",
                                         "crypto", Confidence.MEDIUM, "rea.list_strings on sample"))
    report = app.reports.render(pid)
    assert exe.execution_id in report and "rea.list_strings on sample" in report


def test_08_handles_missing_tools_gracefully(tmp_path: Path) -> None:
    app = build_app(announced=[], present=[])
    pid = app.projects.init_project("t", "general", "synthetic").project_id
    path = str(write(tmp_path, "s.elf", elf_bytes()))
    app.projects.authorize_artifact(pid, path)
    plan = app.research.plan(pid, path)
    assert plan.steps == () and "rea.binary_overview" in plan.missing
    with pytest.raises(ToolNotCallable):
        app.registry.current().require_usable("rea.binary_overview")


def test_09_enforces_authorization_boundaries(tmp_path: Path) -> None:
    app = build_app()
    pid = app.projects.init_project("t", "general", "synthetic").project_id
    art = app.projects.authorize_artifact(pid, str(write(tmp_path, "s.elf", elf_bytes())))
    denied = [
        app.execution.execute(pid, ExecutionRequest("rea.list_strings", "0" * 64)),
        app.execution.execute(pid, ExecutionRequest("rea.start_frida_session", art.sha256)),
        app.execution.execute(pid, ExecutionRequest("rea.execute_rizin_command", art.sha256,
                                                    {"command": "!sh"})),
    ]
    assert all(r.status is ExecutionStatus.REJECTED for r in denied)
    assert app.transport.calls == []
    assert app.auditor.audit(pid).passed


def test_10_no_unsupported_claims_of_integration() -> None:
    registry = build_registry([f"mcp__rea__{t}" for t in ("open_binary", "list_strings")],
                              SystemEnvironmentProbe().probe(EXTERNAL_TOOLS))
    assert registry.query(status=ToolStatus.VERIFIED) == []
    assert all(t.evidence_ids for t in registry if t.status is ToolStatus.VERIFIED)
