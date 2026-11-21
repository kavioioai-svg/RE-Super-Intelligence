from __future__ import annotations

import pytest

from resi.domain.enums import Module, SecurityClass, ToolStatus
from resi.domain.errors import ToolNotCallable
from resi.domain.models import Approval, Scope, ToolDescriptor
from resi.domain.registry import (
    CapabilityRegistry,
    OverlayEntry,
    build_registry,
    normalise_tool_name,
    validate_descriptor,
)
from tests.support import require

TARGET = "b" * 64


@pytest.mark.parametrize(("raw", "expected"), [
    ("mcp__rea__open_binary", "rea.open_binary"),
    ("mcp__remote-devices__rea__binary_overview", "rea.binary_overview"),
    ("mcp__ghidra-mcp__decompile_function", "ghidra-mcp.decompile_function"),
    ("rea.list_strings", "rea.list_strings"),
    ("not a tool", None),
    ("", None),
])
def test_normalises_agent_tool_spellings(raw: str, expected: str | None) -> None:
    assert normalise_tool_name(raw) == expected


class TestBuildRegistry:
    def test_announced_tools_are_discovered_and_absent_are_unverified(self) -> None:
        reg = build_registry(["mcp__rea__list_strings"])
        assert require(reg.get("rea.list_strings")).status is ToolStatus.DISCOVERED
        assert require(reg.get("rea.open_binary")).status is ToolStatus.UNVERIFIED

    def test_unknown_tools_are_kept_and_treated_as_dynamic(self) -> None:
        tool = build_registry(["mcp__ghidra__decompile"]).get("ghidra.decompile")
        assert tool is not None
        assert tool.module is Module.UNCATALOGUED
        assert tool.security_class is SecurityClass.DYNAMIC
        assert tool.status is ToolStatus.DISCOVERED

    def test_overlay_classifies_other_mcp_servers(self) -> None:
        overlay = {"ghidra.decompile": OverlayEntry(Module.BINARY, SecurityClass.READ_ONLY,
                                                    ("elf",), ("decompile",))}
        tool = build_registry(["mcp__ghidra__decompile"], overlay=overlay).get("ghidra.decompile")
        assert tool is not None
        assert (tool.module, tool.security_class) == (Module.BINARY, SecurityClass.READ_ONLY)

    def test_external_tool_status_comes_from_probe(self) -> None:
        reg = build_registry([], {"cli.rizin": ToolStatus.DISCOVERED})
        assert reg.is_usable("cli.rizin")
        assert not reg.is_usable("cli.ghidra")

    def test_every_entry_has_the_specified_fields(self) -> None:
        reg = build_registry(["mcp__rea__list_strings"])
        assert len(reg) > 200
        for tool in reg:
            assert validate_descriptor(tool) == ()
            assert tool.permissions and tool.failure_conditions and tool.environment


class TestVerification:
    def test_verify_requires_evidence(self) -> None:
        reg = build_registry(["mcp__rea__list_strings"])
        with pytest.raises(ValueError, match="evidence"):
            reg.verify("rea.list_strings", "1.0", " ")
        promoted = reg.verify("rea.list_strings", "1.0", "exe-1")
        assert promoted.status is ToolStatus.VERIFIED and promoted.evidence_ids == ("exe-1",)

    def test_cannot_verify_a_missing_tool(self) -> None:
        with pytest.raises(ToolNotCallable):
            build_registry([]).verify("rea.list_strings", "1.0", "exe-1")

    def test_require_usable(self) -> None:
        reg = CapabilityRegistry()
        with pytest.raises(ToolNotCallable, match="not in the registry"):
            reg.require_usable("rea.nothing")


class TestScope:
    def _tool(self, sec: SecurityClass, name: str = "rea.start_frida_session") -> ToolDescriptor:
        tool = require(build_registry([f"mcp__rea__{name.split('.')[1]}"]).get(name))
        assert tool.security_class is sec
        return tool

    def test_read_only_needs_only_authorized_target(self) -> None:
        tool = self._tool(SecurityClass.READ_ONLY, "rea.list_strings")
        scope = Scope("p", "owner")
        assert not scope.check(tool, TARGET).allowed
        scope.authorized_artifacts.add(TARGET)
        assert scope.check(tool, TARGET).allowed

    def test_dynamic_needs_matching_approval(self) -> None:
        tool = self._tool(SecurityClass.DYNAMIC)
        scope = Scope("p", "owner", {TARGET})
        decision = scope.check(tool, TARGET)
        assert not decision.allowed and "per-target approval" in decision.reason
        scope.approvals.append(Approval("a1", "rea.*frida*", TARGET, "analyst", "yes", "t"))
        assert scope.check(tool, TARGET).allowed
        assert not scope.check(tool, "c" * 64).allowed  # approval is target-bound

    def test_single_use_approval_is_consumed(self) -> None:
        tool = self._tool(SecurityClass.DEVICE_MUTATING, "rea.install_adb_package")
        scope = Scope("p", "owner", authorized_targets={"device-1"})
        assert "per-action" in scope.check(tool, "device-1").reason
        scope.approvals.append(Approval("a1", tool.id, "device-1", "analyst", "ok", "t", True))
        decision = scope.check(tool, "device-1")
        assert decision.allowed
        scope.consume(decision)
        assert not scope.check(tool, "device-1").allowed
