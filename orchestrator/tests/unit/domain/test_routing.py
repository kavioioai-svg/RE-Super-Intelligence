from __future__ import annotations

from resi.domain.enums import Module
from resi.domain.enums import ToolStatus as TS
from resi.domain.learning import ToolStats
from resi.domain.models import Artifact, Scope
from resi.domain.registry import build_registry
from resi.domain.routing import plan_research

SHA = "d" * 64
ELF = Artifact("x", SHA, 10, "elf", Module.BINARY, "magic")
ANNOUNCED = [f"mcp__rea__{t}" for t in ("binary_overview", "list_strings", "list_procedures",
                                        "get_call_graph", "procedure_pseudo_code")]


def scope() -> Scope:
    return Scope("p", "owner", {SHA})


def test_refuses_unauthorized_artifact() -> None:
    plan = plan_research(ELF, build_registry(ANNOUNCED), Scope("p", "owner"))
    assert not plan.authorized and plan.steps == ()


def test_routes_elf_to_announced_tools_in_order() -> None:
    plan = plan_research(ELF, build_registry(ANNOUNCED), scope())
    assert [s.tool_id for s in plan.steps] == [
        "rea.binary_overview", "rea.list_strings", "rea.list_procedures", "rea.get_call_graph",
        "rea.procedure_pseudo_code"]
    assert plan.missing == ()


def test_missing_tools_reported_and_fallbacks_used() -> None:
    reg = build_registry(["mcp__rea__binary_overview"], {"cli.rizin": TS.DISCOVERED})
    plan = plan_research(ELF, reg, scope())
    substitutions = {s.substituted_for for s in plan.steps if s.tool_id == "cli.rizin"}
    assert substitutions == {"rea.list_strings", "rea.list_procedures", "rea.procedure_pseudo_code"}
    assert "rea.get_call_graph" in plan.missing  # no fallback exists for call graphs


def test_learning_demotes_a_failing_tool_to_its_fallback() -> None:
    reg = build_registry(ANNOUNCED, {"cli.rizin": TS.DISCOVERED})
    stats = {("rea.list_strings", "elf"): ToolStats("rea.list_strings", "elf", failures=8)}
    plan = plan_research(ELF, reg, scope(), stats=stats)
    tools = [s.tool_id for s in plan.steps]
    assert "rea.list_strings" not in tools and "cli.rizin" in tools
    step = next(s for s in plan.steps if s.tool_id == "cli.rizin")
    assert "demoted" in step.rationale


def test_learning_reorders_but_keeps_the_anchor_first() -> None:
    reg = build_registry(ANNOUNCED)
    stats = {
        ("rea.procedure_pseudo_code", "elf"): ToolStats("rea.procedure_pseudo_code", "elf", 30, 0),
        ("rea.list_strings", "elf"): ToolStats("rea.list_strings", "elf", 2, 3),
    }
    plan = plan_research(ELF, reg, scope(), stats=stats)
    assert plan.steps[0].tool_id == "rea.binary_overview"
    assert plan.steps[1].tool_id == "rea.procedure_pseudo_code"
    assert [s.order for s in plan.steps] == list(range(1, len(plan.steps) + 1))


def test_dynamic_steps_are_flagged_for_approval() -> None:
    reg = build_registry(["mcp__rea__inspect_firmware_regions"], {"cli.qemu": TS.DISCOVERED})
    fw = Artifact("x", SHA, 10, "uimage", Module.FIRMWARE, "magic")
    plan = plan_research(fw, reg, scope(), profile="firmware")
    assert any("emulate in isolation" in r for r in plan.rules)


def test_medical_profile_rules_are_attached() -> None:
    plan = plan_research(ELF, build_registry(ANNOUNCED), scope(), profile="medical-device")
    assert any("clinically validated" in r for r in plan.rules)
