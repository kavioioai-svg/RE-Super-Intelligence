"""Research planning: route an artifact to tools that are installed and allowed,
then let learned tool statistics refine the order."""

from __future__ import annotations

import random
from dataclasses import replace

from .enums import Module
from .learning import ToolStats, score_tool, stats_for
from .models import Artifact, PlanStep, ResearchPlan, Scope
from .profiles import get_profile
from .registry import CapabilityRegistry

Route = tuple[tuple[str, str], ...]

_FIRMWARE: Route = (
    ("rea.inspect_artifact", "Identify container and components"),
    ("rea.inspect_firmware_regions", "Region map and entropy"),
    ("rea.extract_firmware", "Extract into the isolated artifact store"),
)
_VISION: Route = (
    ("py.numpy", "Load and summarise the point cloud / mesh"),
    ("py.open3d", "Normals, registration, surface reconstruction"),
    ("py.trimesh", "Mesh validity, watertightness, measurements"),
)
_PE: Route = (
    ("rea.binary_overview", "Architecture, sections, imports"),
    ("rea.inspect_signature", "Code signing status"),
    ("rea.inspect_pe_resources", "Embedded resources"),
    ("rea.list_strings", "Strings"),
    ("rea.list_procedures", "Function inventory"),
)
_MACHO: Route = (
    ("rea.inspect_macho", "Load commands, linked libraries, entitlements"),
    ("rea.inspect_signature", "Code signing status"),
    ("rea.get_objc_classes", "Objective-C class inventory"),
    ("rea.analyze_swift_types", "Swift type metadata"),
    ("rea.list_procedures", "Function inventory"),
)
_ANDROID: Route = (
    ("rea.inspect_android_package", "Manifest, permissions, components"),
    ("rea.decode_android_resources", "Resources and configuration"),
    ("rea.project_android_application_graph", "Application architecture graph"),
    ("rea.search_android_classes", "Locate classes for the research question"),
    ("rea.identify_flutter_build", "Framework detection"),
)
_PCAP: Route = (
    ("rea.inspect_pcap_capture", "Conversations, protocols, timing"),
    ("rea.inspect_packet_fields", "Field-level dissection"),
)

ROUTES: dict[str, Route] = {
    "elf": (
        ("rea.binary_overview", "Architecture, sections, entry point, analysis backend"),
        ("rea.list_strings", "Strings for feature and protocol hints"),
        ("rea.list_procedures", "Function inventory"),
        ("rea.get_call_graph", "Call structure from the entry point"),
        ("rea.procedure_pseudo_code", "Decompile functions selected from the above"),
    ),
    "pe": _PE,
    "dos-mz": _PE,
    "macho": _MACHO,
    "macho-fat": _MACHO,
    "wasm": (
        ("rea.inspect_wasm_artifact", "Imports, exports, memory"),
        ("rea.list_procedures", "Function inventory"),
    ),
    "apk": _ANDROID,
    "aab": _ANDROID,
    "ipa": (
        ("rea.inspect_plist", "Info.plist and entitlements"),
        ("rea.project_apple_application_graph", "Application architecture graph"),
        ("rea.inspect_macho", "Main executable structure"),
    ),
    "jar": (("rea.inspect_managed_artifact", "Class and member inventory"),),
    "java-class": (("rea.inspect_managed_artifact", "Class and member inventory"),),
    "pcap": _PCAP,
    "pcapng": _PCAP,
    "javascript": (
        ("rea.analyze_web_bundle", "Bundle structure, chunks, modules"),
        ("rea.recover_javascript_sources", "Source maps and module recovery"),
        ("rea.trace_web_module_imports", "Dependency graph"),
    ),
    "sqlite": (("rea.inspect_sqlite_database", "Schema and table inventory"),),
    **{k: _FIRMWARE for k in ("uimage", "squashfs", "gzip", "high-entropy-blob", "zip-corrupt")},
    **{k: _VISION for k in ("ply", "pcd", "stl-ascii", "stl-binary", "off-mesh")},
}
UNKNOWN_ROUTE: Route = (("rea.inspect_artifact", "Identify, then re-classify"),)

FALLBACKS: dict[str, tuple[str, ...]] = {
    "rea.binary_overview": ("cli.rizin", "cli.ghidra"),
    "rea.list_strings": ("cli.rizin",),
    "rea.list_procedures": ("cli.rizin", "cli.ghidra"),
    "rea.procedure_pseudo_code": ("cli.ghidra", "cli.rizin"),
    "rea.inspect_pcap_capture": ("cli.tshark",),
    "rea.inspect_packet_fields": ("cli.tshark",),
    "rea.inspect_android_package": ("cli.apktool", "cli.jadx"),
    "rea.inspect_firmware_regions": ("cli.binwalk",),
    "rea.extract_firmware": ("cli.unblob", "cli.binwalk"),
    "py.open3d": ("py.trimesh", "py.numpy"),
}


CORROBORATION: dict[str, tuple[str, str]] = {
    kind: ("cli.rizin", ("Independent second engine (RESI-run): corroborate format, imports, "
                         "functions - use resi_run_local"))
    for kind in ("elf", "pe", "dos-mz", "macho", "macho-fat", "wasm")
}


def route_for(artifact: Artifact) -> Route:
    if artifact.kind in ROUTES:
        return ROUTES[artifact.kind]
    return _VISION if artifact.module is Module.VISION else UNKNOWN_ROUTE


def _choose(tool_id: str, registry: CapabilityRegistry,
            stats: dict[tuple[str, str], ToolStats], kind: str) -> tuple[str | None, str | None, str]:
    """Pick the tool or its first usable, non-demoted fallback."""
    candidates = (tool_id, *FALLBACKS.get(tool_id, ()))
    for candidate in candidates:
        if not registry.is_usable(candidate):
            continue
        if stats_for(stats, candidate, kind).demoted and candidate != candidates[-1]:
            continue  # learned to avoid; try the next option
        substituted = None if candidate == tool_id else tool_id
        note = "" if substituted is None else f"substituted for {tool_id}"
        if stats_for(stats, tool_id, kind).demoted and substituted:
            note += " (primary demoted by learned failure rate)"
        return candidate, substituted, note
    return None, None, ""


def plan_research(
    artifact: Artifact,
    registry: CapabilityRegistry,
    scope: Scope,
    profile: str = "general",
    stats: dict[tuple[str, str], ToolStats] | None = None,
    explore: bool = False,
    seed: int = 0,
) -> ResearchPlan:
    """Build an ordered, authorized plan. Learning only reorders steps after the
    first (the anchor that opens the artifact) and never adds forbidden tools."""
    prof = get_profile(profile)
    rules = prof.rules
    if not scope.in_scope(artifact.sha256):
        return ResearchPlan(
            artifact.artifact_id, artifact.kind, artifact.module, profile,
            missing=("AUTHORIZATION: artifact not in scope - record the owner's statement first",),
            rules=rules, authorized=False, target=artifact.sha256,
        )
    stats = stats or {}
    rng = random.Random(seed)
    steps: list[PlanStep] = []
    missing: list[str] = []
    for tool_id, purpose in route_for(artifact):
        chosen, substituted, note = _choose(tool_id, registry, stats, artifact.kind)
        if chosen is None:
            missing.append(tool_id)
            continue
        tool = registry.require_usable(chosen)
        tool_stats = stats_for(stats, chosen, artifact.kind)
        learned = score_tool(tool_stats, explore=explore, rng=rng) if tool_stats.trials else None
        rationale = "; ".join(x for x in (note, tool_stats.explain() if tool_stats.trials else "") if x)
        decision = scope.check(tool, artifact.sha256)  # same gate the execution path applies
        steps.append(PlanStep(len(steps) + 1, chosen, purpose, tool.security_class, tool.status,
                              substituted, learned, rationale, decision.allowed, decision.reason))

    recommended: list[str] = []
    second = CORROBORATION.get(artifact.kind)
    if second and second[0] not in {s.tool_id for s in steps}:
        if registry.is_usable(second[0]):
            tool = registry.require_usable(second[0])
            decision = scope.check(tool, artifact.sha256)
            steps.append(PlanStep(len(steps) + 1, tool.id, second[1], tool.security_class,
                                  tool.status, None, None, "cross-tool corroboration",
                                  decision.allowed, decision.reason))
        else:
            recommended.append(second[0])

    if stats and len(steps) > 2:
        anchor, rest = steps[0], steps[1:]
        rest.sort(key=lambda s: -(s.learned_score if s.learned_score is not None else 0.5))
        steps = [anchor, *rest]
    steps = [replace(s, order=i) for i, s in enumerate(steps, start=1)]
    needs_approval = tuple(s.tool_id for s in steps if not s.allowed)
    return ResearchPlan(artifact.artifact_id, artifact.kind, artifact.module, profile,
                        tuple(steps), tuple(missing), needs_approval, rules, target=artifact.sha256,
                        recommended=tuple(recommended))
