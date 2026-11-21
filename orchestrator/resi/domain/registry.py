"""Capability registry aggregate and its construction from discovery results."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, replace

from .catalog import DEFAULT_TIMEOUTS, EXTERNAL_TOOLS, REA_CATALOGUE
from .enums import Module, SecurityClass, ToolStatus
from .errors import NotFound, ToolNotCallable
from .models import ToolDescriptor

_MCP_NAME = re.compile(r"^mcp__(?:remote-devices__)?(?P<server>[A-Za-z0-9-]+)__(?P<tool>[A-Za-z0-9_.-]+)$")
_DOTTED = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+$")

_PERMISSIONS: dict[SecurityClass, tuple[str, ...]] = {
    SecurityClass.READ_ONLY: ("read_artifact",),
    SecurityClass.LOCAL_WRITE: ("read_artifact", "write_analysis_db"),
    SecurityClass.DYNAMIC: ("read_artifact", "execute_or_attach", "explicit_approval"),
    SecurityClass.DEVICE_MUTATING: ("modify_device", "explicit_per_action_approval"),
}


def normalise_tool_name(raw: str) -> str | None:
    """Map an announced MCP tool name to ``server.tool``.

    Accepts the common agent spellings ``mcp__<server>__<tool>`` and
    ``mcp__remote-devices__<server>__<tool>``, plus already-dotted ids.
    Returns None for anything unrecognisable.
    """
    raw = raw.strip()
    match = _MCP_NAME.match(raw)
    if match:
        return f"{match.group('server')}.{match.group('tool')}"
    return raw if _DOTTED.match(raw) else None


@dataclass(frozen=True, slots=True)
class OverlayEntry:
    """User-supplied classification for a tool RESI does not catalogue."""

    module: Module
    security_class: SecurityClass
    input_types: tuple[str, ...] = ("any",)
    operations: tuple[str, ...] = ("external",)


class CapabilityRegistry:
    """Aggregate root over tool descriptors."""

    def __init__(self, tools: Iterable[ToolDescriptor] = ()):
        self._tools: dict[str, ToolDescriptor] = {t.id: t for t in tools}

    def __len__(self) -> int:
        return len(self._tools)

    def __iter__(self) -> Iterator[ToolDescriptor]:
        return iter(sorted(self._tools.values(), key=lambda t: t.id))

    def get(self, tool_id: str) -> ToolDescriptor | None:
        return self._tools.get(normalise_tool_name(tool_id) or tool_id)

    def require_usable(self, tool_id: str) -> ToolDescriptor:
        tool = self.get(tool_id)
        if tool is None:
            raise ToolNotCallable(f"{tool_id}: not in the registry")
        if not tool.status.usable:
            raise ToolNotCallable(f"{tool_id}: status {tool.status.value} - not callable")
        return tool

    def is_usable(self, tool_id: str) -> bool:
        tool = self.get(tool_id)
        return tool is not None and tool.status.usable

    def query(
        self,
        module: Module | None = None,
        status: ToolStatus | None = None,
        security_class: SecurityClass | None = None,
        input_type: str | None = None,
        usable_only: bool = False,
    ) -> list[ToolDescriptor]:
        return [
            t
            for t in self
            if (module is None or t.module is module)
            and (status is None or t.status is status)
            and (security_class is None or t.security_class is security_class)
            and (input_type is None or t.accepts(input_type))
            and (not usable_only or t.status.usable)
        ]

    def verify(self, tool_id: str, version: str, evidence_id: str) -> ToolDescriptor:
        """Promote a tool to ``verified``. Requires evidence: never by assertion."""
        if not evidence_id.strip():
            raise ValueError("verification requires an evidence id")
        tool = self.get(tool_id)
        if tool is None:
            raise NotFound(tool_id)
        if not tool.status.usable:
            raise ToolNotCallable(f"{tool_id} is {tool.status.value}; it cannot be verified")
        promoted = replace(
            tool,
            status=ToolStatus.VERIFIED,
            version=version,
            evidence_ids=(*tool.evidence_ids, evidence_id),
        )
        self._tools[promoted.id] = promoted
        return promoted

    def summary(self) -> dict[str, dict[str, int]]:
        counts: dict[str, dict[str, int]] = {}
        for tool in self:
            bucket = counts.setdefault(tool.module.value, {s.value: 0 for s in ToolStatus})
            bucket[tool.status.value] += 1
        return counts


def _descriptor(
    tool_id: str,
    module: Module,
    group: str,
    sec: SecurityClass,
    inputs: tuple[str, ...],
    ops: tuple[str, ...],
    status: ToolStatus,
    version: str,
    environment: str,
) -> ToolDescriptor:
    name = tool_id.split(".", 1)[1]
    return ToolDescriptor(
        id=tool_id,
        server=tool_id.split(".", 1)[0],
        module=module,
        group=group,
        version=version,
        input_types=inputs,
        operations=ops,
        permissions=_PERMISSIONS[sec],
        environment=environment,
        timeout_s=DEFAULT_TIMEOUTS.get(name, 120 if environment == "mcp" else 300),
        output_schema="recorded from first execution",
        failure_conditions=("timeout", "transport_error", "unexpected_output"),
        security_class=sec,
        status=status,
    )


def build_registry(
    announced: Iterable[str],
    external_status: Mapping[str, ToolStatus] | None = None,
    overlay: Mapping[str, OverlayEntry] | None = None,
    discovered_on: str = "unknown",
) -> CapabilityRegistry:
    """Assemble the registry from what is actually present.

    * Catalogued tools that were announced become ``discovered``; absent ones
      become ``unverified``.
    * Announced tools RESI does not know are kept (never silently dropped). With
      an overlay entry they get its classification; without one they are
      ``uncatalogued`` and treated as class D - the conservative default.
    """
    names = {n for n in (normalise_tool_name(a) for a in announced) if n}
    overlay = overlay or {}
    external_status = external_status or {}
    found = f"discovered-{discovered_on}"
    tools: list[ToolDescriptor] = []
    catalogued: set[str] = set()

    for group in REA_CATALOGUE:
        for name in group.tools:
            tool_id = f"rea.{name}"
            catalogued.add(tool_id)
            present = tool_id in names
            tools.append(
                _descriptor(tool_id, group.module, group.group, group.security_class,
                            group.input_types, group.operations,
                            ToolStatus.DISCOVERED if present else ToolStatus.UNVERIFIED,
                            found if present else "n/a", "mcp")
            )

    for tool_id in sorted(names - catalogued):
        entry = overlay.get(tool_id)
        if entry:
            tools.append(_descriptor(tool_id, entry.module, "overlay", entry.security_class,
                                     entry.input_types, entry.operations,
                                     ToolStatus.DISCOVERED, found, "mcp"))
        else:
            tools.append(_descriptor(tool_id, Module.UNCATALOGUED, "uncatalogued",
                                     SecurityClass.DYNAMIC, ("any",), ("unknown",),
                                     ToolStatus.DISCOVERED, found, "mcp"))

    for ext in EXTERNAL_TOOLS:
        status = external_status.get(ext.id, ToolStatus.UNVERIFIED)
        environment = "cli" if ext.id.startswith("cli.") else "python"
        tools.append(_descriptor(ext.id, ext.module, "external", ext.security_class, ("any",),
                                 ("external",), status,
                                 found if status.usable else "n/a", environment))
    return CapabilityRegistry(tools)


def validate_descriptor(tool: ToolDescriptor) -> tuple[str, ...]:
    """Structural checks a registry entry must pass before it is trusted."""
    problems: list[str] = []
    if tool.status is ToolStatus.VERIFIED and not tool.evidence_ids:
        problems.append(f"{tool.id}: verified without evidence")
    if not tool.input_types or not tool.operations:
        problems.append(f"{tool.id}: missing input types or operations")
    if tool.timeout_s <= 0:
        problems.append(f"{tool.id}: non-positive timeout")
    return tuple(problems)
