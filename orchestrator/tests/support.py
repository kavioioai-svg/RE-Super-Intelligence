"""Deterministic test doubles and builders shared across the suite."""

from __future__ import annotations

import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar

from resi.adapters.outbound.infrastructure import (
    InMemoryRegistryRepository,
    LocalArtifactReader,
    MemoryAuditLog,
)
from resi.adapters.outbound.memory_store import InMemoryStore
from resi.application.evidence import EvidenceService, HypothesisService
from resi.application.execution import ToolExecutionService
from resi.application.knowledge import KnowledgeService
from resi.application.learning import LearningService
from resi.application.projects import ProjectService
from resi.application.registry_service import RegistryService
from resi.application.reporting import ReportService
from resi.application.research import ResearchService
from resi.application.security_audit import SecurityAuditor
from resi.domain.catalog import ExternalTool
from resi.domain.enums import ToolStatus

T = TypeVar("T")


def require(value: T | None) -> T:
    """Narrow an Optional in tests, failing loudly when it is None."""
    assert value is not None
    return value


class FakeClock:
    def __init__(self) -> None:
        self.tick = 0

    def now(self) -> str:
        self.tick += 1
        return f"2026-01-01T00:00:{self.tick:02d}.000+00:00"

    def monotonic_ms(self) -> float:
        self.tick += 1
        return float(self.tick * 10)


class SequentialIds:
    def __init__(self) -> None:
        self.counter = 0

    def new(self, prefix: str) -> str:
        self.counter += 1
        return f"{prefix}-{self.counter:04d}"


class StaticProbe:
    def __init__(self, present: Sequence[str] = ()) -> None:
        self.present = set(present)

    def probe(self, tools: Sequence[ExternalTool]) -> dict[str, ToolStatus]:
        return {t.id: ToolStatus.DISCOVERED if t.id in self.present else ToolStatus.UNVERIFIED
                for t in tools}


@dataclass
class ScriptedTransport:
    """Returns scripted results per tool; raises when the script holds an exception."""

    script: dict[str, list[Any]] = field(default_factory=dict)
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def invoke(self, tool_id: str, args: Mapping[str, Any], timeout_s: int) -> Any:
        self.calls.append((tool_id, dict(args)))
        queue = self.script.get(tool_id, [{"ok": True}])
        result = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(result, BaseException):
            raise result
        return result


@dataclass
class App:
    store: InMemoryStore
    audit: MemoryAuditLog
    transport: ScriptedTransport
    projects: ProjectService
    registry: RegistryService
    research: ResearchService
    execution: ToolExecutionService
    evidence: EvidenceService
    hypotheses: HypothesisService
    knowledge: KnowledgeService
    learning: LearningService
    auditor: SecurityAuditor
    reports: ReportService


ANNOUNCED = tuple(
    f"mcp__rea__{t}"
    for t in ("binary_overview", "list_strings", "list_procedures", "get_call_graph",
              "procedure_pseudo_code", "execute_rizin_command", "start_frida_session",
              "install_adb_package", "inspect_pcap_capture", "batch_decompile")
)


def build_app(announced: Sequence[str] = ANNOUNCED, present: Sequence[str] = ("cli.rizin",),
              embedder: Any = None) -> App:
    store, audit, clock, ids = InMemoryStore(), MemoryAuditLog(), FakeClock(), SequentialIds()
    transport = ScriptedTransport()
    reader = LocalArtifactReader()
    projects = ProjectService(store, store, reader, clock, ids)
    registry = RegistryService(InMemoryRegistryRepository(), StaticProbe(present), clock)
    registry.refresh(announced)
    knowledge = KnowledgeService(store, store, clock, ids, embedder)
    return App(
        store, audit, transport, projects, registry,
        ResearchService(reader, projects, registry, store),
        ToolExecutionService(projects, registry, store, store, audit, clock, ids, transport),
        EvidenceService(store, store, knowledge, clock, ids),
        HypothesisService(store, clock, ids), knowledge, LearningService(store, knowledge),
        SecurityAuditor(projects, registry, store, store), ReportService(projects, store),
    )


def elf_bytes(machine: int = 0xB7, bits: int = 64) -> bytes:
    if bits == 64:
        header = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8 + struct.pack(
            "<HHIQQQIHHHHHH", 2, machine, 1, 0x400080, 64, 0, 0, 64, 56, 0, 64, 0, 0)
    else:
        header = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8 + struct.pack(
            "<HHIIIIIHHHHHH", 2, machine, 1, 0x8048000, 52, 0, 0, 52, 32, 0, 40, 0, 0)
    return header + b"\x00" * 200


def write(tmp: Path, name: str, data: bytes) -> Path:
    path = tmp / name
    path.write_bytes(data)
    return path
