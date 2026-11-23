"""Composition root: the only module that knows concrete adapters.

Inbound adapters (CLI, MCP server) ask for a ``Container``; use cases never
import adapters. Swap persistence, transport or embedder here without
touching the domain or application layers.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Self

from .adapters.outbound.contribution_store import (
    FilePendingIdStore,
    InMemoryPendingIdStore,
    SqliteContributionStore,
)
from .adapters.outbound.infrastructure import (
    FilesystemDocumentSource,
    HashingEmbedder,
    InMemoryRegistryRepository,
    JsonlAuditLog,
    JsonRegistryRepository,
    LocalArtifactReader,
    MemoryAuditLog,
    SystemClock,
    SystemEnvironmentProbe,
    UuidIdGenerator,
)
from .adapters.outbound.local_tools import CompositeTransport, LocalToolTransport
from .adapters.outbound.memory_store import InMemoryStore
from .adapters.outbound.sqlite_store import SqliteStore
from .application.contributions import ContributionService, IngestionService, RankingService
from .application.evidence import EvidenceService, HypothesisService
from .application.execution import ToolExecutionService
from .application.knowledge import KnowledgeService
from .application.learning import LearningService
from .application.playbooks import PlaybookService
from .application.ports import AuditLog, Embedder, RegistryRepository, ToolTransport
from .application.projects import ProjectService
from .application.registry_service import RegistryService
from .application.reporting import ReportService
from .application.research import ResearchService
from .application.security_audit import SecurityAuditor
from .application.vision import VisionService
from .domain.catalog import builtin_tool_ids


def default_home() -> Path:
    return Path(os.environ.get("RESI_HOME", Path.home() / ".resi")).expanduser()


@dataclass(frozen=True, slots=True)
class Container:
    projects: ProjectService
    registry: RegistryService
    research: ResearchService
    execution: ToolExecutionService
    evidence: EvidenceService
    hypotheses: HypothesisService
    knowledge: KnowledgeService
    learning: LearningService
    playbooks: PlaybookService
    auditor: SecurityAuditor
    reports: ReportService
    audit_log: AuditLog
    contributions: ContributionService
    _close: Callable[[], None] = field(default=lambda: None, repr=False)

    def close(self) -> None:
        """Release persistence resources (idempotent)."""
        self._close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> None:
        self.close()

    @staticmethod
    def vision() -> VisionService:
        """Built on demand so the core works without the optional numpy extra."""
        from .adapters.outbound.vision_numpy import NumpyPointCloudAnalyzer

        return VisionService(NumpyPointCloudAnalyzer())


def build_container(home: Path | None = None, in_memory: bool = False,
                    transport: ToolTransport | None = None,
                    embedder: Embedder | None = None, use_default_embedder: bool = True) -> Container:
    clock, ids, reader = SystemClock(), UuidIdGenerator(), LocalArtifactReader()
    store: SqliteStore | InMemoryStore
    registry_repo: RegistryRepository
    audit: AuditLog
    pending: FilePendingIdStore | InMemoryPendingIdStore
    if in_memory:
        store, registry_repo, audit = InMemoryStore(), InMemoryRegistryRepository(), MemoryAuditLog()
        pending = InMemoryPendingIdStore()
    else:
        root = home or default_home()
        root.mkdir(parents=True, exist_ok=True)
        store = SqliteStore(root / "resi.db")
        registry_repo = JsonRegistryRepository(root / "registry.json")
        audit = JsonlAuditLog(root / "audit.log")
        pending = FilePendingIdStore(root / "contribution-pending.json")
    if embedder is None and use_default_embedder:
        embedder = HashingEmbedder()

    projects = ProjectService(store, store, reader, clock, ids)
    registry = RegistryService(registry_repo, SystemEnvironmentProbe(), clock)
    knowledge = KnowledgeService(store, store, clock, ids, embedder)
    return Container(
        projects=projects,
        registry=registry,
        research=ResearchService(reader, projects, registry, store),
        execution=ToolExecutionService(projects, registry, store, store, audit, clock, ids,
                                       CompositeTransport(LocalToolTransport(reader), transport)),
        evidence=EvidenceService(store, store, knowledge, clock, ids),
        hypotheses=HypothesisService(store, clock, ids),
        knowledge=knowledge,
        learning=LearningService(store, knowledge),
        playbooks=PlaybookService(FilesystemDocumentSource(), knowledge),
        auditor=SecurityAuditor(projects, registry, store, store),
        reports=ReportService(projects, store),
        audit_log=audit,
        contributions=ContributionService(store, pending, builtin_tool_ids()),
        _close=store.close if isinstance(store, SqliteStore) else (lambda: None),
    )


@dataclass(frozen=True, slots=True)
class IngestionContainer:
    """Private ingestion side: a contributions database, separate from any user store."""

    store: SqliteContributionStore
    ingestion: IngestionService
    ranking: RankingService


def build_ingestion(db_path: Path, max_bytes: int | None = None) -> IngestionContainer:
    store = SqliteContributionStore(db_path)
    ingestion = (IngestionService(store, SystemClock(), builtin_tool_ids()) if max_bytes is None
                 else IngestionService(store, SystemClock(), builtin_tool_ids(), max_bytes))
    return IngestionContainer(store, ingestion, RankingService(store))
