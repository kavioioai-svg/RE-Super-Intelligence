"""Ports: the contracts the application needs from the outside world.

Use cases depend only on these Protocols. Adapters in ``resi.adapters``
implement them; ``resi.bootstrap`` wires the two together.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from ..domain.catalog import ExternalTool
from ..domain.enums import ClaimKind, ToolStatus
from ..domain.models import (
    Artifact,
    ArtifactSample,
    CalibrationPoint,
    Claim,
    Episode,
    ExecutionRecord,
    Experiment,
    Hypothesis,
    KnowledgeDocument,
    Project,
    Scope,
)
from ..domain.registry import CapabilityRegistry

# --- driven ports: infrastructure ------------------------------------------------


class Clock(Protocol):
    def now(self) -> str:
        """Current UTC time as ISO-8601."""

    def monotonic_ms(self) -> float:
        """Monotonic milliseconds, for measuring latency."""


class IdGenerator(Protocol):
    def new(self, prefix: str) -> str: ...


class ArtifactReader(Protocol):
    def read(self, path: str) -> ArtifactSample:
        """Hash the file and return its head (and archive member names for ZIPs)."""

    def read_bytes(self, path: str) -> bytes:
        """Whole-file read, bounded by the adapter's size limit."""


class ToolTransport(Protocol):
    def supports(self, tool_id: str) -> bool:
        """Whether this transport can execute the tool (otherwise the agent must)."""

    def invoke(self, tool_id: str, args: Mapping[str, Any], timeout_s: int) -> Any:
        """Call a tool. Raise TimeoutError on timeout; any other exception is a failure."""


class EnvironmentProbe(Protocol):
    def probe(self, tools: Sequence[ExternalTool]) -> dict[str, ToolStatus]:
        """Report which external CLIs / Python libraries are present."""


@dataclass(frozen=True, slots=True)
class MarkdownDocument:
    path: str
    title: str
    origin: str  # e.g. the skill folder a file belongs to
    text: str


class DocumentSource(Protocol):
    def markdown_documents(self, paths: Sequence[str]) -> list[MarkdownDocument]:
        """Markdown files at, or under, the given paths (bounded in count and size)."""


class Embedder(Protocol):
    def embed(self, text: str) -> tuple[float, ...]: ...


class PointCloudAnalyzer(Protocol):
    def analyse_synthetic(self, seed: int) -> dict[str, Any]: ...


class AuditLog(Protocol):
    def append(self, event: Mapping[str, Any]) -> None: ...

    def read(self, project_id: str | None = None) -> list[dict[str, Any]]: ...


# --- driven ports: persistence ---------------------------------------------------


class RegistryRepository(Protocol):
    def load(self) -> CapabilityRegistry | None: ...

    def save(self, registry: CapabilityRegistry) -> None: ...


class ScopeRepository(Protocol):
    def get_scope(self, project_id: str) -> Scope | None: ...

    def save_scope(self, scope: Scope) -> None: ...


class EvidenceRepository(Protocol):
    def save_project(self, project: Project) -> None: ...

    def get_project(self, project_id: str) -> Project | None: ...

    def save_artifact(self, project_id: str, artifact: Artifact) -> None: ...

    def get_artifact(self, artifact_id: str) -> Artifact | None: ...

    def save_execution(self, record: ExecutionRecord) -> None: ...

    def get_execution(self, execution_id: str) -> ExecutionRecord | None: ...

    def list_executions(self, project_id: str) -> list[ExecutionRecord]: ...

    def save_claim(self, claim: Claim) -> None:
        """Insert or replace by claim_id."""

    def list_claims(self, project_id: str, kind: ClaimKind | None = None) -> list[Claim]: ...

    def save_hypothesis(self, hypothesis: Hypothesis) -> None: ...

    def get_hypothesis(self, hypothesis_id: str) -> Hypothesis | None: ...

    def list_hypotheses(self, project_id: str) -> list[Hypothesis]: ...

    def save_experiment(self, experiment: Experiment) -> None: ...

    def get_experiment(self, experiment_id: str) -> Experiment | None: ...

    def list_experiments(self, hypothesis_id: str) -> list[Experiment]: ...


class KnowledgeRepository(Protocol):
    def save_document(self, doc: KnowledgeDocument) -> None:
        """Insert or replace by doc_id."""

    def find_by_source(self, source_ref: str) -> KnowledgeDocument | None: ...

    def list_documents(
        self,
        project_id: str | None = None,
        kinds: Sequence[str] | None = None,
        include_quarantined: bool = False,
    ) -> list[KnowledgeDocument]: ...


class EpisodeRepository(Protocol):
    def add_episode(self, episode: Episode) -> None: ...

    def list_episodes(self, tool_id: str | None = None) -> list[Episode]: ...

    def add_calibration(self, point: CalibrationPoint) -> None: ...

    def list_calibration(self) -> list[CalibrationPoint]: ...
