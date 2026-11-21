"""In-memory repositories: ephemeral agent sessions and fast tests."""

from __future__ import annotations

from collections.abc import Sequence
from copy import deepcopy

from ...domain.enums import ClaimKind
from ...domain.models import (
    Artifact,
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


class InMemoryStore:
    """Implements the same repository ports as SqliteStore, with no persistence."""

    def __init__(self) -> None:
        self._projects: dict[str, Project] = {}
        self._scopes: dict[str, Scope] = {}
        self._artifacts: dict[str, Artifact] = {}
        self._executions: dict[str, ExecutionRecord] = {}
        self._claims: dict[str, Claim] = {}
        self._hypotheses: dict[str, Hypothesis] = {}
        self._experiments: dict[str, Experiment] = {}
        self._documents: dict[str, KnowledgeDocument] = {}
        self._episodes: list[Episode] = []
        self._calibration: list[CalibrationPoint] = []

    # EvidenceRepository
    def save_project(self, project: Project) -> None:
        self._projects[project.project_id] = project

    def get_project(self, project_id: str) -> Project | None:
        return self._projects.get(project_id)

    def save_artifact(self, project_id: str, artifact: Artifact) -> None:
        self._artifacts[artifact.artifact_id] = artifact

    def get_artifact(self, artifact_id: str) -> Artifact | None:
        return self._artifacts.get(artifact_id)

    def save_execution(self, record: ExecutionRecord) -> None:
        self._executions[record.execution_id] = record

    def get_execution(self, execution_id: str) -> ExecutionRecord | None:
        return self._executions.get(execution_id)

    def list_executions(self, project_id: str) -> list[ExecutionRecord]:
        return [e for e in self._executions.values() if e.project_id == project_id]

    def save_claim(self, claim: Claim) -> None:
        self._claims[claim.claim_id] = claim  # dict keeps first-insertion order on replace

    def list_claims(self, project_id: str, kind: ClaimKind | None = None) -> list[Claim]:
        return [c for c in self._claims.values()
                if c.project_id == project_id and (kind is None or c.kind is kind)]

    def save_hypothesis(self, hypothesis: Hypothesis) -> None:
        self._hypotheses[hypothesis.hypothesis_id] = hypothesis

    def get_hypothesis(self, hypothesis_id: str) -> Hypothesis | None:
        return self._hypotheses.get(hypothesis_id)

    def list_hypotheses(self, project_id: str) -> list[Hypothesis]:
        return [h for h in self._hypotheses.values() if h.project_id == project_id]

    def save_experiment(self, experiment: Experiment) -> None:
        self._experiments[experiment.experiment_id] = experiment

    def get_experiment(self, experiment_id: str) -> Experiment | None:
        return self._experiments.get(experiment_id)

    def list_experiments(self, hypothesis_id: str) -> list[Experiment]:
        return [e for e in self._experiments.values() if e.hypothesis_id == hypothesis_id]

    # ScopeRepository - copies so callers cannot mutate stored state by accident
    def get_scope(self, project_id: str) -> Scope | None:
        scope = self._scopes.get(project_id)
        return deepcopy(scope) if scope else None

    def save_scope(self, scope: Scope) -> None:
        self._scopes[scope.project_id] = deepcopy(scope)

    # KnowledgeRepository
    def save_document(self, doc: KnowledgeDocument) -> None:
        self._documents[doc.doc_id] = doc

    def find_by_source(self, source_ref: str) -> KnowledgeDocument | None:
        return next((d for d in self._documents.values() if d.source_ref == source_ref), None)

    def list_documents(self, project_id: str | None = None, kinds: Sequence[str] | None = None,
                       include_quarantined: bool = False) -> list[KnowledgeDocument]:
        return [d for d in self._documents.values()
                if (project_id is None or d.project_id == project_id)
                and (not kinds or d.kind in kinds)
                and (include_quarantined or d.trusted)]

    # EpisodeRepository
    def add_episode(self, episode: Episode) -> None:
        self._episodes.append(episode)

    def list_episodes(self, tool_id: str | None = None) -> list[Episode]:
        return [e for e in self._episodes if tool_id is None or e.tool_id == tool_id]

    def add_calibration(self, point: CalibrationPoint) -> None:
        self._calibration.append(point)

    def list_calibration(self) -> list[CalibrationPoint]:
        return list(self._calibration)
