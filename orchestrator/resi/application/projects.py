"""Project lifecycle and authorization scope.

Scope changes (authorizing artifacts/targets, granting approvals) are
human-only operations. Inbound adapters that serve autonomous agents (the MCP
server) deliberately do not expose them, so an agent cannot grant itself
permission.
"""

from __future__ import annotations

from ..domain.classification import classify
from ..domain.errors import NotFound
from ..domain.models import Approval, Artifact, Project, Scope
from ..domain.profiles import get_profile
from .ports import ArtifactReader, Clock, EvidenceRepository, IdGenerator, ScopeRepository


class ProjectService:
    def __init__(self, evidence: EvidenceRepository, scopes: ScopeRepository,
                 reader: ArtifactReader, clock: Clock, ids: IdGenerator):
        self._evidence = evidence
        self._scopes = scopes
        self._reader = reader
        self._clock = clock
        self._ids = ids

    def init_project(self, name: str, profile: str, owner_statement: str) -> Project:
        if not owner_statement.strip():
            raise ValueError("record who owns the target and what research is authorized")
        get_profile(profile)  # fail fast on unknown profiles
        project = Project(self._ids.new("prj"), name, profile, owner_statement, self._clock.now())
        self._evidence.save_project(project)
        self._scopes.save_scope(Scope(project.project_id, owner_statement))
        return project

    def project(self, project_id: str) -> Project:
        project = self._evidence.get_project(project_id)
        if project is None:
            raise NotFound(f"project {project_id}")
        return project

    def scope(self, project_id: str) -> Scope:
        scope = self._scopes.get_scope(project_id)
        if scope is None:
            raise NotFound(f"scope for project {project_id}")
        return scope

    def record_scope_usage(self, scope: Scope) -> None:
        """Persist approval consumption after an execution (no new grants)."""
        stored = self.scope(scope.project_id)
        stored.consumed_approvals |= scope.consumed_approvals
        self._scopes.save_scope(stored)

    def authorize_artifact(self, project_id: str, path: str) -> Artifact:
        self.project(project_id)
        artifact = classify(self._reader.read(path))
        scope = self.scope(project_id)
        scope.authorized_artifacts.add(artifact.sha256)
        self._scopes.save_scope(scope)
        self._evidence.save_artifact(project_id, artifact)
        return artifact

    def authorize_target(self, project_id: str, target: str) -> None:
        """Authorize a non-file target: a URL, package id, process name or device serial."""
        if not target.strip():
            raise ValueError("target must be non-empty")
        scope = self.scope(project_id)
        scope.authorized_targets.add(target)
        self._scopes.save_scope(scope)

    def approve(self, project_id: str, tool_pattern: str, target: str, approved_by: str,
                statement: str, single_use: bool = False) -> Approval:
        if not statement.strip():
            raise ValueError("an approval must record the approver's words verbatim")
        scope = self.scope(project_id)
        if not scope.in_scope(target):
            raise ValueError(f"authorize {target!r} before approving dynamic work on it")
        approval = Approval(self._ids.new("apr"), tool_pattern, target, approved_by, statement,
                            self._clock.now(), single_use)
        scope.approvals.append(approval)
        self._scopes.save_scope(scope)
        return approval
