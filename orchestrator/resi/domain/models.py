"""Entities and value objects of the research domain."""

from __future__ import annotations

import fnmatch
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .enums import (
    ClaimKind,
    Confidence,
    ExecutionStatus,
    HypothesisStatus,
    Module,
    SecurityClass,
    ToolStatus,
    Verification,
)

# --- artifacts -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ArtifactSample:
    """What an ArtifactReader returns: enough bytes to classify, never the whole file."""

    path: str
    size: int
    sha256: str
    head: bytes
    archive_members: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class Artifact:
    path: str
    sha256: str
    size: int
    kind: str
    module: Module
    evidence: str
    details: Mapping[str, Any] = field(default_factory=dict, compare=False)

    @property
    def artifact_id(self) -> str:
        return f"art-{self.sha256[:12]}"


# --- capabilities ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ToolDescriptor:
    """One registry entry, carrying every field the specification requires."""

    id: str
    server: str
    module: Module
    group: str
    version: str
    input_types: tuple[str, ...]
    operations: tuple[str, ...]
    permissions: tuple[str, ...]
    environment: str
    timeout_s: int
    output_schema: str
    failure_conditions: tuple[str, ...]
    security_class: SecurityClass
    status: ToolStatus
    evidence_ids: tuple[str, ...] = ()

    @property
    def name(self) -> str:
        return self.id.split(".", 1)[1] if "." in self.id else self.id

    def accepts(self, kind: str) -> bool:
        return kind in self.input_types or "any" in self.input_types


# --- authorization ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Approval:
    """A human's explicit permission for dynamic or device-mutating work."""

    approval_id: str
    tool_pattern: str  # exact tool id or glob, e.g. "rea.*frida*"
    target: str
    approved_by: str
    statement: str  # the user's words, verbatim
    granted_at: str
    single_use: bool = False

    def covers(self, tool_id: str, target: str) -> bool:
        return self.target == target and fnmatch.fnmatchcase(tool_id, self.tool_pattern)


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    reason: str
    approval_id: str | None = None


@dataclass(slots=True)
class Scope:
    """Aggregate: everything a human has authorized for one project.

    The default is read-only static research on explicitly listed artifacts.
    """

    project_id: str
    owner_statement: str
    authorized_artifacts: set[str] = field(default_factory=set)
    authorized_targets: set[str] = field(default_factory=set)
    approvals: list[Approval] = field(default_factory=list)
    consumed_approvals: set[str] = field(default_factory=set)

    def in_scope(self, target: str) -> bool:
        return target in self.authorized_artifacts or target in self.authorized_targets

    def check(self, tool: ToolDescriptor, target: str) -> Decision:
        if not self.in_scope(target):
            return Decision(False, f"target {target!r} is not in the authorized scope")
        if not tool.security_class.requires_approval:
            return Decision(True, f"class {tool.security_class.value} on an authorized target")
        for approval in self.approvals:
            if approval.approval_id in self.consumed_approvals:
                continue
            if approval.covers(tool.id, target):
                return Decision(True, f"approved by {approval.approved_by}", approval.approval_id)
        kind = "per-action" if tool.security_class is SecurityClass.DEVICE_MUTATING else "per-target"
        return Decision(False, f"class {tool.security_class.value} needs explicit {kind} approval")

    def consume(self, decision: Decision) -> None:
        if decision.approval_id is None:
            return
        approval = next(a for a in self.approvals if a.approval_id == decision.approval_id)
        if approval.single_use:
            self.consumed_approvals.add(approval.approval_id)

    def approval_exists_for(self, tool_id: str, target: str) -> bool:
        return any(a.covers(tool_id, target) for a in self.approvals)


@dataclass(frozen=True, slots=True)
class Project:
    project_id: str
    name: str
    profile: str
    owner_statement: str
    created_at: str


# --- execution -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    tool_id: str
    target: str
    args: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ExecutionRecord:
    execution_id: str
    project_id: str
    artifact_id: str | None
    tool_id: str
    tool_version: str
    target: str
    args_hash: str
    started_at: str
    finished_at: str
    status: ExecutionStatus
    output: Any
    output_digest: str
    truncated: bool
    attempts: int
    latency_ms: float
    error: str = ""
    flags: tuple[str, ...] = ()

    @property
    def succeeded(self) -> bool:
        return self.status is ExecutionStatus.OK


# --- evidence --------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Claim:
    """One traceable research claim (the spec's evidence record)."""

    claim_id: str
    project_id: str
    artifact_id: str
    source_hash: str
    tool_id: str
    tool_version: str
    execution_id: str | None
    kind: ClaimKind
    observation: str
    interpretation: str
    confidence: Confidence
    verification: Verification = Verification.UNVERIFIED
    reproduction: str = ""
    limitations: str = ""
    subject: str = ""  # normalised key for cross-tool corroboration, e.g. "fn@0x4012a0:aes128"
    created_at: str = ""


@dataclass(frozen=True, slots=True)
class Hypothesis:
    hypothesis_id: str
    project_id: str
    statement: str
    prediction: str
    falsified_if: str
    status: HypothesisStatus
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class Experiment:
    experiment_id: str
    hypothesis_id: str
    plan: str
    security_class: SecurityClass
    priority: float
    created_at: str
    execution_id: str | None = None
    outcome: str | None = None
    supports: bool | None = None


# --- planning --------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PlanStep:
    order: int
    tool_id: str
    purpose: str
    security_class: SecurityClass
    status: ToolStatus
    substituted_for: str | None = None
    learned_score: float | None = None
    rationale: str = ""
    allowed: bool = True  # the guardrail's verdict for this step, right now
    gate: str = ""  # why: the same reason Scope.check gives at execution time


@dataclass(frozen=True, slots=True)
class ResearchPlan:
    artifact_id: str
    kind: str
    module: Module
    profile: str
    steps: tuple[PlanStep, ...] = ()
    missing: tuple[str, ...] = ()
    needs_approval: tuple[str, ...] = ()
    rules: tuple[str, ...] = ()
    authorized: bool = True
    target: str = ""  # pass exactly this as `target` when executing or recording steps
    recommended: tuple[str, ...] = ()  # optional tools that would strengthen this plan


# --- memory ----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class KnowledgeDocument:
    doc_id: str
    kind: str  # finding | lesson | note | playbook
    title: str
    text: str
    created_at: str
    project_id: str | None = None
    tags: tuple[str, ...] = ()
    source_ref: str = ""
    trusted: bool = True  # False = quarantined (guardrail flagged it)
    flags: tuple[str, ...] = ()
    vector: tuple[float, ...] | None = field(default=None, compare=False)
    # Last time the content changed. created_at is kept across upserts, so "new"
    # (created_at) and "new or changed" (updated_at) can be told apart.
    updated_at: str = ""


@dataclass(frozen=True, slots=True)
class Episode:
    """One learning observation: how a tool behaved on an artifact kind."""

    episode_id: str
    tool_id: str
    context: str  # artifact kind, or "any"
    success: bool
    latency_ms: float
    recorded_at: str
    failure_reason: str = ""
    validated_claims: int = 0
    downgraded_claims: int = 0
    kind: str = "execution"  # "execution" | "claim_feedback"
    tool_version: str = ""  # registry version at the time; "" for episodes recorded earlier

    @property
    def counts_as_trial(self) -> bool:
        """Guardrail rejections reflect scope, not tool reliability."""
        return self.kind == "execution" and not self.failure_reason.startswith("rejected")


@dataclass(frozen=True, slots=True)
class CalibrationPoint:
    claim_id: str
    confidence: Confidence
    correct: bool
    recorded_at: str


@dataclass(frozen=True, slots=True)
class StoredContribution:
    """An accepted learning contribution: validated aggregate counters only."""

    contribution_id: str
    digest: str  # identity of the counters; tells a retry from a conflicting reuse
    schema_version: int
    accepted_on: str  # UTC date only
    payload: dict[str, Any]
