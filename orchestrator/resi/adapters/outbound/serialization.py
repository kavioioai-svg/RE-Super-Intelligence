"""Mapping between domain objects and JSON-safe dictionaries (shared by persistence adapters)."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from ...domain.enums import (
    ClaimKind,
    Confidence,
    ExecutionStatus,
    HypothesisStatus,
    Module,
    SecurityClass,
    ToolStatus,
    Verification,
)
from ...domain.models import (
    Approval,
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
    ToolDescriptor,
)


def to_dict(obj: Any) -> dict[str, Any]:
    """Dataclass -> dict with enums flattened to their values and tuples to lists."""

    def clean(value: Any) -> Any:
        if hasattr(value, "value") and hasattr(type(value), "__members__"):
            return value.value
        if isinstance(value, (tuple, list)):
            return [clean(v) for v in value]
        if isinstance(value, set):
            return sorted(clean(v) for v in value)
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items()}
        return value

    return {k: clean(v) for k, v in asdict(obj).items()}


def tool_from_dict(d: dict[str, Any]) -> ToolDescriptor:
    return ToolDescriptor(
        id=d["id"], server=d["server"], module=Module(d["module"]), group=d["group"],
        version=d["version"], input_types=tuple(d["input_types"]),
        operations=tuple(d["operations"]), permissions=tuple(d["permissions"]),
        environment=d["environment"], timeout_s=int(d["timeout_s"]),
        output_schema=d["output_schema"], failure_conditions=tuple(d["failure_conditions"]),
        security_class=SecurityClass(d["security_class"]), status=ToolStatus(d["status"]),
        evidence_ids=tuple(d.get("evidence_ids", ())),
    )


def artifact_from_dict(d: dict[str, Any]) -> Artifact:
    return Artifact(d["path"], d["sha256"], int(d["size"]), d["kind"], Module(d["module"]),
                    d["evidence"], d.get("details", {}))


def project_from_dict(d: dict[str, Any]) -> Project:
    return Project(d["project_id"], d["name"], d["profile"], d["owner_statement"], d["created_at"])


def scope_to_dict(scope: Scope) -> dict[str, Any]:
    return {
        "project_id": scope.project_id,
        "owner_statement": scope.owner_statement,
        "authorized_artifacts": sorted(scope.authorized_artifacts),
        "authorized_targets": sorted(scope.authorized_targets),
        "approvals": [to_dict(a) for a in scope.approvals],
        "consumed_approvals": sorted(scope.consumed_approvals),
    }


def scope_from_dict(d: dict[str, Any]) -> Scope:
    return Scope(
        project_id=d["project_id"], owner_statement=d["owner_statement"],
        authorized_artifacts=set(d.get("authorized_artifacts", ())),
        authorized_targets=set(d.get("authorized_targets", ())),
        approvals=[Approval(**a) for a in d.get("approvals", ())],
        consumed_approvals=set(d.get("consumed_approvals", ())),
    )


def execution_from_dict(d: dict[str, Any]) -> ExecutionRecord:
    return ExecutionRecord(
        d["execution_id"], d["project_id"], d.get("artifact_id"), d["tool_id"], d["tool_version"],
        d["target"], d["args_hash"], d["started_at"], d["finished_at"],
        ExecutionStatus(d["status"]), d.get("output"), d["output_digest"], bool(d["truncated"]),
        int(d["attempts"]), float(d["latency_ms"]), d.get("error", ""), tuple(d.get("flags", ())),
    )


def claim_from_dict(d: dict[str, Any]) -> Claim:
    return Claim(
        claim_id=d["claim_id"], project_id=d["project_id"], artifact_id=d["artifact_id"],
        source_hash=d["source_hash"], tool_id=d["tool_id"], tool_version=d["tool_version"],
        execution_id=d.get("execution_id"), kind=ClaimKind(d["kind"]),
        observation=d["observation"], interpretation=d["interpretation"],
        confidence=Confidence(d["confidence"]), verification=Verification(d["verification"]),
        reproduction=d.get("reproduction", ""), limitations=d.get("limitations", ""),
        subject=d.get("subject", ""), created_at=d.get("created_at", ""),
    )


def hypothesis_from_dict(d: dict[str, Any]) -> Hypothesis:
    return Hypothesis(d["hypothesis_id"], d["project_id"], d["statement"], d["prediction"],
                      d["falsified_if"], HypothesisStatus(d["status"]), d["created_at"],
                      d["updated_at"])


def experiment_from_dict(d: dict[str, Any]) -> Experiment:
    supports = d.get("supports")
    return Experiment(d["experiment_id"], d["hypothesis_id"], d["plan"],
                      SecurityClass(d["security_class"]), float(d["priority"]), d["created_at"],
                      d.get("execution_id"), d.get("outcome"),
                      None if supports is None else bool(supports))


def document_from_dict(d: dict[str, Any]) -> KnowledgeDocument:
    vector = d.get("vector")
    return KnowledgeDocument(
        doc_id=d["doc_id"], kind=d["kind"], title=d["title"], text=d["text"],
        created_at=d["created_at"], project_id=d.get("project_id"), tags=tuple(d.get("tags", ())),
        source_ref=d.get("source_ref", ""), trusted=bool(d.get("trusted", True)),
        flags=tuple(d.get("flags", ())), vector=tuple(vector) if vector else None,
        updated_at=d.get("updated_at") or d["created_at"],  # older records predate the field
    )


def episode_from_dict(d: dict[str, Any]) -> Episode:
    return Episode(d["episode_id"], d["tool_id"], d["context"], bool(d["success"]),
                   float(d["latency_ms"]), d["recorded_at"], d.get("failure_reason", ""),
                   int(d.get("validated_claims", 0)), int(d.get("downgraded_claims", 0)),
                   d.get("kind", "execution"), d.get("tool_version", ""))


def calibration_from_dict(d: dict[str, Any]) -> CalibrationPoint:
    return CalibrationPoint(d["claim_id"], Confidence(d["confidence"]), bool(d["correct"]),
                            d["recorded_at"])
