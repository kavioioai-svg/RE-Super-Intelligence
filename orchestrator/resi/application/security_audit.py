"""Security Auditor: an independent check that guardrails actually held.

The auditor re-derives every verdict from stored records rather than trusting
what the execution path decided at the time, so a bypassed or buggy
guardrail shows up as a finding.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..domain.enums import ExecutionStatus
from ..domain.guardrails import (
    detect_cleanroom_leaks,
    detect_pii,
    detect_prompt_injection,
    detect_secrets,
)
from ..domain.profiles import get_profile
from ..domain.registry import validate_descriptor
from .ports import EvidenceRepository, KnowledgeRepository
from .projects import ProjectService
from .registry_service import RegistryService


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


_ORDER = {s: i for i, s in enumerate(Severity)}


@dataclass(frozen=True, slots=True)
class SecurityFinding:
    code: str
    severity: Severity
    message: str
    reference: str


@dataclass(frozen=True, slots=True)
class AuditResult:
    project_id: str
    findings: tuple[SecurityFinding, ...]

    @property
    def passed(self) -> bool:
        return not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings)

    def counts(self) -> dict[str, int]:
        return {s.value: sum(1 for f in self.findings if f.severity is s) for s in Severity}


class SecurityAuditor:
    def __init__(self, projects: ProjectService, registry: RegistryService,
                 evidence: EvidenceRepository, knowledge: KnowledgeRepository):
        self._projects = projects
        self._registry = registry
        self._evidence = evidence
        self._knowledge = knowledge

    def audit(self, project_id: str) -> AuditResult:
        project = self._projects.project(project_id)
        scope = self._projects.scope(project_id)
        registry = self._registry.current()
        medical = get_profile(project.profile).medical
        findings: list[SecurityFinding] = []

        for record in self._evidence.list_executions(project_id):
            if record.status is ExecutionStatus.REJECTED:
                continue  # the guardrail worked; nothing to report
            tool = registry.get(record.tool_id)
            if not scope.in_scope(record.target):
                findings.append(SecurityFinding(
                    "RESI-S002", Severity.CRITICAL,
                    f"{record.tool_id} ran against out-of-scope target {record.target!r}",
                    record.execution_id))
            if tool and tool.security_class.requires_approval and not scope.approval_exists_for(
                    tool.id, record.target):
                findings.append(SecurityFinding(
                    "RESI-S001", Severity.CRITICAL,
                    f"class {tool.security_class.value} tool {tool.id} ran without a recorded "
                    "human approval", record.execution_id))
            if tool is None:
                findings.append(SecurityFinding(
                    "RESI-S009", Severity.MEDIUM,
                    f"{record.tool_id} is no longer in the registry; its results are unattributable",
                    record.execution_id))
            if any(f.startswith("injection:") for f in record.flags):
                findings.append(SecurityFinding(
                    "RESI-S007", Severity.INFO,
                    f"output of {record.tool_id} contained agent-directed instructions; it was "
                    "treated as data", record.execution_id))

        for claim in self._evidence.list_claims(project_id):
            text = f"{claim.observation}\n{claim.interpretation}\n{claim.reproduction}"
            secrets = detect_secrets(text)
            if secrets:
                findings.append(SecurityFinding(
                    "RESI-S003", Severity.HIGH,
                    f"claim stores unredacted secret material ({', '.join(secrets)})",
                    claim.claim_id))
            pii = detect_pii(text)
            if pii:
                findings.append(SecurityFinding(
                    "RESI-S004", Severity.HIGH if medical else Severity.MEDIUM,
                    f"claim contains personal data ({', '.join(pii)})"
                    f"{' under a medical profile' if medical else ''}", claim.claim_id))

        for doc in self._knowledge.list_documents(project_id, include_quarantined=True):
            if doc.project_id != project_id:
                continue
            if doc.trusted and detect_prompt_injection(f"{doc.title}\n{doc.text}"):
                findings.append(SecurityFinding(
                    "RESI-S005", Severity.HIGH,
                    "trusted memory document contains prompt-injection markers (RAG poisoning risk)",
                    doc.doc_id))
            if doc.trusted and detect_secrets(doc.text):
                findings.append(SecurityFinding(
                    "RESI-S003", Severity.HIGH, "memory document stores secret material",
                    doc.doc_id))

        for tool in registry:
            for problem in validate_descriptor(tool):
                findings.append(SecurityFinding("RESI-S006", Severity.MEDIUM, problem, tool.id))

        findings.sort(key=lambda f: (_ORDER[f.severity], f.code, f.reference))
        return AuditResult(project_id, tuple(findings))

    @staticmethod
    def check_cleanroom(text: str, reference: str = "spec") -> tuple[SecurityFinding, ...]:
        """Gate for anything crossing from research into an implementation workspace."""
        return tuple(
            SecurityFinding("RESI-S008", Severity.HIGH,
                            f"clean-room leak: {leak} found in implementation-bound text", reference)
            for leak in detect_cleanroom_leaks(text)
        )
