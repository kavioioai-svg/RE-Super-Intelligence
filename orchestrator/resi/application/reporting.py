"""Technical Reporter: renders a project's evidence as a Markdown report.

The four evidence categories are always separated, so a hypothesis can never
be read as an established fact.
"""

from __future__ import annotations

from ..domain.enums import ClaimKind, HypothesisStatus, Verification
from ..domain.models import Claim
from .ports import EvidenceRepository
from .projects import ProjectService

_SECTIONS = (
    (ClaimKind.VERIFIED, "Experimentally verified conclusions"),
    (ClaimKind.OBSERVED, "Observed facts"),
    (ClaimKind.TOOL_DERIVED, "Tool-derived interpretations"),
    (ClaimKind.HYPOTHESIS, "Hypotheses (not established)"),
)


def _row(claim: Claim) -> str:
    def cell(text: str) -> str:
        return text.replace("|", "\\|").replace("\n", " ")[:160]

    return (f"| {claim.claim_id} | {cell(claim.observation)} | {cell(claim.interpretation)} | "
            f"{claim.confidence.value} | {claim.verification.value} | {claim.tool_id} | "
            f"{claim.execution_id or '-'} |")


class ReportService:
    def __init__(self, projects: ProjectService, evidence: EvidenceRepository):
        self._projects = projects
        self._evidence = evidence

    def render(self, project_id: str) -> str:
        project = self._projects.project(project_id)
        claims = self._evidence.list_claims(project_id)
        hypotheses = self._evidence.list_hypotheses(project_id)
        executions = self._evidence.list_executions(project_id)
        lines = [
            f"# Research report: {project.name}",
            "",
            f"- Project: `{project.project_id}` (profile `{project.profile}`)",
            f"- Authorization: {project.owner_statement}",
            (f"- Executions: {len(executions)} "
             f"({sum(1 for e in executions if e.succeeded)} succeeded, "
             f"{sum(1 for e in executions if e.status.value == 'rejected')} rejected by guardrails)"),
            f"- Claims: {len(claims)}; hypotheses: {len(hypotheses)}",
            "",
        ]
        header = [
            "| Claim | Observation | Interpretation | Confidence | Verification | Tool | Execution |",
            "|---|---|---|---|---|---|---|",
        ]
        for kind, title in _SECTIONS:
            section = [c for c in claims if c.kind is kind]
            lines += [f"## {title}", ""]
            lines += [*header, *map(_row, section)] if section else ["_None recorded._"]
            lines.append("")
        lines += ["## Hypothesis register", ""]
        if hypotheses:
            lines += ["| Hypothesis | Statement | Falsified if | Status |", "|---|---|---|---|"]
            lines += [f"| {h.hypothesis_id} | {h.statement} | {h.falsified_if} | {h.status.value} |"
                      for h in hypotheses]
        else:
            lines.append("_None recorded._")
        open_items = [h for h in hypotheses if h.status in (HypothesisStatus.OPEN,
                                                            HypothesisStatus.SUPPORTED)]
        downgraded = [c for c in claims if c.verification is Verification.DOWNGRADED]
        lines += ["", "## Unresolved questions", ""]
        lines += [f"- {h.statement} ({h.status.value})" for h in open_items]
        lines += [f"- Downgraded claim {c.claim_id}: {c.limitations}" for c in downgraded]
        if not open_items and not downgraded:
            lines.append("_None._")
        lines += ["", "## Reproduction", ""]
        lines += [f"- {c.claim_id}: {c.reproduction}" for c in claims if c.reproduction] or ["_None._"]
        return "\n".join(lines) + "\n"
