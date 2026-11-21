"""Evidence capture, the Evidence Validator, and the hypothesis/experiment loop."""

from __future__ import annotations

from dataclasses import dataclass, replace

from ..domain.enums import (
    ClaimKind,
    Confidence,
    HypothesisStatus,
    SecurityClass,
    Verification,
)
from ..domain.errors import InvalidClaim, InvalidHypothesis, NotFound
from ..domain.evidence_rules import (
    corroborated_subjects,
    derive_hypothesis_status,
    experiment_priority,
    validate_claim,
)
from ..domain.models import CalibrationPoint, Claim, Episode, Experiment, Hypothesis
from .knowledge import KnowledgeService
from .ports import Clock, EpisodeRepository, EvidenceRepository, IdGenerator


@dataclass(frozen=True, slots=True)
class ClaimInput:
    project_id: str
    artifact_id: str
    source_hash: str
    tool_id: str
    execution_id: str | None
    kind: ClaimKind
    observation: str
    interpretation: str
    confidence: Confidence
    reproduction: str = ""
    limitations: str = ""
    subject: str = ""


@dataclass(frozen=True, slots=True)
class ValidationReport:
    checked: int
    downgraded: tuple[tuple[str, tuple[str, ...]], ...]
    corroborated: tuple[str, ...]
    ingested: int


class EvidenceService:
    """Records claims and runs the Evidence Validator.

    The validator never deletes: unsupported claims are downgraded to
    hypotheses with the reasons appended to their limitations. Claims backed
    by two or more independent tools are promoted to ``supported``. Every
    state change feeds the learning engine (calibration + claim yield) and
    surviving findings are ingested into memory.
    """

    def __init__(self, evidence: EvidenceRepository, episodes: EpisodeRepository,
                 knowledge: KnowledgeService, clock: Clock, ids: IdGenerator):
        self._evidence = evidence
        self._episodes = episodes
        self._knowledge = knowledge
        self._clock = clock
        self._ids = ids

    def _execution_ok(self, execution_id: str | None) -> bool:
        if execution_id is None:
            return False
        record = self._evidence.get_execution(execution_id)
        return record is not None and record.succeeded

    def record_claim(self, data: ClaimInput) -> Claim:
        execution = self._evidence.get_execution(data.execution_id) if data.execution_id else None
        claim = Claim(
            claim_id=self._ids.new("clm"), project_id=data.project_id,
            artifact_id=data.artifact_id, source_hash=data.source_hash, tool_id=data.tool_id,
            tool_version=execution.tool_version if execution else "n/a",
            execution_id=data.execution_id, kind=data.kind, observation=data.observation,
            interpretation=data.interpretation, confidence=data.confidence,
            reproduction=data.reproduction, limitations=data.limitations, subject=data.subject,
            created_at=self._clock.now(),
        )
        issues = validate_claim(claim, self._execution_ok(claim.execution_id))
        if issues:
            raise InvalidClaim(issues)
        self._evidence.save_claim(claim)
        return claim

    def validate(self, project_id: str) -> ValidationReport:
        claims = self._evidence.list_claims(project_id)
        downgraded: list[tuple[str, tuple[str, ...]]] = []
        survivors: list[Claim] = []
        for claim in claims:
            if claim.verification is Verification.DOWNGRADED:
                continue
            issues = validate_claim(claim, self._execution_ok(claim.execution_id))
            if issues:
                note = f"{claim.limitations} | validator: {'; '.join(issues)}".strip(" |")
                self._evidence.save_claim(replace(
                    claim, kind=ClaimKind.HYPOTHESIS, verification=Verification.DOWNGRADED,
                    limitations=note))
                self._feedback(claim, correct=False)
                downgraded.append((claim.claim_id, issues))
            else:
                survivors.append(claim)

        corroborated = corroborated_subjects(survivors)
        ingested = 0
        for claim in survivors:
            if claim.subject in corroborated and claim.verification is Verification.UNVERIFIED:
                promoted = replace(claim, verification=Verification.SUPPORTED)
                self._evidence.save_claim(promoted)
                self._feedback(claim, correct=True)
                if self._knowledge.ingest_claim(promoted).stored:
                    ingested += 1
            elif claim.kind is ClaimKind.VERIFIED and claim.verification is Verification.UNVERIFIED:
                promoted = replace(claim, verification=Verification.VERIFIED)
                self._evidence.save_claim(promoted)
                self._feedback(claim, correct=True)
                if self._knowledge.ingest_claim(promoted).stored:
                    ingested += 1
        return ValidationReport(len(claims), tuple(downgraded), tuple(sorted(corroborated)), ingested)

    def _feedback(self, claim: Claim, correct: bool) -> None:
        """One-time learning signal on a claim's state change (keeps validation idempotent)."""
        now = self._clock.now()
        self._episodes.add_calibration(CalibrationPoint(claim.claim_id, claim.confidence, correct, now))
        artifact = self._evidence.get_artifact(claim.artifact_id)
        self._episodes.add_episode(Episode(
            self._ids.new("epi"), claim.tool_id, artifact.kind if artifact else "any",
            success=correct, latency_ms=0.0, recorded_at=now,
            validated_claims=int(correct), downgraded_claims=int(not correct),
            kind="claim_feedback",
        ))


class HypothesisService:
    """Observation -> hypothesis -> experiment -> evidence -> updated conclusion."""

    def __init__(self, evidence: EvidenceRepository, clock: Clock, ids: IdGenerator):
        self._evidence = evidence
        self._clock = clock
        self._ids = ids

    def propose(self, project_id: str, statement: str, prediction: str,
                falsified_if: str) -> Hypothesis:
        if not falsified_if.strip():
            raise InvalidHypothesis("state what observation would falsify the hypothesis")
        now = self._clock.now()
        hypothesis = Hypothesis(self._ids.new("hyp"), project_id, statement, prediction,
                                falsified_if, HypothesisStatus.OPEN, now, now)
        self._evidence.save_hypothesis(hypothesis)
        return hypothesis

    def plan_experiment(self, hypothesis_id: str, plan: str, security_class: SecurityClass,
                        information_gain: int, relevance: int, cost: int) -> Experiment:
        if self._evidence.get_hypothesis(hypothesis_id) is None:
            raise NotFound(f"hypothesis {hypothesis_id}")
        priority = experiment_priority(information_gain, relevance, cost, security_class.risk)
        experiment = Experiment(self._ids.new("exp"), hypothesis_id, plan, security_class,
                                priority, self._clock.now())
        self._evidence.save_experiment(experiment)
        return experiment

    def ranked_experiments(self, hypothesis_id: str) -> list[Experiment]:
        pending = [e for e in self._evidence.list_experiments(hypothesis_id) if e.supports is None]
        return sorted(pending, key=lambda e: (-e.priority, e.created_at))

    def record_outcome(self, experiment_id: str, execution_id: str, outcome: str,
                       supports: bool) -> HypothesisStatus:
        experiment = self._evidence.get_experiment(experiment_id)
        if experiment is None:
            raise NotFound(f"experiment {experiment_id}")
        record = self._evidence.get_execution(execution_id)
        if record is None or not record.succeeded:
            raise InvalidHypothesis("an experiment outcome needs a successful execution record")
        self._evidence.save_experiment(replace(experiment, execution_id=execution_id,
                                               outcome=outcome, supports=supports))
        hypothesis = self._evidence.get_hypothesis(experiment.hypothesis_id)
        if hypothesis is None:
            raise NotFound(f"hypothesis {experiment.hypothesis_id}")
        outcomes = [e.supports for e in self._evidence.list_experiments(hypothesis.hypothesis_id)
                    if e.supports is not None]
        status = derive_hypothesis_status(outcomes)
        self._evidence.save_hypothesis(replace(hypothesis, status=status,
                                               updated_at=self._clock.now()))
        return status
