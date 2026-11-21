"""The evidence model's rules: what makes a claim acceptable, how hypotheses move."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence

from .enums import ClaimKind, Confidence, HypothesisStatus, Verification
from .models import Claim

SHA256_HEX_LENGTH = 64
SUPPORTING_EXPERIMENTS_FOR_VERIFIED = 2


def validate_claim(claim: Claim, execution_succeeded: bool) -> tuple[str, ...]:
    """Every reason ``claim`` is unacceptable as written (empty tuple = acceptable)."""
    issues: list[str] = []
    if not claim.observation.strip():
        issues.append("observation is empty")
    if len(claim.source_hash) != SHA256_HEX_LENGTH or any(
        c not in "0123456789abcdef" for c in claim.source_hash
    ):
        issues.append("source_hash must be a lowercase sha256 hex digest")
    if claim.kind.needs_execution and not execution_succeeded:
        issues.append(f"a {claim.kind.value} claim must reference a successful execution")
    asserts_verified = claim.kind is ClaimKind.VERIFIED or claim.verification is Verification.VERIFIED
    if asserts_verified and not claim.reproduction.strip():
        issues.append("verified claims need reproduction steps")
    if asserts_verified and claim.confidence is Confidence.LOW:
        issues.append("a verified claim cannot carry low confidence")
    if claim.kind is ClaimKind.HYPOTHESIS and claim.verification is Verification.VERIFIED:
        issues.append("a hypothesis cannot be marked verified - promote it through an experiment")
    return tuple(issues)


def derive_hypothesis_status(outcomes: Sequence[bool]) -> HypothesisStatus:
    """Falsification first: one contradicting experiment rejects the hypothesis.

    ``verified`` needs at least two independent supporting experiments.
    """
    if not outcomes:
        return HypothesisStatus.OPEN
    if not all(outcomes):
        return HypothesisStatus.REJECTED
    if len(outcomes) >= SUPPORTING_EXPERIMENTS_FOR_VERIFIED:
        return HypothesisStatus.VERIFIED
    return HypothesisStatus.SUPPORTED


def experiment_priority(information_gain: int, relevance: int, cost: int, risk: int) -> float:
    """priority = (gain x relevance) / (cost x risk); each factor scored 1-5."""
    for name, value in (("information_gain", information_gain), ("relevance", relevance),
                        ("cost", cost), ("risk", risk)):
        if not 1 <= value <= 5:
            raise ValueError(f"{name} must be between 1 and 5, got {value}")
    return round((information_gain * relevance) / (cost * risk), 3)


def corroborated_subjects(claims: Iterable[Claim], minimum_tools: int = 2) -> set[str]:
    """Subjects asserted by at least ``minimum_tools`` distinct tools with execution-backed claims."""
    tools_by_subject: dict[str, set[str]] = defaultdict(set)
    for claim in claims:
        if claim.subject and claim.kind.needs_execution and claim.verification is not Verification.DOWNGRADED:
            tools_by_subject[claim.subject].add(claim.tool_id)
    return {s for s, tools in tools_by_subject.items() if len(tools) >= minimum_tools}
