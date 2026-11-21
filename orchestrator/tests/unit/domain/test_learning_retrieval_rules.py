from __future__ import annotations

import random
from dataclasses import replace
from typing import Any

import pytest

from resi.domain.enums import ClaimKind, Confidence, HypothesisStatus, Verification
from resi.domain.evidence_rules import (
    corroborated_subjects,
    derive_hypothesis_status,
    experiment_priority,
    validate_claim,
)
from resi.domain.geometry import ellipse_perimeter, relative_error_pct
from resi.domain.learning import (
    ToolStats,
    aggregate,
    calibrate,
    extract_lessons,
    score_tool,
    stats_for,
)
from resi.domain.models import CalibrationPoint, Claim, Episode
from resi.domain.retrieval import BM25Index, Ranked, cosine, reciprocal_rank_fusion, tokenize

SHA = "c" * 64


BASE_CLAIM = Claim(claim_id="c1", project_id="p", artifact_id="a", source_hash=SHA,
                   tool_id="rea.t", tool_version="1", execution_id="e1", kind=ClaimKind.OBSERVED,
                   observation="o", interpretation="i", confidence=Confidence.MEDIUM)


def claim(**overrides: Any) -> Claim:
    return replace(BASE_CLAIM, **overrides)


def episode(tool: str, success: bool, ctx: str = "elf", reason: str = "",
            kind: str = "execution", latency: float = 100.0) -> Episode:
    return Episode(f"e-{random.random()}", tool, ctx, success, latency, "t", reason, kind=kind)


class TestEvidenceRules:
    def test_valid_observed_claim(self) -> None:
        assert validate_claim(claim(), execution_succeeded=True) == ()

    def test_observed_claim_needs_execution(self) -> None:
        assert "successful execution" in validate_claim(claim(), execution_succeeded=False)[0]

    def test_hypothesis_needs_no_execution_but_cannot_be_verified(self) -> None:
        h = claim(kind=ClaimKind.HYPOTHESIS, execution_id=None)
        assert validate_claim(h, False) == ()
        assert validate_claim(claim(kind=ClaimKind.HYPOTHESIS, verification=Verification.VERIFIED),
                              False)

    def test_verified_claim_needs_reproduction_and_not_low_confidence(self) -> None:
        issues = validate_claim(claim(kind=ClaimKind.VERIFIED, confidence=Confidence.LOW), True)
        assert any("reproduction" in i for i in issues)
        assert any("low confidence" in i for i in issues)

    def test_source_hash_must_be_sha256(self) -> None:
        assert validate_claim(claim(source_hash="xyz"), True)

    @pytest.mark.parametrize(("outcomes", "status"), [
        ([], HypothesisStatus.OPEN), ([True], HypothesisStatus.SUPPORTED),
        ([True, True], HypothesisStatus.VERIFIED), ([True, False], HypothesisStatus.REJECTED),
        ([True, True, False], HypothesisStatus.REJECTED),
    ])
    def test_falsification_first(self, outcomes: list[bool], status: HypothesisStatus) -> None:
        assert derive_hypothesis_status(outcomes) is status

    def test_experiment_priority(self) -> None:
        assert experiment_priority(5, 5, 1, 1) == 25.0
        assert experiment_priority(1, 1, 5, 5) == 0.04
        with pytest.raises(ValueError):
            experiment_priority(0, 1, 1, 1)

    def test_corroboration_needs_distinct_tools(self) -> None:
        same = [claim(claim_id="1", subject="fn:aes"), claim(claim_id="2", subject="fn:aes")]
        assert corroborated_subjects(same) == set()
        distinct = [*same, claim(claim_id="3", subject="fn:aes", tool_id="cli.ghidra")]
        assert corroborated_subjects(distinct) == {"fn:aes"}


class TestBandit:
    def test_posterior_and_lower_bound(self) -> None:
        stats = ToolStats("t", "elf", successes=8, failures=2)
        assert stats.posterior_mean == pytest.approx(0.75)
        assert 0 < stats.lower_bound < stats.posterior_mean

    def test_proven_tool_outranks_unproven(self) -> None:
        proven = ToolStats("a", "elf", successes=20, failures=1)
        unproven = ToolStats("b", "elf")
        assert score_tool(proven) > score_tool(unproven)

    def test_demotion_needs_enough_evidence(self) -> None:
        assert not ToolStats("t", "elf", failures=3).demoted
        assert ToolStats("t", "elf", failures=6).demoted

    def test_thompson_sampling_is_seeded(self) -> None:
        stats = ToolStats("t", "elf", successes=3, failures=3)
        a = score_tool(stats, explore=True, rng=random.Random(42))
        b = score_tool(stats, explore=True, rng=random.Random(42))
        assert a == b

    def test_rejections_do_not_count_as_tool_failures(self) -> None:
        stats = aggregate([episode("t", False, reason="rejected: out of scope")] * 5)
        assert stats[("t", "elf")].trials == 0

    def test_claim_feedback_updates_yield_not_trials(self) -> None:
        feedback = Episode("f", "t", "elf", True, 0.0, "t", validated_claims=1, kind="claim_feedback")
        stats = aggregate([episode("t", True), feedback])[("t", "elf")]
        assert stats.trials == 1 and stats.validated_claims == 1

    def test_pooled_fallback_across_contexts(self) -> None:
        stats = aggregate([episode("t", True, ctx="pe"), episode("t", False, ctx="macho")])
        pooled = stats_for(stats, "t", "elf")
        assert (pooled.context, pooled.trials) == ("pooled", 2)


class TestCalibrationAndLessons:
    def test_overconfidence_detected(self) -> None:
        points = [CalibrationPoint(str(i), Confidence.HIGH, i < 4, "t") for i in range(12)]
        report = calibrate(points)
        assert report.reliable and report.overconfident_levels == ("high",)
        assert report.accuracy_by_level["high"] == pytest.approx(4 / 12, abs=1e-3)

    def test_well_calibrated(self) -> None:
        points = [CalibrationPoint(str(i), Confidence.HIGH, i != 0, "t") for i in range(12)]
        assert calibrate(points).overconfident_levels == ()

    def test_lessons_from_recurring_timeouts_and_rejections(self) -> None:
        eps = [episode("rea.batch_decompile", False, reason="timeout after 600s")] * 3
        eps += [episode("rea.batch_decompile", True)]
        eps += [episode("rea.x", False, reason="rejected: needs approval")] * 3
        keys = {lesson.key for lesson in extract_lessons(eps)}
        assert keys == {"timeout:rea.batch_decompile", "rejected:rea.x"}


class TestRetrieval:
    def test_tokenizer_keeps_identifiers(self) -> None:
        assert tokenize("The sub_4012A0 calls AES") == ["sub_4012a0", "calls", "aes"]

    def test_bm25_ranks_relevant_document_first(self) -> None:
        index = BM25Index({"d1": "AES key schedule in sub_401000", "d2": "PNG chunk parser",
                           "d3": "CRC32 table and AES S-box constants"})
        ranked = index.search("AES S-box")
        assert ranked[0].doc_id == "d3" and {r.doc_id for r in ranked} == {"d1", "d3"}

    def test_bm25_empty_cases(self) -> None:
        assert BM25Index({}).search("x") == []
        assert BM25Index({"d": "text"}).search("the of") == []

    def test_cosine_and_fusion(self) -> None:
        assert cosine([1, 0], [1, 0]) == pytest.approx(1.0)
        assert cosine([1, 0], [0, 1]) == 0.0
        fused = reciprocal_rank_fusion([[Ranked("a", 1), Ranked("b", 0.5)],
                                        [Ranked("b", 1), Ranked("c", 0.5)]])
        assert fused[0].doc_id == "b"


def test_geometry() -> None:
    assert ellipse_perimeter(1, 1) == pytest.approx(2 * 3.141592653589793)
    assert relative_error_pct(101, 100) == pytest.approx(1.0)
    with pytest.raises(ValueError):
        ellipse_perimeter(0, 1)
