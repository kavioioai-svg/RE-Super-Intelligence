"""Learning engine: explainable, offline learning from the agent's own history.

Three learners, all pure and deterministic given their inputs:

1. **Tool-outcome bandit** - a Beta-Bernoulli model per (tool, artifact kind).
   Success = the call returned usable output. Utility also rewards claims that
   survived validation and penalises latency. Ranking uses a pessimistic
   lower bound by default (exploit), or seeded Thompson sampling (explore).
2. **Confidence calibration** - compares stated confidence with what the
   validator later confirmed; reports accuracy per level and a Brier score.
3. **Lesson extraction** - recurring failure patterns become plain-language
   lessons that are stored in memory and recalled on later engagements.
"""

from __future__ import annotations

import math
import random
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from .enums import Confidence
from .models import CalibrationPoint, Episode

CONFIDENCE_PROBABILITY = {Confidence.LOW: 0.35, Confidence.MEDIUM: 0.65, Confidence.HIGH: 0.9}
MIN_TRIALS_FOR_DEMOTION = 5
DEMOTION_THRESHOLD = 0.25
MIN_POINTS_FOR_CALIBRATION = 10
OVERCONFIDENCE_MARGIN = 0.15


@dataclass(frozen=True, slots=True)
class ToolStats:
    tool_id: str
    context: str
    successes: int = 0
    failures: int = 0
    validated_claims: int = 0
    downgraded_claims: int = 0
    total_latency_ms: float = 0.0

    @property
    def trials(self) -> int:
        return self.successes + self.failures

    @property
    def alpha(self) -> float:
        return 1.0 + self.successes  # uniform Beta(1, 1) prior

    @property
    def beta(self) -> float:
        return 1.0 + self.failures

    @property
    def posterior_mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    @property
    def posterior_sd(self) -> float:
        a, b = self.alpha, self.beta
        return math.sqrt((a * b) / ((a + b) ** 2 * (a + b + 1)))

    @property
    def lower_bound(self) -> float:
        """Pessimistic estimate (mean - 1 sd): unproven tools don't outrank proven ones."""
        return max(0.0, self.posterior_mean - self.posterior_sd)

    @property
    def claim_yield(self) -> float:
        """Share of this tool's claims that survived validation (0.5 when unknown)."""
        total = self.validated_claims + self.downgraded_claims
        return 0.5 if total == 0 else self.validated_claims / total

    @property
    def mean_latency_ms(self) -> float:
        return self.total_latency_ms / self.trials if self.trials else 0.0

    @property
    def demoted(self) -> bool:
        return self.trials >= MIN_TRIALS_FOR_DEMOTION and self.posterior_mean < DEMOTION_THRESHOLD

    def utility(self, reliability: float) -> float:
        latency_penalty = 1.0 + math.log1p(self.mean_latency_ms / 1000.0)
        return round(reliability * (0.5 + self.claim_yield) / latency_penalty, 4)

    def explain(self) -> str:
        return (f"{self.successes}/{self.trials} successful, "
                f"posterior {self.posterior_mean:.2f}±{self.posterior_sd:.2f}, "
                f"claim yield {self.claim_yield:.2f}, mean latency {self.mean_latency_ms:.0f} ms")


def aggregate(episodes: Iterable[Episode]) -> dict[tuple[str, str], ToolStats]:
    """Fold episodes into stats keyed by (tool_id, context)."""
    acc: dict[tuple[str, str], list[float]] = defaultdict(lambda: [0, 0, 0, 0, 0.0])
    for ep in episodes:
        row = acc[(ep.tool_id, ep.context)]
        if ep.counts_as_trial:
            row[0 if ep.success else 1] += 1
            row[4] += ep.latency_ms
        row[2] += ep.validated_claims
        row[3] += ep.downgraded_claims
    return {
        key: ToolStats(key[0], key[1], int(r[0]), int(r[1]), int(r[2]), int(r[3]), float(r[4]))
        for key, r in acc.items()
    }


def stats_for(stats: dict[tuple[str, str], ToolStats], tool_id: str, context: str) -> ToolStats:
    """Context-specific stats, falling back to pooled stats across contexts."""
    if (tool_id, context) in stats:
        return stats[(tool_id, context)]
    pooled = [s for (t, _), s in stats.items() if t == tool_id]
    if not pooled:
        return ToolStats(tool_id, context)
    return ToolStats(
        tool_id, "pooled",
        sum(s.successes for s in pooled), sum(s.failures for s in pooled),
        sum(s.validated_claims for s in pooled), sum(s.downgraded_claims for s in pooled),
        sum(s.total_latency_ms for s in pooled),
    )


def score_tool(stats: ToolStats, explore: bool = False, rng: random.Random | None = None) -> float:
    """Exploit: utility at the lower bound. Explore: utility at a Thompson sample."""
    if explore:
        sampler = rng or random.Random(0)
        return stats.utility(sampler.betavariate(stats.alpha, stats.beta))
    return stats.utility(stats.lower_bound)


# --- calibration -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CalibrationReport:
    points: int
    accuracy_by_level: dict[str, float | None]
    brier_score: float | None
    overconfident_levels: tuple[str, ...]

    @property
    def reliable(self) -> bool:
        return self.points >= MIN_POINTS_FOR_CALIBRATION


def calibrate(points: Sequence[CalibrationPoint]) -> CalibrationReport:
    by_level: dict[Confidence, list[bool]] = defaultdict(list)
    for p in points:
        by_level[p.confidence].append(p.correct)
    accuracy: dict[str, float | None] = {}
    overconfident: list[str] = []
    for level in Confidence:
        outcomes = by_level.get(level, [])
        if not outcomes:
            accuracy[level.value] = None
            continue
        rate = sum(outcomes) / len(outcomes)
        accuracy[level.value] = round(rate, 3)
        if (len(outcomes) >= MIN_POINTS_FOR_CALIBRATION
                and rate < CONFIDENCE_PROBABILITY[level] - OVERCONFIDENCE_MARGIN):
            overconfident.append(level.value)
    brier = None
    if points:
        brier = round(
            sum((CONFIDENCE_PROBABILITY[p.confidence] - float(p.correct)) ** 2 for p in points)
            / len(points), 4,
        )
    return CalibrationReport(len(points), accuracy, brier, tuple(overconfident))


# --- lessons ---------------------------------------------------------------------

TIMEOUT_RATE_FOR_LESSON = 0.3
MIN_FAILURES_FOR_LESSON = 3


@dataclass(frozen=True, slots=True)
class Lesson:
    key: str  # stable identity so a lesson is stored once and updated in place
    title: str
    text: str
    tags: tuple[str, ...]


def extract_lessons(episodes: Sequence[Episode]) -> list[Lesson]:
    """Turn recurring failures into guidance. Deterministic and idempotent."""
    by_tool: dict[str, list[Episode]] = defaultdict(list)
    for ep in episodes:
        if ep.kind == "execution":
            by_tool[ep.tool_id].append(ep)
    lessons: list[Lesson] = []
    for tool_id, eps in sorted(by_tool.items()):
        failures = [e for e in eps if not e.success]
        if len(failures) < MIN_FAILURES_FOR_LESSON:
            continue
        timeouts = [e for e in failures if "timeout" in e.failure_reason]
        rejected = [e for e in failures if "rejected" in e.failure_reason]
        if len(timeouts) / len(eps) >= TIMEOUT_RATE_FOR_LESSON:
            kinds = sorted({e.context for e in timeouts})
            lessons.append(Lesson(
                f"timeout:{tool_id}", f"{tool_id} frequently times out",
                f"{tool_id} timed out in {len(timeouts)} of {len(eps)} calls "
                f"(artifact kinds: {', '.join(kinds)}). Narrow the request (single function, "
                "smaller address range, fewer items per batch) before retrying.",
                ("lesson", "timeout", tool_id),
            ))
        if len(rejected) >= MIN_FAILURES_FOR_LESSON:
            reasons = sorted({e.failure_reason for e in rejected})[:3]
            lessons.append(Lesson(
                f"rejected:{tool_id}", f"{tool_id} calls are often rejected by guardrails",
                f"{len(rejected)} calls to {tool_id} were rejected ({'; '.join(reasons)}). "
                "Check scope and approvals before planning this tool, or use a read-only "
                "alternative.",
                ("lesson", "guardrail", tool_id),
            ))
    return lessons
