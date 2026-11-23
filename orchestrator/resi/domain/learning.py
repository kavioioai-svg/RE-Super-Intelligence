"""Learning engine: explainable, offline learning from the agent's own history.

Three learners, all pure and deterministic given their inputs:

1. **Tool-outcome bandit** - a Beta-Bernoulli model per (tool, artifact kind).
   Success = the call returned usable output. Utility also rewards claims that
   survived validation and penalises latency. Ranking uses a pessimistic
   lower bound by default (exploit), or seeded Thompson sampling (explore).
   A setup failure (provider unavailable, tool not installed or not
   configured) stops counting once the same tool later succeeds: it measured
   the environment, not the tool. Unresolved setup failures still count.
2. **Confidence calibration** - compares stated confidence with what the
   validator later confirmed; reports accuracy per level and a Brier score.
3. **Lesson extraction** - recurring failure patterns (timeouts, guardrail
   rejections, and setup failures grouped across one server's tools) become
   plain-language lessons that are stored in memory and recalled later.
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

# Setup failures: the tool could not run here, which says nothing about how well it
# analyses an artifact. Checked in order; the first matching category wins.
ENVIRONMENT_FAILURE_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("provider_unavailable", ("provider_unavailable", "provider unavailable")),
    ("not_installed", ("not installed", "filenotfounderror", "executable_missing",
                       "command not found")),
    ("not_configured", ("not_configured", "not configured", "not set in")),
)
ENVIRONMENT_FAILURE_LABELS = {
    "provider_unavailable": "no analysis provider was available",
    "not_installed": "a required program was not installed",
    "not_configured": "the tool was not configured",
}


def environment_failure_category(reason: str) -> str | None:
    """The setup-failure category of ``reason``, or None for a genuine tool failure."""
    lowered = reason.lower()
    if not lowered or lowered.startswith("rejected"):
        return None
    for category, markers in ENVIRONMENT_FAILURE_MARKERS:
        if any(marker in lowered for marker in markers):
            return category
    return None


def last_success_by_tool(episodes: Iterable[Episode]) -> dict[str, str]:
    """Most recent successful execution time per tool, across artifact kinds."""
    latest: dict[str, str] = {}
    for ep in episodes:
        if ep.kind == "execution" and ep.success and ep.recorded_at > latest.get(ep.tool_id, ""):
            latest[ep.tool_id] = ep.recorded_at
    return latest


def is_resolved_environment_failure(ep: Episode, last_success: dict[str, str]) -> bool:
    """A setup failure followed by a later success of the same tool: the setup was fixed."""
    return (ep.kind == "execution" and not ep.success
            and environment_failure_category(ep.failure_reason) is not None
            and ep.recorded_at < last_success.get(ep.tool_id, ""))


@dataclass(frozen=True, slots=True)
class ToolStats:
    tool_id: str
    context: str
    successes: int = 0
    failures: int = 0
    validated_claims: int = 0
    downgraded_claims: int = 0
    total_latency_ms: float = 0.0
    resolved_setup_failures: int = 0  # excluded from trials; see is_resolved_environment_failure

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
        text = (f"{self.successes}/{self.trials} successful, "
                f"posterior {self.posterior_mean:.2f}±{self.posterior_sd:.2f}, "
                f"claim yield {self.claim_yield:.2f}, mean latency {self.mean_latency_ms:.0f} ms")
        if self.resolved_setup_failures:
            text += f", {self.resolved_setup_failures} resolved setup failure(s) excluded"
        return text


def aggregate(episodes: Iterable[Episode]) -> dict[tuple[str, str], ToolStats]:
    """Fold episodes into stats keyed by (tool_id, context).

    Setup failures that a later success of the same tool resolved are excluded
    from trials (and counted separately), so fixing the environment restores a
    tool's standing instead of leaving it penalised forever.
    """
    history = list(episodes)
    last_success = last_success_by_tool(history)
    acc: dict[tuple[str, str], list[float]] = defaultdict(lambda: [0, 0, 0, 0, 0.0, 0])
    for ep in history:
        row = acc[(ep.tool_id, ep.context)]
        if is_resolved_environment_failure(ep, last_success):
            row[5] += 1
        elif ep.counts_as_trial:
            row[0 if ep.success else 1] += 1
            row[4] += ep.latency_ms
        row[2] += ep.validated_claims
        row[3] += ep.downgraded_claims
    return {
        key: ToolStats(key[0], key[1], int(r[0]), int(r[1]), int(r[2]), int(r[3]), float(r[4]),
                       int(r[5]))
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
        sum(s.resolved_setup_failures for s in pooled),
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
    lessons: list[Lesson] = _environment_lessons(episodes)
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


SAMPLE_REASON_CHARS = 200


def _environment_lessons(episodes: Sequence[Episode]) -> list[Lesson]:
    """Recurring setup failures, grouped by server and category across that server's tools.

    One unavailable decompiler fails many tools once each; grouping by server
    (``rea``, ``cli``) sees the pattern that a per-tool count would miss. The
    lesson says whether the setup has since been fixed (every affected tool
    succeeded afterwards) so a later run knows to keep, not repeat, the fix.
    """
    last_success = last_success_by_tool(episodes)
    groups: dict[tuple[str, str], list[Episode]] = defaultdict(list)
    for ep in episodes:
        if ep.kind != "execution" or ep.success:
            continue
        category = environment_failure_category(ep.failure_reason)
        if category is not None:
            groups[(ep.tool_id.split(".", 1)[0], category)].append(ep)
    lessons: list[Lesson] = []
    for (server, category), failures in sorted(groups.items()):
        if len(failures) < MIN_FAILURES_FOR_LESSON:
            continue
        tools = sorted({e.tool_id for e in failures})
        kinds = sorted({e.context for e in failures})
        sample = min(e.failure_reason for e in failures)[:SAMPLE_REASON_CHARS]
        resolved = all(is_resolved_environment_failure(e, last_success) for e in failures)
        advice = (
            "Every affected tool has succeeded since, so the setup is fixed: keep it in place "
            "on new machines. These failures no longer count against the tools' reliability."
            if resolved else
            "Fix the setup named in the example before planning these tools, or plan an "
            "alternative engine; until a later call succeeds they count as unreliable."
        )
        lessons.append(Lesson(
            f"environment:{server}:{category}",
            f"{server} tools fail when {ENVIRONMENT_FAILURE_LABELS[category]}"
            + (" (resolved)" if resolved else ""),
            f"{len(failures)} calls to {server} tools ({', '.join(tools)}) failed because "
            f"{ENVIRONMENT_FAILURE_LABELS[category]} (artifact kinds: {', '.join(kinds)}). "
            f"Example: {sample}. {advice}",
            ("lesson", "environment", category, server),
        ))
    return lessons
