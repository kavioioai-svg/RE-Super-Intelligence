"""Learning loop: turn the agent's history into rankings, calibration and lessons."""

from __future__ import annotations

from dataclasses import dataclass

from ..domain.learning import CalibrationReport, ToolStats, aggregate, calibrate, extract_lessons
from ..domain.models import KnowledgeDocument
from .knowledge import KnowledgeService
from .ports import EpisodeRepository


@dataclass(frozen=True, slots=True)
class ToolInsight:
    tool_id: str
    context: str
    trials: int
    posterior_mean: float
    lower_bound: float
    claim_yield: float
    mean_latency_ms: float
    demoted: bool
    explanation: str


@dataclass(frozen=True, slots=True)
class LearningReport:
    episodes: int
    tools: tuple[ToolInsight, ...]
    calibration: CalibrationReport
    guidance: tuple[str, ...]


def _insight(stats: ToolStats) -> ToolInsight:
    return ToolInsight(stats.tool_id, stats.context, stats.trials,
                       round(stats.posterior_mean, 3), round(stats.lower_bound, 3),
                       round(stats.claim_yield, 3), round(stats.mean_latency_ms, 1),
                       stats.demoted, stats.explain())


class LearningService:
    def __init__(self, episodes: EpisodeRepository, knowledge: KnowledgeService):
        self._episodes = episodes
        self._knowledge = knowledge

    def report(self, context: str | None = None) -> LearningReport:
        episodes = self._episodes.list_episodes()
        stats = aggregate(episodes)
        insights = sorted(
            (_insight(s) for (_, ctx), s in stats.items() if context is None or ctx == context),
            key=lambda i: (-i.lower_bound, i.tool_id),
        )
        calibration = calibrate(self._episodes.list_calibration())
        guidance: list[str] = []
        for insight in insights:
            if insight.demoted:
                guidance.append(f"Avoid {insight.tool_id} on {insight.context}: "
                                f"{insight.explanation}. Plans now prefer its fallback.")
        for level in calibration.overconfident_levels:
            accuracy = calibration.accuracy_by_level[level]
            guidance.append(f"Stated '{level}' confidence held up only {accuracy:.0%} of the time "
                            f"- lower confidence or gather corroboration before asserting.")
        if not calibration.reliable:
            guidance.append(f"Calibration needs more validated claims "
                            f"({calibration.points} so far) before it is reliable.")
        return LearningReport(len(episodes), tuple(insights), calibration, tuple(guidance))

    def refresh_lessons(self) -> list[KnowledgeDocument]:
        """Distil failure patterns into memory. Idempotent: lessons upsert by key."""
        stored: list[KnowledgeDocument] = []
        for lesson in extract_lessons(self._episodes.list_episodes()):
            result = self._knowledge.ingest_lesson(lesson)
            if result.document is not None:
                stored.append(result.document)
        return stored
