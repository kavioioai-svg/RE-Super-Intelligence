"""Classification and planning use cases."""

from __future__ import annotations

from ..domain.classification import classify
from ..domain.learning import aggregate
from ..domain.models import Artifact, ResearchPlan
from ..domain.routing import plan_research
from .ports import ArtifactReader, EpisodeRepository
from .projects import ProjectService
from .registry_service import RegistryService


class ResearchService:
    def __init__(self, reader: ArtifactReader, projects: ProjectService,
                 registry: RegistryService, episodes: EpisodeRepository):
        self._reader = reader
        self._projects = projects
        self._registry = registry
        self._episodes = episodes

    def classify(self, path: str) -> Artifact:
        return classify(self._reader.read(path))

    def plan(self, project_id: str, path: str, adaptive: bool = True,
             explore: bool = False, seed: int = 0) -> ResearchPlan:
        """Plan for an artifact within a project's scope and profile.

        With ``adaptive`` the plan is refined by learned tool statistics;
        ``explore`` switches ranking to seeded Thompson sampling.
        """
        project = self._projects.project(project_id)
        artifact = self.classify(path)
        stats = aggregate(self._episodes.list_episodes()) if adaptive else None
        return plan_research(artifact, self._registry.current(), self._projects.scope(project_id),
                             project.profile, stats, explore, seed)
