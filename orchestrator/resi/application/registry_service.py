"""Capability discovery and registry maintenance."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from ..domain.catalog import EXTERNAL_TOOLS
from ..domain.registry import CapabilityRegistry, OverlayEntry, build_registry
from .ports import Clock, EnvironmentProbe, RegistryRepository


class RegistryService:
    def __init__(self, repository: RegistryRepository, probe: EnvironmentProbe, clock: Clock):
        self._repository = repository
        self._probe = probe
        self._clock = clock

    def refresh(self, announced: Iterable[str],
                overlay: Mapping[str, OverlayEntry] | None = None) -> CapabilityRegistry:
        """Rebuild from announced MCP tools + probed CLIs, keeping earned verifications."""
        previous = self._repository.load()
        registry = build_registry(announced, self._probe.probe(EXTERNAL_TOOLS), overlay,
                                  discovered_on=self._clock.now()[:10])
        if previous is not None:
            for tool in previous:
                if tool.evidence_ids and registry.is_usable(tool.id):
                    for evidence_id in tool.evidence_ids:
                        registry.verify(tool.id, tool.version, evidence_id)
        self._repository.save(registry)
        return registry

    def current(self) -> CapabilityRegistry:
        """The persisted registry, or one built from local probes only."""
        registry = self._repository.load()
        if registry is None:
            registry = build_registry((), self._probe.probe(EXTERNAL_TOOLS),
                                      discovered_on=self._clock.now()[:10])
        return registry

    def verify(self, tool_id: str, version: str, evidence_id: str) -> None:
        registry = self.current()
        registry.verify(tool_id, version, evidence_id)
        self._repository.save(registry)
