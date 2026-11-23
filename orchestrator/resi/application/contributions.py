"""Learning contributions: user-side preview/export, private ingestion, ranking job.

User side (``ContributionService``) only reads local learning data and returns
text; it has no network code. Writing the file is the CLI's job, and nothing
here runs during analysis, install, startup or updates.

Private side (``IngestionService``, ``RankingService``) runs on Kavio's own
infrastructure against a separate contributions database.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from ..domain.contributions import (
    MAX_PAYLOAD_BYTES,
    SCHEMA_VERSION,
    RankingParameters,
    build_contribution,
    contribution_digest,
    rank_contributions,
    render,
    validate_contribution,
)
from ..domain.errors import ContributionConflict, InvalidContribution
from ..domain.models import StoredContribution
from .ports import Clock, ContributionIdStore, ContributionRepository, EpisodeRepository


def _new_contribution_id() -> str:
    return secrets.token_hex(16)


@dataclass(frozen=True, slots=True)
class ExportResult:
    contribution_id: str
    groups: int
    text: str


class ContributionService:
    """Builds the shareable payload from the local learning store."""

    def __init__(self, episodes: EpisodeRepository, pending: ContributionIdStore,
                 tool_ids: frozenset[str],
                 new_id: Callable[[], str] = _new_contribution_id):
        self._episodes = episodes
        self._pending = pending
        self._tool_ids = tool_ids
        self._new_id = new_id

    def _contribution_id(self) -> str:
        current = self._pending.get()
        if current is None:
            current = self._new_id()
            self._pending.put(current)
        return current

    def payload(self) -> dict[str, Any]:
        return build_contribution(self._episodes.list_episodes(),
                                  self._episodes.list_calibration(), self._tool_ids,
                                  self._contribution_id())

    def preview(self) -> str:
        """Exactly the text ``export`` would write now."""
        return render(self.payload())

    def prepare_export(self) -> ExportResult:
        payload = self.payload()
        return ExportResult(payload["contribution_id"], len(payload["tools"]), render(payload))

    def complete_export(self, contribution_id: str) -> None:
        """After the file is written: the next export gets a fresh id."""
        if self._pending.get() == contribution_id:
            self._pending.clear()


@dataclass(frozen=True, slots=True)
class AcceptResult:
    contribution_id: str
    status: Literal["accepted", "duplicate"]
    groups: int


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    duplicates = sorted({k for k in keys if keys.count(k) > 1})
    if duplicates:
        raise InvalidContribution((f"duplicate JSON keys: {duplicates}",))
    return dict(pairs)


class IngestionService:
    """Validates uploaded contributions and stores accepted aggregates only."""

    def __init__(self, repository: ContributionRepository, clock: Clock,
                 tool_ids: frozenset[str], max_bytes: int = MAX_PAYLOAD_BYTES):
        self._repository = repository
        self._clock = clock
        self._tool_ids = tool_ids
        self._max_bytes = min(max_bytes, MAX_PAYLOAD_BYTES)

    @property
    def max_bytes(self) -> int:
        return self._max_bytes

    def accept(self, raw: bytes) -> AcceptResult:
        if len(raw) > self._max_bytes:
            raise InvalidContribution((f"payload larger than {self._max_bytes} bytes",))
        try:
            payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys,
                                 parse_constant=lambda c: _bad_constant(c))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InvalidContribution((f"not valid UTF-8 JSON: {type(exc).__name__}",)) from None
        errors = validate_contribution(payload, self._tool_ids)
        if errors:
            raise InvalidContribution(errors)
        record = StoredContribution(payload["contribution_id"], contribution_digest(payload),
                                    SCHEMA_VERSION, self._clock.now()[:10], payload)
        if self._repository.add(record):
            return AcceptResult(record.contribution_id, "accepted", len(payload["tools"]))
        existing = self._repository.get(record.contribution_id)
        if existing is not None and existing.digest == record.digest:
            return AcceptResult(record.contribution_id, "duplicate", len(payload["tools"]))
        raise ContributionConflict(
            f"contribution {record.contribution_id} was already accepted with different counters")


def _bad_constant(constant: str) -> Any:
    raise InvalidContribution((f"non-finite number {constant} is not allowed",))


class RankingService:
    """Runs the deterministic ranking job over accepted contributions."""

    def __init__(self, repository: ContributionRepository):
        self._repository = repository

    def rank(self, params: RankingParameters | None = None) -> dict[str, Any]:
        return rank_contributions(self._repository.list_payloads(), params)
