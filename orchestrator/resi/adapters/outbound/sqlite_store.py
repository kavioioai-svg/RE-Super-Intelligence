"""SQLite persistence for evidence, scope, knowledge and learning episodes.

Rows hold JSON documents keyed by indexed columns: the schema stays portable
to PostgreSQL (``TEXT``/``JSONB``) if multi-user access is ever required.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, TypeVar

from ...domain.enums import ClaimKind
from ...domain.models import (
    Artifact,
    CalibrationPoint,
    Claim,
    Episode,
    ExecutionRecord,
    Experiment,
    Hypothesis,
    KnowledgeDocument,
    Project,
    Scope,
)
from .serialization import (
    artifact_from_dict,
    calibration_from_dict,
    claim_from_dict,
    document_from_dict,
    episode_from_dict,
    execution_from_dict,
    experiment_from_dict,
    hypothesis_from_dict,
    project_from_dict,
    scope_from_dict,
    scope_to_dict,
    to_dict,
)

T = TypeVar("T")

_SEQUENCED_TABLES = ("executions", "claims", "hypotheses", "experiments", "documents", "episodes")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS projects   (id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scopes     (id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS artifacts  (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS executions (id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
                                       seq INTEGER NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS claims     (id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
                                       kind TEXT NOT NULL, seq INTEGER NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS hypotheses (id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
                                       seq INTEGER NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS experiments(id TEXT PRIMARY KEY, hypothesis_id TEXT NOT NULL,
                                       seq INTEGER NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS documents  (id TEXT PRIMARY KEY, project_id TEXT, kind TEXT NOT NULL,
                                       source_ref TEXT, trusted INTEGER NOT NULL,
                                       seq INTEGER NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS episodes   (id TEXT PRIMARY KEY, tool_id TEXT NOT NULL,
                                       seq INTEGER NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS calibration(id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_exec_project   ON executions(project_id, seq);
CREATE INDEX IF NOT EXISTS ix_claims_project ON claims(project_id, kind, seq);
CREATE INDEX IF NOT EXISTS ix_hyp_project    ON hypotheses(project_id, seq);
CREATE INDEX IF NOT EXISTS ix_exp_hypothesis ON experiments(hypothesis_id, seq);
CREATE INDEX IF NOT EXISTS ix_docs_source    ON documents(source_ref);
CREATE INDEX IF NOT EXISTS ix_docs_project   ON documents(project_id, kind, trusted);
CREATE INDEX IF NOT EXISTS ix_episodes_tool  ON episodes(tool_id, seq);
"""


class SqliteStore:
    """Implements EvidenceRepository, ScopeRepository, KnowledgeRepository and EpisodeRepository."""

    def __init__(self, path: str | Path = ":memory:"):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript(_SCHEMA)
        self._seq = self._max_seq()
        self._closed = False

    def _max_seq(self) -> int:
        """Resume ordering after the highest sequence already stored."""
        best = 0
        for table in _SEQUENCED_TABLES:  # constant names - not user input
            (value,) = self._db.execute(
                f"SELECT COALESCE(MAX(seq), 0) FROM {table}"
            ).fetchone()
            best = max(best, int(value))
        return best

    def close(self) -> None:
        if not self._closed:
            self._db.close()
            self._closed = True

    # -- helpers --------------------------------------------------------------

    def _next(self) -> int:
        self._seq += 1
        return self._seq

    def _write(self, sql: str, params: Sequence[Any]) -> None:
        with self._lock:
            self._db.execute(sql, params)
            self._db.commit()

    def _one(self, sql: str, params: Sequence[Any], parse: Callable[[dict[str, Any]], T]) -> T | None:
        with self._lock:
            row = self._db.execute(sql, params).fetchone()
        return parse(json.loads(row[0])) if row else None

    def _many(self, sql: str, params: Sequence[Any], parse: Callable[[dict[str, Any]], T]) -> list[T]:
        with self._lock:
            rows = self._db.execute(sql, params).fetchall()
        return [parse(json.loads(r[0])) for r in rows]

    @staticmethod
    def _dump(obj: Any) -> str:
        return json.dumps(obj if isinstance(obj, dict) else to_dict(obj), default=str)

    # -- EvidenceRepository ---------------------------------------------------

    def save_project(self, project: Project) -> None:
        self._write("INSERT OR REPLACE INTO projects VALUES (?,?)",
                    (project.project_id, self._dump(project)))

    def get_project(self, project_id: str) -> Project | None:
        return self._one("SELECT body FROM projects WHERE id=?", (project_id,), project_from_dict)

    def save_artifact(self, project_id: str, artifact: Artifact) -> None:
        body = {**to_dict(artifact), "details": dict(artifact.details)}
        self._write("INSERT OR REPLACE INTO artifacts VALUES (?,?,?)",
                    (artifact.artifact_id, project_id, json.dumps(body, default=str)))

    def get_artifact(self, artifact_id: str) -> Artifact | None:
        return self._one("SELECT body FROM artifacts WHERE id=?", (artifact_id,), artifact_from_dict)

    def save_execution(self, record: ExecutionRecord) -> None:
        self._write("INSERT OR REPLACE INTO executions VALUES (?,?,?,?)",
                    (record.execution_id, record.project_id, self._next(), self._dump(record)))

    def get_execution(self, execution_id: str) -> ExecutionRecord | None:
        return self._one("SELECT body FROM executions WHERE id=?", (execution_id,),
                         execution_from_dict)

    def list_executions(self, project_id: str) -> list[ExecutionRecord]:
        return self._many("SELECT body FROM executions WHERE project_id=? ORDER BY seq",
                          (project_id,), execution_from_dict)

    def save_claim(self, claim: Claim) -> None:
        with self._lock:
            row = self._db.execute("SELECT seq FROM claims WHERE id=?", (claim.claim_id,)).fetchone()
        seq = row[0] if row else self._next()  # replacing keeps the original order
        self._write("INSERT OR REPLACE INTO claims VALUES (?,?,?,?,?)",
                    (claim.claim_id, claim.project_id, claim.kind.value, seq, self._dump(claim)))

    def list_claims(self, project_id: str, kind: ClaimKind | None = None) -> list[Claim]:
        if kind is None:
            return self._many("SELECT body FROM claims WHERE project_id=? ORDER BY seq",
                              (project_id,), claim_from_dict)
        return self._many("SELECT body FROM claims WHERE project_id=? AND kind=? ORDER BY seq",
                          (project_id, kind.value), claim_from_dict)

    def save_hypothesis(self, hypothesis: Hypothesis) -> None:
        self._write("INSERT OR REPLACE INTO hypotheses VALUES (?,?,?,?)",
                    (hypothesis.hypothesis_id, hypothesis.project_id, self._next(),
                     self._dump(hypothesis)))

    def get_hypothesis(self, hypothesis_id: str) -> Hypothesis | None:
        return self._one("SELECT body FROM hypotheses WHERE id=?", (hypothesis_id,),
                         hypothesis_from_dict)

    def list_hypotheses(self, project_id: str) -> list[Hypothesis]:
        return self._many("SELECT body FROM hypotheses WHERE project_id=? ORDER BY seq",
                          (project_id,), hypothesis_from_dict)

    def save_experiment(self, experiment: Experiment) -> None:
        self._write("INSERT OR REPLACE INTO experiments VALUES (?,?,?,?)",
                    (experiment.experiment_id, experiment.hypothesis_id, self._next(),
                     self._dump(experiment)))

    def get_experiment(self, experiment_id: str) -> Experiment | None:
        return self._one("SELECT body FROM experiments WHERE id=?", (experiment_id,),
                         experiment_from_dict)

    def list_experiments(self, hypothesis_id: str) -> list[Experiment]:
        return self._many("SELECT body FROM experiments WHERE hypothesis_id=? ORDER BY seq",
                          (hypothesis_id,), experiment_from_dict)

    # -- ScopeRepository ------------------------------------------------------

    def get_scope(self, project_id: str) -> Scope | None:
        return self._one("SELECT body FROM scopes WHERE id=?", (project_id,), scope_from_dict)

    def save_scope(self, scope: Scope) -> None:
        self._write("INSERT OR REPLACE INTO scopes VALUES (?,?)",
                    (scope.project_id, json.dumps(scope_to_dict(scope))))

    # -- KnowledgeRepository --------------------------------------------------

    def save_document(self, doc: KnowledgeDocument) -> None:
        self._write("INSERT OR REPLACE INTO documents VALUES (?,?,?,?,?,?,?)",
                    (doc.doc_id, doc.project_id, doc.kind, doc.source_ref or None,
                     int(doc.trusted), self._next(), self._dump(doc)))

    def find_by_source(self, source_ref: str) -> KnowledgeDocument | None:
        return self._one("SELECT body FROM documents WHERE source_ref=?", (source_ref,),
                         document_from_dict)

    def list_documents(self, project_id: str | None = None, kinds: Sequence[str] | None = None,
                       include_quarantined: bool = False) -> list[KnowledgeDocument]:
        clauses: list[str] = []
        params: list[Any] = []
        if project_id is not None:
            clauses.append("project_id=?")
            params.append(project_id)
        if kinds:
            clauses.append(f"kind IN ({','.join('?' * len(kinds))})")
            params.extend(kinds)
        if not include_quarantined:
            clauses.append("trusted=1")
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        return self._many(f"SELECT body FROM documents{where} ORDER BY seq", params,
                          document_from_dict)

    # -- EpisodeRepository ----------------------------------------------------

    def add_episode(self, episode: Episode) -> None:
        self._write("INSERT OR REPLACE INTO episodes VALUES (?,?,?,?)",
                    (episode.episode_id, episode.tool_id, self._next(), self._dump(episode)))

    def list_episodes(self, tool_id: str | None = None) -> list[Episode]:
        if tool_id is None:
            return self._many("SELECT body FROM episodes ORDER BY seq", (), episode_from_dict)
        return self._many("SELECT body FROM episodes WHERE tool_id=? ORDER BY seq", (tool_id,),
                          episode_from_dict)

    def add_calibration(self, point: CalibrationPoint) -> None:
        self._write("INSERT INTO calibration (body) VALUES (?)", (self._dump(point),))

    def list_calibration(self) -> list[CalibrationPoint]:
        return self._many("SELECT body FROM calibration ORDER BY id", (), calibration_from_dict)
