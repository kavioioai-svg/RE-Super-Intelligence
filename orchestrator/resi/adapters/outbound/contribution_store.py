"""Persistence for learning contributions.

* ``FilePendingIdStore`` (user side): one small file holding the id of the next
  export, so preview and export show the same payload. Cleared after each
  export, so no id outlives one contribution.
* ``SqliteContributionStore`` (private ingestion side): accepted, validated
  aggregates only. No request bodies, credentials or network addresses: the
  table has no column for them.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import closing
from pathlib import Path
from typing import Any

from ...domain.models import StoredContribution

_SCHEMA = """
CREATE TABLE IF NOT EXISTS contributions (
    contribution_id TEXT PRIMARY KEY,
    digest          TEXT NOT NULL,
    schema_version  INTEGER NOT NULL,
    accepted_on     TEXT NOT NULL,
    payload         TEXT NOT NULL
)
"""


class FilePendingIdStore:
    def __init__(self, path: Path):
        self._path = path

    def get(self) -> str | None:
        try:
            value = json.loads(self._path.read_text()).get("contribution_id")
        except (FileNotFoundError, json.JSONDecodeError, AttributeError):
            return None
        return value if isinstance(value, str) else None

    def put(self, contribution_id: str) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"contribution_id": contribution_id}))
        os.chmod(tmp, 0o600)
        tmp.replace(self._path)

    def clear(self) -> None:
        self._path.unlink(missing_ok=True)


class InMemoryPendingIdStore:
    def __init__(self) -> None:
        self._value: str | None = None

    def get(self) -> str | None:
        return self._value

    def put(self, contribution_id: str) -> None:
        self._value = contribution_id

    def clear(self) -> None:
        self._value = None


def _record(row: tuple[Any, ...]) -> StoredContribution:
    return StoredContribution(row[0], row[1], int(row[2]), row[3], json.loads(row[4]))


class SqliteContributionStore:
    """Short-lived connections per call, so the threaded ingestion server stays safe."""

    def __init__(self, path: Path):
        self._path = path
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn, conn:
            conn.execute(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path, timeout=10)

    def get(self, contribution_id: str) -> StoredContribution | None:
        with closing(self._connect()) as conn:
            row = conn.execute("SELECT contribution_id, digest, schema_version, accepted_on, "
                               "payload FROM contributions WHERE contribution_id=?",
                               (contribution_id,)).fetchone()
        return _record(row) if row else None

    def add(self, record: StoredContribution) -> bool:
        payload = json.dumps(record.payload, sort_keys=True, separators=(",", ":"))
        with self._lock, closing(self._connect()) as conn, conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO contributions VALUES (?,?,?,?,?)",
                (record.contribution_id, record.digest, record.schema_version,
                 record.accepted_on, payload))
            return cursor.rowcount == 1

    def list_payloads(self) -> list[dict[str, Any]]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT payload FROM contributions ORDER BY contribution_id").fetchall()
        return [json.loads(r[0]) for r in rows]

    def count(self) -> int:
        with closing(self._connect()) as conn:
            return int(conn.execute("SELECT COUNT(*) FROM contributions").fetchone()[0])


class InMemoryContributionStore:
    def __init__(self) -> None:
        self._records: dict[str, StoredContribution] = {}

    def get(self, contribution_id: str) -> StoredContribution | None:
        return self._records.get(contribution_id)

    def add(self, record: StoredContribution) -> bool:
        if record.contribution_id in self._records:
            return False
        self._records[record.contribution_id] = record
        return True

    def list_payloads(self) -> list[dict[str, Any]]:
        return [self._records[k].payload for k in sorted(self._records)]

    def count(self) -> int:
        return len(self._records)
