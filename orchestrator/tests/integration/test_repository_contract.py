"""One contract, every persistence adapter: proves the stores are interchangeable."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from resi.adapters.outbound.infrastructure import JsonRegistryRepository
from resi.adapters.outbound.memory_store import InMemoryStore
from resi.adapters.outbound.sqlite_store import SqliteStore
from resi.domain.enums import (
    ClaimKind,
    Confidence,
    ExecutionStatus,
    HypothesisStatus,
    Module,
    SecurityClass,
    Verification,
)
from resi.domain.models import (
    Approval,
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
from resi.domain.registry import build_registry
from tests.support import require

SHA = "9" * 64


@pytest.fixture(params=["sqlite", "memory"])
def store(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[SqliteStore | InMemoryStore]:
    if request.param == "sqlite":
        s = SqliteStore(tmp_path / "r.db")
        yield s
        s.close()
    else:
        yield InMemoryStore()


def claim(cid: str, kind: ClaimKind = ClaimKind.OBSERVED) -> Claim:
    return Claim(cid, "p", "a", SHA, "rea.t", "1", "e", kind, "obs", "int", Confidence.HIGH,
                 Verification.UNVERIFIED, "repro", "", "subj", "t")


def test_projects_scope_and_artifacts(store: SqliteStore | InMemoryStore) -> None:
    store.save_project(Project("p", "n", "general", "owner", "t"))
    assert store.get_project("p") == Project("p", "n", "general", "owner", "t")
    scope = Scope("p", "owner", {SHA}, {"dev"},
                  [Approval("a1", "rea.*", SHA, "analyst", "ok", "t", True)], {"a1"})
    store.save_scope(scope)
    loaded = store.get_scope("p")
    assert loaded is not None and loaded.approvals == scope.approvals
    assert loaded.consumed_approvals == {"a1"} and loaded.authorized_targets == {"dev"}
    art = Artifact("x", SHA, 5, "elf", Module.BINARY, "magic", {"machine": "arm"})
    store.save_artifact("p", art)
    got = require(store.get_artifact(art.artifact_id))
    assert got == art and got.details["machine"] == "arm"


def test_executions_round_trip(store: SqliteStore | InMemoryStore) -> None:
    record = ExecutionRecord("e1", "p", None, "rea.t", "1", SHA, "h", "t0", "t1",
                             ExecutionStatus.OK, {"k": [1, 2]}, "d", False, 1, 12.5, "",
                             ("secret:jwt",))
    store.save_execution(record)
    assert store.get_execution("e1") == record
    assert store.list_executions("p") == [record]


def test_claims_replace_in_place_and_filter_by_kind(store: SqliteStore | InMemoryStore) -> None:
    store.save_claim(claim("c1"))
    store.save_claim(claim("c2", ClaimKind.HYPOTHESIS))
    store.save_claim(claim("c1", ClaimKind.HYPOTHESIS))  # replace keeps original position
    assert [c.claim_id for c in store.list_claims("p")] == ["c1", "c2"]
    assert len(store.list_claims("p", ClaimKind.HYPOTHESIS)) == 2
    assert store.list_claims("p", ClaimKind.OBSERVED) == []


def test_hypotheses_and_experiments(store: SqliteStore | InMemoryStore) -> None:
    h = Hypothesis("h1", "p", "s", "pr", "f", HypothesisStatus.OPEN, "t", "t")
    store.save_hypothesis(h)
    e = Experiment("x1", "h1", "plan", SecurityClass.DYNAMIC, 1.5, "t", "e1", "out", False)
    store.save_experiment(e)
    assert store.get_hypothesis("h1") == h and store.list_hypotheses("p") == [h]
    assert store.get_experiment("x1") == e and store.list_experiments("h1") == [e]


def test_knowledge_filters(store: SqliteStore | InMemoryStore) -> None:
    store.save_document(KnowledgeDocument("d1", "lesson", "t", "x", "t", None, ("a",), "lesson:k"))
    store.save_document(KnowledgeDocument("d2", "note", "t", "y", "t", "p", trusted=False,
                                          vector=(0.1, 0.2)))
    assert [d.doc_id for d in store.list_documents()] == ["d1"]
    assert {d.doc_id for d in store.list_documents(include_quarantined=True)} == {"d1", "d2"}
    assert store.list_documents(kinds=["note"], include_quarantined=True)[0].vector == (0.1, 0.2)
    assert require(store.find_by_source("lesson:k")).doc_id == "d1"
    assert store.list_documents(project_id="p") == []


def test_document_updated_at_round_trips(store: SqliteStore | InMemoryStore) -> None:
    doc = KnowledgeDocument("d1", "lesson", "t", "x", "2026-01-01", source_ref="lesson:k",
                            updated_at="2026-01-02")
    store.save_document(doc)
    assert require(store.find_by_source("lesson:k")).updated_at == "2026-01-02"


def test_documents_without_updated_at_fall_back_to_created_at() -> None:
    from resi.adapters.outbound.serialization import document_from_dict
    legacy = {"doc_id": "d1", "kind": "lesson", "title": "t", "text": "x",
              "created_at": "2026-01-01"}
    assert document_from_dict(legacy).updated_at == "2026-01-01"


def test_episodes_and_calibration(store: SqliteStore | InMemoryStore) -> None:
    store.add_episode(Episode("e1", "t1", "elf", True, 5.0, "t"))
    store.add_episode(Episode("e2", "t2", "elf", False, 5.0, "t", "timeout", kind="execution"))
    assert [e.episode_id for e in store.list_episodes()] == ["e1", "e2"]
    assert [e.episode_id for e in store.list_episodes("t2")] == ["e2"]
    store.add_calibration(CalibrationPoint("c", Confidence.LOW, True, "t"))
    assert store.list_calibration() == [CalibrationPoint("c", Confidence.LOW, True, "t")]


def test_sqlite_persists_across_reopen(tmp_path: Path) -> None:
    path = tmp_path / "persist.db"
    first = SqliteStore(path)
    first.save_claim(claim("c1"))
    first.close()
    second = SqliteStore(path)
    second.save_claim(claim("c2"))
    assert [c.claim_id for c in second.list_claims("p")] == ["c1", "c2"]
    second.close()


def test_json_registry_round_trip(tmp_path: Path) -> None:
    repo = JsonRegistryRepository(tmp_path / "registry.json")
    assert repo.load() is None
    registry = build_registry(["mcp__rea__list_strings"])
    registry.verify("rea.list_strings", "2.1", "exe-1")
    repo.save(registry)
    loaded = repo.load()
    assert loaded is not None and list(loaded) == list(registry)
