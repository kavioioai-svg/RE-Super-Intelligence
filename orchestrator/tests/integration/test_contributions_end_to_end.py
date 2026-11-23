"""Learning contributions end to end: CLI preview/export, ingestion, HTTPS, ranking."""

from __future__ import annotations

import ast
import json
import logging
import shutil
import socket
import ssl
import subprocess
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from resi.adapters.inbound.cli import main
from resi.adapters.inbound.ingest_server import (
    ENDPOINT,
    IngestApp,
    IngestConfig,
    build_server,
    tls_context,
    token_digest,
)
from resi.adapters.outbound.contribution_store import (
    FilePendingIdStore,
    InMemoryContributionStore,
    InMemoryPendingIdStore,
    SqliteContributionStore,
)
from resi.adapters.outbound.sqlite_store import SqliteStore
from resi.application.contributions import ContributionService, IngestionService, RankingService
from resi.domain.catalog import builtin_tool_ids
from resi.domain.contributions import MAX_PAYLOAD_BYTES, RankingParameters, render
from resi.domain.enums import ClaimKind, Confidence, Module
from resi.domain.errors import ContributionConflict, InvalidContribution
from resi.domain.models import Artifact, CalibrationPoint, Claim, Episode, Project
from tests.support import FakeClock

IDS = builtin_tool_ids()
TOKEN = "test-token-not-a-secret"
SECRET_STRINGS = ("acme-client", "/Users/alice", "prj-secret", "deadbeef" * 8,
                  "ghidra --dangerous", "PRIVATE MEMO", "mcp_private")


# --- fixtures ----------------------------------------------------------------------


def seed_user_store(home: Path) -> None:
    """A realistic local store full of things that must never be shared."""
    home.mkdir(parents=True, exist_ok=True)
    store = SqliteStore(home / "resi.db")
    try:
        store.save_project(Project("prj-secret", "acme-client firmware", "general",
                                   "PRIVATE MEMO: acme-client contract", "t"))
        artifact = Artifact("/Users/alice/acme-client/fw.bin", "deadbeef" * 8, 10, "elf",
                            Module.BINARY, "ELF magic")
        store.save_artifact("prj-secret", artifact)
        store.save_claim(Claim("clm-1", "prj-secret", artifact.artifact_id, "deadbeef" * 8,
                               "cli.rizin", "1",
                               None, ClaimKind.HYPOTHESIS, "PRIVATE MEMO", "acme-client",
                               Confidence.LOW))
        for i in range(6):
            store.add_episode(Episode(f"e{i}", "cli.rizin", "elf", i != 3, 800.0 + i,
                                      f"2026-01-01T00:00:{i:02d}+00:00",
                                      "" if i != 3 else "ValueError at /Users/alice/fw.bin",
                                      tool_version="ghidra --dangerous"))
        store.add_episode(Episode("e9", "mcp_private.acme_tool", "elf", True, 1.0,
                                  "2026-01-01T00:00:09+00:00"))
        store.add_calibration(CalibrationPoint("clm-1", Confidence.HIGH, True, "t"))
    finally:
        store.close()


@pytest.fixture
def home(tmp_path: Path) -> Path:
    seed_user_store(tmp_path / "home")
    return tmp_path / "home"


def cli(home: Path, *args: str, capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    code = main(["--home", str(home), *args])
    out = capsys.readouterr()
    return code, out.out, out.err


# --- user side: preview and export ---------------------------------------------------


class TestPreviewAndExport:
    def test_preview_matches_export_byte_for_byte(self, home: Path, tmp_path: Path,
                                                  capsys: pytest.CaptureFixture[str]) -> None:
        code, preview, _ = cli(home, "contribute", "preview", capsys=capsys)
        assert code == 0
        assert cli(home, "contribute", "preview", capsys=capsys)[1] == preview  # stable
        out = tmp_path / "contribution.json"
        code, _, err = cli(home, "contribute", "export", "--out", str(out), capsys=capsys)
        assert code == 0 and out.read_text() == preview
        assert json.loads(err)["contribution_id"] == json.loads(preview)["contribution_id"]

    def test_each_export_gets_a_fresh_id(self, home: Path, tmp_path: Path,
                                         capsys: pytest.CaptureFixture[str]) -> None:
        first, second = tmp_path / "a.json", tmp_path / "b.json"
        cli(home, "contribute", "export", "--out", str(first), capsys=capsys)
        cli(home, "contribute", "export", "--out", str(second), capsys=capsys)
        a, b = json.loads(first.read_text()), json.loads(second.read_text())
        assert a["contribution_id"] != b["contribution_id"]
        assert {**a, "contribution_id": ""} == {**b, "contribution_id": ""}
        assert not (home / "contribution-pending.json").exists()

    def test_export_refuses_to_overwrite(self, home: Path, tmp_path: Path,
                                         capsys: pytest.CaptureFixture[str]) -> None:
        out = tmp_path / "c.json"
        out.write_text("keep")
        assert cli(home, "contribute", "export", "--out", str(out), capsys=capsys)[0] == 1
        assert out.read_text() == "keep"
        assert cli(home, "contribute", "export", "--out", str(out), "--force",
                   capsys=capsys)[0] == 0

    def test_sensitive_data_never_enters_the_export(self, home: Path, tmp_path: Path,
                                                    capsys: pytest.CaptureFixture[str]) -> None:
        out = tmp_path / "c.json"
        cli(home, "contribute", "export", "--out", str(out), capsys=capsys)
        text = out.read_text()
        for secret in (*SECRET_STRINGS, "art-deadbeef", "clm-1", "fw.bin", "ValueError"):
            assert secret not in text
        payload = json.loads(text)
        assert [r["tool_id"] for r in payload["tools"]] == ["cli.rizin"]
        assert payload["tools"][0]["tool_version"] == "unspecified"
        assert (payload["tools"][0]["successes"], payload["tools"][0]["failures"]) == (5, 1)

    def test_contribution_commands_work_offline(self, home: Path, tmp_path: Path,
                                                capsys: pytest.CaptureFixture[str],
                                                monkeypatch: pytest.MonkeyPatch) -> None:
        def no_network(*_: Any, **__: Any) -> Any:
            raise AssertionError("contribution commands must not touch the network")

        monkeypatch.setattr(socket.socket, "connect", no_network)
        monkeypatch.setattr(socket.socket, "connect_ex", no_network)
        monkeypatch.setattr(socket, "create_connection", no_network)
        monkeypatch.setattr(socket, "getaddrinfo", no_network)
        assert cli(home, "contribute", "preview", capsys=capsys)[0] == 0
        assert cli(home, "contribute", "export", "--out", str(tmp_path / "x.json"),
                   capsys=capsys)[0] == 0

    def test_client_side_modules_have_no_network_code(self) -> None:
        root = Path(__file__).resolve().parents[2] / "resi"
        client = [root / "domain" / "contributions.py", root / "application" / "contributions.py",
                  root / "adapters" / "outbound" / "contribution_store.py", root / "bootstrap.py",
                  root / "adapters" / "inbound" / "cli.py"]
        banned = {"socket", "ssl", "http", "urllib", "requests", "httpx"}
        for path in client:
            tree = ast.parse(path.read_text())
            names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import)
                     for a in n.names}
            names |= {n.module.split(".")[0] for n in ast.walk(tree)
                      if isinstance(n, ast.ImportFrom) and n.module and not n.level}
            assert not names & banned, f"{path.name} imports {names & banned}"

    def test_contribute_is_not_exposed_to_agents_over_mcp(self) -> None:
        from resi.adapters.inbound.mcp_server import TOOLS

        assert not [t for t in TOOLS if "contribut" in t.name]

    def test_pending_id_file_round_trip(self, tmp_path: Path) -> None:
        store = FilePendingIdStore(tmp_path / "p.json")
        assert store.get() is None
        store.put("a" * 32)
        assert store.get() == "a" * 32 and oct((tmp_path / "p.json").stat().st_mode)[-3:] == "600"
        store.clear()
        store.clear()
        assert store.get() is None
        (tmp_path / "p.json").write_text("not json")
        assert store.get() is None


# --- private side: ingestion ---------------------------------------------------------


def exported(seed: int = 0, successes: int = 9, failures: int = 1) -> bytes:
    episodes = [Episode(f"e{i}", "rea.list_procedures", "macho", i < successes, 300.0,
                        f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}+00:00")
                for i in range(successes + failures)]

    class Repo:
        def list_episodes(self, tool_id: str | None = None) -> list[Episode]:
            return episodes

        def list_calibration(self) -> list[CalibrationPoint]:
            return [CalibrationPoint("c", Confidence.MEDIUM, True, "t")]

        def add_episode(self, episode: Episode) -> None: ...

        def add_calibration(self, point: CalibrationPoint) -> None: ...

    service = ContributionService(Repo(), InMemoryPendingIdStore(), IDS,
                                  new_id=lambda: f"{seed:032x}")
    return service.preview().encode()


@pytest.fixture
def ingestion() -> tuple[IngestionService, InMemoryContributionStore]:
    store = InMemoryContributionStore()
    return IngestionService(store, FakeClock(), IDS), store


class TestIngestion:
    def test_accepts_and_stores_only_validated_aggregates(
            self, ingestion: tuple[IngestionService, InMemoryContributionStore]) -> None:
        service, store = ingestion
        result = service.accept(exported())
        assert (result.status, result.groups) == ("accepted", 1)
        record = store.get(f"{0:032x}")
        assert record is not None and record.accepted_on == "2026-01-01"
        assert set(record.payload) == {"schema", "schema_version", "contribution_id", "tools",
                                       "calibration"}

    def test_retries_are_idempotent_and_cannot_double_count(
            self, ingestion: tuple[IngestionService, InMemoryContributionStore]) -> None:
        service, store = ingestion
        body = exported()
        assert service.accept(body).status == "accepted"
        assert service.accept(body).status == "duplicate"
        reformatted = json.dumps(json.loads(body), separators=(",", ":")).encode()
        assert service.accept(reformatted).status == "duplicate"  # same counters, other bytes
        assert store.count() == 1
        ranked = RankingService(store).rank()["tools"][0]["sample"]
        assert ranked["trials"] == 10 and ranked["contributions"] == 1

    def test_conflicting_reuse_of_an_id_is_rejected(
            self, ingestion: tuple[IngestionService, InMemoryContributionStore]) -> None:
        service, store = ingestion
        service.accept(exported(seed=1, successes=9))
        with pytest.raises(ContributionConflict):
            service.accept(exported(seed=1, successes=8))
        assert store.count() == 1

    @pytest.mark.parametrize("body", [
        b"not json", b"\xff\xfe", b"[]", b'{"schema": "resi.contribution"}',
        b'{"a": 1, "a": 2}', b'{"x": NaN}',
    ])
    def test_malformed_payloads_are_rejected(
            self, body: bytes,
            ingestion: tuple[IngestionService, InMemoryContributionStore]) -> None:
        service, store = ingestion
        with pytest.raises(InvalidContribution):
            service.accept(body)
        assert store.count() == 0

    def test_unknown_fields_are_rejected(
            self, ingestion: tuple[IngestionService, InMemoryContributionStore]) -> None:
        service, _ = ingestion
        payload = json.loads(exported())
        payload["tools"][0]["hostname"] = "alice-mbp"
        with pytest.raises(InvalidContribution, match="unknown field 'hostname'"):
            service.accept(json.dumps(payload).encode())

    def test_size_limit(self, ingestion: tuple[IngestionService, InMemoryContributionStore]) -> None:
        service, _ = ingestion
        with pytest.raises(InvalidContribution, match="larger than"):
            service.accept(b" " * (MAX_PAYLOAD_BYTES + 1))
        small = IngestionService(InMemoryContributionStore(), FakeClock(), IDS, max_bytes=10)
        assert small.max_bytes == 10
        with pytest.raises(InvalidContribution):
            small.accept(exported())

    def test_sqlite_store_is_idempotent(self, tmp_path: Path) -> None:
        store = SqliteContributionStore(tmp_path / "c.db")
        service = IngestionService(store, FakeClock(), IDS)
        service.accept(exported(seed=7))
        assert service.accept(exported(seed=7)).status == "duplicate"
        assert store.count() == 1 and len(store.list_payloads()) == 1
        columns = [r[1] for r in __import__("sqlite3").connect(tmp_path / "c.db").execute(
            "PRAGMA table_info(contributions)").fetchall()]
        assert columns == ["contribution_id", "digest", "schema_version", "accepted_on", "payload"]


# --- private side: HTTP app ------------------------------------------------------------


def request(app: IngestApp, body: bytes = b"", method: str = "POST", path: str = ENDPOINT,
            **headers: str) -> tuple[int, dict[str, Any]]:
    base = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json",
            "Content-Length": str(len(body))}
    base.update({k.replace("_", "-"): v for k, v in headers.items()})
    base = {k: v for k, v in base.items() if v != "-"}
    return app.handle(method, path, base, lambda n: body[:n])


class TestHttpApp:
    @pytest.fixture
    def app(self) -> IngestApp:
        return IngestApp(IngestionService(InMemoryContributionStore(), FakeClock(), IDS),
                         token_digest(TOKEN))

    def test_status_codes(self, app: IngestApp) -> None:
        body = exported()
        assert request(app, body)[0] == 201
        assert request(app, body)[0] == 200
        assert request(app, exported(successes=3))[0] == 409  # same id, other counters
        assert request(app, b'{"bad": 1}')[0] == 400
        assert request(app, body, Authorization="Bearer wrong")[0] == 401
        assert request(app, body, Authorization="-")[0] == 401
        assert request(app, body, Authorization="Basic abc")[0] == 401
        assert request(app, body, Content_Type="text/plain")[0] == 415
        assert request(app, body, Content_Length="-")[0] == 411
        assert request(app, body, Content_Length="abc")[0] == 400
        assert request(app, body, Content_Length="-5")[0] == 400
        assert request(app, body, Content_Length=str(MAX_PAYLOAD_BYTES + 1))[0] == 413
        assert request(app, body, method="GET")[0] == 405
        assert request(app, path="/v1/other")[0] == 404
        assert request(app, method="GET", path="/v1/health") == (200, {"status": "ok"})
        assert request(app, path="/v1/health")[0] == 405

    def test_auth_is_checked_before_the_body_is_read(self, app: IngestApp) -> None:
        def explode(_: int) -> bytes:
            raise AssertionError("body read before authentication")

        assert app.handle("POST", ENDPOINT, {"Content-Length": "5"}, explode)[0] == 401

    def test_config_from_env(self, tmp_path: Path) -> None:
        env = {"RESI_INGEST_DB": str(tmp_path / "c.db"), "RESI_INGEST_TOKEN_SHA256":
               token_digest(TOKEN).upper(), "RESI_INGEST_CERT": "c.pem",
               "RESI_INGEST_KEY": "k.pem"}
        config = IngestConfig.from_env(env)
        assert config.token_sha256 == token_digest(TOKEN) and config.port == 8443
        with pytest.raises(ValueError, match="missing"):
            IngestConfig.from_env({})
        with pytest.raises(ValueError, match="SHA-256"):
            IngestConfig.from_env({**env, "RESI_INGEST_TOKEN_SHA256": TOKEN})
        with pytest.raises(ValueError, match="MAX_BYTES"):
            IngestConfig.from_env({**env, "RESI_INGEST_MAX_BYTES": "0"})


# --- private side: real HTTPS round trip -------------------------------------------------


@pytest.fixture
def tls_files(tmp_path: Path) -> tuple[Path, Path]:
    if shutil.which("openssl") is None:
        pytest.skip("openssl not available to create a test certificate")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
    return cert, key


@pytest.fixture
def https_server(tmp_path: Path, tls_files: tuple[Path, Path]) -> Iterator[tuple[str, Path]]:
    store = SqliteContributionStore(tmp_path / "server.db")
    app = IngestApp(IngestionService(store, FakeClock(), IDS), token_digest(TOKEN))
    server = build_server(app, "localhost", 0, tls_context(*tls_files))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://localhost:{server.server_address[1]}", tls_files[0]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def post(url: str, cafile: Path, body: bytes, token: str = TOKEN) -> tuple[int, dict[str, Any]]:
    context = ssl.create_default_context(cafile=str(cafile))
    req = urllib.request.Request(f"{url}{ENDPOINT}", data=body, method="POST", headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=context, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, json.loads(exc.read())


class TestHttpsServer:
    def test_round_trip_over_tls_without_logging_secrets(
            self, https_server: tuple[str, Path], caplog: pytest.LogCaptureFixture) -> None:
        url, cafile = https_server
        body = exported(seed=42)
        with caplog.at_level(logging.INFO, logger="resi.ingest"):
            assert post(url, cafile, body)[0] == 201
            assert post(url, cafile, body)[0] == 200
            assert post(url, cafile, body, token="nope")[0] == 401
        logged = "\n".join(r.getMessage() for r in caplog.records)
        assert "POST /v1/contributions -> 201" in logged
        for secret in ("127.0.0.1", "::1", TOKEN, f"{42:032x}", "rea.list_procedures"):
            assert secret not in logged

    def test_plain_http_is_refused(self, https_server: tuple[str, Path]) -> None:
        url, _ = https_server
        with pytest.raises((urllib.error.URLError, ConnectionError, OSError)):
            urllib.request.urlopen(url.replace("https", "http") + "/v1/health", timeout=5)


# --- CLI: accept and rank ------------------------------------------------------------------


def test_cli_accept_and_rank_are_deterministic(tmp_path: Path,
                                               capsys: pytest.CaptureFixture[str]) -> None:
    files = []
    for i in range(4):
        path = tmp_path / f"c{i}.json"
        path.write_bytes(exported(seed=i, successes=9 - i % 2))
        files.append(str(path))
    db = tmp_path / "private.db"
    assert main(["ingest", "accept", "--db", str(db), *files, files[0]]) == 0
    accepted = json.loads(capsys.readouterr().out)
    assert [r["status"] for r in accepted] == ["accepted"] * 4 + ["duplicate"]
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema": "resi.contribution", "extra": 1}')
    assert main(["ingest", "accept", "--db", str(db), str(bad)]) == 1
    capsys.readouterr()
    out1, out2 = tmp_path / "r1.json", tmp_path / "r2.json"
    assert main(["ingest", "rank", "--db", str(db), "--out", str(out1)]) == 0
    assert main(["ingest", "rank", "--db", str(db), "--out", str(out2), "--min-samples", "30"]) == 0
    capsys.readouterr()
    assert out1.read_text() == out2.read_text()
    ranking = json.loads(out1.read_text())
    assert ranking["input"]["contributions"] == 4
    assert ranking["tools"][0]["sample"]["trials"] == 38  # 10 + 9 + 10 + 9
    assert ranking["tools"][0]["status"] == "ranked"
    assert main(["ingest", "rank", "--db", str(db), "--min-samples", "1000"]) == 0
    sparse = json.loads(capsys.readouterr().out)
    assert sparse["tools"][0]["use_local_ranking"] is True
    assert render(RankingService(SqliteContributionStore(db)).rank(
        RankingParameters(min_samples=1000))) == render(sparse)
