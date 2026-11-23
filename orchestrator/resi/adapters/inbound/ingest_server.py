"""Private HTTPS endpoint that accepts explicitly uploaded learning contributions.

Runs on Kavio's own infrastructure, never on user machines. Configuration and
credentials come from the environment at deploy time:

    RESI_INGEST_DB            path of the contributions SQLite database (required)
    RESI_INGEST_TOKEN_SHA256  hex SHA-256 of the bearer token uploaders send (required)
    RESI_INGEST_CERT          TLS certificate chain, PEM (required)
    RESI_INGEST_KEY           TLS private key, PEM (required)
    RESI_INGEST_HOST          bind address (default 127.0.0.1)
    RESI_INGEST_PORT          port (default 8443)
    RESI_INGEST_MAX_BYTES     request size limit, capped by the schema limit (default 262144)

The token itself is never stored, only its hash. Request bodies, credentials
and client addresses are never written to contribution records or logs.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from ...application.contributions import IngestionService
from ...domain.contributions import MAX_PAYLOAD_BYTES
from ...domain.errors import ContributionConflict, InvalidContribution

ENDPOINT = "/v1/contributions"
HEALTH = "/v1/health"
MAX_ERRORS_RETURNED = 50
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

log = logging.getLogger("resi.ingest")


@dataclass(frozen=True, slots=True)
class IngestConfig:
    db_path: Path
    token_sha256: str
    cert_path: Path
    key_path: Path
    host: str = "127.0.0.1"
    port: int = 8443
    max_bytes: int = MAX_PAYLOAD_BYTES

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> IngestConfig:
        missing = [k for k in ("RESI_INGEST_DB", "RESI_INGEST_TOKEN_SHA256", "RESI_INGEST_CERT",
                               "RESI_INGEST_KEY") if not env.get(k)]
        if missing:
            raise ValueError(f"missing deploy-time configuration: {', '.join(missing)}")
        token_hash = env["RESI_INGEST_TOKEN_SHA256"].strip().lower()
        if not _HEX64.match(token_hash):
            raise ValueError("RESI_INGEST_TOKEN_SHA256 must be a hex SHA-256 digest")
        max_bytes = int(env.get("RESI_INGEST_MAX_BYTES", MAX_PAYLOAD_BYTES))
        if not 1 <= max_bytes <= MAX_PAYLOAD_BYTES:
            raise ValueError(f"RESI_INGEST_MAX_BYTES must be between 1 and {MAX_PAYLOAD_BYTES}")
        return cls(Path(env["RESI_INGEST_DB"]), token_hash, Path(env["RESI_INGEST_CERT"]),
                   Path(env["RESI_INGEST_KEY"]), env.get("RESI_INGEST_HOST", "127.0.0.1"),
                   int(env.get("RESI_INGEST_PORT", "8443")), max_bytes)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class IngestApp:
    """Request handling without HTTP plumbing: method, path, headers, body -> status, JSON."""

    def __init__(self, service: IngestionService, token_sha256: str):
        self._service = service
        self._token_sha256 = token_sha256

    def _authorized(self, headers: Mapping[str, str]) -> bool:
        scheme, _, token = headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return False
        return hmac.compare_digest(token_digest(token.strip()), self._token_sha256)

    def handle(self, method: str, path: str, headers: Mapping[str, str],
               read_body: Callable[[int], bytes]) -> tuple[int, dict[str, Any]]:
        headers = {k.lower(): v for k, v in headers.items()}
        if path == HEALTH:
            return (200, {"status": "ok"}) if method == "GET" else (405, {"error": "method"})
        if path != ENDPOINT:
            return 404, {"error": "not found"}
        if method != "POST":
            return 405, {"error": "use POST"}
        if not self._authorized(headers):  # before reading a single body byte
            return 401, {"error": "missing or invalid bearer token"}
        if headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
            return 415, {"error": "Content-Type must be application/json"}
        raw_length = headers.get("content-length")
        if raw_length is None:
            return 411, {"error": "Content-Length required"}
        try:
            length = int(raw_length)
        except ValueError:
            return 400, {"error": "invalid Content-Length"}
        if length < 0:
            return 400, {"error": "invalid Content-Length"}
        if length > self._service.max_bytes:
            return 413, {"error": f"payload larger than {self._service.max_bytes} bytes"}
        body = read_body(length)
        try:
            result = self._service.accept(body)
        except InvalidContribution as exc:
            return 400, {"error": "invalid contribution",
                         "details": list(exc.errors[:MAX_ERRORS_RETURNED])}
        except ContributionConflict:
            return 409, {"error": "contribution id already used with different counters"}
        status = 201 if result.status == "accepted" else 200
        return status, {"status": result.status, "contribution_id": result.contribution_id,
                        "groups": result.groups}


def _handler(app: IngestApp) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "resi-ingest"
        sys_version = ""
        timeout = 30

        def _respond(self) -> None:
            status, body = app.handle(self.command, self.path.split("?", 1)[0],
                                      dict(self.headers.items()), self.rfile.read)
            data = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            # Method, path and status only: no client address, headers or body.
            log.info("%s %s -> %d", self.command, self.path.split("?", 1)[0], status)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _respond

        def log_message(self, format: str, *args: Any) -> None:
            """Silence BaseHTTPRequestHandler, whose default logs the client address."""

    return Handler


def build_server(app: IngestApp, host: str, port: int,
                 tls: ssl.SSLContext | None) -> ThreadingHTTPServer:
    """``tls=None`` is for in-process tests only; ``serve`` always requires TLS."""
    server = ThreadingHTTPServer((host, port), _handler(app))
    if tls is not None:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    return server


def tls_context(cert: Path, key: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    return context


def serve(config: IngestConfig, service: IngestionService) -> None:  # pragma: no cover
    server = build_server(IngestApp(service, config.token_sha256), config.host, config.port,
                          tls_context(config.cert_path, config.key_path))
    log.info("resi ingest listening on https://%s:%d%s", config.host, config.port, ENDPOINT)
    with server:
        server.serve_forever()
