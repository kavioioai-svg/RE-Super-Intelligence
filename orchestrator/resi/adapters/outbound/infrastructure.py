"""Small infrastructure adapters: clock, ids, filesystem, registry file, audit log,
environment probe, transport and embedder."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import shutil
import threading
import time
import uuid
import zipfile
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path
from typing import Any

from ...application.ports import MarkdownDocument
from ...domain.catalog import ExternalTool
from ...domain.enums import ToolStatus
from ...domain.errors import ClassificationError
from ...domain.models import ArtifactSample
from ...domain.registry import CapabilityRegistry
from ...domain.retrieval import tokenize
from .serialization import to_dict, tool_from_dict

HEAD_BYTES = 4096
MAX_READ_BYTES = 1 << 30  # 1 GiB ceiling for whole-file reads


class SystemClock:
    def now(self) -> str:
        return datetime.now(UTC).isoformat(timespec="milliseconds")

    def monotonic_ms(self) -> float:
        return time.monotonic() * 1000.0


class UuidIdGenerator:
    def new(self, prefix: str) -> str:
        return f"{prefix}-{uuid.uuid4().hex[:12]}"


class LocalArtifactReader:
    """Reads only the head of a file plus ZIP member names; never executes anything."""

    def read(self, path: str) -> ArtifactSample:
        file = Path(path).expanduser()
        if not file.is_file():
            raise ClassificationError(f"artifact not found: {file}")
        digest = hashlib.sha256()
        with file.open("rb") as handle:
            head = handle.read(HEAD_BYTES)
            digest.update(head)
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        members: tuple[str, ...] | None = None
        if head[:4] == b"PK\x03\x04":
            try:
                with zipfile.ZipFile(file) as archive:
                    members = tuple(archive.namelist())
            except zipfile.BadZipFile:
                members = None
        return ArtifactSample(str(file), file.stat().st_size, digest.hexdigest(), head, members)

    def read_bytes(self, path: str) -> bytes:
        file = Path(path).expanduser()
        if not file.is_file():
            raise ClassificationError(f"file not found: {file}")
        size = file.stat().st_size
        if size > MAX_READ_BYTES:
            raise ClassificationError(f"{file} is {size} bytes; limit is {MAX_READ_BYTES}")
        return file.read_bytes()


class JsonRegistryRepository:
    def __init__(self, path: str | Path):
        self._path = Path(path)

    def load(self) -> CapabilityRegistry | None:
        if not self._path.is_file():
            return None
        data = json.loads(self._path.read_text())
        return CapabilityRegistry(tool_from_dict(t) for t in data["tools"])

    def save(self, registry: CapabilityRegistry) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"tools": [to_dict(t) for t in registry]}, indent=2))
        tmp.replace(self._path)  # atomic on POSIX


class InMemoryRegistryRepository:
    def __init__(self) -> None:
        self._registry: CapabilityRegistry | None = None

    def load(self) -> CapabilityRegistry | None:
        return self._registry

    def save(self, registry: CapabilityRegistry) -> None:
        self._registry = registry


class JsonlAuditLog:
    """Append-only JSON-lines audit trail."""

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._lock = threading.Lock()

    def append(self, event: Mapping[str, Any]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(dict(event), default=str) + "\n")

    def read(self, project_id: str | None = None) -> list[dict[str, Any]]:
        if not self._path.is_file():
            return []
        events = [json.loads(line) for line in self._path.read_text().splitlines() if line]
        return [e for e in events if project_id is None or e.get("project_id") == project_id]


class MemoryAuditLog:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def append(self, event: Mapping[str, Any]) -> None:
        self.events.append(dict(event))

    def read(self, project_id: str | None = None) -> list[dict[str, Any]]:
        return [e for e in self.events if project_id is None or e.get("project_id") == project_id]


class SystemEnvironmentProbe:
    """Detects CLIs on PATH and importable Python libraries. Never runs them."""

    def probe(self, tools: Sequence[ExternalTool]) -> dict[str, ToolStatus]:
        status: dict[str, ToolStatus] = {}
        for tool in tools:
            present = any(shutil.which(exe) for exe in tool.executables)
            if tool.python_import:
                present = present or importlib.util.find_spec(tool.python_import) is not None
            status[tool.id] = ToolStatus.DISCOVERED if present else ToolStatus.UNVERIFIED
        return status


class CallableTransport:
    """Adapts any ``(tool_id, args) -> result`` callable (e.g. an agent's MCP client)
    and enforces the timeout."""

    def __init__(self, call: Callable[[str, Mapping[str, Any]], Any]):
        self._call = call

    def supports(self, tool_id: str) -> bool:
        return True

    def invoke(self, tool_id: str, args: Mapping[str, Any], timeout_s: int) -> Any:
        pool = ThreadPoolExecutor(max_workers=1)
        future = pool.submit(self._call, tool_id, args)
        try:
            return future.result(timeout=timeout_s)
        except FutureTimeout:
            raise TimeoutError(f"{tool_id} exceeded {timeout_s}s") from None
        finally:
            pool.shutdown(wait=False, cancel_futures=True)


class FilesystemDocumentSource:
    """Reads Markdown from files or directory trees, skipping hidden and vendored folders."""

    MAX_FILES = 500
    MAX_FILE_BYTES = 2_000_000
    SKIP_DIRS = frozenset({"node_modules", "__pycache__", "venv", ".venv"})

    def markdown_documents(self, paths: Sequence[str]) -> list[MarkdownDocument]:
        files: list[Path] = []
        for raw in paths:
            root = Path(raw).expanduser()
            if root.is_file() and root.suffix.lower() == ".md":
                files.append(root)
            elif root.is_dir():
                files.extend(sorted(
                    f for f in root.rglob("*.md")
                    if f.is_file() and not any(part.startswith(".") or part in self.SKIP_DIRS
                                               for part in f.relative_to(root).parts[:-1])))
        documents: list[MarkdownDocument] = []
        for file in dict.fromkeys(files):  # de-duplicate, keep order
            if len(documents) >= self.MAX_FILES:
                break
            if file.stat().st_size > self.MAX_FILE_BYTES:
                continue
            try:
                text = file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            documents.append(MarkdownDocument(str(file), self._title(file, text),
                                              self._origin(file), text))
        return documents

    @staticmethod
    def _title(file: Path, text: str) -> str:
        for line in text.splitlines()[:40]:
            if line.startswith("name:"):
                return line.split(":", 1)[1].strip() or file.stem
            if line.startswith("# "):
                return line[2:].strip()
        return file.stem

    @staticmethod
    def _origin(file: Path) -> str:
        for parent in file.parents:
            if (parent / "SKILL.md").is_file():
                return parent.name
        return file.parent.name


class HashingEmbedder:
    """Dependency-free feature-hashing embedder (unigrams + bigrams, L2-normalised).

    Good enough for hybrid recall over identifiers and technical vocabulary;
    swap in a neural embedder by implementing the same ``embed`` port.
    """

    def __init__(self, dimensions: int = 512):
        if dimensions <= 0:
            raise ValueError("dimensions must be positive")
        self._dimensions = dimensions

    def embed(self, text: str) -> tuple[float, ...]:
        vector = [0.0] * self._dimensions
        tokens = tokenize(text)
        features = tokens + [f"{a}_{b}" for a, b in pairwise(tokens)]
        for feature in features:
            digest = hashlib.blake2b(feature.encode(), digest_size=8).digest()
            index = int.from_bytes(digest[:4], "little") % self._dimensions
            sign = 1.0 if digest[4] & 1 else -1.0
            vector[index] += sign
        norm = math.sqrt(sum(v * v for v in vector))
        return tuple(round(v / norm, 6) for v in vector) if norm else tuple(vector)
