"""Tools RESI executes itself: the reconstruction scorecard and local engines (Rizin).

Every invocation arrives through ToolExecutionService, which has already
authorized the call, filtered free-form commands and replaced ``path`` with the
authorized artifact file. These adapters add the last layer: no shell, a
timeout, no user configuration files, and bounded output.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from ...application.ports import ArtifactReader, ToolTransport
from ...domain.reconstruction import FunctionRange, RangeScore, Scorecard, score_reconstruction

MAX_STDERR_CHARS = 4_000


@dataclass(frozen=True, slots=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):
    def run(self, argv: Sequence[str], timeout_s: int) -> CommandResult: ...


class SubprocessRunner:
    """Runs an argv list directly (never through a shell)."""

    def run(self, argv: Sequence[str], timeout_s: int) -> CommandResult:
        try:
            done = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout_s,
                                  check=False, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"{argv[0]} exceeded {timeout_s}s") from None
        return CommandResult(done.returncode, done.stdout, done.stderr)


def _range(score: RangeScore) -> dict[str, Any]:
    return {"name": score.name, "match_pct": score.match_pct, "identical": score.identical,
            "original_offset": score.original_offset, "original_size": score.original_size,
            "rebuilt_size": score.rebuilt_size, "compared_bytes": score.compared_bytes,
            "matched_bytes": score.matched_bytes, "excluded_volatile_bytes": score.excluded_bytes,
            "first_difference": score.first_difference}


def scorecard_to_dict(card: Scorecard) -> dict[str, Any]:
    return {
        "verdict": card.verdict, "match_pct": card.match_pct, "format": card.format,
        "architecture": card.architecture, "original_sha256": card.original_sha256,
        "rebuilt_sha256": card.rebuilt_sha256, "original_size": card.original_size,
        "rebuilt_size": card.rebuilt_size, "overall": _range(card.overall),
        "differing_sections": [_range(s) for s in card.sections if not s.identical],
        "identical_sections": [s.name for s in card.sections if s.identical],
        "functions": [_range(f) for f in card.functions],
        "volatile_regions": [{"name": v.name, "offset": v.offset, "size": v.size,
                              "reason": v.reason} for v in card.volatile_regions],
        "missing_sections": list(card.missing_sections),
        "extra_sections": list(card.extra_sections),
    }


def _functions(raw: object) -> tuple[FunctionRange, ...]:
    if not raw:
        return ()
    if not isinstance(raw, list):
        raise TypeError("functions must be a list of {name, original_offset, size, rebuilt_offset?}")
    out = []
    for item in raw:
        if not isinstance(item, dict):
            raise TypeError("each function must be an object")
        out.append(FunctionRange(str(item["name"]), int(item["original_offset"]), int(item["size"]),
                                 None if item.get("rebuilt_offset") is None
                                 else int(item["rebuilt_offset"])))
    return tuple(out)


class LocalToolTransport:
    """Executes ``resi.reconstruction_score`` and ``cli.rizin``."""

    def __init__(self, reader: ArtifactReader, runner: CommandRunner | None = None,
                 which: Callable[[str], str | None] = shutil.which):
        self._reader = reader
        self._runner = runner or SubprocessRunner()
        self._which = which

    def supports(self, tool_id: str) -> bool:
        return tool_id in ("resi.reconstruction_score", "cli.rizin")

    def invoke(self, tool_id: str, args: Mapping[str, Any], timeout_s: int) -> Any:
        if tool_id == "resi.reconstruction_score":
            return self._score(args)
        if tool_id == "cli.rizin":
            return self._rizin(args, timeout_s)
        raise ValueError(f"unsupported local tool {tool_id}")

    def _score(self, args: Mapping[str, Any]) -> dict[str, Any]:
        rebuilt = args.get("rebuilt")
        if not rebuilt:
            raise ValueError("pass 'rebuilt': the path of your rebuilt binary")
        card = score_reconstruction(self._reader.read_bytes(str(args["path"])),
                                    self._reader.read_bytes(str(rebuilt)),
                                    _functions(args.get("functions")))
        return scorecard_to_dict(card)

    def _rizin(self, args: Mapping[str, Any], timeout_s: int) -> dict[str, Any]:
        command = str(args.get("command", "")).strip()
        if not command:
            raise ValueError("pass 'command', e.g. 'ij', 'iSj', 'iij', 'izj', 'aaa;aflj', 'pdfj @ main'")
        exe = self._which("rizin")
        if exe is None:
            raise FileNotFoundError("rizin is not installed on this machine")
        # -N: ignore user rc files, -q: quiet, file opened read-only (no -w).
        result = self._runner.run([exe, "-N", "-q", "-c", command, str(args["path"])], timeout_s)
        if result.exit_code != 0:
            raise RuntimeError(f"rizin exited {result.exit_code}: {result.stderr[:500]}")
        output: Any = result.stdout
        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError:
            pass
        return {"engine": "rizin", "command": command, "output": output,
                "stderr": result.stderr[:MAX_STDERR_CHARS]}


class CompositeTransport:
    """Local tools first; everything else goes to the host agent's transport, if any."""

    def __init__(self, local: ToolTransport, fallback: ToolTransport | None = None):
        self._local = local
        self._fallback = fallback

    def supports(self, tool_id: str) -> bool:
        return self._local.supports(tool_id) or bool(self._fallback and self._fallback.supports(tool_id))

    def invoke(self, tool_id: str, args: Mapping[str, Any], timeout_s: int) -> Any:
        if self._local.supports(tool_id):
            return self._local.invoke(tool_id, args, timeout_s)
        if self._fallback is None:
            raise RuntimeError(f"no transport for {tool_id}")
        return self._fallback.invoke(tool_id, args, timeout_s)
