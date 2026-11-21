"""Security guardrails: pure detectors and filters.

Everything returned by a tool is untrusted data. These guards run before
output is logged, stored as evidence, or admitted into long-term memory.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from .errors import CommandRejected

# --- secret redaction ------------------------------------------------------------

_SECRETS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("private-key",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
     "[REDACTED:private-key]"),
    ("aws-key-id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED:aws-key-id]"),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "[REDACTED:github-token]"),
    ("api-key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"), "[REDACTED:api-key]"),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"), "[REDACTED:slack-token]"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
     "[REDACTED:jwt]"),
    ("auth-header",
     re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer|basic)\s+[A-Za-z0-9._~+/=\-]+"),
     r"\1\2 [REDACTED]"),
    ("credential-assignment",
     re.compile(r"(?i)\b(password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|"
                r"(?:access|auth|refresh|bearer)?[_-]?token)"
                r"(\s*[:=]\s*)(['\"]?)[^\s'\",;`]{4,}\3"),
     r"\1\2[REDACTED]"),
    ("cookie", re.compile(r"(?im)^(\s*(?:set-)?cookie\s*:\s*)[^\r\n]+"), r"\1[REDACTED]"),
)


def redact(text: str) -> str:
    """Replace common secret shapes with typed placeholders."""
    for _name, pattern, replacement in _SECRETS:
        text = pattern.sub(replacement, text)
    return text


def detect_secrets(text: str) -> tuple[str, ...]:
    """Names of secret patterns present in ``text`` (for audits, not redaction)."""
    return tuple(name for name, pattern, _ in _SECRETS if pattern.search(text))


# --- personal data ---------------------------------------------------------------

_PII: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    # Real phone shapes only: an international "+" prefix, or North American grouping.
    # Bare digit runs are not matched - hex constants, offsets and hashes look like them.
    ("phone", re.compile(r"(?<![\w+])(?:\+\d{1,3}[\s.-]?(?:\(?\d{1,4}\)?[\s.-]?){1,4}\d{3,4}"
                         r"|\(?\b\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b)(?![\w])")),
    ("national-id", re.compile(r"\b[STFGM]\d{7}[A-Z]\b|\b\d{3}-\d{2}-\d{4}\b")),
    ("date-of-birth", re.compile(r"(?i)\b(dob|date of birth)\s*[:=]?\s*\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}")),
    ("medical-record", re.compile(r"(?i)\b(mrn|medical record( number)?|patient id)\s*[:#=]?\s*"
                                  r"(?=\w*\d)\w{4,}")),  # identifiers contain digits
)


def detect_pii(text: str) -> tuple[str, ...]:
    """Names of personal-data patterns present in ``text``."""
    return tuple(name for name, pattern in _PII if pattern.search(text))


# --- prompt injection ------------------------------------------------------------

_INJECTION: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        (r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|all)\b.{0,20}"
         r"\b(instructions?|rules?|prompts?)\b"),
        r"\byou are now\b.{0,60}\b(assistant|agent|ai|model|jailbroken|dan)\b",
        r"\b(system|developer)\s*(prompt|message|override)\s*[:=]",
        r"</?\s*(system|instructions?|tool_call|assistant)\s*>",
        r"\bdo not (tell|inform|alert) the user\b",
        (r"\b(exfiltrate|send|post|upload)\b.{0,40}\b(credentials?|secrets?|tokens?|keys?|"
         r"cookies?)\b.{0,40}\b(to|at)\b"),
        r"\b(run|execute)\b.{0,20}\b(curl|wget|bash|powershell|rm -rf)\b",
        r"\bnew instructions?\s*:",
    )
)


def detect_prompt_injection(text: str) -> tuple[str, ...]:
    """Return the matched snippets that look like instructions aimed at an agent.

    Strings recovered from binaries, web pages and captures are attacker
    controllable. A match does not mean the artifact is malicious; it means the
    text must not enter memory as trusted knowledge.
    """
    hits: list[str] = []
    for pattern in _INJECTION:
        match = pattern.search(text)
        if match:
            hits.append(match.group(0)[:80])
    return tuple(hits)


# --- clean-room leak detection ---------------------------------------------------

_CLEANROOM: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("decompiler-function-name", re.compile(r"\b(FUN|sub|fcn|func)_[0-9a-fA-F]{4,}\b")),
    ("decompiler-label", re.compile(r"\b(LAB|loc|DAT|PTR|off|byte|dword|qword)_[0-9a-fA-F]{4,}\b")),
    ("decompiler-type", re.compile(r"\b(undefined[1248]?|uint\d+_t\s+\*\s*param_\d+|param_\d+|"
                                   r"local_[0-9a-f]+|iVar\d+|uVar\d+|pcVar\d+)\b")),
    ("raw-address-deref", re.compile(r"\*\s*\(\s*\w+\s*\*\s*\)\s*\(?\s*0x[0-9a-fA-F]{6,}")),
    ("disassembly", re.compile(r"(?m)^\s*(0x)?[0-9a-fA-F]{6,}\s*[:|]?\s+(mov|push|pop|call|jmp|"
                               r"lea|ldr|str|bl|cmp)\b")),
)


def detect_cleanroom_leaks(text: str) -> tuple[str, ...]:
    """Find decompiler artefacts in text destined for an implementation workspace."""
    return tuple(name for name, pattern in _CLEANROOM if pattern.search(text))


# --- free-form command filtering -------------------------------------------------

_Rule = tuple[re.Pattern[str], str]
_COMMON: tuple[_Rule, ...] = (
    (re.compile(r"^\s*#?!"), "shell escape"),
    (re.compile(r"[|<>`]|\$\("), "shell pipe, redirection or substitution"),
)
_RIZIN_WRITE: tuple[_Rule, ...] = (
    (re.compile(r"^\s*o\+"), "open for writing"),
    (re.compile(r"^\s*w[a-z0-9]*\b"), "write command"),
    (re.compile(r"^\s*r[+-]?\s*\d"), "resize file"),
)
_RIZIN_EXEC: tuple[_Rule, ...] = (
    (re.compile(r"^\s*(dc[a-z]*|ds[a-z]*|ood|doo|do)\b"), "execution command"),
)
_GDB: tuple[_Rule, ...] = (
    (re.compile(r"^\s*(shell|pipe|dump|restore|source|python|py|pi)\b"),
     "host access, file write or script execution"),
)
COMMAND_RULES: dict[str, tuple[_Rule, ...]] = {
    "rizin": _COMMON + _RIZIN_WRITE + _RIZIN_EXEC,  # local engine run by RESI itself
    "execute_rizin_command": _COMMON + _RIZIN_WRITE + _RIZIN_EXEC,
    "cutter_command": _COMMON + _RIZIN_WRITE + _RIZIN_EXEC,
    # debug sessions are already approval-gated: stepping is allowed, writes are not
    "rizin_debug_command": _COMMON + _RIZIN_WRITE,
    "gdb_console": _COMMON + _GDB,
}


def is_freeform_command_tool(tool_name: str) -> bool:
    return tool_name in COMMAND_RULES


def check_command(tool_name: str, command: str) -> None:
    """Raise CommandRejected if a free-form command is unsafe for this tool."""
    rules = COMMAND_RULES.get(tool_name, _COMMON)
    for part in re.split(r";|\n", command):
        if not part.strip():
            continue
        for pattern, reason in rules:
            if pattern.search(part):
                raise CommandRejected(f"{tool_name}: rejected {part.strip()!r} ({reason})")


# --- output normalisation --------------------------------------------------------

MAX_OUTPUT_CHARS = 200_000


@dataclass(frozen=True, slots=True)
class GuardedOutput:
    value: Any
    truncated: bool
    flags: tuple[str, ...]


def guard_output(raw: Any, limit: int = MAX_OUTPUT_CHARS) -> GuardedOutput:
    """Redact, truncate and scan tool output. Structured output stays structured."""
    text = raw if isinstance(raw, str) else json.dumps(raw, default=str)
    flags: list[str] = [f"secret:{n}" for n in detect_secrets(text)]
    flags += [f"injection:{h}" for h in detect_prompt_injection(text)]
    clean = redact(text)
    truncated = len(clean) > limit
    if truncated:
        clean = clean[:limit]
        flags.append("truncated")
    if isinstance(raw, str) or truncated:
        return GuardedOutput(clean, truncated, tuple(flags))
    try:
        return GuardedOutput(json.loads(clean), False, tuple(flags))
    except json.JSONDecodeError:
        return GuardedOutput(clean, False, tuple(flags))


@dataclass(frozen=True, slots=True)
class MemoryVerdict:
    """Decision on whether text may enter long-term memory, and how."""

    text: str
    trusted: bool
    blocked: bool
    flags: tuple[str, ...]


def screen_for_memory(text: str, medical_profile: bool) -> MemoryVerdict:
    """Admission control for the knowledge base.

    * Secrets are always redacted.
    * Prompt-injection markers quarantine the document (stored, never recalled
      as trusted context).
    * Personal data is blocked outright under medical profiles; otherwise it is
      quarantined.
    """
    flags: list[str] = []
    pii = detect_pii(text)
    injection = detect_prompt_injection(text)
    secrets = detect_secrets(text)
    flags += [f"secret:{s}" for s in secrets]
    flags += [f"pii:{p}" for p in pii]
    flags += [f"injection:{i}" for i in injection]
    if pii and medical_profile:
        return MemoryVerdict("", trusted=False, blocked=True, flags=tuple(flags))
    trusted = not pii and not injection
    return MemoryVerdict(redact(text), trusted=trusted, blocked=False, flags=tuple(flags))


def summarise_flags(flags: Sequence[str]) -> str:
    kinds = sorted({f.split(":", 1)[0] for f in flags})
    return ", ".join(kinds) if kinds else "none"
