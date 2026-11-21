"""Split Markdown procedures into retrievable, attributed playbook sections."""

from __future__ import annotations

import re
from dataclasses import dataclass

_HEADING = re.compile(r"^(#{1,4})\s+(.+?)\s*#*\s*$")
_FRONTMATTER = re.compile(r"\A---\n.*?\n---\n", re.DOTALL)
MAX_SECTION_CHARS = 4_000
MIN_SECTION_CHARS = 40


@dataclass(frozen=True, slots=True)
class PlaybookSection:
    title: str  # "Document › Parent › Section"
    anchor: str  # stable slug, used for idempotent upserts
    text: str


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "section"


def _split_long(text: str, limit: int) -> list[str]:
    if len(text) <= limit:
        return [text]
    parts, current = [], ""
    for paragraph in text.split("\n\n"):
        if current and len(current) + len(paragraph) + 2 > limit:
            parts.append(current)
            current = ""
        current = f"{current}\n\n{paragraph}" if current else paragraph
        while len(current) > limit:  # a single oversized paragraph
            parts.append(current[:limit])
            current = current[limit:]
    if current:
        parts.append(current)
    return parts


def chunk_markdown(text: str, document: str, limit: int = MAX_SECTION_CHARS) -> list[PlaybookSection]:
    """Split ``text`` at headings (levels 1-4), keeping the heading path in each title.

    Frontmatter is dropped, sections shorter than a sentence are skipped, and
    oversized sections are split at paragraph boundaries. Deterministic: the
    same input always yields the same anchors, so re-imports update in place.
    """
    body = _FRONTMATTER.sub("", text, count=1)
    stack: list[tuple[int, str]] = []  # (heading level, title)
    sections: list[PlaybookSection] = []
    buffer: list[str] = []
    seen: dict[str, int] = {}

    def flush() -> None:
        content = "\n".join(buffer).strip()
        buffer.clear()
        if len(content) < MIN_SECTION_CHARS:
            return
        titles = [title for _, title in stack]
        if titles and titles[0].casefold() == document.casefold():
            titles = titles[1:]  # the document's own H1 repeats its name
        heading = " › ".join(titles) if titles else "Overview"
        base = slugify(heading)
        for i, piece in enumerate(_split_long(content, limit)):
            anchor = base if i == 0 else f"{base}-part-{i + 1}"
            count = seen.get(anchor, 0)
            seen[anchor] = count + 1
            if count:
                anchor = f"{anchor}-{count + 1}"
            sections.append(PlaybookSection(f"{document} › {heading}", anchor, piece))

    in_code = False
    for line in body.splitlines():
        if line.lstrip().startswith("```"):
            in_code = not in_code
        match = None if in_code else _HEADING.match(line)
        if match:
            flush()
            level = len(match.group(1))
            while stack and stack[-1][0] >= level:  # siblings replace, parents stay
                stack.pop()
            stack.append((level, match.group(2).strip()))
            continue
        buffer.append(line)
    flush()
    return sections
