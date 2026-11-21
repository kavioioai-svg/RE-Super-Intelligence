"""Import expert procedures (RESI's own and other installed RE skills) into memory."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ..domain.playbooks import chunk_markdown
from .knowledge import KnowledgeService
from .ports import DocumentSource


@dataclass(frozen=True, slots=True)
class PlaybookImport:
    files: int
    sections_stored: int
    sections_quarantined: int
    sections_blocked: int
    sources: tuple[str, ...]


class PlaybookService:
    def __init__(self, source: DocumentSource, knowledge: KnowledgeService):
        self._source = source
        self._knowledge = knowledge

    def import_paths(self, paths: Sequence[str]) -> PlaybookImport:
        """Import Markdown files (or every ``*.md`` under directories) as playbooks.

        Each section keeps its origin in ``source_ref`` and tags, so retrieval
        always shows where guidance came from. Re-importing updates sections in
        place. All text passes memory admission control: anything that looks
        like an injected instruction is quarantined, never recalled as trusted.
        """
        files = stored = quarantined = blocked = 0
        sources: list[str] = []
        for document in self._source.markdown_documents(paths):
            files += 1
            sources.append(document.path)
            for section in chunk_markdown(document.text, document.title):
                result = self._knowledge.remember(
                    section.title, section.text, kind="playbook",
                    tags=("playbook", document.origin), source_ref=f"playbook:{document.path}#{section.anchor}")
                if result.document is None:
                    blocked += 1
                elif result.document.trusted:
                    stored += 1
                else:
                    quarantined += 1
        return PlaybookImport(files, stored, quarantined, blocked, tuple(sources))
