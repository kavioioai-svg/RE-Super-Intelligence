"""Retrieval for RAG: BM25 lexical ranking, cosine similarity, rank fusion.

Pure Python and deterministic. Vectors come from an Embedder port supplied by
the application layer; this module only does the arithmetic.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

_TOKEN = re.compile(r"[A-Za-z0-9_]+")
_STOPWORDS = frozenset(
    ["a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has", "have", "in", "is", "it", "its", "of", "on", "or", "that", "the", "this", "to", "was", "were", "will", "with"]
)


def tokenize(text: str) -> list[str]:
    """Lowercase alphanumeric tokens; keeps identifiers like sub_4012a0 intact."""
    return [t for t in (m.group(0).lower() for m in _TOKEN.finditer(text)) if t not in _STOPWORDS]


@dataclass(frozen=True, slots=True)
class Ranked:
    doc_id: str
    score: float


class BM25Index:
    """Okapi BM25 over an in-memory corpus (k1=1.5, b=0.75)."""

    def __init__(self, corpus: Mapping[str, str], k1: float = 1.5, b: float = 0.75):
        self._k1, self._b = k1, b
        self._tf: dict[str, Counter[str]] = {d: Counter(tokenize(t)) for d, t in corpus.items()}
        self._len = {d: sum(tf.values()) for d, tf in self._tf.items()}
        self._avg = (sum(self._len.values()) / len(self._len)) if self._len else 0.0
        df: Counter[str] = Counter()
        for tf in self._tf.values():
            df.update(tf.keys())
        n = len(self._tf)
        self._idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    def search(self, query: str, k: int = 5) -> list[Ranked]:
        terms = tokenize(query)
        if not terms or not self._tf:
            return []
        scores: dict[str, float] = {}
        for doc_id, tf in self._tf.items():
            norm = self._k1 * (1 - self._b + self._b * self._len[doc_id] / (self._avg or 1.0))
            score = sum(
                self._idf.get(t, 0.0) * tf[t] * (self._k1 + 1) / (tf[t] + norm)
                for t in terms
                if t in tf
            )
            if score > 0:
                scores[doc_id] = score
        ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
        return [Ranked(d, round(s, 6)) for d, s in ranked[:k]]


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    if len(a) != len(b):
        raise ValueError("vectors must have the same dimension")
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return 0.0 if na == 0 or nb == 0 else dot / (na * nb)


def vector_search(query: Sequence[float], vectors: Mapping[str, Sequence[float]], k: int = 5) -> list[Ranked]:
    scored = [(d, cosine(query, v)) for d, v in vectors.items()]
    ranked = sorted((s for s in scored if s[1] > 0), key=lambda kv: (-kv[1], kv[0]))
    return [Ranked(d, round(s, 6)) for d, s in ranked[:k]]


def reciprocal_rank_fusion(rankings: Sequence[Sequence[Ranked]], k: int = 60, limit: int = 5) -> list[Ranked]:
    """Combine ranked lists without needing comparable scores (Cormack et al., 2009)."""
    fused: dict[str, float] = {}
    for ranking in rankings:
        for position, item in enumerate(ranking, start=1):
            fused[item.doc_id] = fused.get(item.doc_id, 0.0) + 1.0 / (k + position)
    ranked = sorted(fused.items(), key=lambda kv: (-kv[1], kv[0]))
    return [Ranked(d, round(s, 6)) for d, s in ranked[:limit]]
