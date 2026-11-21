"""Reconstruction scorecard: how close is a rebuilt binary to the original?

Byte-for-byte comparison of the whole file and of each section (matched by
name, so a shifted layout still scores per section), with build-volatile
regions excluded. Optional per-function scores when the caller supplies
function file ranges (for example from a decompiler's function list).

Verdicts, strongest first:
    identical                   - same SHA-256
    identical-except-volatile   - every compared byte matches; only build noise differs
    near                        - >= 99 % of compared bytes match
    partial                     - >= 50 %
    different                   - below 50 %
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

from .binary_layout import BinaryLayout, Section, VolatileRegion, parse_layout

NEAR_THRESHOLD = 99.0
PARTIAL_THRESHOLD = 50.0


@dataclass(frozen=True, slots=True)
class FunctionRange:
    name: str
    original_offset: int
    size: int
    rebuilt_offset: int | None = None  # defaults to the original offset


@dataclass(frozen=True, slots=True)
class RangeScore:
    name: str
    original_offset: int
    original_size: int
    rebuilt_size: int
    compared_bytes: int
    matched_bytes: int
    excluded_bytes: int
    first_difference: int | None  # offset relative to the start of the range

    @property
    def match_pct(self) -> float:
        """Percentage of compared bytes that match; never rounds a mismatch up to 100."""
        if self.compared_bytes == 0:
            return 100.0 if self.original_size == self.rebuilt_size else 0.0
        pct = round(100.0 * self.matched_bytes / self.compared_bytes, 4)
        return min(pct, 99.9999) if self.matched_bytes < self.compared_bytes else pct

    @property
    def identical(self) -> bool:
        return self.matched_bytes == self.compared_bytes and self.original_size == self.rebuilt_size


@dataclass(frozen=True, slots=True)
class Scorecard:
    verdict: str
    original_sha256: str
    rebuilt_sha256: str
    format: str
    architecture: str
    original_size: int
    rebuilt_size: int
    overall: RangeScore
    sections: tuple[RangeScore, ...]
    functions: tuple[RangeScore, ...]
    volatile_regions: tuple[VolatileRegion, ...]
    missing_sections: tuple[str, ...]
    extra_sections: tuple[str, ...]

    @property
    def match_pct(self) -> float:
        return self.overall.match_pct


def _volatile_mask(length: int, regions: Sequence[VolatileRegion]) -> bytearray:
    mask = bytearray(length)
    for region in regions:
        start, end = max(0, region.offset), min(length, region.end)
        if start < end:
            mask[start:end] = b"\x01" * (end - start)
    return mask


BLOCK = 4096


def _score(name: str, a: bytes, a_start: int, a_len: int, a_mask: bytearray,
           b: bytes, b_start: int, b_len: int, b_mask: bytearray) -> RangeScore:
    """Positional comparison of two ranges, skipping volatile bytes in either file.

    Blocks with no volatile bytes are compared as slices; only blocks that differ
    or contain volatile bytes fall back to per-byte work, so large identical
    binaries score in linear time with a small constant.
    """
    a_len = max(0, min(a_len, len(a) - a_start))
    b_len_avail = max(0, min(b_len, len(b) - b_start))
    span = max(a_len, b_len)
    compared = matched = excluded = 0
    first: int | None = None
    for block in range(0, span, BLOCK):
        stop = min(span, block + BLOCK)
        a_lo, a_hi = a_start + block, a_start + min(stop, a_len)
        b_lo, b_hi = b_start + block, b_start + min(stop, b_len_avail)
        full = (a_hi - a_lo) == (b_hi - b_lo) == (stop - block)
        clean = (a_mask[a_lo:a_hi].count(1) == 0) and (b_mask[b_lo:b_hi].count(1) == 0)
        if full and clean and a[a_lo:a_hi] == b[b_lo:b_hi]:
            compared += stop - block
            matched += stop - block
            continue
        for i in range(block, stop):
            ai, bi = a_start + i, b_start + i
            in_a, in_b = i < a_len, i < b_len_avail
            if (in_a and a_mask[ai]) or (in_b and b_mask[bi]):
                excluded += 1
                continue
            compared += 1
            if in_a and in_b and a[ai] == b[bi]:
                matched += 1
            elif first is None:
                first = i
    return RangeScore(name, a_start, a_len, b_len, compared, matched, excluded, first)


def _verdict(identical_hash: bool, overall: RangeScore) -> str:
    if identical_hash:
        return "identical"
    if overall.identical:
        return "identical-except-volatile"
    if overall.match_pct >= NEAR_THRESHOLD:
        return "near"
    if overall.match_pct >= PARTIAL_THRESHOLD:
        return "partial"
    return "different"


def score_reconstruction(original: bytes, rebuilt: bytes,
                         functions: Sequence[FunctionRange] = ()) -> Scorecard:
    """Score ``rebuilt`` against ``original``. Pure and deterministic."""
    a_layout: BinaryLayout = parse_layout(original)
    b_layout: BinaryLayout = parse_layout(rebuilt, prefer_cpu=a_layout.architecture)
    a_mask = _volatile_mask(len(original), a_layout.volatile)
    b_mask = _volatile_mask(len(rebuilt), b_layout.volatile)

    overall = _score("<whole file>", original, 0, len(original), a_mask,
                     rebuilt, 0, len(rebuilt), b_mask)
    b_by_name: dict[str, Section] = {s.name: s for s in b_layout.sections}
    section_scores = tuple(
        _score(s.name, original, s.offset, s.size, a_mask,
               rebuilt, b_by_name[s.name].offset, b_by_name[s.name].size, b_mask)
        for s in a_layout.sections if s.name in b_by_name
    )
    a_names = {s.name for s in a_layout.sections}
    function_scores = tuple(
        _score(f.name, original, f.original_offset, f.size, a_mask,
               rebuilt, f.original_offset if f.rebuilt_offset is None else f.rebuilt_offset,
               f.size, b_mask)
        for f in functions
    )
    same_hash = hashlib.sha256(original).digest() == hashlib.sha256(rebuilt).digest()
    return Scorecard(
        verdict=_verdict(same_hash, overall),
        original_sha256=hashlib.sha256(original).hexdigest(),
        rebuilt_sha256=hashlib.sha256(rebuilt).hexdigest(),
        format=a_layout.format,
        architecture=a_layout.architecture,
        original_size=len(original),
        rebuilt_size=len(rebuilt),
        overall=overall,
        sections=section_scores,
        functions=function_scores,
        volatile_regions=a_layout.volatile,
        missing_sections=tuple(sorted(a_names - set(b_by_name))),
        extra_sections=tuple(sorted(set(b_by_name) - a_names)),
    )
