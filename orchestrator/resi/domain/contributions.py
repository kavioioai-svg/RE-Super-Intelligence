"""Learning contributions: the shared-statistics schema, its validator and the ranking job.

A contribution is an opt-in, user-exported file of aggregate counters. It is
built from the same episodes and calibration points the local learning engine
uses, with the same outcome rules, and contains nothing else:

* per (built-in tool id, tool version, artifact kind): successes, failures,
  latency buckets, validated and downgraded claims;
* per stated confidence level: how many claims the validator upheld or
  overturned;
* a random contribution id, new for every export, used only to make uploads
  idempotent.

Everything here is pure: no I/O, no clock, no randomness. Callers supply the
contribution id and the set of built-in tool ids.
"""

from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .enums import Confidence
from .hashing import stable_digest
from .learning import (
    CONFIDENCE_PROBABILITY,
    OVERCONFIDENCE_MARGIN,
    is_resolved_environment_failure,
    last_success_by_tool,
)
from .models import CalibrationPoint, Episode

# --- schema ----------------------------------------------------------------------

SCHEMA = "resi.contribution"
SCHEMA_VERSION = 1
MAX_PAYLOAD_BYTES = 256 * 1024
MAX_GROUPS = 2_000
MAX_COUNTER = 10_000_000

TOP_LEVEL_FIELDS = frozenset({"schema", "schema_version", "contribution_id", "tools",
                              "calibration"})
TOOL_FIELDS = frozenset({"tool_id", "tool_version", "artifact_kind", "successes", "failures",
                         "latency_ms_buckets", "validated_claims", "downgraded_claims"})
CALIBRATION_FIELDS = frozenset({"upheld", "overturned"})
CONFIDENCE_LEVELS = tuple(level.value for level in Confidence)

# Upper bounds in milliseconds; the last bucket is open-ended.
LATENCY_BUCKETS: tuple[tuple[str, float], ...] = (
    ("lt_1s", 1_000.0), ("1s_10s", 10_000.0), ("10s_60s", 60_000.0), ("ge_60s", math.inf),
)
LATENCY_BUCKET_NAMES = tuple(name for name, _ in LATENCY_BUCKETS)

# The classifier's own kinds (domain/classification.py) plus the planner's
# generic contexts. Anything else is reported as "other".
ARTIFACT_KINDS = frozenset({
    "aab", "apk", "dos-mz", "elf", "gzip", "high-entropy-blob", "ipa", "jar", "java-class",
    "javascript", "macho", "macho-fat", "off-mesh", "openapi", "pcap", "pcapng", "pcd", "pe",
    "ply", "raw", "sqlite", "squashfs", "stl-ascii", "stl-binary", "uimage", "unknown-binary",
    "url", "wasm", "zip", "zip-corrupt", "any", "other",
})

UNSPECIFIED_VERSION = "unspecified"
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,39}$")
# Registry stamps record when this installation discovered or verified a tool,
# not which version it is; a per-installation date is a quasi-identifier.
_INSTALL_STAMP = re.compile(r"^(discovered|verified|builtin)-\d{4}-\d{2}-\d{2}$")
_CONTRIBUTION_ID = re.compile(r"^[0-9a-f]{32}$")
_ACCESS_DENIAL_MARKERS = ("permission denied", "access denied", "operation not permitted",
                          "not authorized", "unauthorized", "authorizationdenied", "forbidden")


def coarse_version(raw: str) -> str:
    """A shareable tool version, or "unspecified" for installation stamps and free text."""
    if not raw or raw == "n/a" or _INSTALL_STAMP.match(raw) or not _VERSION.match(raw):
        return UNSPECIFIED_VERSION
    return raw


def coarse_kind(raw: str) -> str:
    return raw if raw in ARTIFACT_KINDS else "other"


def is_access_denial(reason: str) -> bool:
    """Guardrail rejections and permission errors: scope decisions, not tool failures."""
    lowered = reason.lower()
    return lowered.startswith("rejected") or any(m in lowered for m in _ACCESS_DENIAL_MARKERS)


def latency_bucket(latency_ms: float) -> str:
    return next(name for name, upper in LATENCY_BUCKETS if latency_ms < upper)


# --- building a contribution -----------------------------------------------------


@dataclass(slots=True)
class _Group:
    successes: int = 0
    failures: int = 0
    validated: int = 0
    downgraded: int = 0
    latency: dict[str, int] = field(default_factory=lambda: dict.fromkeys(LATENCY_BUCKET_NAMES, 0))

    def empty(self) -> bool:
        return not (self.successes or self.failures or self.validated or self.downgraded)


def build_contribution(episodes: Sequence[Episode], calibration: Iterable[CalibrationPoint],
                       builtin_tool_ids: frozenset[str], contribution_id: str) -> dict[str, Any]:
    """The complete payload a user may choose to share. Deterministic for fixed inputs.

    Outcome rules are the local learning engine's: a trial is an execution
    episode that is not an access denial and not a setup failure the same tool
    later recovered from; claim feedback adds validated or downgraded claims.
    """
    if not _CONTRIBUTION_ID.match(contribution_id):
        raise ValueError("contribution_id must be 32 lowercase hex characters")
    last_success = last_success_by_tool(episodes)
    groups: dict[tuple[str, str, str], _Group] = defaultdict(_Group)
    for ep in episodes:
        if ep.tool_id not in builtin_tool_ids:
            continue
        group = groups[(ep.tool_id, coarse_version(ep.tool_version), coarse_kind(ep.context))]
        if ep.kind == "execution":
            if (not ep.counts_as_trial or is_access_denial(ep.failure_reason)
                    or is_resolved_environment_failure(ep, last_success)):
                continue
            if ep.success:
                group.successes += 1
            else:
                group.failures += 1
            group.latency[latency_bucket(ep.latency_ms)] += 1
        group.validated += ep.validated_claims
        group.downgraded += ep.downgraded_claims
    tools = [
        {"tool_id": tool_id, "tool_version": version, "artifact_kind": kind,
         "successes": g.successes, "failures": g.failures, "latency_ms_buckets": dict(g.latency),
         "validated_claims": g.validated, "downgraded_claims": g.downgraded}
        for (tool_id, version, kind), g in sorted(groups.items()) if not g.empty()
    ]
    by_level = {level: {"upheld": 0, "overturned": 0} for level in CONFIDENCE_LEVELS}
    for point in calibration:
        by_level[point.confidence.value]["upheld" if point.correct else "overturned"] += 1
    return {"schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "contribution_id": contribution_id, "tools": tools, "calibration": by_level}


def render(payload: Mapping[str, Any]) -> str:
    """The exact text written by export and shown by preview."""
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def contribution_digest(payload: Mapping[str, Any]) -> str:
    """Identity of the counters, used to tell an identical retry from a conflicting reuse."""
    return stable_digest(payload)


# --- validation ------------------------------------------------------------------


def _is_counter(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_COUNTER


def _fields(obj: Mapping[str, Any], allowed: frozenset[str], where: str) -> list[str]:
    errors = [f"{where}: unknown field {k!r}" for k in sorted(set(obj) - allowed)]
    errors += [f"{where}: missing field {k!r}" for k in sorted(allowed - set(obj))]
    return errors


def _validate_tool_row(row: object, where: str, builtin_tool_ids: frozenset[str]) -> list[str]:
    if not isinstance(row, dict):
        return [f"{where}: must be an object"]
    errors = _fields(row, TOOL_FIELDS, where)
    if errors:
        return errors
    if row["tool_id"] not in builtin_tool_ids:
        errors.append(f"{where}.tool_id: not a built-in tool id")
    version = row["tool_version"]
    if not isinstance(version, str) or coarse_version(version) != version:
        errors.append(f"{where}.tool_version: not an allowed version string")
    if row["artifact_kind"] not in ARTIFACT_KINDS:
        errors.append(f"{where}.artifact_kind: not an allowed kind")
    for name in ("successes", "failures", "validated_claims", "downgraded_claims"):
        if not _is_counter(row[name]):
            errors.append(f"{where}.{name}: must be an integer from 0 to {MAX_COUNTER}")
    buckets = row["latency_ms_buckets"]
    if not isinstance(buckets, dict):
        return [*errors, f"{where}.latency_ms_buckets: must be an object"]
    errors += _fields(buckets, frozenset(LATENCY_BUCKET_NAMES), f"{where}.latency_ms_buckets")
    if not errors:
        if not all(_is_counter(v) for v in buckets.values()):
            errors.append(f"{where}.latency_ms_buckets: counters must be integers "
                          f"from 0 to {MAX_COUNTER}")
        elif sum(buckets.values()) != row["successes"] + row["failures"]:
            errors.append(f"{where}.latency_ms_buckets: must sum to successes + failures")
    return errors


def validate_contribution(payload: object, builtin_tool_ids: frozenset[str]) -> tuple[str, ...]:
    """Every reason ``payload`` is unacceptable (empty tuple = acceptable)."""
    if not isinstance(payload, dict):
        return ("payload must be a JSON object",)
    errors = _fields(payload, TOP_LEVEL_FIELDS, "payload")
    if errors:
        return tuple(errors)
    if payload["schema"] != SCHEMA:
        errors.append(f"schema must be {SCHEMA!r}")
    if payload["schema_version"] != SCHEMA_VERSION or isinstance(payload["schema_version"], bool):
        errors.append(f"unsupported schema_version (this server accepts {SCHEMA_VERSION})")
    cid = payload["contribution_id"]
    if not isinstance(cid, str) or not _CONTRIBUTION_ID.match(cid):
        errors.append("contribution_id must be 32 lowercase hex characters")
    tools = payload["tools"]
    if not isinstance(tools, list):
        errors.append("tools must be a list")
    elif len(tools) > MAX_GROUPS:
        errors.append(f"tools: at most {MAX_GROUPS} groups")
    else:
        seen: set[tuple[Any, ...]] = set()
        for i, row in enumerate(tools):
            row_errors = _validate_tool_row(row, f"tools[{i}]", builtin_tool_ids)
            errors += row_errors
            if not row_errors and isinstance(row, dict):
                key = (row["tool_id"], row["tool_version"], row["artifact_kind"])
                if key in seen:
                    errors.append(f"tools[{i}]: duplicate group {key}")
                seen.add(key)
    calibration = payload["calibration"]
    if not isinstance(calibration, dict):
        errors.append("calibration must be an object")
    else:
        errors += _fields(calibration, frozenset(CONFIDENCE_LEVELS), "calibration")
        for level in CONFIDENCE_LEVELS:
            counts = calibration.get(level)
            if level in calibration and not isinstance(counts, dict):
                errors.append(f"calibration.{level}: must be an object")
            elif isinstance(counts, dict):
                level_errors = _fields(counts, CALIBRATION_FIELDS, f"calibration.{level}")
                errors += level_errors or [
                    f"calibration.{level}.{k}: must be an integer from 0 to {MAX_COUNTER}"
                    for k in sorted(CALIBRATION_FIELDS) if not _is_counter(counts[k])]
    return tuple(errors)


# --- ranking ---------------------------------------------------------------------

RANKING_SCHEMA = "resi.ranking"
RANKING_SCHEMA_VERSION = 1
MIN_SAMPLES = 30  # trials pooled for a (tool, version, kind) group before it is ranked
MIN_CONTRIBUTIONS = 3  # independent contributions behind a ranked group
PRIOR_STRENGTH = 10.0  # pseudo-trials pulling a group toward its tool's pooled rate
MIN_CALIBRATION_POINTS = 30


@dataclass(frozen=True, slots=True)
class RankingParameters:
    min_samples: int = MIN_SAMPLES
    min_contributions: int = MIN_CONTRIBUTIONS
    prior_strength: float = PRIOR_STRENGTH
    min_calibration_points: int = MIN_CALIBRATION_POINTS

    def __post_init__(self) -> None:
        if self.min_samples < 1 or self.min_contributions < 1 or self.min_calibration_points < 1:
            raise ValueError("thresholds must be at least 1")
        if self.prior_strength < 0:
            raise ValueError("prior_strength must be non-negative")


@dataclass(slots=True)
class _Pool:
    successes: int = 0
    failures: int = 0
    validated: int = 0
    downgraded: int = 0
    contributions: int = 0
    latency: dict[str, int] = field(default_factory=lambda: dict.fromkeys(LATENCY_BUCKET_NAMES, 0))

    @property
    def trials(self) -> int:
        return self.successes + self.failures


def _beta_summary(successes: float, failures: float) -> tuple[float, float]:
    """Mean and pessimistic lower bound (mean - 1 sd) of Beta(1 + s, 1 + f)."""
    a, b = 1.0 + successes, 1.0 + failures
    mean = a / (a + b)
    sd = math.sqrt((a * b) / ((a + b) ** 2 * (a + b + 1)))
    return mean, max(0.0, mean - sd)


def rank_contributions(payloads: Sequence[Mapping[str, Any]],
                       params: RankingParameters | None = None) -> dict[str, Any]:
    """Pool accepted contributions into a reviewable, data-only ranking artifact.

    Deterministic: the result depends only on the set of payloads and the
    parameters, never on input order or the clock.
    """
    params = params or RankingParameters()
    ordered = sorted(payloads, key=lambda p: str(p["contribution_id"]))
    pools: dict[tuple[str, str, str], _Pool] = defaultdict(_Pool)
    tool_totals: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    levels = {level: [0, 0] for level in CONFIDENCE_LEVELS}
    for payload in ordered:
        for row in payload["tools"]:
            pool = pools[(row["tool_id"], row["tool_version"], row["artifact_kind"])]
            pool.successes += row["successes"]
            pool.failures += row["failures"]
            pool.validated += row["validated_claims"]
            pool.downgraded += row["downgraded_claims"]
            pool.contributions += 1
            for name in LATENCY_BUCKET_NAMES:
                pool.latency[name] += row["latency_ms_buckets"][name]
            tool_totals[row["tool_id"]][0] += row["successes"]
            tool_totals[row["tool_id"]][1] += row["failures"]
        for level in CONFIDENCE_LEVELS:
            levels[level][0] += payload["calibration"][level]["upheld"]
            levels[level][1] += payload["calibration"][level]["overturned"]

    results: list[dict[str, Any]] = []
    for (tool_id, version, kind), pool in sorted(pools.items()):
        s_all, f_all = tool_totals[tool_id]
        prior = (s_all + 1.0) / (s_all + f_all + 2.0)  # the tool's pooled rate, all versions/kinds
        m = params.prior_strength
        mean, lower = _beta_summary(pool.successes + m * prior, pool.failures + m * (1 - prior))
        claims = pool.validated + pool.downgraded
        ranked = (pool.trials >= params.min_samples
                  and pool.contributions >= params.min_contributions)
        results.append({
            "tool_id": tool_id, "tool_version": version, "artifact_kind": kind,
            "sample": {"trials": pool.trials, "successes": pool.successes,
                       "failures": pool.failures, "contributions": pool.contributions,
                       "claims": claims},
            "raw_success_rate": round(pool.successes / pool.trials, 4) if pool.trials else None,
            "smoothed_success_rate": round(mean, 4),
            "smoothed_lower_bound": round(lower, 4),
            "claim_yield": round(pool.validated / claims, 4) if claims else None,
            "latency_ms_buckets": dict(pool.latency),
            "status": "ranked" if ranked else "insufficient_data",
            "use_local_ranking": not ranked,
            "rank": None,
        })
    by_kind: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in results:
        if result["status"] == "ranked":
            by_kind[result["artifact_kind"]].append(result)
    for group in by_kind.values():
        group.sort(key=lambda r: (-r["smoothed_lower_bound"], r["tool_id"], r["tool_version"]))
        for position, result in enumerate(group, start=1):
            result["rank"] = position

    calibration: dict[str, Any] = {}
    brier_sum, brier_n = 0.0, 0
    for level in CONFIDENCE_LEVELS:
        upheld, overturned = levels[level]
        n = upheld + overturned
        stated = CONFIDENCE_PROBABILITY[Confidence(level)]
        accuracy = upheld / n if n else None
        enough = n >= params.min_calibration_points
        calibration[level] = {
            "points": n, "upheld": upheld, "overturned": overturned,
            "stated_probability": stated,
            "upheld_rate": round(accuracy, 4) if accuracy is not None else None,
            "status": "measured" if enough else "insufficient_data",
            "overconfident": bool(enough and accuracy is not None
                                  and accuracy < stated - OVERCONFIDENCE_MARGIN),
        }
        brier_sum += upheld * (stated - 1.0) ** 2 + overturned * stated ** 2
        brier_n += n
    return {
        "schema": RANKING_SCHEMA,
        "schema_version": RANKING_SCHEMA_VERSION,
        "input": {"contributions": len(ordered),
                  "digest": stable_digest(sorted(contribution_digest(p) for p in ordered))},
        "parameters": {"min_samples": params.min_samples,
                       "min_contributions": params.min_contributions,
                       "prior_strength": params.prior_strength,
                       "min_calibration_points": params.min_calibration_points},
        "tools": results,
        "calibration": {"levels": calibration,
                        "brier_score": round(brier_sum / brier_n, 4) if brier_n else None,
                        "proxy_note": "upheld/overturned are Evidence Validator outcomes, a "
                                      "proxy for correctness, not ground truth"},
    }
