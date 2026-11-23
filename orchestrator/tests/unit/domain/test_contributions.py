from __future__ import annotations

import copy
import json
import random
from typing import Any

import pytest

from resi.domain.catalog import builtin_tool_ids
from resi.domain.contributions import (
    LATENCY_BUCKET_NAMES,
    MAX_COUNTER,
    MAX_GROUPS,
    TOOL_FIELDS,
    TOP_LEVEL_FIELDS,
    RankingParameters,
    build_contribution,
    coarse_kind,
    coarse_version,
    contribution_digest,
    is_access_denial,
    latency_bucket,
    rank_contributions,
    render,
    validate_contribution,
)
from resi.domain.enums import Confidence
from resi.domain.models import CalibrationPoint, Episode

IDS = builtin_tool_ids()
CID = "0123456789abcdef0123456789abcdef"


def ep(tool: str = "rea.list_procedures", success: bool = True, when: int = 1,
       reason: str = "", ctx: str = "macho", version: str = "", latency: float = 500.0,
       kind: str = "execution", validated: int = 0, downgraded: int = 0) -> Episode:
    return Episode(f"e{when}-{random.random()}", tool, ctx, success, latency,
                   f"2026-01-01T00:00:{when:02d}+00:00", reason, validated, downgraded, kind,
                   version)


def payload(rows: list[dict[str, Any]] | None = None, cid: str = CID,
            calibration: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"schema": "resi.contribution", "schema_version": 1, "contribution_id": cid,
            "tools": rows if rows is not None else [row()],
            "calibration": calibration or {lvl: {"upheld": 0, "overturned": 0}
                                           for lvl in ("low", "medium", "high")}}


def row(tool: str = "rea.list_procedures", version: str = "unspecified", kind: str = "macho",
        s: int = 3, f: int = 1, validated: int = 0, downgraded: int = 0) -> dict[str, Any]:
    return {"tool_id": tool, "tool_version": version, "artifact_kind": kind,
            "successes": s, "failures": f,
            "latency_ms_buckets": {"lt_1s": s + f, "1s_10s": 0, "10s_60s": 0, "ge_60s": 0},
            "validated_claims": validated, "downgraded_claims": downgraded}


def keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {k for v in value.values() for k in keys(v)}
    if isinstance(value, list):
        return {k for v in value for k in keys(v)}
    return set()


class TestBuild:
    def test_counts_reuse_local_outcome_rules(self) -> None:
        eps = [ep(success=True, when=1, latency=200), ep(success=False, when=2, reason="ValueError",
                                                       latency=2_500),
               ep(success=False, when=3, reason="rejected: out of scope"),        # guardrail
               ep(success=False, when=4, reason="PermissionError: Permission denied"),  # access
               ep(tool="rea.x_unknown", when=5),                                   # not built-in
               ep(kind="claim_feedback", success=True, validated=1, when=6)]
        rows = build_contribution(eps, [], IDS, CID)["tools"]
        assert len(rows) == 1
        r = rows[0]
        assert (r["successes"], r["failures"], r["validated_claims"]) == (1, 1, 1)
        assert r["latency_ms_buckets"] == {"lt_1s": 1, "1s_10s": 1, "10s_60s": 0, "ge_60s": 0}

    def test_resolved_setup_failures_are_not_failures(self) -> None:
        eps = [ep(success=False, when=1, reason="provider_unavailable: none"), ep(when=2)]
        r = build_contribution(eps, [], IDS, CID)["tools"][0]
        assert (r["successes"], r["failures"]) == (1, 0)

    def test_calibration_by_confidence_level(self) -> None:
        points = [CalibrationPoint("c1", Confidence.HIGH, True, "t"),
                  CalibrationPoint("c2", Confidence.HIGH, False, "t"),
                  CalibrationPoint("c3", Confidence.LOW, True, "t")]
        cal = build_contribution([], points, IDS, CID)["calibration"]
        assert cal == {"low": {"upheld": 1, "overturned": 0},
                       "medium": {"upheld": 0, "overturned": 0},
                       "high": {"upheld": 1, "overturned": 1}}

    def test_only_allowlisted_fields_and_values(self) -> None:
        eps = [ep(ctx="/Users/alice/clients/acme/firmware.bin", version="/Users/alice/x",
                  reason="boom at /Users/alice/secret.bin", success=False),
               ep(tool="mcp_private.acme_tool", ctx="elf")]
        out = build_contribution(eps, [], IDS, CID)
        assert keys(out) <= TOP_LEVEL_FIELDS | TOOL_FIELDS | set(LATENCY_BUCKET_NAMES) | {
            "low", "medium", "high", "upheld", "overturned"}
        text = render(out)
        for secret in ("/Users", "alice", "acme", "secret", "boom", "mcp_private"):
            assert secret not in text
        assert out["tools"][0]["artifact_kind"] == "other"
        assert out["tools"][0]["tool_version"] == "unspecified"
        assert validate_contribution(out, IDS) == ()

    def test_deterministic_and_order_independent(self) -> None:
        eps = [ep(when=i, success=i % 3 != 0, tool=t)
               for i, t in enumerate(["rea.list_procedures", "cli.rizin"] * 5, start=1)]
        assert render(build_contribution(eps, [], IDS, CID)) == render(
            build_contribution(list(reversed(eps)), [], IDS, CID))

    def test_rejects_malformed_contribution_id(self) -> None:
        with pytest.raises(ValueError):
            build_contribution([], [], IDS, "installation-0001")

    @pytest.mark.parametrize(("raw", "expected"), [
        ("", "unspecified"), ("n/a", "unspecified"), ("discovered-2026-11-21", "unspecified"),
        ("verified-2026-11-21", "unspecified"), ("builtin-2026-11-21", "unspecified"),
        ("ghidra-12.1.4", "ghidra-12.1.4"), ("has space", "unspecified"), ("x" * 41, "unspecified"),
    ])
    def test_coarse_version(self, raw: str, expected: str) -> None:
        assert coarse_version(raw) == expected

    def test_helpers(self) -> None:
        assert coarse_kind("macho") == "macho" and coarse_kind("weird") == "other"
        assert is_access_denial("rejected: x") and is_access_denial("HTTP 403 Forbidden")
        assert not is_access_denial("timeout after 120s")
        assert [latency_bucket(v) for v in (0, 999, 1_000, 59_999, 60_000)] == [
            "lt_1s", "lt_1s", "1s_10s", "10s_60s", "ge_60s"]


class TestValidation:
    def test_valid_payload(self) -> None:
        assert validate_contribution(payload(), IDS) == ()

    @pytest.mark.parametrize("mutate", [
        lambda p: p.update(extra="x"),                                       # unknown top field
        lambda p: p["tools"][0].update(path="/Users/a"),                     # unknown row field
        lambda p: p["tools"][0]["latency_ms_buckets"].update(lt_1ms=0),      # unknown bucket
        lambda p: p["calibration"]["high"].update(note="x"),                 # unknown level field
        lambda p: p["calibration"].update(certain={"upheld": 0, "overturned": 0}),
        lambda p: p.pop("contribution_id"),                                  # missing field
        lambda p: p.update(schema_version=2),
        lambda p: p.update(schema_version=True),
        lambda p: p.update(schema="other"),
        lambda p: p.update(contribution_id="ABC"),
        lambda p: p["tools"][0].update(tool_id="mcp_private.tool"),
        lambda p: p["tools"][0].update(tool_version="discovered-2026-01-01"),
        lambda p: p["tools"][0].update(artifact_kind="firmware.bin"),
        lambda p: p["tools"][0].update(successes=-1),
        lambda p: p["tools"][0].update(successes=True),
        lambda p: p["tools"][0].update(failures=1.5),
        lambda p: p["tools"][0].update(validated_claims=MAX_COUNTER + 1),
        lambda p: p["tools"][0]["latency_ms_buckets"].update(lt_1s=99),     # sum mismatch
        lambda p: p["tools"].append(copy.deepcopy(p["tools"][0])),           # duplicate group
        lambda p: p["calibration"]["low"].update(upheld="3"),
        lambda p: p.update(tools={}),
        lambda p: p.update(calibration=[]),
    ])
    def test_rejects(self, mutate: Any) -> None:
        bad = payload()
        mutate(bad)
        assert validate_contribution(bad, IDS)

    def test_rejects_non_objects_and_too_many_groups(self) -> None:
        assert validate_contribution([], IDS) and validate_contribution("x", IDS)
        assert validate_contribution(payload(["x"]), IDS)  # type: ignore[list-item]
        many = payload([row(kind=k) for k in ["macho"]] * (MAX_GROUPS + 1))
        assert any("at most" in e for e in validate_contribution(many, IDS))

    def test_digest_ignores_key_order(self) -> None:
        a = payload()
        b = json.loads(json.dumps(dict(reversed(list(a.items())))))
        assert contribution_digest(a) == contribution_digest(b)


def contributions(n: int, s: int, f: int, tool: str = "rea.list_procedures",
                  kind: str = "macho") -> list[dict[str, Any]]:
    return [payload([row(tool, kind=kind, s=s, f=f)], cid=f"{i:032x}") for i in range(n)]


class TestRanking:
    def test_sparse_groups_keep_local_ranking(self) -> None:
        result = rank_contributions(contributions(2, 5, 0))["tools"][0]
        assert result["status"] == "insufficient_data" and result["use_local_ranking"]
        assert result["rank"] is None
        assert result["sample"] == {"trials": 10, "successes": 10, "failures": 0,
                                    "contributions": 2, "claims": 0}

    def test_many_trials_from_too_few_contributors_stay_local(self) -> None:
        result = rank_contributions(contributions(1, 500, 0))["tools"][0]
        assert result["status"] == "insufficient_data"

    def test_ranks_within_artifact_kind_by_smoothed_lower_bound(self) -> None:
        data = contributions(4, 9, 1, tool="rea.list_procedures")
        data += [payload([row("cli.rizin", s=6, f=4)], cid=f"{i + 100:032x}") for i in range(4)]
        tools = rank_contributions(data)["tools"]
        ranked = {r["tool_id"]: r for r in tools}
        assert ranked["rea.list_procedures"]["rank"] == 1 and ranked["cli.rizin"]["rank"] == 2
        assert all(r["status"] == "ranked" for r in tools)

    def test_smoothing_pulls_toward_the_tools_pooled_rate(self) -> None:
        data = contributions(5, 90, 10)
        data += [payload([row(version="ghidra-12.1.4", s=1, f=0)], cid=f"{i + 50:032x}")
                 for i in range(1)]
        rows = {r["tool_version"]: r for r in rank_contributions(data)["tools"]}
        small = rows["ghidra-12.1.4"]
        assert small["raw_success_rate"] == 1.0
        assert 0.8 < small["smoothed_success_rate"] < 0.95  # shrunk toward ~0.9, not 1.0

    def test_deterministic_regardless_of_input_order(self) -> None:
        data = contributions(5, 7, 3) + contributions(3, 2, 2, tool="cli.rizin", kind="elf")
        shuffled = data[:]
        random.Random(4).shuffle(shuffled)
        assert render(rank_contributions(data)) == render(rank_contributions(shuffled))

    def test_calibration_is_separate_and_thresholded(self) -> None:
        cal = {"low": {"upheld": 1, "overturned": 0}, "medium": {"upheld": 0, "overturned": 0},
               "high": {"upheld": 10, "overturned": 10}}
        data = [payload(cid=f"{i:032x}", calibration=cal) for i in range(2)]
        levels = rank_contributions(data)["calibration"]["levels"]
        assert levels["high"]["points"] == 40 and levels["high"]["status"] == "measured"
        assert levels["high"]["overconfident"]  # 0.5 upheld vs 0.9 stated
        assert levels["low"]["status"] == "insufficient_data"

    def test_parameters_are_validated_and_published(self) -> None:
        with pytest.raises(ValueError):
            RankingParameters(min_samples=0)
        with pytest.raises(ValueError):
            RankingParameters(prior_strength=-1)
        out = rank_contributions([], RankingParameters(min_samples=5))
        assert out["parameters"]["min_samples"] == 5 and out["tools"] == []
        assert out["calibration"]["brier_score"] is None
