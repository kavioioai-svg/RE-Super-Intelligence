from __future__ import annotations

import pytest

pytest.importorskip("numpy")

from resi.adapters.outbound.vision_numpy import NumpyPointCloudAnalyzer
from resi.application.vision import VisionService


def test_synthetic_analysis_is_reproducible_and_accurate() -> None:
    service = VisionService(NumpyPointCloudAnalyzer())
    first, second = service.analyse_synthetic(7), service.analyse_synthetic(7)
    assert first == second  # same seed -> byte-identical result
    assert first["dataset"]["data_sha256"] == second["dataset"]["data_sha256"]
    assert first["error"]["semi_a_pct"] < 0.5 and first["error"]["semi_b_pct"] < 0.5
    assert first["error"]["perimeter_pct"] < 0.5
    assert first["measured"]["semi_a_sd_mm"] > 0  # uncertainty is always reported
    assert "not clinically validated" in first["status"]


def test_different_seed_changes_data_not_conclusions() -> None:
    service = VisionService(NumpyPointCloudAnalyzer())
    a, b = service.analyse_synthetic(1), service.analyse_synthetic(2)
    assert a["dataset"]["data_sha256"] != b["dataset"]["data_sha256"]
    assert abs(a["measured"]["semi_a_mm"] - b["measured"]["semi_a_mm"]) < 1.0
