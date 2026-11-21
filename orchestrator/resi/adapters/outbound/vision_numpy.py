"""PointCloudAnalyzer backed by numpy (optional ``vision`` extra).

Generates a seeded synthetic phantom (an elliptic cylinder) with known
ground truth and recovers its dimensions with bootstrap uncertainty.
No real-world data is involved at any point.
"""

from __future__ import annotations

import hashlib
import importlib
import json
from typing import Any

from ...domain.geometry import ellipse_perimeter, relative_error_pct

BOOTSTRAP_ROUNDS = 50


class NumpyPointCloudAnalyzer:
    def __init__(self, points: int = 20_000, semi_a_mm: float = 160.0, semi_b_mm: float = 110.0,
                 height_mm: float = 400.0, noise_mm: float = 1.0):
        try:
            # Loaded dynamically: numpy is an optional extra and is used untyped here.
            self._np: Any = importlib.import_module("numpy")
        except ImportError as exc:  # pragma: no cover - depends on the environment
            raise RuntimeError("install the vision extra: pip install 'resi[vision]'") from exc
        self._truth = {"semi_a_mm": semi_a_mm, "semi_b_mm": semi_b_mm,
                       "height_mm": height_mm, "noise_mm": noise_mm}
        self._points = points

    def _phantom(self, seed: int) -> Any:
        np = self._np
        rng = np.random.default_rng(seed)
        theta = rng.uniform(0.0, 2 * np.pi, self._points)
        z = rng.uniform(0.0, self._truth["height_mm"], self._points)
        cloud = np.column_stack([self._truth["semi_a_mm"] * np.cos(theta),
                                 self._truth["semi_b_mm"] * np.sin(theta), z])
        return cloud + rng.normal(0.0, self._truth["noise_mm"], cloud.shape)

    def _fit_axes(self, xy: Any) -> tuple[float, float]:
        np = self._np
        design = np.column_stack([xy[:, 0] ** 2, xy[:, 1] ** 2])
        coef, *_ = np.linalg.lstsq(design, np.ones(len(xy)), rcond=None)
        return float(1 / np.sqrt(coef[0])), float(1 / np.sqrt(coef[1]))

    def analyse_synthetic(self, seed: int) -> dict[str, Any]:
        np = self._np
        cloud = self._phantom(seed)
        xy = cloud[:, :2] - cloud[:, :2].mean(axis=0)
        semi_a, semi_b = self._fit_axes(xy)
        rng = np.random.default_rng(seed + 1)
        boots = np.array([self._fit_axes(xy[rng.integers(0, len(xy), len(xy))])
                          for _ in range(BOOTSTRAP_ROUNDS)])
        perimeter = ellipse_perimeter(semi_a, semi_b)
        true_perimeter = ellipse_perimeter(self._truth["semi_a_mm"], self._truth["semi_b_mm"])
        measured = {
            "semi_a_mm": round(semi_a, 3), "semi_a_sd_mm": round(float(boots[:, 0].std()), 3),
            "semi_b_mm": round(semi_b, 3), "semi_b_sd_mm": round(float(boots[:, 1].std()), 3),
            "height_mm": round(float(cloud[:, 2].max() - cloud[:, 2].min()), 3),
            "perimeter_mm": round(perimeter, 3),
        }
        return {
            "dataset": {"kind": "synthetic-elliptic-cylinder", "seed": seed,
                        "points": len(cloud),
                        "data_sha256": hashlib.sha256(np.round(cloud, 6).tobytes()).hexdigest()},
            "ground_truth": self._truth,
            "measured": measured,
            "error": {
                "semi_a_pct": round(relative_error_pct(semi_a, self._truth["semi_a_mm"]), 3),
                "semi_b_pct": round(relative_error_pct(semi_b, self._truth["semi_b_mm"]), 3),
                "perimeter_pct": round(relative_error_pct(perimeter, true_perimeter), 3),
            },
            "result_sha256": hashlib.sha256(json.dumps(measured, sort_keys=True).encode()).hexdigest(),
            "status": "research output - not clinically validated",
        }
