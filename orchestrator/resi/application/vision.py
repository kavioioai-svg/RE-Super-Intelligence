"""3D vision research use cases."""

from __future__ import annotations

from typing import Any

from .ports import PointCloudAnalyzer


class VisionService:
    def __init__(self, analyzer: PointCloudAnalyzer):
        self._analyzer = analyzer

    def analyse_synthetic(self, seed: int = 7) -> dict[str, Any]:
        """Reproducible end-to-end run on a synthetic phantom with known ground truth."""
        return self._analyzer.analyse_synthetic(seed)
