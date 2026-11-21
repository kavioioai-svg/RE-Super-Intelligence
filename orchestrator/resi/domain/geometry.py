"""Pure geometry used by the 3D vision track."""

from __future__ import annotations

import math


def ellipse_perimeter(semi_a: float, semi_b: float) -> float:
    """Ramanujan's second approximation; relative error < 1e-9 for moderate aspect ratios."""
    if semi_a <= 0 or semi_b <= 0:
        raise ValueError("semi-axes must be positive")
    h = ((semi_a - semi_b) ** 2) / ((semi_a + semi_b) ** 2)
    return math.pi * (semi_a + semi_b) * (1 + 3 * h / (10 + math.sqrt(4 - 3 * h)))


def relative_error_pct(measured: float, truth: float) -> float:
    if truth == 0:
        raise ValueError("truth must be non-zero")
    return 100.0 * abs(measured - truth) / abs(truth)
