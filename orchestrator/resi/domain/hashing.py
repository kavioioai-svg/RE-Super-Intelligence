"""Deterministic digests for arguments and outputs."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def stable_digest(value: Any) -> str:
    """SHA-256 of a canonical JSON rendering; identical inputs give identical digests."""
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
