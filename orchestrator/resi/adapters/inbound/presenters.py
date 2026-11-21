"""Convert application results into JSON-safe structures for inbound adapters."""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from enum import Enum
from typing import Any


def present(value: Any) -> Any:
    """Recursively turn dataclasses, enums, tuples and sets into JSON-safe values."""
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        data = {f.name: present(getattr(value, f.name)) for f in fields(value)}
        data.pop("vector", None)  # embeddings are noise for agents and humans
        for prop in ("artifact_id", "passed", "stored", "succeeded"):
            if hasattr(type(value), prop) and isinstance(getattr(type(value), prop), property):
                data[prop] = present(getattr(value, prop))
        return data
    if isinstance(value, dict):
        return {str(k): present(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [present(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted(present(v) for v in value)
    if isinstance(value, bytes):
        return value.hex()
    return value
