"""Closed vocabularies used across the domain."""

from __future__ import annotations

from enum import Enum


class SecurityClass(str, Enum):
    """How much a tool can affect the world. Drives the approval gate."""

    READ_ONLY = "R"
    LOCAL_WRITE = "L"
    DYNAMIC = "D"
    DEVICE_MUTATING = "M"

    @property
    def requires_approval(self) -> bool:
        return self in (SecurityClass.DYNAMIC, SecurityClass.DEVICE_MUTATING)

    @property
    def retryable(self) -> bool:
        """Only side-effect-free classes may be retried automatically."""
        return not self.requires_approval

    @property
    def risk(self) -> int:
        """Risk factor (1-5) used by experiment prioritisation."""
        return {"R": 1, "L": 3, "D": 5, "M": 5}[self.value]


class ToolStatus(str, Enum):
    VERIFIED = "verified"  # exercised on an approved sample, evidence on file
    DISCOVERED = "discovered"  # announced / installed, never exercised
    UNVERIFIED = "unverified"  # named by the spec but not found
    INCOMPATIBLE = "incompatible"  # present but unusable on this platform

    @property
    def usable(self) -> bool:
        return self in (ToolStatus.VERIFIED, ToolStatus.DISCOVERED)


class Module(str, Enum):
    BINARY = "binary"
    RUNTIME = "runtime"
    FIRMWARE = "firmware"
    MOBILE = "mobile"
    PROTOCOL = "protocol"
    WEB = "web"
    VISION = "vision"
    EVIDENCE = "evidence"
    UNCATALOGUED = "uncatalogued"


class ClaimKind(str, Enum):
    OBSERVED = "observed"  # what a tool literally returned
    TOOL_DERIVED = "tool_derived"  # a tool's interpretation (decompiler, dissector)
    HYPOTHESIS = "hypothesis"  # an analyst / model inference, not yet tested
    VERIFIED = "verified"  # confirmed by an experiment that could have failed

    @property
    def needs_execution(self) -> bool:
        return self is not ClaimKind.HYPOTHESIS


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Verification(str, Enum):
    UNVERIFIED = "unverified"
    SUPPORTED = "supported"
    VERIFIED = "verified"
    REJECTED = "rejected"
    DOWNGRADED = "downgraded"


class HypothesisStatus(str, Enum):
    OPEN = "open"
    SUPPORTED = "supported"
    REJECTED = "rejected"
    VERIFIED = "verified"


class ExecutionStatus(str, Enum):
    OK = "ok"
    ERROR = "error"
    TIMEOUT = "timeout"
    REJECTED = "rejected"
