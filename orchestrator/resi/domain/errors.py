"""Domain exceptions. Adapters translate these into exit codes or messages."""

from __future__ import annotations


class ResiError(Exception):
    """Base class for every expected RESI failure."""


class AuthorizationDenied(ResiError):
    """The target or the tool's security class is outside the recorded scope."""


class ToolNotCallable(ResiError):
    """The tool is absent from the registry or not in a usable status."""


class CommandRejected(ResiError):
    """A free-form command failed the safety filter."""


class InvalidClaim(ResiError):
    """An evidence claim does not meet the evidence model's requirements."""

    def __init__(self, issues: tuple[str, ...]):
        super().__init__("; ".join(issues))
        self.issues = issues


class InvalidHypothesis(ResiError):
    """A hypothesis is not falsifiable or an outcome lacks a backing execution."""


class UnknownProfile(ResiError):
    """The requested research profile does not exist."""


class NotFound(ResiError):
    """A referenced project, hypothesis or experiment does not exist."""


class ClassificationError(ResiError):
    """The artifact could not be read or parsed."""
