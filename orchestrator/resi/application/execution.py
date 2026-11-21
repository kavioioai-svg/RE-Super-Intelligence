"""Guarded tool execution.

Every call follows the same path, whether RESI drives the transport or the
host agent made the call through its own MCP client and records it here:

    authorize -> filter command -> execute (timeout, safe retry)
    -> redact + scan output -> persist execution -> audit -> learn
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

from ..domain.catalog import LOCAL_ENGINES
from ..domain.enums import ExecutionStatus
from ..domain.errors import (
    AuthorizationDenied,
    CommandRejected,
    NotFound,
    ResiError,
    ToolNotCallable,
)
from ..domain.guardrails import check_command, guard_output, is_freeform_command_tool
from ..domain.hashing import stable_digest
from ..domain.models import (
    Decision,
    Episode,
    ExecutionRecord,
    ExecutionRequest,
    ToolDescriptor,
)
from ..domain.registry import CapabilityRegistry
from .ports import (
    AuditLog,
    Clock,
    EpisodeRepository,
    EvidenceRepository,
    IdGenerator,
    ToolTransport,
)
from .projects import ProjectService
from .registry_service import RegistryService


class TransportUnavailable(ResiError):
    """RESI cannot run this tool itself; the agent calls it and uses ``record_external``."""


LOCAL_ENVIRONMENTS = ("builtin", "cli")


@dataclass(frozen=True, slots=True)
class SecurityCheck:
    """Dry-run verdict for a proposed call: nothing is executed."""

    allowed: bool
    tool_id: str
    security_class: str | None
    reason: str


class ToolExecutionService:
    def __init__(self, projects: ProjectService, registry: RegistryService,
                 evidence: EvidenceRepository, episodes: EpisodeRepository, audit: AuditLog,
                 clock: Clock, ids: IdGenerator, transport: ToolTransport | None = None):
        self._projects = projects
        self._registry = registry
        self._evidence = evidence
        self._episodes = episodes
        self._audit = audit
        self._clock = clock
        self._ids = ids
        self._transport = transport

    # -- public API -----------------------------------------------------------

    def check(self, project_id: str, request: ExecutionRequest) -> SecurityCheck:
        """Would this call be allowed? Lets any agent ask before acting."""
        request, _ = self._normalise(request, None)
        try:
            tool, decision = self._authorize(self._registry.current(), project_id, request)
        except (ToolNotCallable, AuthorizationDenied, CommandRejected) as exc:
            known = self._registry.current().get(request.tool_id)
            return SecurityCheck(False, request.tool_id,
                                 known.security_class.value if known else None, str(exc))
        return SecurityCheck(True, tool.id, tool.security_class.value, decision.reason)

    def execute(self, project_id: str, request: ExecutionRequest,
                artifact_id: str | None = None) -> ExecutionRecord:
        started, t0 = self._clock.now(), self._clock.monotonic_ms()
        request, artifact_id = self._normalise(request, artifact_id)
        try:
            tool, decision = self._authorize(self._registry.current(), project_id, request)
        except (ToolNotCallable, AuthorizationDenied, CommandRejected) as exc:
            return self._reject(project_id, request, artifact_id, started, str(exc))
        if self._transport is None or not self._transport.supports(tool.id):
            raise TransportUnavailable(
                f"RESI cannot run {tool.id} itself: call it through your agent's MCP client, "
                "then record it with resi_record_execution")
        try:
            args = self._local_args(tool, request, artifact_id)
        except AuthorizationDenied as exc:
            return self._reject(project_id, request, artifact_id, started, str(exc))
        request = replace(request, args=args)

        status, raw, error, attempts = ExecutionStatus.ERROR, None, "", 0
        max_attempts = 2 if tool.security_class.retryable else 1
        for attempts in range(1, max_attempts + 1):
            try:
                raw = self._transport.invoke(tool.id, request.args, tool.timeout_s)
            except TimeoutError:
                status, error = ExecutionStatus.TIMEOUT, f"timeout after {tool.timeout_s}s"
                continue
            except Exception as exc:  # noqa: BLE001 - port boundary: failures become evidence
                status, error = ExecutionStatus.ERROR, f"{type(exc).__name__}: {exc}"
                continue
            status, error = ExecutionStatus.OK, ""
            break
        return self._complete(project_id, request, artifact_id, tool, decision, started,
                              self._clock.monotonic_ms() - t0, status, raw, error, attempts)

    def record_external(self, project_id: str, request: ExecutionRequest, raw_output: Any,
                        succeeded: bool = True, latency_ms: float = 0.0, error: str = "",
                        artifact_id: str | None = None) -> ExecutionRecord:
        """Record a call the host agent made itself. Guardrails still apply: an
        out-of-scope or unapproved call is recorded as rejected and audited."""
        started = self._clock.now()
        request, artifact_id = self._normalise(request, artifact_id)
        try:
            tool, decision = self._authorize(self._registry.current(), project_id, request)
        except (ToolNotCallable, AuthorizationDenied, CommandRejected) as exc:
            return self._reject(project_id, request, artifact_id, started,
                                f"{exc} (reported by agent as already executed)")
        status = ExecutionStatus.OK if succeeded else ExecutionStatus.ERROR
        return self._complete(project_id, request, artifact_id, tool, decision, started,
                              latency_ms, status, raw_output if succeeded else None, error, 1)

    def verify_tool(self, execution_id: str, version: str = "") -> ToolDescriptor:
        """Promote a tool to ``verified`` using one of its own successful executions on an
        authorized target. Evidence, not assertion: there is no other way in."""
        record = self._evidence.get_execution(execution_id)
        if record is None:
            raise NotFound(f"execution {execution_id}")
        if not record.succeeded:
            raise ToolNotCallable(f"{execution_id} did not succeed ({record.status.value}); "
                                  "a tool is verified only by a successful run")
        if not self._projects.scope(record.project_id).in_scope(record.target):
            raise AuthorizationDenied(f"{execution_id} ran against an out-of-scope target")
        self._registry.verify(record.tool_id, version or f"verified-{record.finished_at[:10]}",
                              execution_id)
        verified = self._registry.current().get(record.tool_id)
        if verified is None:  # pragma: no cover - verify() raises first
            raise NotFound(record.tool_id)
        self._audit.append({"event": "tool_verified", "at": self._clock.now(),
                            "project_id": record.project_id, "tool": record.tool_id,
                            "execution_id": execution_id, "version": verified.version})
        return verified

    # -- internals ------------------------------------------------------------

    def _authorize(self, registry: CapabilityRegistry, project_id: str,
                   request: ExecutionRequest) -> tuple[ToolDescriptor, Decision]:
        tool = registry.require_usable(request.tool_id)
        decision = self._projects.scope(project_id).check(tool, request.target)
        if not decision.allowed:
            raise AuthorizationDenied(f"{tool.id}: {decision.reason}")
        if is_freeform_command_tool(tool.name):
            check_command(tool.name, str(request.args.get("command", "")))
        return tool, decision

    def _local_args(self, tool: ToolDescriptor, request: ExecutionRequest,
                    artifact_id: str | None) -> Mapping[str, Any]:
        """Local engines and built-ins only ever open the authorized artifact file.

        The agent cannot choose the path: it is taken from the artifact record and
        re-hashed against the authorized target immediately before the run.
        """
        if tool.environment not in LOCAL_ENVIRONMENTS and tool.id not in LOCAL_ENGINES:
            return request.args
        artifact = self._evidence.get_artifact(artifact_id) if artifact_id else None
        if artifact is None or artifact.sha256 != request.target:
            raise AuthorizationDenied(f"{tool.id}: local tools run only on an authorized "
                                      "artifact file (pass its path or SHA-256 as target)")
        if self._projects.resolve_target(artifact.path) != artifact.sha256:
            raise AuthorizationDenied(f"{tool.id}: {artifact.path} changed since it was "
                                      "authorized; re-authorize it")
        return {**request.args, "path": artifact.path}

    def _normalise(self, request: ExecutionRequest,
                   artifact_id: str | None) -> tuple[ExecutionRequest, str | None]:
        """Resolve file-path targets to SHA-256 so plans and guardrails agree, and fill in
        the artifact id when the target is a known artifact."""
        target = self._projects.resolve_target(request.target)
        if artifact_id is None and len(target) == 64:
            candidate = f"art-{target[:12]}"
            if self._evidence.get_artifact(candidate) is not None:
                artifact_id = candidate
        return (request if target == request.target else replace(request, target=target)), artifact_id

    def _context(self, artifact_id: str | None) -> str:
        if artifact_id is None:
            return "any"
        artifact = self._evidence.get_artifact(artifact_id)
        return artifact.kind if artifact else "any"

    def _reject(self, project_id: str, request: ExecutionRequest, artifact_id: str | None,
                started: str, reason: str) -> ExecutionRecord:
        record = ExecutionRecord(
            self._ids.new("exe"), project_id, artifact_id, request.tool_id, "n/a", request.target,
            stable_digest(dict(request.args)), started, self._clock.now(),
            ExecutionStatus.REJECTED, None, "", False, 0, 0.0, reason,
        )
        self._persist(record, reason=f"rejected: {reason}")
        return record

    def _complete(self, project_id: str, request: ExecutionRequest, artifact_id: str | None,
                  tool: ToolDescriptor, decision: Decision, started: str, latency_ms: float,
                  status: ExecutionStatus, raw: Any, error: str, attempts: int) -> ExecutionRecord:
        scope = self._projects.scope(project_id)
        scope.consume(decision)
        self._projects.record_scope_usage(scope)
        guarded = guard_output(raw) if status is ExecutionStatus.OK else None
        record = ExecutionRecord(
            self._ids.new("exe"), project_id, artifact_id, tool.id, tool.version, request.target,
            stable_digest(dict(request.args)), started, self._clock.now(), status,
            guarded.value if guarded else None,
            stable_digest(guarded.value) if guarded else "",
            guarded.truncated if guarded else False, attempts, round(latency_ms, 2),
            error, guarded.flags if guarded else (),
        )
        self._persist(record, reason=error, security_class=tool.security_class.value,
                      decision=decision.reason)
        return record

    def _persist(self, record: ExecutionRecord, reason: str = "",
                 security_class: str | None = None, decision: str | None = None) -> None:
        self._evidence.save_execution(record)
        self._episodes.add_episode(Episode(
            self._ids.new("epi"), record.tool_id, self._context(record.artifact_id),
            record.succeeded, record.latency_ms, record.finished_at,
            failure_reason="" if record.succeeded else (reason or record.status.value),
        ))
        event: Mapping[str, Any] = {
            "event": "execution", "at": record.finished_at, "project_id": record.project_id,
            "execution_id": record.execution_id, "tool": record.tool_id, "target": record.target,
            "status": record.status.value, "class": security_class, "decision": decision,
            "attempts": record.attempts, "latency_ms": record.latency_ms,
            "flags": list(record.flags), "error": record.error,
        }
        self._audit.append(event)
