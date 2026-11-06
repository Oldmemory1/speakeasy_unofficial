"""Request construction for model-only child execution.

This module turns resolved target evidence and decoded process-launch facts
into one stable request record. It performs no target I/O, process creation,
queue insertion, or child execution.
"""

from __future__ import annotations

import hashlib
import shlex
from dataclasses import dataclass, field
from typing import Any

from .models import ChildExecutionState, ResolvedChildTarget


def canonicalize_command_line(command_line: str) -> str:
    """Normalize command-line formatting without changing its meaning.

    Args:
        command_line: Original command line supplied by the API caller.

    Returns:
        The command line with surrounding whitespace and quote formatting
        removed. Argument order and case are preserved.

    Side effects:
        None.
    """

    command_line = command_line.strip()
    if not command_line:
        return ""
    try:
        tokens = shlex.split(command_line, posix=False)
    except ValueError:
        return " ".join(command_line.split())
    return " ".join(token.strip('"') for token in tokens)


@dataclass
class ChildExecutionRequest:
    """Mutable stage-one request record returned to existing API handlers.

    Args:
        launch_id: Stable identifier assigned by the request factory.
        source_api: API handler that requested the launch.
        parent_pid: Emulated parent process id, when available.
        parent_tid: Emulated requesting thread id, when available.
        parent_launch_id: Parent child launch id for nested requests.
        root_sample_sha256: Identity of the root sample.
        depth: One-based child depth.
        requested_target: Original target argument or command-derived target.
        normalized_target: Canonical Windows target path.
        working_directory: Emulated working directory used for resolution.
        command_line: Complete original command line.
        command_sha256: SHA-256 of the canonical command line.
        target_source: Origin of resolved target bytes.
        target_sha256: SHA-256 of target bytes, when available.
        target_size: Target size in bytes.
        target_format: Detected target format.
        target_arch: Detected target architecture.
        target_module_type: Detected PE module kind.
        target_entrypoint_rva: Relative address of the PE entry point.
        target_resolved: Whether complete target bytes were available.
        eligible: Whether admission currently allows process-object creation.
        state: Current stage-one lifecycle state.
        process_object_created: Whether a process object was created.
        created_child_pid: PID assigned to the created process object.
        skip_reason: Machine-readable reason for an intentional skip.
        rejection_reason: Machine-readable reason for rejection/unavailability.
        target_bytes: Private target bytes excluded from equality and repr.
        target_format_detail: Detailed target format label for reporting.

    This record mutates only its own stage-one fields. It never mutates the
    emulated process object or attaches undeclared attributes to engine types.
    """

    launch_id: str
    source_api: str
    parent_pid: int | None
    parent_tid: int | None
    parent_launch_id: str | None
    root_sample_sha256: str | None
    depth: int
    requested_target: str
    normalized_target: str
    working_directory: str
    command_line: str
    command_sha256: str
    target_source: str
    target_sha256: str | None
    target_size: int
    target_format: str
    target_arch: str
    target_module_type: str
    target_entrypoint_rva: int
    target_resolved: bool
    eligible: bool
    state: str
    process_object_created: bool = False
    created_child_pid: int | None = None
    skip_reason: str | None = None
    rejection_reason: str | None = None
    target_bytes: bytes | None = field(default=None, repr=False, compare=False)
    target_format_detail: str = "unknown"

    def mark_process_created(self, process: Any) -> None:
        """Record process-object creation on this request.

        Args:
            process: Emulated process object exposing ``pid`` or ``id``.

        Returns:
            ``None``.

        Side effects:
            Mutates only this request. The supplied engine object is read, not
            modified; callers retain ownership of process-object state.
        """

        self.process_object_created = True
        self.created_child_pid = int(getattr(process, "pid", process.id))
        if self.state == ChildExecutionState.ELIGIBLE.value:
            self.state = ChildExecutionState.PROCESS_OBJECT_CREATED.value

    def to_report_dict(self) -> dict[str, Any]:
        """Return a JSON-safe request view without target bytes.

        Returns:
            A new dictionary containing report fields only.

        Side effects:
            None.
        """

        return {
            "launch_id": self.launch_id,
            "source_api": self.source_api,
            "parent_pid": self.parent_pid,
            "parent_tid": self.parent_tid,
            "parent_launch_id": self.parent_launch_id,
            "root_sample_sha256": self.root_sample_sha256,
            "depth": self.depth,
            "requested_target": self.requested_target,
            "normalized_target": self.normalized_target,
            "working_directory": self.working_directory,
            "command_line": self.command_line,
            "command_sha256": self.command_sha256,
            "target_source": self.target_source,
            "target_sha256": self.target_sha256,
            "target_size": self.target_size,
            "target_format": self.target_format,
            "target_format_detail": self.target_format_detail,
            "target_arch": self.target_arch,
            "target_module_type": self.target_module_type,
            "target_entrypoint_rva": self.target_entrypoint_rva,
            "target_resolved": self.target_resolved,
            "eligible": self.eligible,
            "state": self.state,
            "process_object_created": self.process_object_created,
            "created_child_pid": self.created_child_pid,
            "thread_queued": False,
            "entrypoint_reached": False,
            "skip_reason": self.skip_reason,
            "rejection_reason": self.rejection_reason,
        }


@dataclass
class ChildExecutionRequestFactory:
    """Build stable model-only requests from already-resolved facts.

    Args:
        sequence: Last launch sequence assigned by this factory. The next
            request receives ``sequence + 1``.

    The factory owns only launch-id allocation and request construction. It
    does not resolve paths, create processes, enqueue work, or execute code.
    """

    sequence: int = 0

    def build(
        self,
        *,
        source_api: str,
        path: str | None,
        command_line: str,
        cwd: str | None,
        target: ResolvedChildTarget,
        parent_pid: int | None,
        parent_tid: int | None,
        parent_launch_id: str | None,
        root_sample_sha256: str | None,
        depth: int,
    ) -> ChildExecutionRequest:
        """Create one request with a root-local monotonic launch id.

        Args:
            source_api: API handler that requested the launch.
            path: Explicit target path, if supplied by the API.
            command_line: Complete original command line.
            cwd: Emulated working directory, if supplied by the API.
            target: Resolver-owned evidence for the selected target bytes.
            parent_pid: Emulated parent process id.
            parent_tid: Emulated requesting thread id.
            parent_launch_id: Parent child launch id for nested requests.
            root_sample_sha256: Root sample digest.
            depth: One-based child depth computed by the registry.

        Returns:
            A mutable request whose state is ``target_resolved`` when bytes are
            available, otherwise ``unavailable``.

        Side effects:
            Increments this factory's launch sequence. No engine or target
            state is changed.
        """

        self.sequence += 1
        requested_target = (path or "").strip().strip('"')
        if not requested_target:
            requested_target = _command_target(command_line)
        payload = target.payload_ref
        command_sha256 = hashlib.sha256(
            canonicalize_command_line(command_line).encode(
                "utf-8",
                errors="replace",
            )
        ).hexdigest()
        skip_reason = (
            target.reason if target.file_format == "uri" else None
        )
        rejection_reason = (
            None if skip_reason is not None else target.reason
        )
        return ChildExecutionRequest(
            launch_id=f"child-{self.sequence:06d}",
            source_api=source_api,
            parent_pid=parent_pid,
            parent_tid=parent_tid,
            parent_launch_id=parent_launch_id,
            root_sample_sha256=root_sample_sha256,
            depth=depth,
            requested_target=requested_target,
            normalized_target=target.normalized_path,
            working_directory=cwd or "",
            command_line=command_line,
            command_sha256=command_sha256,
            target_source=target.source.value,
            target_sha256=target.sha256,
            target_size=target.size,
            target_format=target.file_format,
            target_format_detail=target.file_format,
            target_arch=target.arch,
            target_module_type=target.module_type,
            target_entrypoint_rva=target.entrypoint_rva,
            target_resolved=target.resolved,
            eligible=False,
            state=(
                ChildExecutionState.TARGET_RESOLVED.value
                if target.resolved
                else ChildExecutionState.UNAVAILABLE.value
            ),
            skip_reason=skip_reason,
            rejection_reason=rejection_reason,
            target_bytes=payload.data if payload is not None else None,
        )


def _command_target(command_line: str) -> str:
    """Return the executable token from a command line.

    Args:
        command_line: Command line that may start with a quoted path.

    Returns:
        The first token without surrounding quotes, or an empty string.

    Side effects:
        None.
    """

    if not command_line:
        return ""
    try:
        tokens = shlex.split(command_line, posix=False)
    except ValueError:
        tokens = command_line.split()
    if not tokens:
        return ""
    return tokens[0].strip().strip('"')


__all__ = [
    "ChildExecutionRequest",
    "ChildExecutionRequestFactory",
    "canonicalize_command_line",
]
