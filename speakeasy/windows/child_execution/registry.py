"""Model-only orchestration for child launch requests.

The registry composes explicit resolver, request factory, and policy
dependencies. It records request and process-object facts but never queues or
executes child code.
"""

from __future__ import annotations

from typing import Any

from .models import AdmissionDecision
from .policy import ChildExecutionPolicy
from .request import ChildExecutionRequest, ChildExecutionRequestFactory
from .targets import ChildTargetResolver


class ChildExecutionRegistry:
    """Keep model-only child requests for one emulator instance.

    Args:
        emu: Emulator context read by the target resolver.
        policy: Admission policy; defaults to the conservative stage-one policy.
        fixtures: Optional normalized fixture path-to-bytes mappings.
        resolver: Optional explicit target resolver dependency.
        request_factory: Optional explicit request factory dependency.

    The registry owns request history, launch depth, and the active parent
    launch id. It never owns or starts a child process run.
    """

    def __init__(
        self,
        emu: Any,
        policy: ChildExecutionPolicy | None = None,
        fixtures: dict[str, bytes] | None = None,
        *,
        resolver: ChildTargetResolver | None = None,
        request_factory: ChildExecutionRequestFactory | None = None,
    ) -> None:
        self.emu = emu
        self.policy = policy or ChildExecutionPolicy()
        self.resolver = resolver or ChildTargetResolver(emu, fixtures)
        self.request_factory = request_factory or ChildExecutionRequestFactory()
        self.requests: list[ChildExecutionRequest] = []
        self.active_depth = 0
        self.active_launch_id: str | None = None

    @property
    def allow_execution(self) -> bool:
        """Return whether child execution is enabled.

        Returns:
            Always ``False`` in stage two.

        Side effects:
            None.
        """

        return False

    def register_fixture(self, path: str, data: bytes) -> None:
        """Register explicit fixture bytes with the resolver.

        Args:
            path: Windows-style fixture path.
            data: Exact bytes to serve for that path.

        Returns:
            ``None``.

        Side effects:
            Updates resolver-owned fixture state only.
        """

        self.resolver.register_fixture(path, data)

    def create_request(
        self,
        source_api: str,
        path: str | None,
        command_line: str | None,
        cwd: str | None = None,
    ) -> ChildExecutionRequest:
        """Resolve, construct, and evaluate one model-only request.

        Args:
            source_api: API handler that requested a process launch.
            path: Explicit target path, if supplied.
            command_line: Complete command line supplied by the caller.
            cwd: Optional emulated working directory.

        Returns:
            The recorded request with its final stage-one admission state.

        Side effects:
            Appends exactly one request to this registry. It does not create a
            process, enqueue work, or execute child code.
        """

        command_line = command_line or ""
        working_directory = cwd or getattr(self.emu, "cd", "")
        target = self.resolver.resolve(path, command_line, cwd=cwd)
        parent = getattr(self.emu, "curr_process", None)
        parent_thread = getattr(self.emu, "curr_thread", None)
        request = self.request_factory.build(
            source_api=source_api,
            path=path,
            command_line=command_line,
            cwd=working_directory,
            target=target,
            parent_pid=(
                int(getattr(parent, "pid", parent.id))
                if parent is not None
                else None
            ),
            parent_tid=(
                int(parent_thread.tid)
                if parent_thread is not None
                else None
            ),
            parent_launch_id=self.active_launch_id,
            root_sample_sha256=self.resolver.root_sample_sha256 or None,
            depth=self.active_depth + 1,
        )
        decision = self.policy.evaluate(
            request,
            launch_history=tuple(self.requests),
        )
        self._apply_decision(request, decision)
        self.requests.append(request)
        return request

    def summary(self) -> dict[str, Any]:
        """Return aggregate model-only request and policy facts.

        Returns:
            A new report-compatible dictionary without request objects.

        Side effects:
            None.
        """

        states: dict[str, int] = {}
        for request in self.requests:
            states[request.state] = states.get(request.state, 0) + 1
        return {
            "mode": self.policy.mode,
            "policy": {
                "max_depth": self.policy.max_depth,
                "max_children_per_root": (
                    self.policy.max_children_per_root
                ),
                "max_target_bytes": self.policy.max_target_bytes,
                "per_child_timeout_sec": (
                    self.policy.per_child_timeout_sec
                ),
                "per_child_max_api_count": (
                    self.policy.per_child_max_api_count
                ),
                "per_child_max_instructions": (
                    self.policy.per_child_max_instructions
                ),
                "allowed_sources": list(self.policy.allowed_sources),
            },
            "execution_enabled": self.allow_execution,
            "request_count": len(self.requests),
            "eligible_count": sum(
                request.eligible for request in self.requests
            ),
            "target_resolved_count": sum(
                request.target_resolved for request in self.requests
            ),
            "process_object_created_count": sum(
                request.process_object_created
                for request in self.requests
            ),
            "thread_queued_count": 0,
            "entrypoint_reached_count": 0,
            "states": states,
        }

    def to_report_dict(self) -> dict[str, Any]:
        """Return the report-compatible registry snapshot.

        Returns:
            Aggregate facts plus serialized request records.

        Side effects:
            None.
        """

        return {
            **self.summary(),
            "requests": [
                request.to_report_dict() for request in self.requests
            ],
        }

    @staticmethod
    def _apply_decision(
        request: ChildExecutionRequest,
        decision: AdmissionDecision,
    ) -> None:
        """Apply an immutable policy decision to the registry-owned request.

        Args:
            request: Request owned by this registry.
            decision: Policy result to record.

        Returns:
            ``None``.

        Side effects:
            Mutates only the supplied request's state and reason fields.
        """

        request.eligible = decision.eligible
        request.state = decision.state.value
        if decision.state.value == "skipped":
            request.skip_reason = decision.reason or request.skip_reason
        elif decision.reason is not None:
            request.rejection_reason = decision.reason
        if not request.target_resolved and not request.rejection_reason:
            request.rejection_reason = "target_unavailable"


__all__ = ["ChildExecutionRegistry"]
