"""Project internal child-execution snapshots into the public report schema.

The projection is deliberately read-only.  It consumes frozen child DTOs and
emits serializable ``speakeasy.report`` models without exposing emulator
processes, scheduler queues, target bytes, or private runtime state.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from typing import Any

from speakeasy.report import (
    ChildExecutionBudgetReport,
    ChildExecutionBudgetUsageReport,
    ChildExecutionFailureReport,
    ChildExecutionOwnership,
    ChildExecutionReport,
    ChildExecutionRequestReport,
    ChildExecutionResultReport,
)

from .models import (
    BudgetUsage,
    ChildExecutionReportData,
    ChildExecutionState,
    ChildFailure,
    ChildLaunchRecord,
    ChildRunResult,
    ExecutionBudget,
)

_QUEUED_OR_LATER_STATES = frozenset(
    {
        ChildExecutionState.THREAD_QUEUED,
        ChildExecutionState.ENTRYPOINT_REACHED,
        ChildExecutionState.COMPLETED,
        ChildExecutionState.PARTIAL,
    }
)
_ENTRYPOINT_OR_LATER_STATES = frozenset(
    {
        ChildExecutionState.ENTRYPOINT_REACHED,
        ChildExecutionState.COMPLETED,
        ChildExecutionState.PARTIAL,
    }
)
_TERMINAL_RESULT_STATES = frozenset(
    {
        ChildExecutionState.COMPLETED,
        ChildExecutionState.PARTIAL,
        ChildExecutionState.FAILED,
    }
)


class ChildExecutionReportProjectionError(ValueError):
    """Raised when an internal child snapshot cannot be projected safely."""


class ChildExecutionReportProjector:
    """Convert one immutable internal snapshot into the public report model.

    Args:
        policy: Optional read-only policy summary supplied by the caller.  It
            is copied into the public report without exposing options objects.

    The projector owns only the copied policy summary.  Its output contains
    only report-safe scalar values and typed report models.
    """

    def __init__(self, *, policy: Mapping[str, Any] | None = None) -> None:
        """Create a projector with an optional copied policy summary.

        Args:
            policy: Serializable policy facts to attach to projected reports.
                ``None`` produces an empty policy mapping.

        Side effects:
            Copies the supplied mapping.  The caller's mapping is not retained.
        """

        self._policy = dict(policy or {})

    def project(
        self,
        snapshot: ChildExecutionReportData,
    ) -> ChildExecutionReport:
        """Project one internal child snapshot for serialization.

        Args:
            snapshot: Immutable dispatcher snapshot containing launch records
                and terminal child results.

        Returns:
            A validated public report whose request and result objects contain
            no engine references or target payload bytes.

        Side effects:
            None.  The input snapshot and all collaborator state are unchanged.

        Raises:
            ChildExecutionReportProjectionError: If counts, ownership, or
                result state are internally inconsistent.
        """

        self._validate_snapshot(snapshot)
        states = Counter(record.state.value for record in snapshot.records)
        results_by_launch_id = {
            result.launch_id: result for result in snapshot.results
        }
        return ChildExecutionReport(
            mode=snapshot.mode,
            policy=dict(self._policy),
            execution_enabled=snapshot.execution_enabled,
            request_count=snapshot.request_count,
            eligible_count=snapshot.eligible_count,
            target_resolved_count=snapshot.target_resolved_count,
            process_object_created_count=snapshot.process_object_created_count,
            thread_queued_count=snapshot.thread_queued_count,
            entrypoint_reached_count=snapshot.entrypoint_reached_count,
            states=dict(sorted(states.items())),
            requests=[
                self._project_request(
                    record,
                    results_by_launch_id.get(record.request.launch_id),
                )
                for record in snapshot.records
            ],
            results=[
                self._project_result(result) for result in snapshot.results
            ],
        )

    def from_report_data(
        self,
        snapshot: ChildExecutionReportData,
    ) -> ChildExecutionReport:
        """Compatibility spelling for projecting one child snapshot.

        Args:
            snapshot: Immutable dispatcher snapshot.

        Returns:
            The same validated report returned by :meth:`project`.
        """

        return self.project(snapshot)

    def _validate_snapshot(self, snapshot: ChildExecutionReportData) -> None:
        """Validate snapshot counts and lineage before constructing a report.

        Args:
            snapshot: Internal immutable snapshot to validate.

        Returns:
            ``None`` when all summary values agree with the launch records.

        Side effects:
            None.

        Raises:
            ChildExecutionReportProjectionError: If a count or result lineage
                is inconsistent.
        """

        records = snapshot.records
        if snapshot.request_count != len(records):
            raise ChildExecutionReportProjectionError(
                "request_count does not match launch records"
            )

        expected_counts = {
            "eligible_count": sum(
                record.decision is not None and record.decision.eligible
                for record in records
            ),
            "target_resolved_count": sum(
                record.target is not None and record.target.resolved
                for record in records
            ),
            "process_object_created_count": sum(
                record.process is not None for record in records
            ),
            "thread_queued_count": sum(
                record.state in _QUEUED_OR_LATER_STATES for record in records
            ),
            "entrypoint_reached_count": sum(
                record.state in _ENTRYPOINT_OR_LATER_STATES
                for record in records
            ),
        }
        actual_counts = {
            "eligible_count": snapshot.eligible_count,
            "target_resolved_count": snapshot.target_resolved_count,
            "process_object_created_count": (
                snapshot.process_object_created_count
            ),
            "thread_queued_count": snapshot.thread_queued_count,
            "entrypoint_reached_count": snapshot.entrypoint_reached_count,
        }
        for name, expected in expected_counts.items():
            if actual_counts[name] != expected:
                raise ChildExecutionReportProjectionError(
                    f"{name} does not match launch records"
                )

        records_by_launch_id = {}
        roots: set[str] = set()
        for record in records:
            launch_id = record.request.launch_id
            if launch_id in records_by_launch_id:
                raise ChildExecutionReportProjectionError(
                    f"duplicate child launch id: {launch_id}"
                )
            records_by_launch_id[launch_id] = record
            roots.add(record.request.root_sample_sha256)

        if len(roots) > 1:
            raise ChildExecutionReportProjectionError(
                "child snapshot contains multiple root sample identities"
            )

        result_ids: set[str] = set()
        for result in snapshot.results:
            if result.launch_id in result_ids:
                raise ChildExecutionReportProjectionError(
                    f"duplicate child result for launch id: {result.launch_id}"
                )
            result_ids.add(result.launch_id)
            self._validate_result(result, records_by_launch_id)

    @staticmethod
    def _validate_result(
        result: ChildRunResult,
        records_by_launch_id: dict[str, ChildLaunchRecord],
    ) -> None:
        """Validate one terminal result against its launch record.

        Args:
            result: Terminal child result to validate.
            records_by_launch_id: Launch records indexed by stable identifier.

        Returns:
            ``None`` when ownership and terminal state are consistent.

        Side effects:
            None.

        Raises:
            ChildExecutionReportProjectionError: If ownership is orphaned,
                mismatched, or the result is not terminal.
        """

        record = records_by_launch_id.get(result.launch_id)
        if record is None:
            raise ChildExecutionReportProjectionError(
                f"child result has no launch record: {result.launch_id}"
            )

        request = record.request
        ownership = result.ownership
        if ownership.launch_id != result.launch_id:
            raise ChildExecutionReportProjectionError(
                f"result ownership launch id mismatch: {result.launch_id}"
            )
        if ownership.root_sample_sha256 != request.root_sample_sha256:
            raise ChildExecutionReportProjectionError(
                f"result root sample mismatch: {result.launch_id}"
            )
        if ownership.parent_pid != request.parent_pid:
            raise ChildExecutionReportProjectionError(
                f"result parent pid mismatch: {result.launch_id}"
            )
        if ownership.depth != request.depth:
            raise ChildExecutionReportProjectionError(
                f"result depth mismatch: {result.launch_id}"
            )
        if ownership.child_pid <= 0:
            raise ChildExecutionReportProjectionError(
                f"result child pid is invalid: {result.launch_id}"
            )
        if result.state not in _TERMINAL_RESULT_STATES:
            raise ChildExecutionReportProjectionError(
                f"result state is not terminal: {result.launch_id}"
            )
        if len(set(result.run_indexes)) != len(result.run_indexes):
            raise ChildExecutionReportProjectionError(
                f"result run indexes are duplicated: {result.launch_id}"
            )
        if any(index < 0 for index in result.run_indexes):
            raise ChildExecutionReportProjectionError(
                f"result run index is negative: {result.launch_id}"
            )
        ChildExecutionReportProjector._validate_usage(result.usage)

    @staticmethod
    def _validate_usage(usage: BudgetUsage) -> None:
        """Reject negative consumption counters.

        Args:
            usage: Mutable counters owned by one completed child run.

        Returns:
            ``None`` when every counter is non-negative.

        Side effects:
            None.

        Raises:
            ChildExecutionReportProjectionError: If a counter is negative.
        """

        if (
            usage.timeout_seconds_used < 0
            or usage.api_count_used < 0
            or usage.instructions_used < 0
        ):
            raise ChildExecutionReportProjectionError(
                "child budget usage cannot be negative"
            )

    @staticmethod
    def _project_request(
        record: ChildLaunchRecord,
        result: ChildRunResult | None = None,
    ) -> ChildExecutionRequestReport:
        """Project one launch record without exposing runtime objects.

        Args:
            record: Frozen child launch record.

        Returns:
            Serializable request, target-resolution, and admission evidence.

        Side effects:
            None.
        """

        request = record.request
        target = record.target
        decision = record.decision
        process = record.process
        state = record.state
        return ChildExecutionRequestReport(
            launch_id=request.launch_id,
            source_api=request.source_api,
            parent_pid=request.parent_pid,
            parent_tid=request.parent_tid,
            parent_launch_id=request.parent_launch_id,
            root_sample_sha256=request.root_sample_sha256,
            depth=request.depth,
            requested_target=request.target,
            normalized_target=request.normalized_target,
            working_directory=request.working_directory,
            command_line=request.command_line,
            command_sha256=request.command_sha256,
            target_source=(
                target.source.value
                if target is not None
                else "unavailable"
            ),
            target_sha256=target.sha256 if target is not None else None,
            target_size=target.size if target is not None else 0,
            target_format=(
                target.file_format if target is not None else "unknown"
            ),
            target_format_detail=(
                target.file_format if target is not None else "unknown"
            ),
            target_arch=target.arch if target is not None else "unknown",
            target_module_type=(
                target.module_type if target is not None else "unknown"
            ),
            target_entrypoint_rva=(
                target.entrypoint_rva if target is not None else 0
            ),
            target_resolved=(
                target.resolved if target is not None else False
            ),
            eligible=decision.eligible if decision is not None else False,
            state=state.value,
            process_object_created=process is not None,
            created_child_pid=process.pid if process is not None else None,
            thread_queued=state in _QUEUED_OR_LATER_STATES,
            entrypoint_reached=(
                state in _ENTRYPOINT_OR_LATER_STATES
                or bool(result is not None and result.entrypoint_reached)
            ),
            skip_reason=(
                record.reason
                if state == ChildExecutionState.SKIPPED
                else None
            ),
            rejection_reason=(
                record.reason
                if state
                in {
                    ChildExecutionState.REJECTED,
                    ChildExecutionState.UNAVAILABLE,
                }
                else None
            ),
        )

    @staticmethod
    def _project_result(result: ChildRunResult) -> ChildExecutionResultReport:
        """Project one terminal result into a stable report model.

        Args:
            result: Terminal child result.

        Returns:
            Serializable result with ownership, limits, usage, run indexes,
            and optional structured failure.

        Side effects:
            None.
        """

        return ChildExecutionResultReport(
            launch_id=result.launch_id,
            ownership=ChildExecutionOwnership(
                root_sample_sha256=result.ownership.root_sample_sha256,
                launch_id=result.ownership.launch_id,
                parent_pid=result.ownership.parent_pid,
                child_pid=result.ownership.child_pid,
                depth=result.ownership.depth,
            ),
            state=result.state.value,
            outcome=result.outcome.value,
            termination_reason=result.termination_reason.value,
            budget=ChildExecutionReportProjector._project_budget(result.budget),
            usage=ChildExecutionReportProjector._project_usage(result.usage),
            run_indexes=list(result.run_indexes),
            failure=ChildExecutionReportProjector._project_failure(
                result.error
            ),
        )

    @staticmethod
    def _project_budget(budget: ExecutionBudget) -> ChildExecutionBudgetReport:
        """Project immutable execution limits.

        Args:
            budget: Child execution limits.

        Returns:
            Serializable budget limits.

        Side effects:
            None.
        """

        return ChildExecutionBudgetReport(
            source=budget.source,
            timeout_seconds=budget.timeout_seconds,
            max_api_count=budget.max_api_count,
            max_instructions=budget.max_instructions,
        )

    @staticmethod
    def _project_usage(
        usage: BudgetUsage,
    ) -> ChildExecutionBudgetUsageReport:
        """Project per-child consumption counters.

        Args:
            usage: Counters owned by the completed child run.

        Returns:
            Serializable budget usage.

        Side effects:
            None.
        """

        return ChildExecutionBudgetUsageReport(
            timeout_seconds_used=usage.timeout_seconds_used,
            api_count_used=usage.api_count_used,
            instructions_used=usage.instructions_used,
        )

    @staticmethod
    def _project_failure(
        failure: ChildFailure | None,
    ) -> ChildExecutionFailureReport | None:
        """Project an optional child-local failure.

        Args:
            failure: Structured failure from a child result.

        Returns:
            Serializable failure, or ``None`` when no error was recorded.

        Side effects:
            None.
        """

        if failure is None:
            return None
        return ChildExecutionFailureReport(
            kind=failure.kind.value,
            message=failure.message,
            pc=failure.pc,
            api_name=failure.api_name,
        )


ChildExecutionReportAdapter = ChildExecutionReportProjector


__all__ = [
    "ChildExecutionReportAdapter",
    "ChildExecutionReportProjectionError",
    "ChildExecutionReportProjector",
]
