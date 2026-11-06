"""Deterministic production scheduler for controlled child execution.

This module owns the only production child queue and the only production drain
path.  Request discovery, target resolution, admission, process creation, and
report projection remain in their respective modules.  The scheduler receives
already admitted launches, preserves FIFO order, and composes the injected
loader, context manager, runner, and budget factory.

The implementation deliberately has no engine globals and never patches or
mutates collaborator instances.  All inputs and outputs cross explicit
protocols declared in :mod:`speakeasy.windows.child_execution.interfaces`.
"""

from __future__ import annotations

from dataclasses import replace

from .interfaces import (
    ChildBudgetFactory,
    ChildContextManager,
    ChildResultSink,
    ChildRunnerProtocol,
    ChildRuntimeLoader,
)
from .models import (
    AdmissionDecision,
    BudgetUsage,
    ChildEventOwnership,
    ChildExecutionReportData,
    ChildExecutionState,
    ChildFailure,
    ChildFailureKind,
    ChildLaunchRecord,
    ChildLaunchRequest,
    ChildOutcome,
    ChildRunResult,
    ChildTerminationReason,
    EmulatedProcessProtocol,
    ExecutionBudget,
    ParentRunOutcome,
    ResolvedChildTarget,
)

_PARENT_FAILURE_STATUSES = frozenset(
    {
        "failed",
        "error",
        "stopped",
        "crashed",
        "simulation_error",
        "timed_out",
        "timeout",
        "instruction_budget",
        "internal_error",
    }
)
_TERMINAL_RESULT_STATES = frozenset(
    {
        ChildExecutionState.COMPLETED,
        ChildExecutionState.PARTIAL,
        ChildExecutionState.FAILED,
    }
)


class ChildExecutionScheduler:
    """Own the sole FIFO queue and drain path for admitted child launches.

    Args:
        loader: Loads exact target bytes as a non-primary child image.
        context_manager: Activates a child context and restores its parent on
            every exit path.
        runner: Executes and finalizes exactly one loaded child image.
        budget_factory: Creates equal child limits and independent usage.
        result_sink: Optional reporting sink invoked once per terminal result.
            It cannot alter queue state or execution decisions.

    The scheduler owns queue order, queue transitions, parent-intake closure,
    and the bound drain lifecycle.  It does not resolve targets, admit
    requests, create process objects, or expose engine handles through public
    snapshots.
    """

    def __init__(
        self,
        loader: ChildRuntimeLoader,
        context_manager: ChildContextManager,
        runner: ChildRunnerProtocol,
        budget_factory: ChildBudgetFactory,
        result_sink: ChildResultSink | None = None,
    ) -> None:
        self._loader = loader
        self._context_manager = context_manager
        self._runner = runner
        self._budget_factory = budget_factory
        self._result_sink = result_sink
        self._records: list[ChildLaunchRecord] = []
        self._record_indexes: dict[str, int] = {}
        self._results: list[ChildRunResult] = []
        self._result_ids: set[str] = set()
        self._usage_ids: set[int] = set()
        self._drain_started = False
        self._stop_reason: str | None = None

    def submit(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
        decision: AdmissionDecision,
        process: EmulatedProcessProtocol,
    ) -> ChildLaunchRecord:
        """Append one admitted launch to the FIFO without executing it.

        Args:
            request: Immutable request already admitted by policy.
            target: Resolved target evidence for the same request.
            decision: Eligible admission decision.
            process: Existing emulated process object with a positive pid.

        Returns:
            The immutable ``thread_queued`` launch record.

        Side effects:
            Appends exactly one record to the scheduler-owned FIFO.  This
            method never loads an image, switches context, or executes code.

        Raises:
            RuntimeError: If the queue is draining, stopped, or the launch id
                was already submitted.
            ValueError: If any input violates the frozen scheduler contract.
        """

        self._ensure_intake_open()
        launch_id = request.launch_id
        if launch_id in self._record_indexes:
            raise RuntimeError(f"duplicate child launch id: {launch_id}")
        if not decision.eligible:
            raise ValueError("scheduler only accepts eligible launches")
        if not target.resolved:
            raise ValueError("scheduler only accepts resolved targets")
        if target.normalized_path.casefold() != request.normalized_target.casefold():
            raise ValueError("target path does not match the launch request")
        if process.pid <= 0:
            raise ValueError("queued process must have a positive pid")

        record = ChildLaunchRecord(
            request=request,
            target=target,
            decision=decision,
            process=process,
            state=ChildExecutionState.THREAD_QUEUED,
            reason=None,
        )
        self._record_indexes[launch_id] = len(self._records)
        self._records.append(record)
        return record

    def drain(
        self,
        parent_result: ParentRunOutcome,
    ) -> tuple[ChildRunResult, ...]:
        """Execute queued children in FIFO order after parent completion.

        Args:
            parent_result: Final parent outcome and authoritative parent
                budget.  Child intake is permanently closed for this call.

        Returns:
            Child-local terminal results in queue order.  Repeated calls return
            the same immutable results and never execute work again.

        Side effects:
            Loads, activates, and executes queued children.  A failed parent,
            changed parent budget, stop request, or scheduler-integrity failure
            prevents additional starts.  Parent outcome is never modified.
        """

        if self._drain_started:
            return tuple(self._results)
        self._drain_started = True

        if parent_result.status.lower() in _PARENT_FAILURE_STATUSES:
            self._stop_pending("parent_stopped")
        elif any(
            record.request.parent_budget != parent_result.budget
            for record in self._records
            if record.state is ChildExecutionState.THREAD_QUEUED
        ):
            self._stop_pending("parent_budget_changed")

        for record in self._records:
            if self._stop_reason is not None:
                break
            if record.state is not ChildExecutionState.THREAD_QUEUED:
                continue

            result = self._execute(record)
            self._record_result(result)
            self._append_result(result)
            self._publish(result)

        return tuple(self._results)

    def stop(self, reason: str) -> None:
        """Stop pending work and permanently close the scheduler.

        Args:
            reason: Machine-readable lifecycle or integrity reason.

        Returns:
            ``None``.

        Side effects:
            Marks queued-but-not-started records as skipped, closes intake,
            and prevents any later drain from starting new child work.
            Completed results are retained unchanged.
        """

        if not reason:
            raise ValueError("stop reason cannot be empty")
        if self._stop_reason is not None:
            return
        self._drain_started = True
        self._stop_pending(reason)

    def snapshot(self) -> ChildExecutionReportData:
        """Return an immutable snapshot without exposing queue internals.

        Returns:
            Execution-enabled counts, launch records, and terminal child
            results.  Engine processes, target bytes, and mutable scheduler
            lists are not exposed.

        Side effects:
            None.
        """

        records = tuple(self._records)
        results = tuple(self._results)
        return ChildExecutionReportData(
            mode="scheduled",
            execution_enabled=True,
            request_count=len(records),
            eligible_count=sum(
                record.decision is not None and record.decision.eligible
                for record in records
            ),
            target_resolved_count=sum(
                record.target is not None and record.target.resolved
                for record in records
            ),
            process_object_created_count=sum(
                record.process is not None for record in records
            ),
            # Every scheduler record crossed submit(), so queue insertion is a
            # historical fact even when its final state is failed or skipped.
            thread_queued_count=len(records),
            entrypoint_reached_count=sum(
                result.entrypoint_reached for result in results
            ),
            records=records,
            results=results,
        )

    def _ensure_intake_open(self) -> None:
        """Reject submissions after draining or stopping.

        Returns:
            ``None`` when the queue still accepts admitted launches.

        Side effects:
            None.

        Raises:
            RuntimeError: If the scheduler no longer accepts launches.
        """

        if self._drain_started:
            raise RuntimeError("child scheduler intake is closed")
        if self._stop_reason is not None:
            raise RuntimeError(f"child scheduler stopped: {self._stop_reason}")

    def _execute(self, record: ChildLaunchRecord) -> ChildRunResult:
        """Execute one queued record and convert boundary errors to results.

        Args:
            record: A ``thread_queued`` record owned by this scheduler.

        Returns:
            One terminal child result.  Load and runtime failures remain local
            to this child; context-integrity failures mark the scheduler
            stopped before any later child can start.

        Side effects:
            Loads the image, activates and restores child context, executes the
            injected runner, and allocates one independent usage counter.
        """

        request = record.request
        target = record.target
        process = record.process
        if target is None or process is None:
            return self._failure_result(
                record,
                ChildFailureKind.SCHEDULER,
                "scheduler record is missing its resolved target or process",
                ChildTerminationReason.INTERNAL_ERROR,
                ExecutionBudget(
                    timeout_seconds=request.parent_budget.timeout_seconds,
                    max_api_count=request.parent_budget.max_api_count,
                    max_instructions=request.parent_budget.max_instructions,
                ),
                BudgetUsage(),
                fatal_reason="scheduler_record_invalid",
            )

        ownership = ChildEventOwnership(
            root_sample_sha256=request.root_sample_sha256,
            launch_id=request.launch_id,
            parent_pid=request.parent_pid,
            child_pid=process.pid,
            depth=request.depth,
        )

        try:
            budget, usage = self._budget_factory.for_child(
                request.parent_budget
            )
        except Exception as exc:
            return self._failure_result(
                record,
                ChildFailureKind.SCHEDULER,
                f"cannot allocate child budget: {type(exc).__name__}: {exc}",
                ChildTerminationReason.INTERNAL_ERROR,
                request.parent_budget,
                BudgetUsage(),
                fatal_reason="child_budget_allocation_failed",
            )

        if not self._budget_matches_parent(budget, request.parent_budget):
            return self._failure_result(
                record,
                ChildFailureKind.SCHEDULER,
                "child budget limits do not match the parent",
                ChildTerminationReason.INTERNAL_ERROR,
                budget,
                usage,
                fatal_reason="child_budget_mismatch",
            )
        if id(usage) in self._usage_ids:
            return self._failure_result(
                record,
                ChildFailureKind.SCHEDULER,
                "child usage counter is shared with another run",
                ChildTerminationReason.INTERNAL_ERROR,
                budget,
                usage,
                fatal_reason="child_usage_reused",
            )
        self._usage_ids.add(id(usage))

        try:
            image = self._loader.load(request, target)
        except Exception as exc:
            return self._failure_result(
                record,
                ChildFailureKind.LOAD,
                f"cannot load child image: {type(exc).__name__}: {exc}",
                self._termination_for_error(
                    exc,
                    ChildTerminationReason.LOAD_ERROR,
                ),
                budget,
                usage,
            )

        result: ChildRunResult | None = None
        try:
            context_session = self._context_manager.enter(
                request,
                image,
                ownership,
            )
            with context_session as context:
                try:
                    result = self._runner.run(
                        request,
                        target,
                        image,
                        context,
                        budget,
                        usage,
                    )
                except Exception as exc:
                    return self._failure_result(
                        record,
                        ChildFailureKind.RUNTIME,
                        f"child runner failed: {type(exc).__name__}: {exc}",
                        self._termination_for_error(
                            exc,
                            ChildTerminationReason.INTERNAL_ERROR,
                        ),
                        budget,
                        usage,
                    )
        except Exception as exc:
            return self._failure_result(
                record,
                ChildFailureKind.CONTEXT,
                f"cannot maintain child context: {type(exc).__name__}: {exc}",
                self._termination_for_error(
                    exc,
                    ChildTerminationReason.INTERNAL_ERROR,
                ),
                budget,
                usage,
                fatal_reason="child_context_integrity_failed",
            )

        if result is None:
            return self._failure_result(
                record,
                ChildFailureKind.RUNTIME,
                "child runner returned no result",
                ChildTerminationReason.INTERNAL_ERROR,
                budget,
                usage,
            )
        if result.launch_id != request.launch_id:
            return self._failure_result(
                record,
                ChildFailureKind.SCHEDULER,
                "child runner returned a result for another launch",
                ChildTerminationReason.INTERNAL_ERROR,
                budget,
                usage,
                fatal_reason="child_result_ownership_mismatch",
            )
        if result.state not in _TERMINAL_RESULT_STATES:
            return self._failure_result(
                record,
                ChildFailureKind.SCHEDULER,
                "child runner returned a non-terminal result",
                ChildTerminationReason.INTERNAL_ERROR,
                budget,
                usage,
            )
        if result.budget != budget or result.ownership != ownership:
            return self._failure_result(
                record,
                ChildFailureKind.SCHEDULER,
                "child result budget or ownership does not match the launch",
                ChildTerminationReason.INTERNAL_ERROR,
                budget,
                usage,
                fatal_reason="child_result_contract_mismatch",
            )
        return result

    def _failure_result(
        self,
        record: ChildLaunchRecord,
        kind: ChildFailureKind,
        message: str,
        termination_reason: ChildTerminationReason,
        budget: ExecutionBudget,
        usage: BudgetUsage,
        *,
        fatal_reason: str | None = None,
    ) -> ChildRunResult:
        """Build a terminal child-local failure and optionally stop the queue.

        Args:
            record: Launch record owning the failed boundary.
            kind: Module boundary at which the failure occurred.
            message: Human-readable diagnostic retained in the child report.
            termination_reason: Stable machine-readable termination reason.
            budget: Child or inherited limits associated with this attempt.
            usage: Usage counter owned only by this child attempt.
            fatal_reason: Optional scheduler reason that prevents later starts.

        Returns:
            A terminal ``FAILED`` child result with no invented run evidence.

        Side effects:
            When ``fatal_reason`` is supplied, closes intake and marks pending
            work as skipped.  The parent outcome is never changed.
        """

        if fatal_reason is not None:
            self._stop_pending(fatal_reason)
        request = record.request
        process = record.process
        child_pid = process.pid if process is not None else 0
        return ChildRunResult(
            launch_id=request.launch_id,
            ownership=ChildEventOwnership(
                root_sample_sha256=request.root_sample_sha256,
                launch_id=request.launch_id,
                parent_pid=request.parent_pid,
                child_pid=child_pid,
                depth=request.depth,
            ),
            state=ChildExecutionState.FAILED,
            outcome=ChildOutcome.ERROR,
            termination_reason=termination_reason,
            budget=budget,
            usage=usage,
            run_indexes=(),
            error=ChildFailure(kind=kind, message=message),
            entrypoint_reached=False,
        )

    def _record_result(self, result: ChildRunResult) -> None:
        """Replace the queued record with the result's latest lifecycle state.

        Args:
            result: Validated terminal child result.

        Returns:
            ``None``.

        Side effects:
            Replaces one scheduler-owned immutable launch record.
        """

        index = self._record_indexes[result.launch_id]
        record = self._records[index]
        self._records[index] = replace(
            record,
            state=result.state,
            reason=result.termination_reason.value,
        )

    def _append_result(self, result: ChildRunResult) -> None:
        """Append one terminal result exactly once.

        Args:
            result: Validated terminal child result.

        Returns:
            ``None``.

        Side effects:
            Appends to scheduler-owned result history after a duplicate check.
        """

        if result.launch_id in self._result_ids:
            self._stop_pending("duplicate_child_result")
            return
        self._result_ids.add(result.launch_id)
        self._results.append(result)

    def _publish(self, result: ChildRunResult) -> None:
        """Publish one result through the optional reporting sink.

        Args:
            result: Terminal child result to publish.

        Returns:
            ``None``.

        Side effects:
            Calls the injected sink once.  Sink failures stop later child
            starts because report consistency can no longer be guaranteed.
        """

        if self._result_sink is None:
            return
        try:
            self._result_sink.publish(result)
        except Exception:
            self._stop_pending("child_result_sink_failed")

    def _stop_pending(self, reason: str) -> None:
        """Stop all queued records and prevent subsequent starts.

        Args:
            reason: Machine-readable stop reason retained on skipped records.

        Returns:
            ``None``.

        Side effects:
            Sets the scheduler stop reason and replaces each still-queued
            record with a skipped record.  Results already emitted are kept.
        """

        if self._stop_reason is None:
            self._stop_reason = reason
        for index, record in enumerate(self._records):
            if record.state is ChildExecutionState.THREAD_QUEUED:
                self._records[index] = replace(
                    record,
                    state=ChildExecutionState.SKIPPED,
                    reason=self._stop_reason,
                )

    @staticmethod
    def _budget_matches_parent(
        budget: ExecutionBudget,
        parent_budget: ExecutionBudget,
    ) -> bool:
        """Return whether all three child limits equal their parent limits.

        Args:
            budget: Fresh budget allocated by the injected factory.
            parent_budget: Immutable budget captured from the parent.

        Returns:
            ``True`` only when timeout, API, and instruction limits match.

        Side effects:
            None.
        """

        return (
            budget.timeout_seconds == parent_budget.timeout_seconds
            and budget.max_api_count == parent_budget.max_api_count
            and budget.max_instructions == parent_budget.max_instructions
        )

    @staticmethod
    def _termination_for_error(
        error: Exception,
        fallback: ChildTerminationReason,
    ) -> ChildTerminationReason:
        """Extract a valid child termination reason from a boundary error.

        Args:
            error: Loader, context, or runner failure.
            fallback: Reason used when the error has no valid classification.

        Returns:
            A stable child termination reason.

        Side effects:
            None.
        """

        reason = getattr(error, "termination_reason", None)
        if isinstance(reason, ChildTerminationReason):
            return reason
        return fallback


__all__ = ["ChildExecutionScheduler"]
