"""Single orchestration entry point for controlled child launches.

The dispatcher composes the frozen request, target, admission, process, and
scheduler interfaces.  It intentionally has no runtime loader, entry hook,
runner, or concrete queue implementation; those belong to later stages.
"""

from __future__ import annotations

from dataclasses import replace

from .interfaces import (
    ChildAdmissionPolicyProtocol,
    ChildProcessFactory,
    ChildRequestFactory,
    ChildSchedulerProtocol,
    ChildTargetResolverProtocol,
)
from .models import (
    ChildExecutionOptions,
    ChildExecutionReportData,
    ChildExecutionState,
    ChildLaunchRecord,
    ChildRunResult,
    ParentExecutionSnapshot,
    ParentRunOutcome,
    ProcessCreationResult,
    ProcessLaunchOutcome,
    ProcessLaunchSpec,
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


class ChildLaunchDispatcher:
    """Coordinate one child launch without executing child code.

    Args:
        request_factory: Builds immutable launch requests.
        target_resolver: Resolves approved target bytes.
        admission_policy: Evaluates depth, count, duplicate, and target policy.
        process_factory: Creates emulated process objects for eligible requests.
        scheduler: Optional scheduler dependency.  It is required only when
            child execution is enabled.
        options: Explicit child-execution policy and enablement.

    The dispatcher owns launch-record transitions and intake state.  It does
    not own target bytes, process objects, scheduler queues, or child runs.
    All collaborating objects are supplied explicitly; production code never
    patches concrete instances or injects undeclared attributes.
    """

    def __init__(
        self,
        request_factory: ChildRequestFactory,
        target_resolver: ChildTargetResolverProtocol,
        admission_policy: ChildAdmissionPolicyProtocol,
        process_factory: ChildProcessFactory,
        scheduler: ChildSchedulerProtocol | None,
        options: ChildExecutionOptions,
    ) -> None:
        if options.enabled and scheduler is None:
            raise ValueError("enabled child execution requires a scheduler")

        self._request_factory = request_factory
        self._target_resolver = target_resolver
        self._admission_policy = admission_policy
        self._process_factory = process_factory
        self._scheduler = scheduler
        self._options = options
        self._records: list[ChildLaunchRecord] = []
        self._results: list[ChildRunResult] = []
        self._parent_context: ParentExecutionSnapshot | None = None
        self._parent_finished = False

    def submit(
        self,
        spec: ProcessLaunchSpec,
        *,
        parent_context: ParentExecutionSnapshot,
    ) -> ProcessLaunchOutcome:
        """Create, resolve, admit, and conditionally enqueue one request.

        Args:
            spec: Decoded parameters from a process-launch API handler.
            parent_context: Frozen root identity, parent process/thread, cwd,
                and parent execution budget.

        Returns:
            Request, target evidence, admission decision, and process-object
            creation result.  API handlers use ``creation.created_pid`` for
            their return value; process creation does not imply execution.

        Side effects:
            Appends or replaces one dispatcher-owned launch record.  In
            disabled mode it never calls the scheduler.  In enabled mode it
            delegates an eligible request only after process-object creation.

        Raises:
            RuntimeError: If parent intake has already been closed.
            ValueError: If ``parent_context`` changes root identity or budget
                after the first request.
        """

        self._ensure_intake_open()
        self._establish_parent_context(parent_context)

        request = self._request_factory.build(
            spec,
            root_sample_sha256=parent_context.root_sample_sha256,
            parent_pid=parent_context.pid,
            parent_tid=parent_context.tid,
            parent_launch_id=None,
            depth=1,
            parent_budget=parent_context.budget,
            cwd=parent_context.cwd,
        )
        self._append_record(
            ChildLaunchRecord(
                request=request,
                state=ChildExecutionState.REQUESTED,
            )
        )

        target = self._target_resolver.resolve(request)
        self._replace_current_record(
            ChildLaunchRecord(
                request=request,
                target=target,
                state=ChildExecutionState.TARGET_RESOLVED,
                reason=target.reason,
            )
        )

        decision = self._admission_policy.evaluate(
            request,
            target,
            launch_history=tuple(self._records[:-1]),
        )
        self._replace_current_record(
            ChildLaunchRecord(
                request=request,
                target=target,
                decision=decision,
                state=decision.state,
                reason=decision.reason,
            )
        )
        if not decision.eligible:
            return ProcessLaunchOutcome(
                request=request,
                resolution=target,
                decision=decision,
                creation=_not_created(decision.reason),
            )

        creation = self._process_factory.create(request, target)
        if not creation.created:
            self._replace_current_record(
                replace(
                    self._current_record(),
                    state=ChildExecutionState.FAILED,
                    reason=creation.reason,
                )
            )
            return ProcessLaunchOutcome(
                request=request,
                resolution=target,
                decision=decision,
                creation=creation,
            )

        created_record = replace(
            self._current_record(),
            process=creation.process,
            state=ChildExecutionState.PROCESS_OBJECT_CREATED,
        )
        self._replace_current_record(created_record)

        if not (self._options.enabled and self._scheduler is not None):
            return ProcessLaunchOutcome(
                request=request,
                resolution=target,
                decision=decision,
                creation=creation,
            )

        queued_record = self._scheduler.submit(
            request,
            target,
            decision,
            creation.process,
        )
        self._replace_current_record(queued_record)
        return ProcessLaunchOutcome(
            request=request,
            resolution=target,
            decision=decision,
            creation=creation,
        )

    def parent_finished(self, parent_result: ParentRunOutcome) -> None:
        """Close parent intake and delegate bounded child draining.

        Args:
            parent_result: Final parent status, termination reason, coverage,
                budget, and parent usage.

        Returns:
            ``None``.

        Side effects:
            Closes intake permanently.  A failed or stopped parent invokes
            ``scheduler.stop`` and never drains.  Otherwise, if a scheduler is
            present, its public ``drain`` method is called and returned results
            are retained for reporting.  This method is idempotent.
        """

        if self._parent_finished:
            return
        self._parent_finished = True
        if not self._options.enabled or self._scheduler is None:
            return
        if parent_result.status.lower() in _PARENT_FAILURE_STATUSES:
            self._scheduler.stop(parent_result.termination_reason)
            self._refresh_from_scheduler()
            return
        self._results.extend(self._scheduler.drain(parent_result))
        self._refresh_from_scheduler()

    def stop(self, reason: str) -> None:
        """Propagate a stop and close parent intake.

        Args:
            reason: Machine-readable scheduler reason.

        Returns:
            ``None``.

        Side effects:
            Closes intake permanently and, when a scheduler exists, delegates
            the stop through its public interface.  Parent results are not
            rewritten.
        """

        self._parent_finished = True
        if self._options.enabled and self._scheduler is not None:
            self._scheduler.stop(reason)

    def report(self) -> ChildExecutionReportData:
        """Return an immutable child execution summary.

        Returns:
            Counts, immutable launch records, and completed child results.
            Internal lists and collaborating engine objects are never exposed.

        Side effects:
            None.
        """

        self._refresh_from_scheduler()
        records = tuple(self._records)
        return ChildExecutionReportData(
            mode="scheduled" if self._options.enabled else "model_only",
            execution_enabled=self._options.enabled,
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
            thread_queued_count=sum(
                record.state in _QUEUED_OR_LATER_STATES
                for record in records
            ),
            entrypoint_reached_count=sum(
                record.state in _ENTRYPOINT_OR_LATER_STATES
                for record in records
            ),
            records=records,
            results=tuple(self._results),
        )

    def _refresh_from_scheduler(self) -> None:
        """Merge the scheduler's authoritative record and result snapshot.

        Returns:
            ``None``.

        Side effects:
            Replaces matching dispatcher-owned record snapshots with the
            scheduler's latest immutable state and retains scheduler results.
            Model-only mode and compatibility fakes that return ``None`` are
            left unchanged.  No engine object or mutable queue is exposed.
        """

        if not self._options.enabled or self._scheduler is None:
            return
        snapshot = self._scheduler.snapshot()
        if not isinstance(snapshot, ChildExecutionReportData):
            return

        records_by_launch_id = {
            record.request.launch_id: record for record in snapshot.records
        }
        self._records = [
            records_by_launch_id.get(record.request.launch_id, record)
            for record in self._records
        ]
        results_by_launch_id = {
            result.launch_id: result for result in self._results
        }
        for result in snapshot.results:
            results_by_launch_id[result.launch_id] = result
        self._results = list(results_by_launch_id.values())

    def _ensure_intake_open(self) -> None:
        """Reject submissions after parent intake has closed.

        Returns:
            ``None`` when intake remains open.

        Side effects:
            None.

        Raises:
            RuntimeError: If ``parent_finished`` or ``stop`` already ran.
        """

        if self._parent_finished:
            raise RuntimeError("parent child-execution intake is closed")

    def _establish_parent_context(
        self,
        parent_context: ParentExecutionSnapshot,
    ) -> None:
        """Freeze and validate the root context for the dispatcher lifetime.

        Args:
            parent_context: Candidate root identity and budget.

        Returns:
            ``None``.

        Side effects:
            Stores the first parent snapshot only.

        Raises:
            ValueError: If root identity or budget changes.
        """

        if self._parent_context is None:
            self._parent_context = parent_context
            return
        if (
            parent_context.root_sample_sha256
            != self._parent_context.root_sample_sha256
            or parent_context.pid != self._parent_context.pid
            or parent_context.cwd != self._parent_context.cwd
            or parent_context.budget != self._parent_context.budget
        ):
            raise ValueError("parent context changed during one dispatcher run")

    def _append_record(self, record: ChildLaunchRecord) -> None:
        """Append a snapshot for a new transition.

        Args:
            record: Immutable record produced by the dispatcher.

        Returns:
            ``None``.

        Side effects:
            Appends only to the dispatcher-owned record history.
        """

        self._records.append(record)

    def _replace_current_record(self, record: ChildLaunchRecord) -> None:
        """Replace the current launch snapshot rather than mutating it.

        Args:
            record: Updated immutable snapshot for the current request.

        Returns:
            ``None``.

        Side effects:
            Replaces the last dispatcher-owned record.
        """

        self._records[-1] = record

    def _current_record(self) -> ChildLaunchRecord:
        """Return the current immutable launch snapshot.

        Returns:
            The most recently recorded snapshot.

        Side effects:
            None.

        Raises:
            RuntimeError: If called before any request was recorded.
        """

        if not self._records:
            raise RuntimeError("no child launch record is active")
        return self._records[-1]


def _not_created(reason: str | None) -> ProcessCreationResult:
    """Create explicit process-creation failure evidence.

    Args:
        reason: Admission reason retained for diagnostics.

    Returns:
        A failed ``ProcessCreationResult`` with no process or pid.

    Side effects:
        None.
    """

    return ProcessCreationResult(
        process=None,
        created_pid=None,
        created_tid=None,
        created=False,
        reason=reason,
    )
__all__ = ["ChildLaunchDispatcher"]
