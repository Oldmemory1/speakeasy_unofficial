from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from speakeasy.windows.child_execution.dispatcher import ChildLaunchDispatcher
from speakeasy.windows.child_execution.models import (
    AdmissionDecision,
    BudgetUsage,
    ChildExecutionOptions,
    ChildExecutionState,
    ChildLaunchRecord,
    ChildLaunchRequest,
    ChildTargetSource,
    ExecutionBudget,
    ParentExecutionSnapshot,
    ParentRunOutcome,
    ProcessCreationResult,
    ProcessLaunchSpec,
    ResolvedChildTarget,
)


class FakeRequestFactory:
    """Build deterministic requests from explicit dispatcher input."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def build(self, spec: ProcessLaunchSpec, **kwargs: Any) -> ChildLaunchRequest:
        """Return a stable request and record the supplied build arguments."""

        self.calls.append({"spec": spec, **kwargs})
        target = spec.target or r"C:\fixtures\child.exe"
        return ChildLaunchRequest(
            launch_id="child-000001",
            root_sample_sha256=kwargs["root_sample_sha256"],
            parent_launch_id=kwargs["parent_launch_id"],
            source_api=spec.source_api,
            parent_pid=kwargs["parent_pid"],
            parent_tid=kwargs["parent_tid"],
            depth=kwargs["depth"],
            target=target,
            normalized_target=target,
            working_directory=kwargs["cwd"],
            command_line=spec.command_line,
            command_sha256="c" * 64,
            parent_budget=kwargs["parent_budget"],
        )


class FakeTargetResolver:
    """Resolve the fixed fixture used by dispatcher tests."""

    def __init__(self, resolved: bool = True) -> None:
        self.resolved = resolved

    def resolve(self, request: ChildLaunchRequest) -> ResolvedChildTarget:
        """Return target evidence without accessing engine state."""

        return ResolvedChildTarget(
            source=ChildTargetSource.FIXTURE,
            normalized_path=request.normalized_target,
            payload_ref=None,
            sha256="a" * 64 if self.resolved else None,
            size=4096,
            file_format="pe" if self.resolved else "unknown",
            arch="x86",
            module_type="exe",
            entrypoint_rva=0x1000,
            resolved=self.resolved,
            reason=None if self.resolved else "target_unavailable",
        )

    def register_fixture(self, normalized_path: str, data: bytes) -> None:
        """Accept fixture registration as part of the resolver protocol."""


class FakeAdmissionPolicy:
    """Apply a caller-selected admission decision."""

    def __init__(
        self,
        eligible: bool,
        reason: str | None = None,
    ) -> None:
        self.eligible = eligible
        self.reason = reason
        self.history_sizes: list[int] = []

    def evaluate(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
        *,
        launch_history: tuple[ChildLaunchRecord, ...],
    ) -> AdmissionDecision:
        """Return one deterministic immutable decision."""

        self.history_sizes.append(len(launch_history))
        state = (
            ChildExecutionState.ELIGIBLE
            if self.eligible
            else ChildExecutionState.REJECTED
        )
        return AdmissionDecision(
            eligible=self.eligible,
            state=state,
            reason=self.reason,
        )


class FakeProcess:
    """Minimal explicit process object for process-factory tests."""

    def __init__(self, pid: int = 4200) -> None:
        self.id = pid
        self.pid = pid
        self.path = r"C:\fixtures\child.exe"
        self.cmdline = '"C:\\fixtures\\child.exe"'
        self.threads: list[Any] = []


class FakeProcessFactory:
    """Return an explicit process-creation result."""

    def __init__(self, created: bool = True) -> None:
        self.created = created
        self.calls: list[tuple[ChildLaunchRequest, ResolvedChildTarget]] = []

    def create(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
    ) -> ProcessCreationResult:
        """Return configured creation evidence and record the call."""

        self.calls.append((request, target))
        if not self.created:
            return ProcessCreationResult(
                process=None,
                created_pid=None,
                created_tid=None,
                created=False,
                reason="load_error",
            )
        process = FakeProcess()
        return ProcessCreationResult(
            process=process,
            created_pid=process.pid,
            created_tid=4201,
            created=True,
        )


class FakeScheduler:
    """Record calls to the public scheduler protocol."""

    def __init__(self) -> None:
        self.submissions: list[
            tuple[ChildLaunchRequest, ResolvedChildTarget, AdmissionDecision, Any]
        ] = []
        self.drain_calls: list[ParentRunOutcome] = []
        self.stops: list[str] = []

    def submit(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
        decision: AdmissionDecision,
        process: Any,
    ) -> ChildLaunchRecord:
        """Record one queued snapshot without running child code."""

        self.submissions.append((request, target, decision, process))
        return ChildLaunchRecord(
            request=request,
            target=target,
            decision=decision,
            process=process,
            state=ChildExecutionState.THREAD_QUEUED,
        )

    def drain(self, parent_result: ParentRunOutcome) -> tuple[Any, ...]:
        """Record a drain request and return no synthetic child results."""

        self.drain_calls.append(parent_result)
        return ()

    def stop(self, reason: str) -> None:
        """Record a stop reason."""

        self.stops.append(reason)

    def snapshot(self) -> Any:
        """Return no report because the dispatcher owns report snapshots."""

        return None


def _budget() -> ExecutionBudget:
    return ExecutionBudget(
        timeout_seconds=61.5,
        max_api_count=2_345,
        max_instructions=6_789_012,
    )


def _parent_context() -> ParentExecutionSnapshot:
    return ParentExecutionSnapshot(
        root_sample_sha256="f" * 64,
        pid=111,
        tid=112,
        cwd=r"C:\work",
        budget=_budget(),
    )


def _spec() -> ProcessLaunchSpec:
    return ProcessLaunchSpec(
        source_api="CreateProcessW",
        target=r"C:\fixtures\child.exe",
        command_line='"C:\\fixtures\\child.exe" /quiet',
        working_directory=r"C:\work",
    )


def _parent_result(status: str = "ok") -> ParentRunOutcome:
    return ParentRunOutcome(
        status=status,
        termination_reason="normal_exit" if status == "ok" else "parent_stopped",
        coverage_complete=status == "ok",
        budget=_budget(),
        usage=BudgetUsage(),
    )


def _dispatcher(
    *,
    enabled: bool,
    eligible: bool = True,
    created: bool = True,
) -> tuple[
    ChildLaunchDispatcher,
    FakeRequestFactory,
    FakeProcessFactory,
    FakeScheduler,
]:
    request_factory = FakeRequestFactory()
    process_factory = FakeProcessFactory(created)
    scheduler = FakeScheduler()
    dispatcher = ChildLaunchDispatcher(
        request_factory=request_factory,
        target_resolver=FakeTargetResolver(),
        admission_policy=FakeAdmissionPolicy(eligible, "rejected"),
        process_factory=process_factory,
        scheduler=scheduler,
        options=ChildExecutionOptions(enabled=enabled),
    )
    return dispatcher, request_factory, process_factory, scheduler


def test_model_only_records_process_without_scheduling() -> None:
    dispatcher, _, process_factory, scheduler = _dispatcher(enabled=False)

    outcome = dispatcher.submit(_spec(), parent_context=_parent_context())
    report = dispatcher.report()

    assert outcome.creation.created is True
    assert outcome.creation.created_pid == 4200
    assert len(process_factory.calls) == 1
    assert scheduler.submissions == []
    assert report.execution_enabled is False
    assert report.request_count == 1
    assert report.process_object_created_count == 1
    assert report.thread_queued_count == 0


def test_enabled_dispatcher_delegates_only_admitted_request() -> None:
    dispatcher, _, _, scheduler = _dispatcher(enabled=True)

    outcome = dispatcher.submit(_spec(), parent_context=_parent_context())

    assert outcome.decision.eligible is True
    assert len(scheduler.submissions) == 1
    assert dispatcher.report().thread_queued_count == 1


def test_rejected_request_never_creates_process_or_schedules() -> None:
    dispatcher, _, process_factory, scheduler = _dispatcher(
        enabled=True,
        eligible=False,
    )

    outcome = dispatcher.submit(_spec(), parent_context=_parent_context())

    assert outcome.creation.created is False
    assert process_factory.calls == []
    assert scheduler.submissions == []
    assert dispatcher.report().eligible_count == 0


def test_failed_process_creation_is_reported_and_not_scheduled() -> None:
    dispatcher, _, _, scheduler = _dispatcher(enabled=True, created=False)

    outcome = dispatcher.submit(_spec(), parent_context=_parent_context())
    report = dispatcher.report()

    assert outcome.creation.created is False
    assert scheduler.submissions == []
    assert report.process_object_created_count == 0
    assert report.thread_queued_count == 0
    assert report.records[-1].state is ChildExecutionState.FAILED
    assert report.records[-1].reason == "load_error"


def test_parent_finished_drains_and_closes_intake() -> None:
    dispatcher, _, _, scheduler = _dispatcher(enabled=True)
    dispatcher.submit(_spec(), parent_context=_parent_context())

    dispatcher.parent_finished(_parent_result())
    dispatcher.parent_finished(_parent_result())

    assert len(scheduler.drain_calls) == 1
    with pytest.raises(RuntimeError, match="closed"):
        dispatcher.submit(_spec(), parent_context=_parent_context())


def test_model_only_parent_finish_and_stop_never_touch_scheduler() -> None:
    dispatcher, _, _, scheduler = _dispatcher(enabled=False)

    dispatcher.parent_finished(_parent_result())
    dispatcher.stop("verification_stop")

    assert scheduler.drain_calls == []
    assert scheduler.stops == []


def test_failed_parent_stops_without_draining() -> None:
    dispatcher, _, _, scheduler = _dispatcher(enabled=True)
    dispatcher.submit(_spec(), parent_context=_parent_context())

    dispatcher.parent_finished(_parent_result(status="failed"))

    assert scheduler.stops == ["parent_stopped"]
    assert scheduler.drain_calls == []


@pytest.mark.parametrize(
    "status",
    [
        "simulation_error",
        "timed_out",
        "instruction_budget",
        "internal_error",
    ],
)
def test_non_ok_parent_status_stops_without_draining(status: str) -> None:
    dispatcher, _, _, scheduler = _dispatcher(enabled=True)
    dispatcher.submit(_spec(), parent_context=_parent_context())

    dispatcher.parent_finished(_parent_result(status=status))

    assert scheduler.stops == ["parent_stopped"]
    assert scheduler.drain_calls == []


def test_report_is_immutable_snapshot() -> None:
    dispatcher, _, _, _ = _dispatcher(enabled=False)
    dispatcher.submit(_spec(), parent_context=_parent_context())
    first = dispatcher.report()

    dispatcher.submit(_spec(), parent_context=_parent_context())
    second = dispatcher.report()

    assert first.request_count == 1
    assert second.request_count == 2
    assert first.records is not second.records


def test_parent_context_cannot_change_between_requests() -> None:
    dispatcher, _, _, _ = _dispatcher(enabled=False)
    dispatcher.submit(_spec(), parent_context=_parent_context())
    changed = replace(
        _parent_context(),
        budget=replace(_budget(), timeout_seconds=62.0),
    )

    with pytest.raises(ValueError, match="parent context"):
        dispatcher.submit(_spec(), parent_context=changed)
