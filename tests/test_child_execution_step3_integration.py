from __future__ import annotations

from dataclasses import replace
from typing import Any

from speakeasy.windows.child_execution import (
    ChildLaunchDispatcher,
    ExecutionBudgetFactory,
)
from speakeasy.windows.child_execution.interfaces import ChildExecutionDispatcher
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


class RequestFactory:
    """Build one request from the public dispatcher inputs."""

    def build(self, spec: ProcessLaunchSpec, **kwargs: Any) -> ChildLaunchRequest:
        """Return a fixed request without engine access."""

        return ChildLaunchRequest(
            launch_id="child-000001",
            root_sample_sha256=kwargs["root_sample_sha256"],
            parent_launch_id=kwargs["parent_launch_id"],
            source_api=spec.source_api,
            parent_pid=kwargs["parent_pid"],
            parent_tid=kwargs["parent_tid"],
            depth=kwargs["depth"],
            target=spec.target or r"C:\fixture.exe",
            normalized_target=spec.target or r"C:\fixture.exe",
            working_directory=kwargs["cwd"],
            command_line=spec.command_line,
            command_sha256="1" * 64,
            parent_budget=kwargs["parent_budget"],
        )


class Resolver:
    """Resolve one synthetic PE fixture."""

    def resolve(self, request: ChildLaunchRequest) -> ResolvedChildTarget:
        """Return target evidence without reading an engine."""

        return ResolvedChildTarget(
            source=ChildTargetSource.FIXTURE,
            normalized_path=request.normalized_target,
            payload_ref=None,
            sha256="2" * 64,
            size=1024,
            file_format="pe",
            arch="x86",
            module_type="exe",
            entrypoint_rva=0x1000,
            resolved=True,
            reason=None,
        )

    def register_fixture(self, normalized_path: str, data: bytes) -> None:
        """Accept a fixture without external effects."""


class Policy:
    """Admit a resolved target."""

    def evaluate(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
        *,
        launch_history: tuple[ChildLaunchRecord, ...],
    ) -> AdmissionDecision:
        """Return an eligible decision."""

        return AdmissionDecision(
            eligible=True,
            state=ChildExecutionState.ELIGIBLE,
            reason=None,
        )


class Process:
    """Minimal explicit process object."""

    id = 5000
    pid = 5000
    path = r"C:\fixture.exe"
    cmdline = '"C:\\fixture.exe"'
    threads: list[Any] = []


class ProcessFactory:
    """Create one explicit process object."""

    def create(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
    ) -> ProcessCreationResult:
        """Return process-created evidence without executing it."""

        process = Process()
        return ProcessCreationResult(
            process=process,
            created_pid=process.pid,
            created_tid=5001,
            created=True,
        )


class Scheduler:
    """Record scheduler submissions and drains without running queues."""

    def __init__(self) -> None:
        self.submit_calls = 0
        self.drain_calls = 0
        self.stop_reasons: list[str] = []

    def submit(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
        decision: AdmissionDecision,
        process: Any,
    ) -> ChildLaunchRecord:
        """Return a queued snapshot."""

        self.submit_calls += 1
        return ChildLaunchRecord(
            request=request,
            target=target,
            decision=decision,
            process=process,
            state=ChildExecutionState.THREAD_QUEUED,
        )

    def drain(self, parent_result: ParentRunOutcome) -> tuple[Any, ...]:
        """Record a drain request and return no child results."""

        self.drain_calls += 1
        return ()

    def stop(self, reason: str) -> None:
        """Record one stop reason."""

        self.stop_reasons.append(reason)

    def snapshot(self) -> Any:
        """Return no state because reports are dispatcher-owned."""

        return None


def _parent_budget() -> ExecutionBudget:
    return ExecutionBudget(
        timeout_seconds=119.0,
        max_api_count=4_321,
        max_instructions=8_765_432,
    )


def _context(budget: ExecutionBudget) -> ParentExecutionSnapshot:
    return ParentExecutionSnapshot(
        root_sample_sha256="3" * 64,
        pid=100,
        tid=101,
        cwd=r"C:\work",
        budget=budget,
    )


def _spec() -> ProcessLaunchSpec:
    return ProcessLaunchSpec(
        source_api="WinExec",
        target=r"C:\fixture.exe",
        command_line=r'"C:\fixture.exe"',
        working_directory=r"C:\work",
    )


def _dispatcher(
    *,
    enabled: bool,
    budget: ExecutionBudget,
) -> tuple[ChildLaunchDispatcher, Scheduler]:
    scheduler = Scheduler()
    return (
        ChildLaunchDispatcher(
            request_factory=RequestFactory(),
            target_resolver=Resolver(),
            admission_policy=Policy(),
            process_factory=ProcessFactory(),
            scheduler=scheduler,
            options=ChildExecutionOptions(enabled=enabled),
        ),
        scheduler,
    )


def test_budget_and_dispatcher_preserve_parent_limits_and_usage_owner() -> None:
    budget_factory = ExecutionBudgetFactory()
    parent_budget = budget_factory.capture_parent(
        type(
            "Config",
            (),
            {
                "timeout": 119.0,
                "max_api_count": 4_321,
                "max_instructions": 8_765_432,
            },
        )()
    )
    child_budget, child_usage = budget_factory.for_child(parent_budget)
    _, sibling_usage = budget_factory.for_child(parent_budget)
    dispatcher, _ = _dispatcher(enabled=False, budget=child_budget)

    outcome = dispatcher.submit(_spec(), parent_context=_context(child_budget))
    budget_factory.observe_api(child_usage)

    assert outcome.request.parent_budget == parent_budget
    assert outcome.request.parent_budget.max_instructions == 8_765_432
    assert child_usage is not sibling_usage
    assert sibling_usage == BudgetUsage()


def test_disabled_dispatcher_never_calls_scheduler() -> None:
    dispatcher, scheduler = _dispatcher(
        enabled=False,
        budget=_parent_budget(),
    )

    dispatcher.submit(_spec(), parent_context=_context(_parent_budget()))

    assert scheduler.submit_calls == 0
    assert dispatcher.report().thread_queued_count == 0


def test_enabled_dispatcher_uses_explicit_scheduler_once_per_request() -> None:
    dispatcher, scheduler = _dispatcher(
        enabled=True,
        budget=_parent_budget(),
    )

    dispatcher.submit(_spec(), parent_context=_context(_parent_budget()))
    dispatcher.parent_finished(
        ParentRunOutcome(
            status="ok",
            termination_reason="normal_exit",
            coverage_complete=True,
            budget=_parent_budget(),
            usage=BudgetUsage(),
        )
    )

    assert scheduler.submit_calls == 1
    assert scheduler.drain_calls == 1


def test_parent_failure_propagates_stop_and_closes_intake() -> None:
    dispatcher, scheduler = _dispatcher(
        enabled=True,
        budget=_parent_budget(),
    )
    dispatcher.parent_finished(
        ParentRunOutcome(
            status="failed",
            termination_reason="parent_stopped",
            coverage_complete=False,
            budget=_parent_budget(),
            usage=BudgetUsage(),
        )
    )

    assert scheduler.stop_reasons == ["parent_stopped"]
    assert scheduler.drain_calls == 0


def test_report_snapshot_does_not_alias_dispatcher_records() -> None:
    dispatcher, _ = _dispatcher(
        enabled=False,
        budget=_parent_budget(),
    )
    dispatcher.submit(_spec(), parent_context=_context(_parent_budget()))
    before = dispatcher.report()
    changed_context = replace(
        _context(_parent_budget()),
        budget=replace(_parent_budget(), timeout_seconds=120.0),
    )

    assert before.request_count == 1
    assert isinstance(before.records, tuple)
    assert changed_context.budget != _parent_budget()


def test_stage3_services_are_available_from_stable_package() -> None:
    factory = ExecutionBudgetFactory()
    parent_budget = factory.capture_parent(
        type(
            "Config",
            (),
            {
                "timeout": 1.0,
                "max_api_count": 2,
                "max_instructions": 3,
            },
        )()
    )
    child_budget, child_usage = factory.for_child(parent_budget)

    assert isinstance(child_budget, ExecutionBudget)
    assert child_usage == BudgetUsage()
    assert callable(ChildLaunchDispatcher)


def test_concrete_dispatcher_implements_frozen_protocol() -> None:
    dispatcher, _ = _dispatcher(
        enabled=False,
        budget=_parent_budget(),
    )

    assert isinstance(dispatcher, ChildExecutionDispatcher)
