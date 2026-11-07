from __future__ import annotations

from dataclasses import replace
from typing import Any

from speakeasy.windows.child_execution.budget import ExecutionBudgetFactory
from speakeasy.windows.child_execution.interfaces import ChildRunnerProtocol
from speakeasy.windows.child_execution.models import (
    BudgetUsage,
    ChildEventOwnership,
    ChildExecutionState,
    ChildFailureKind,
    ChildLaunchRequest,
    ChildOutcome,
    ChildProcessContext,
    ChildTargetSource,
    ChildTerminationReason,
    ExecutionBudget,
    LoadedChildImage,
    ResolvedChildTarget,
)
from speakeasy.windows.child_execution.runner import (
    ChildBudgetHooks,
    ChildExecutionBackendResult,
    ChildExecutionRunner,
    ChildExecutionRuntimeError,
)


class ObjectStub:
    """Small explicit runtime object used instead of patching an emulator."""

    def __init__(self, value: int) -> None:
        self.id = value
        self.pid = value
        self.tid = value
        self.path = r"C:\fixture.exe"
        self.cmdline = '"C:\\fixture.exe"'
        self.threads: list[Any] = []
        self.base = 0x400000 + value
        self.image_size = 0x1000
        self.emu_path = r"C:\fixture.exe"
        self.type = "module_entry"
        self.start_addr = self.base
        self.process_context = None
        self.thread = None


class EntrypointObserver:
    """Record explicit arm and actual entrypoint-hook evidence."""

    def __init__(self) -> None:
        self.armed_launch_ids: list[str] = []
        self.disarmed_launch_ids: list[str] = []
        self.reached_launch_ids: set[str] = set()

    def arm(self, context: ChildProcessContext) -> None:
        """Record the child context before backend execution."""

        self.armed_launch_ids.append(context.ownership.launch_id)

    def disarm(self, launch_id: str) -> None:
        """Record removal of a pending one-shot observation hook."""

        self.disarmed_launch_ids.append(launch_id)

    def reached(self, launch_id: str) -> bool:
        """Return only entrypoints reported by the fake backend hook."""

        return launch_id in self.reached_launch_ids

    def fire(self, launch_id: str) -> None:
        """Simulate a call into the engine's armed one-shot hook."""

        self.reached_launch_ids.add(launch_id)


class Clock:
    """Deterministic monotonic clock controlled by each test backend."""

    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        """Return the current deterministic time in seconds."""

        return self.value


class Backend:
    """Fake backend that exercises only the public runner callback contract."""

    def __init__(
        self,
        observer: EntrypointObserver,
        *,
        reach_entrypoint: bool = True,
        api_calls: int = 0,
        instruction_batches: tuple[int, ...] = (),
        advance_time: float = 0.0,
        run_indexes: tuple[int, ...] = (7,),
        raised: Exception | None = None,
    ) -> None:
        self._observer = observer
        self._reach_entrypoint = reach_entrypoint
        self._api_calls = api_calls
        self._instruction_batches = instruction_batches
        self._advance_time = advance_time
        self._run_indexes = run_indexes
        self._raised = raised
        self.call_count = 0
        self.last_hooks: ChildBudgetHooks | None = None

    def run(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
        image: LoadedChildImage,
        context: ChildProcessContext,
        budget_hooks: ChildBudgetHooks,
    ) -> ChildExecutionBackendResult:
        """Execute synthetic hooks and return explicit runtime evidence."""

        self.call_count += 1
        self.last_hooks = budget_hooks
        if self._raised is not None:
            raise self._raised
        if self._reach_entrypoint:
            self._observer.fire(request.launch_id)
        for _ in range(self._api_calls):
            if not budget_hooks.observe_api():
                break
        for count in self._instruction_batches:
            if not budget_hooks.observe_instructions(count):
                break
        if self._advance_time:
            self._advance_time = 0.0
            if not budget_hooks.should_continue():
                return ChildExecutionBackendResult(self._run_indexes)
        return ChildExecutionBackendResult(self._run_indexes)


def _budget(
    *,
    timeout: float = 30.0,
    max_api_count: int = 20,
    max_instructions: int = 10_000,
) -> ExecutionBudget:
    return ExecutionBudget(
        timeout_seconds=timeout,
        max_api_count=max_api_count,
        max_instructions=max_instructions,
    )


def _run_inputs(
    budget: ExecutionBudget,
) -> tuple[
    ChildLaunchRequest,
    ResolvedChildTarget,
    LoadedChildImage,
    ChildProcessContext,
]:
    launch_id = "child-000007"
    ownership = ChildEventOwnership(
        root_sample_sha256="1" * 64,
        launch_id=launch_id,
        parent_pid=100,
        child_pid=200,
        depth=1,
    )
    request = ChildLaunchRequest(
        launch_id=launch_id,
        root_sample_sha256=ownership.root_sample_sha256,
        parent_launch_id=None,
        source_api="CreateProcess",
        parent_pid=ownership.parent_pid,
        parent_tid=101,
        depth=1,
        target=r"C:\fixture.exe",
        normalized_target=r"C:\fixture.exe",
        working_directory=r"C:\work",
        command_line=r'"C:\fixture.exe"',
        command_sha256="2" * 64,
        parent_budget=budget,
    )
    target = ResolvedChildTarget(
        source=ChildTargetSource.FIXTURE,
        normalized_path=request.normalized_target,
        payload_ref=None,
        sha256="3" * 64,
        size=1024,
        file_format="pe",
        arch="x86",
        module_type="exe",
        entrypoint_rva=0x1000,
        resolved=True,
        reason=None,
    )
    module = ObjectStub(0x400000)
    image = LoadedChildImage(
        request_launch_id=launch_id,
        module=module,
        image_base=module.base,
        entrypoint_address=module.base + 0x1000,
        primary=False,
    )
    process = ObjectStub(200)
    thread = ObjectStub(201)
    run = ObjectStub(202)
    run.process_context = process
    run.thread = thread
    context = ChildProcessContext(
        process=process,
        thread=thread,
        module=module,
        run=run,
        ownership=ownership,
    )
    return request, target, image, context


def _runner(
    backend: Backend,
    observer: EntrypointObserver,
    clock: Clock,
) -> ChildExecutionRunner:
    return ChildExecutionRunner(
        backend=backend,
        entrypoint_observer=observer,
        budget_factory=ExecutionBudgetFactory(),
        clock=clock,
    )


def test_runner_implements_frozen_child_runner_protocol() -> None:
    observer = EntrypointObserver()
    runner = _runner(Backend(observer), observer, Clock())

    assert isinstance(runner, ChildRunnerProtocol)


def test_runner_arms_observer_and_reports_only_actual_entrypoint_evidence() -> None:
    budget = _budget()
    request, target, image, context = _run_inputs(budget)
    observer = EntrypointObserver()
    backend = Backend(observer)
    runner = _runner(backend, observer, Clock())

    result = runner.run(
        request,
        target,
        image,
        context,
        budget,
        BudgetUsage(),
    )

    assert backend.last_hooks is not None
    assert observer.armed_launch_ids == [request.launch_id]
    assert observer.disarmed_launch_ids == [request.launch_id]
    assert result.state is ChildExecutionState.COMPLETED
    assert result.outcome is ChildOutcome.OK
    assert result.termination_reason is ChildTerminationReason.NORMAL_EXIT
    assert result.run_indexes == (7,)
    assert result.ownership == context.ownership
    assert result.error is None


def test_runner_reports_partial_when_run_queued_but_entrypoint_never_fired() -> None:
    budget = _budget()
    request, target, image, context = _run_inputs(budget)
    observer = EntrypointObserver()
    runner = _runner(Backend(observer, reach_entrypoint=False), observer, Clock())

    result = runner.run(
        request,
        target,
        image,
        context,
        budget,
        BudgetUsage(),
    )

    assert result.state is ChildExecutionState.PARTIAL
    assert result.outcome is ChildOutcome.PARTIAL
    assert result.termination_reason is ChildTerminationReason.ENTRYPOINT_MISSING
    assert result.error is not None
    assert result.error.kind is ChildFailureKind.RUNTIME


def test_runner_reports_failure_when_no_child_run_was_queued() -> None:
    budget = _budget()
    request, target, image, context = _run_inputs(budget)
    observer = EntrypointObserver()
    runner = _runner(
        Backend(observer, reach_entrypoint=False, run_indexes=()),
        observer,
        Clock(),
    )

    result = runner.run(
        request,
        target,
        image,
        context,
        budget,
        BudgetUsage(),
    )

    assert result.state is ChildExecutionState.FAILED
    assert result.outcome is ChildOutcome.ERROR
    assert result.termination_reason is ChildTerminationReason.INVALID_FETCH
    assert result.error is not None


def test_api_budget_stops_at_first_excess_call_and_isolates_failure() -> None:
    budget = _budget(max_api_count=2)
    request, target, image, context = _run_inputs(budget)
    observer = EntrypointObserver()
    backend = Backend(observer, api_calls=3)
    usage = BudgetUsage()

    result = _runner(backend, observer, Clock()).run(
        request,
        target,
        image,
        context,
        budget,
        usage,
    )

    assert usage.api_count_used == 3
    assert result.state is ChildExecutionState.PARTIAL
    assert result.outcome is ChildOutcome.PARTIAL
    assert result.termination_reason is ChildTerminationReason.MAX_API_COUNT
    assert result.error is not None
    assert result.error.kind is ChildFailureKind.BUDGET


def test_instruction_budget_uses_each_child_usage_counter() -> None:
    budget = _budget(max_instructions=10)
    request, target, image, context = _run_inputs(budget)
    observer = EntrypointObserver()
    backend = Backend(observer, instruction_batches=(6, 6))
    first_usage = BudgetUsage()
    sibling_usage = BudgetUsage()
    runner = _runner(backend, observer, Clock())

    result = runner.run(
        request,
        target,
        image,
        context,
        budget,
        first_usage,
    )

    assert result.termination_reason is ChildTerminationReason.MAX_INSTRUCTIONS
    assert first_usage.instructions_used == 12
    assert sibling_usage.instructions_used == 0


def test_timeout_uses_injected_clock_and_does_not_touch_parent_budget() -> None:
    budget = _budget(timeout=5.0)
    request, target, image, context = _run_inputs(budget)
    observer = EntrypointObserver()
    clock = Clock()

    class AdvancingBackend(Backend):
        """Advance the injected clock before checking the budget."""

        def run(self, request, target, image, context, budget_hooks):
            clock.value += self._advance_time
            self._advance_time = 0.0
            assert not budget_hooks.should_continue()
            return ChildExecutionBackendResult(self._run_indexes)

    result = _runner(AdvancingBackend(observer, advance_time=6.0), observer, clock).run(
        request,
        target,
        image,
        context,
        budget,
        BudgetUsage(),
    )

    assert result.termination_reason is ChildTerminationReason.TIMEOUT
    assert budget.timeout_seconds == 5.0


def test_expected_backend_error_is_returned_as_child_failure() -> None:
    budget = _budget()
    request, target, image, context = _run_inputs(budget)
    observer = EntrypointObserver()
    failure = ChildExecutionRuntimeError(
        "invalid child fetch",
        kind=ChildFailureKind.RUNTIME,
        termination_reason=ChildTerminationReason.INVALID_MEMORY,
        run_indexes=(7,),
        pc=0x401000,
        fault_address=0x14,
        access_type="read",
        api_name="kernel32.LeaveCriticalSection",
    )
    runner = _runner(Backend(observer, raised=failure), observer, Clock())

    result = runner.run(
        request,
        target,
        image,
        context,
        budget,
        BudgetUsage(),
    )

    assert result.state is ChildExecutionState.FAILED
    assert result.outcome is ChildOutcome.ERROR
    assert result.termination_reason is ChildTerminationReason.INVALID_MEMORY
    assert result.run_indexes == (7,)
    assert result.error is not None
    assert result.error.message == "invalid child fetch"
    assert result.error.pc == 0x401000
    assert result.error.fault_address == 0x14
    assert result.error.access_type == "read"
    assert result.error.api_name == "kernel32.LeaveCriticalSection"


def test_unexpected_backend_exception_is_contained() -> None:
    budget = _budget()
    request, target, image, context = _run_inputs(budget)
    observer = EntrypointObserver()
    runner = _runner(Backend(observer, raised=RuntimeError("boom")), observer, Clock())

    result = runner.run(
        request,
        target,
        image,
        context,
        budget,
        BudgetUsage(),
    )

    assert result.state is ChildExecutionState.FAILED
    assert result.termination_reason is ChildTerminationReason.INTERNAL_ERROR
    assert result.error is not None
    assert result.error.kind is ChildFailureKind.RUNTIME
    assert "boom" in result.error.message


def test_primary_image_and_identity_mismatch_are_rejected_before_backend() -> None:
    budget = _budget()
    request, target, image, context = _run_inputs(budget)
    observer = EntrypointObserver()
    backend = Backend(observer)
    runner = _runner(backend, observer, Clock())
    primary_image = LoadedChildImage(
        request_launch_id=image.request_launch_id,
        module=image.module,
        image_base=image.image_base,
        entrypoint_address=image.entrypoint_address,
        primary=True,  # type: ignore[arg-type]
    )

    primary_result = runner.run(
        request,
        target,
        primary_image,
        context,
        budget,
        BudgetUsage(),
    )
    mismatch_result = runner.run(
        request,
        target,
        replace(image, request_launch_id="child-999999"),
        context,
        budget,
        BudgetUsage(),
    )

    assert backend.call_count == 0
    assert primary_result.termination_reason is ChildTerminationReason.LOAD_ERROR
    assert mismatch_result.termination_reason is ChildTerminationReason.LOAD_ERROR


def test_runner_rejects_unresolved_target_before_backend() -> None:
    budget = _budget()
    request, target, image, context = _run_inputs(budget)
    observer = EntrypointObserver()
    backend = Backend(observer)

    result = _runner(backend, observer, Clock()).run(
        request,
        replace(target, resolved=False, reason="target_unavailable"),
        image,
        context,
        budget,
        BudgetUsage(),
    )

    assert backend.call_count == 0
    assert result.termination_reason is ChildTerminationReason.TARGET_UNAVAILABLE
    assert result.error is not None
    assert result.error.kind is ChildFailureKind.TARGET


def test_runner_rejects_entrypoint_and_reused_usage_before_backend() -> None:
    budget = _budget()
    request, target, image, context = _run_inputs(budget)
    observer = EntrypointObserver()
    backend = Backend(observer)
    runner = _runner(backend, observer, Clock())

    entrypoint_result = runner.run(
        request,
        target,
        replace(image, entrypoint_address=image.entrypoint_address + 4),
        context,
        budget,
        BudgetUsage(),
    )
    usage_result = runner.run(
        request,
        target,
        image,
        context,
        budget,
        BudgetUsage(api_count_used=1),
    )

    assert backend.call_count == 0
    assert (
        entrypoint_result.termination_reason
        is ChildTerminationReason.ENTRYPOINT_OUT_OF_RANGE
    )
    assert usage_result.termination_reason is ChildTerminationReason.INTERNAL_ERROR
    assert usage_result.error is not None
    assert usage_result.error.kind is ChildFailureKind.BUDGET
