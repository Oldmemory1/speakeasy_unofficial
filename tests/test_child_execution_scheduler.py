from __future__ import annotations

from contextlib import AbstractContextManager
from types import TracebackType
from typing import Any

import pytest

from speakeasy.windows.child_execution.budget import ExecutionBudgetFactory
from speakeasy.windows.child_execution.dispatcher import ChildLaunchDispatcher
from speakeasy.windows.child_execution.interfaces import (
    ChildResultSink,
    ChildSchedulerProtocol,
)
from speakeasy.windows.child_execution.models import (
    AdmissionDecision,
    BudgetUsage,
    ChildEventOwnership,
    ChildExecutionOptions,
    ChildExecutionState,
    ChildLaunchRequest,
    ChildOutcome,
    ChildProcessContext,
    ChildRunResult,
    ChildTargetSource,
    ChildTerminationReason,
    ExecutionBudget,
    LoadedChildImage,
    ParentExecutionSnapshot,
    ParentRunOutcome,
    ProcessCreationResult,
    ProcessLaunchSpec,
    ResolvedChildTarget,
)
from speakeasy.windows.child_execution.scheduler import ChildExecutionScheduler


class ProcessStub:
    """Process surface required by scheduler and context contracts."""

    def __init__(self, pid: int) -> None:
        self.id = pid
        self.pid = pid
        self.path = r"C:\fixtures\child.exe"
        self.cmdline = r'"C:\fixtures\child.exe"'
        self.threads: list[ThreadStub] = []


class ThreadStub:
    """Thread surface required by context contracts."""

    def __init__(self, tid: int) -> None:
        self.id = tid
        self.tid = tid


class ModuleStub:
    """Module surface required by loaded-image contracts."""

    def __init__(self) -> None:
        self.base = 0x500000
        self.image_size = 0x4000
        self.emu_path = r"C:\fixtures\child.exe"


class RunStub:
    """Run surface binding one child process and thread."""

    def __init__(
        self,
        process: ProcessStub,
        thread: ThreadStub,
        start_addr: int,
    ) -> None:
        self.type = "module_entry"
        self.start_addr = start_addr
        self.process_context = process
        self.thread = thread


class LoaderStub:
    """Record FIFO loads and selectively raise boundary errors."""

    def __init__(self) -> None:
        self.loaded_launch_ids: list[str] = []
        self.fail_launch_ids: set[str] = set()

    def load(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
    ) -> LoadedChildImage:
        """Return a non-primary image or raise for a configured launch."""

        assert target.resolved
        self.loaded_launch_ids.append(request.launch_id)
        if request.launch_id in self.fail_launch_ids:
            raise OSError("synthetic load failure")
        module = ModuleStub()
        return LoadedChildImage(
            request_launch_id=request.launch_id,
            module=module,
            image_base=module.base,
            entrypoint_address=module.base + 0x1000,
            primary=False,
        )


class ContextSession(AbstractContextManager[ChildProcessContext]):
    """Provide one explicit activation and restore pair."""

    def __init__(
        self,
        backend: ContextManagerStub,
        request: ChildLaunchRequest,
        image: LoadedChildImage,
        ownership: ChildEventOwnership,
    ) -> None:
        self._backend = backend
        self._request = request
        self._image = image
        self._ownership = ownership

    def __enter__(self) -> ChildProcessContext:
        """Activate child context or raise a configured boundary error."""

        if self._request.launch_id in self._backend.fail_launch_ids:
            self._backend.restore_count += 1
            raise RuntimeError("synthetic context failure")
        process = ProcessStub(self._ownership.child_pid)
        thread = ThreadStub(300)
        run = RunStub(process, thread, self._image.entrypoint_address)
        self._backend.activated_launch_ids.append(self._request.launch_id)
        return ChildProcessContext(
            process=process,
            thread=thread,
            module=self._image.module,
            run=run,
            ownership=self._ownership,
        )

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        """Record one parent restoration and preserve body exceptions."""

        self._backend.restore_count += 1
        return False


class ContextManagerStub:
    """Create context sessions and record explicit activation and restore."""

    def __init__(self) -> None:
        self.activated_launch_ids: list[str] = []
        self.fail_launch_ids: set[str] = set()
        self.restore_count = 0

    def enter(
        self,
        request: ChildLaunchRequest,
        image: LoadedChildImage,
        ownership: ChildEventOwnership,
    ) -> AbstractContextManager[ChildProcessContext]:
        """Return one session without switching context yet."""

        return ContextSession(self, request, image, ownership)


class RunnerStub:
    """Return one completed result using the scheduler-owned usage object."""

    def __init__(self) -> None:
        self.run_launch_ids: list[str] = []
        self.usage_ids: list[int] = []
        self.fail_launch_ids: set[str] = set()
        self.entrypoint_missing_launch_ids: set[str] = set()

    def run(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
        image: LoadedChildImage,
        context: ChildProcessContext,
        budget: ExecutionBudget,
        usage: BudgetUsage,
    ) -> ChildRunResult:
        """Return terminal evidence without entering an engine."""

        del target, image
        self.run_launch_ids.append(request.launch_id)
        self.usage_ids.append(id(usage))
        if request.launch_id in self.fail_launch_ids:
            raise RuntimeError("synthetic runner failure")
        entrypoint_reached = (
            request.launch_id not in self.entrypoint_missing_launch_ids
        )
        return ChildRunResult(
            launch_id=request.launch_id,
            ownership=context.ownership,
            state=(
                ChildExecutionState.COMPLETED
                if entrypoint_reached
                else ChildExecutionState.PARTIAL
            ),
            outcome=ChildOutcome.OK if entrypoint_reached else ChildOutcome.PARTIAL,
            termination_reason=(
                ChildTerminationReason.NORMAL_EXIT
                if entrypoint_reached
                else ChildTerminationReason.TIMEOUT
            ),
            budget=budget,
            usage=usage,
            run_indexes=(len(self.run_launch_ids),),
            error=None,
            entrypoint_reached=entrypoint_reached,
        )


class ReusingBudgetFactory(ExecutionBudgetFactory):
    """Return one shared usage object to exercise scheduler integrity checks."""

    def __init__(self) -> None:
        self.usage = BudgetUsage()

    def for_child(
        self,
        parent_budget: ExecutionBudget,
    ) -> tuple[ExecutionBudget, BudgetUsage]:
        """Return equal limits with a deliberately reused usage object."""

        child_budget, _ignored = super().for_child(parent_budget)
        return child_budget, self.usage


class MismatchedBudgetFactory(ExecutionBudgetFactory):
    """Return child limits that violate the parent/child equality contract."""

    def for_child(
        self,
        parent_budget: ExecutionBudget,
    ) -> tuple[ExecutionBudget, BudgetUsage]:
        """Return a fresh usage object with a lower hidden child limit."""

        child_budget, usage = super().for_child(parent_budget)
        return (
            ExecutionBudget(
                timeout_seconds=child_budget.timeout_seconds,
                max_api_count=child_budget.max_api_count - 1,
                max_instructions=child_budget.max_instructions,
            ),
            usage,
        )


class ResultSink:
    """Record published child results without changing scheduler state."""

    def __init__(self) -> None:
        self.launch_ids: list[str] = []

    def publish(self, result: ChildRunResult) -> None:
        """Record one terminal result."""

        self.launch_ids.append(result.launch_id)


class DispatcherRequestFactory:
    """Build deterministic requests through the public dispatcher inputs."""

    def __init__(self) -> None:
        self.count = 0

    def build(self, spec: ProcessLaunchSpec, **kwargs: Any) -> ChildLaunchRequest:
        """Return one request and retain all supplied parent facts."""

        self.count += 1
        return ChildLaunchRequest(
            launch_id=f"child-{self.count:06d}",
            root_sample_sha256=kwargs["root_sample_sha256"],
            parent_launch_id=kwargs["parent_launch_id"],
            source_api=spec.source_api,
            parent_pid=kwargs["parent_pid"],
            parent_tid=kwargs["parent_tid"],
            depth=kwargs["depth"],
            target=spec.target or r"C:\fixtures\child.exe",
            normalized_target=spec.target or r"C:\fixtures\child.exe",
            working_directory=kwargs["cwd"],
            command_line=spec.command_line,
            command_sha256="c" * 64,
            parent_budget=kwargs["parent_budget"],
        )


class DispatcherTargetResolver:
    """Resolve the fixed test target without reading an engine."""

    def resolve(self, request: ChildLaunchRequest) -> ResolvedChildTarget:
        """Return resolved target evidence for the request."""

        return _target(request)

    def register_fixture(self, normalized_path: str, data: bytes) -> None:
        """Accept an unused explicit fixture registration."""

        del normalized_path, data


class DispatcherAdmissionPolicy:
    """Admit every already resolved dispatcher request."""

    def evaluate(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
        *,
        launch_history: tuple[Any, ...],
    ) -> AdmissionDecision:
        """Return an eligible immutable decision."""

        del request, target, launch_history
        return _decision()


class DispatcherProcessFactory:
    """Create one explicit process object for an admitted request."""

    def create(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
    ) -> ProcessCreationResult:
        """Return process creation evidence without executing child code."""

        del target
        process = ProcessStub(700)
        return ProcessCreationResult(
            process=process,
            created_pid=process.pid,
            created_tid=701,
            created=True,
        )


def _budget() -> ExecutionBudget:
    return ExecutionBudget(
        timeout_seconds=71.5,
        max_api_count=3_331,
        max_instructions=8_887_777,
    )


def _request(ordinal: int) -> ChildLaunchRequest:
    return ChildLaunchRequest(
        launch_id=f"child-{ordinal:06d}",
        root_sample_sha256="a" * 64,
        parent_launch_id=None,
        source_api="CreateProcess",
        parent_pid=100,
        parent_tid=101,
        depth=1,
        target=r"C:\fixtures\child.exe",
        normalized_target=r"C:\fixtures\child.exe",
        working_directory=r"C:\fixtures",
        command_line=r'"C:\fixtures\child.exe"',
        command_sha256=f"{ordinal:064x}"[-64:],
        parent_budget=_budget(),
    )


def _target(request: ChildLaunchRequest) -> ResolvedChildTarget:
    return ResolvedChildTarget(
        source=ChildTargetSource.FIXTURE,
        normalized_path=request.normalized_target,
        payload_ref=None,
        sha256="b" * 64,
        size=4096,
        file_format="pe",
        arch="x86",
        module_type="exe",
        entrypoint_rva=0x1000,
        resolved=True,
        reason=None,
    )


def _decision() -> AdmissionDecision:
    return AdmissionDecision(
        eligible=True,
        state=ChildExecutionState.ELIGIBLE,
        reason=None,
    )


def _parent_result(
    *,
    status: str = "ok",
    budget: ExecutionBudget | None = None,
) -> ParentRunOutcome:
    return ParentRunOutcome(
        status=status,
        termination_reason=(
            "normal_exit" if status == "ok" else "parent_stopped"
        ),
        coverage_complete=status == "ok",
        budget=budget or _budget(),
        usage=BudgetUsage(),
    )


def _scheduler(
    *,
    budget_factory: ExecutionBudgetFactory | None = None,
    result_sink: ChildResultSink | None = None,
) -> tuple[
    ChildExecutionScheduler,
    LoaderStub,
    ContextManagerStub,
    RunnerStub,
]:
    loader = LoaderStub()
    context_manager = ContextManagerStub()
    runner = RunnerStub()
    scheduler = ChildExecutionScheduler(
        loader=loader,
        context_manager=context_manager,
        runner=runner,
        budget_factory=budget_factory or ExecutionBudgetFactory(),
        result_sink=result_sink,
    )
    return scheduler, loader, context_manager, runner


def _submit(
    scheduler: ChildExecutionScheduler,
    ordinal: int,
) -> None:
    request = _request(ordinal)
    scheduler.submit(
        request,
        _target(request),
        _decision(),
        ProcessStub(200 + ordinal),
    )


def test_scheduler_implements_frozen_protocol() -> None:
    scheduler, _, _, _ = _scheduler()

    assert isinstance(scheduler, ChildSchedulerProtocol)


def test_dispatcher_uses_production_scheduler_as_only_drain_path() -> None:
    scheduler, loader, _, runner = _scheduler()
    dispatcher = ChildLaunchDispatcher(
        request_factory=DispatcherRequestFactory(),
        target_resolver=DispatcherTargetResolver(),
        admission_policy=DispatcherAdmissionPolicy(),
        process_factory=DispatcherProcessFactory(),
        scheduler=scheduler,
        options=ChildExecutionOptions(enabled=True),
    )
    parent_context = ParentExecutionSnapshot(
        root_sample_sha256="a" * 64,
        pid=100,
        tid=101,
        cwd=r"C:\fixtures",
        budget=_budget(),
    )

    outcome = dispatcher.submit(
        ProcessLaunchSpec(
            source_api="CreateProcess",
            target=r"C:\fixtures\child.exe",
            command_line=r'"C:\fixtures\child.exe"',
            working_directory=r"C:\fixtures",
        ),
        parent_context=parent_context,
    )

    assert outcome.creation.created is True
    assert loader.loaded_launch_ids == []
    dispatcher.parent_finished(_parent_result())
    report = dispatcher.report()

    assert loader.loaded_launch_ids == ["child-000001"]
    assert runner.run_launch_ids == ["child-000001"]
    assert report.records[0].state is ChildExecutionState.COMPLETED
    assert report.results[0].state is ChildExecutionState.COMPLETED


def test_submit_only_queues_without_loading_or_executing() -> None:
    scheduler, loader, context_manager, runner = _scheduler()

    _submit(scheduler, 1)
    snapshot = scheduler.snapshot()

    assert loader.loaded_launch_ids == []
    assert context_manager.activated_launch_ids == []
    assert runner.run_launch_ids == []
    assert snapshot.request_count == 1
    assert snapshot.thread_queued_count == 1
    assert snapshot.records[0].state is ChildExecutionState.THREAD_QUEUED


def test_drain_executes_fifo_with_equal_limits_and_independent_usage() -> None:
    sink = ResultSink()
    scheduler, loader, context_manager, runner = _scheduler(
        result_sink=sink
    )
    _submit(scheduler, 1)
    _submit(scheduler, 2)

    results = scheduler.drain(_parent_result())
    snapshot = scheduler.snapshot()

    assert loader.loaded_launch_ids == ["child-000001", "child-000002"]
    assert context_manager.activated_launch_ids == [
        "child-000001",
        "child-000002",
    ]
    assert runner.run_launch_ids == ["child-000001", "child-000002"]
    assert len(set(runner.usage_ids)) == 2
    assert context_manager.restore_count == 2
    assert sink.launch_ids == ["child-000001", "child-000002"]
    assert [result.launch_id for result in results] == [
        "child-000001",
        "child-000002",
    ]
    assert all(result.budget == _budget() for result in results)
    assert results[0].usage is not results[1].usage
    assert snapshot.entrypoint_reached_count == 2
    assert all(
        record.state is ChildExecutionState.COMPLETED
        for record in snapshot.records
    )


def test_repeated_drain_never_replays_queue() -> None:
    scheduler, loader, _, _ = _scheduler()
    _submit(scheduler, 1)

    first = scheduler.drain(_parent_result())
    second = scheduler.drain(_parent_result())

    assert first == second
    assert loader.loaded_launch_ids == ["child-000001"]
    with pytest.raises(RuntimeError, match="closed"):
        _submit(scheduler, 2)


def test_partial_child_does_not_infer_entrypoint_from_terminal_state() -> None:
    scheduler, _, _, runner = _scheduler()
    runner.entrypoint_missing_launch_ids.add("child-000001")
    _submit(scheduler, 1)

    results = scheduler.drain(_parent_result())
    snapshot = scheduler.snapshot()

    assert results[0].state is ChildExecutionState.PARTIAL
    assert results[0].entrypoint_reached is False
    assert snapshot.records[0].state is ChildExecutionState.PARTIAL
    assert snapshot.entrypoint_reached_count == 0


def test_failed_parent_stops_pending_work_without_loading() -> None:
    scheduler, loader, context_manager, runner = _scheduler()
    _submit(scheduler, 1)

    results = scheduler.drain(_parent_result(status="failed"))
    snapshot = scheduler.snapshot()

    assert results == ()
    assert loader.loaded_launch_ids == []
    assert context_manager.activated_launch_ids == []
    assert runner.run_launch_ids == []
    assert snapshot.records[0].state is ChildExecutionState.SKIPPED
    assert snapshot.records[0].reason == "parent_stopped"


def test_changed_parent_budget_stops_all_pending_work() -> None:
    scheduler, loader, _, _ = _scheduler()
    _submit(scheduler, 1)
    changed = ExecutionBudget(
        timeout_seconds=72.5,
        max_api_count=3_331,
        max_instructions=8_887_777,
    )

    results = scheduler.drain(_parent_result(budget=changed))

    assert results == ()
    assert loader.loaded_launch_ids == []
    assert scheduler.snapshot().records[0].reason == "parent_budget_changed"


def test_load_failure_is_child_local_and_next_child_continues() -> None:
    scheduler, loader, _, runner = _scheduler()
    loader.fail_launch_ids.add("child-000001")
    _submit(scheduler, 1)
    _submit(scheduler, 2)

    results = scheduler.drain(_parent_result())

    assert runner.run_launch_ids == ["child-000002"]
    assert len(results) == 2
    assert results[0].state is ChildExecutionState.FAILED
    assert results[0].termination_reason is ChildTerminationReason.LOAD_ERROR
    assert results[1].state is ChildExecutionState.COMPLETED
    assert scheduler.snapshot().thread_queued_count == 2


def test_context_integrity_failure_stops_later_children() -> None:
    scheduler, loader, context_manager, runner = _scheduler()
    context_manager.fail_launch_ids.add("child-000001")
    _submit(scheduler, 1)
    _submit(scheduler, 2)

    results = scheduler.drain(_parent_result())
    snapshot = scheduler.snapshot()

    assert loader.loaded_launch_ids == ["child-000001"]
    assert runner.run_launch_ids == []
    assert len(results) == 1
    assert results[0].state is ChildExecutionState.FAILED
    assert results[0].error is not None
    assert results[0].error.kind.value == "context"
    assert snapshot.records[1].state is ChildExecutionState.SKIPPED
    assert snapshot.records[1].reason == "child_context_integrity_failed"


def test_runner_failure_is_child_local_and_next_child_continues() -> None:
    scheduler, loader, context_manager, runner = _scheduler()
    runner.fail_launch_ids.add("child-000001")
    _submit(scheduler, 1)
    _submit(scheduler, 2)

    results = scheduler.drain(_parent_result())

    assert loader.loaded_launch_ids == ["child-000001", "child-000002"]
    assert runner.run_launch_ids == ["child-000001", "child-000002"]
    assert context_manager.restore_count == 2
    assert len(results) == 2
    assert results[0].state is ChildExecutionState.FAILED
    assert results[0].error is not None
    assert results[0].error.kind.value == "runtime"
    assert results[1].state is ChildExecutionState.COMPLETED


def test_mismatched_child_budget_prevents_every_child_start() -> None:
    scheduler, loader, _, runner = _scheduler(
        budget_factory=MismatchedBudgetFactory()
    )
    _submit(scheduler, 1)
    _submit(scheduler, 2)

    results = scheduler.drain(_parent_result())
    snapshot = scheduler.snapshot()

    assert loader.loaded_launch_ids == []
    assert runner.run_launch_ids == []
    assert len(results) == 1
    assert results[0].error is not None
    assert results[0].error.message == "child budget limits do not match the parent"
    assert snapshot.records[1].reason == "child_budget_mismatch"


def test_shared_usage_counter_prevents_second_child_start() -> None:
    scheduler, loader, _, runner = _scheduler(
        budget_factory=ReusingBudgetFactory()
    )
    _submit(scheduler, 1)
    _submit(scheduler, 2)

    results = scheduler.drain(_parent_result())
    snapshot = scheduler.snapshot()

    assert loader.loaded_launch_ids == ["child-000001"]
    assert runner.run_launch_ids == ["child-000001"]
    assert len(results) == 2
    assert results[1].error is not None
    assert results[1].error.message == "child usage counter is shared with another run"
    assert snapshot.records[1].state is ChildExecutionState.FAILED


def test_explicit_stop_prevents_drain_from_starting_work() -> None:
    scheduler, loader, _, runner = _scheduler()
    _submit(scheduler, 1)

    scheduler.stop("operator_stop")
    results = scheduler.drain(_parent_result())

    assert results == ()
    assert loader.loaded_launch_ids == []
    assert runner.run_launch_ids == []
    assert scheduler.snapshot().records[0].state is ChildExecutionState.SKIPPED


def test_submit_rejects_mismatched_target_path() -> None:
    scheduler, _, _, _ = _scheduler()
    request = _request(1)
    target = _target(request)
    mismatched = ResolvedChildTarget(
        source=target.source,
        normalized_path=r"C:\fixtures\other.exe",
        payload_ref=target.payload_ref,
        sha256=target.sha256,
        size=target.size,
        file_format=target.file_format,
        arch=target.arch,
        module_type=target.module_type,
        entrypoint_rva=target.entrypoint_rva,
        resolved=target.resolved,
        reason=target.reason,
    )

    with pytest.raises(ValueError, match="target path"):
        scheduler.submit(
            request,
            mismatched,
            _decision(),
            ProcessStub(201),
        )


def test_submit_rejects_ineligible_decision() -> None:
    scheduler, _, _, _ = _scheduler()
    request = _request(1)

    with pytest.raises(ValueError, match="eligible"):
        scheduler.submit(
            request,
            _target(request),
            AdmissionDecision(
                eligible=False,
                state=ChildExecutionState.REJECTED,
                reason="depth_limit",
            ),
            ProcessStub(201),
        )
