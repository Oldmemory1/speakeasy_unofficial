from __future__ import annotations

from collections.abc import Callable

import pytest

from speakeasy.windows.child_execution.interfaces import (
    ChildContextManager,
    ChildEntrypointObserver,
)
from speakeasy.windows.child_execution.models import (
    ChildEventOwnership,
    ChildLaunchRequest,
    ChildProcessContext,
    ExecutionBudget,
    LoadedChildImage,
)
from speakeasy.windows.child_execution.runtime_context import (
    ChildContextSession,
    ChildEntrypointObservationError,
    ChildRuntimeContextBackend,
    ChildRuntimeContextError,
    ChildRuntimeContextManager,
    OneShotChildEntrypointObserver,
    ParentRuntimeContext,
)


class ExplicitProcess:
    """Process stub exposing the public child process contract."""

    def __init__(self, pid: int) -> None:
        self.id = pid
        self.pid = pid
        self.path = r"C:\fixtures\child.exe"
        self.cmdline = r'"C:\fixtures\child.exe"'
        self.threads: list[ExplicitThread] = []


class ExplicitThread:
    """Thread stub exposing the public child thread contract."""

    def __init__(self, tid: int) -> None:
        self.id = tid
        self.tid = tid


class ExplicitModule:
    """Module stub exposing the public child module contract."""

    def __init__(self) -> None:
        self.base = 0x500000
        self.image_size = 0x5000
        self.emu_path = r"C:\fixtures\child.exe"


class ExplicitRun:
    """Run stub exposing only fields read by the context manager."""

    def __init__(
        self,
        process: ExplicitProcess,
        thread: ExplicitThread,
        start_addr: int,
    ) -> None:
        self.type = "module_entry"
        self.start_addr = start_addr
        self.process_context = process
        self.thread = thread


class ExplicitContextBackend:
    """Backend stub that records activation and restores explicit handles."""

    def __init__(self, context: ChildProcessContext) -> None:
        self.context = context
        self.parent = ParentRuntimeContext(
            process=ExplicitProcess(100),
            thread=ExplicitThread(101),
            run=None,
        )
        self.restored: list[ParentRuntimeContext] = []
        self.activation_count = 0
        self.activation_error: Exception | None = None

    def capture_parent(self) -> ParentRuntimeContext:
        """Return a deterministic parent snapshot."""

        return self.parent

    def activate(
        self,
        request: ChildLaunchRequest,
        image: LoadedChildImage,
        ownership: ChildEventOwnership,
    ) -> ChildProcessContext:
        """Return the configured child context or raise a configured error."""

        self.activation_count += 1
        if self.activation_error is not None:
            raise self.activation_error
        return self.context

    def restore_parent(self, parent: ParentRuntimeContext) -> None:
        """Record restoration of one exact parent snapshot."""

        self.restored.append(parent)


class ExplicitHook:
    """Code hook stub recording whether it was disabled."""

    def __init__(self) -> None:
        self.disabled = False

    def disable(self) -> None:
        """Disable this explicit hook."""

        self.disabled = True


class ExplicitHookBackend:
    """Code-hook backend stub recording one explicit hook registration."""

    def __init__(self) -> None:
        self.callback: Callable[[object, int, int], bool] | None = None
        self.boundaries: tuple[int, int] | None = None
        self.hook = ExplicitHook()
        self.add_count = 0

    def add_code_hook(
        self,
        callback: Callable[[object, int, int], bool],
        *,
        begin: int,
        end: int,
    ) -> ExplicitHook:
        """Record the registered callback and return its hook handle."""

        self.callback = callback
        self.boundaries = (begin, end)
        self.add_count += 1
        return self.hook


def _request() -> ChildLaunchRequest:
    return ChildLaunchRequest(
        launch_id="child-000001",
        root_sample_sha256="1" * 64,
        parent_launch_id=None,
        source_api="CreateProcess",
        parent_pid=100,
        parent_tid=101,
        depth=1,
        target=r"C:\fixtures\child.exe",
        normalized_target=r"C:\fixtures\child.exe",
        working_directory=r"C:\fixtures",
        command_line=r'"C:\fixtures\child.exe"',
        command_sha256="2" * 64,
        parent_budget=ExecutionBudget(
            timeout_seconds=30.0,
            max_api_count=100,
            max_instructions=10_000,
        ),
    )


def _inputs() -> tuple[
    ChildLaunchRequest,
    LoadedChildImage,
    ChildEventOwnership,
    ChildProcessContext,
]:
    request = _request()
    ownership = ChildEventOwnership(
        root_sample_sha256=request.root_sample_sha256,
        launch_id=request.launch_id,
        parent_pid=request.parent_pid,
        child_pid=200,
        depth=request.depth,
    )
    module = ExplicitModule()
    process = ExplicitProcess(ownership.child_pid)
    thread = ExplicitThread(201)
    run = ExplicitRun(process, thread, module.base + 0x1000)
    image = LoadedChildImage(
        request_launch_id=request.launch_id,
        module=module,
        image_base=module.base,
        entrypoint_address=run.start_addr,
        primary=False,
    )
    context = ChildProcessContext(
        process=process,
        thread=thread,
        module=module,
        run=run,
        ownership=ownership,
    )
    return request, image, ownership, context


def test_context_implementations_satisfy_frozen_protocols() -> None:
    _, _, _, context = _inputs()
    backend = ExplicitContextBackend(context)
    hook_backend = ExplicitHookBackend()

    assert isinstance(backend, ChildRuntimeContextBackend)
    assert isinstance(
        ChildRuntimeContextManager(backend),
        ChildContextManager,
    )
    assert isinstance(
        OneShotChildEntrypointObserver(hook_backend),
        ChildEntrypointObserver,
    )


def test_context_manager_activates_child_and_restores_parent_on_normal_exit() -> None:
    request, image, ownership, context = _inputs()
    backend = ExplicitContextBackend(context)
    manager = ChildRuntimeContextManager(backend)

    with manager.enter(request, image, ownership) as active:
        assert active is context
        assert backend.restored == []

    assert backend.activation_count == 1
    assert backend.restored == [backend.parent]


def test_context_manager_restores_parent_and_preserves_body_exception() -> None:
    request, image, ownership, context = _inputs()
    backend = ExplicitContextBackend(context)

    with pytest.raises(RuntimeError, match="child body failed"):
        with ChildRuntimeContextManager(backend).enter(
            request,
            image,
            ownership,
        ):
            raise RuntimeError("child body failed")

    assert len(backend.restored) == 1


def test_context_manager_restores_parent_when_activation_fails() -> None:
    request, image, ownership, context = _inputs()
    backend = ExplicitContextBackend(context)
    backend.activation_error = OSError("activation failed")

    with pytest.raises(ChildRuntimeContextError, match="cannot activate"):
        with ChildRuntimeContextManager(backend).enter(
            request,
            image,
            ownership,
        ):
            pytest.fail("failed activation must not yield a context")

    assert len(backend.restored) == 1


def test_context_manager_rolls_back_mismatched_child_context() -> None:
    request, image, ownership, context = _inputs()
    context.ownership = ChildEventOwnership(
        root_sample_sha256=ownership.root_sample_sha256,
        launch_id="child-999999",
        parent_pid=ownership.parent_pid,
        child_pid=ownership.child_pid,
        depth=ownership.depth,
    )
    backend = ExplicitContextBackend(context)

    with pytest.raises(ChildRuntimeContextError, match="ownership"):
        with ChildRuntimeContextManager(backend).enter(
            request,
            image,
            ownership,
        ):
            pytest.fail("mismatched context must not be yielded")

    assert len(backend.restored) == 1


def test_context_session_is_single_use() -> None:
    request, image, ownership, context = _inputs()
    backend = ExplicitContextBackend(context)
    session = ChildRuntimeContextManager(backend).enter(
        request,
        image,
        ownership,
    )

    assert isinstance(session, ChildContextSession)
    session.__enter__()
    session.__exit__(None, None, None)
    with pytest.raises(ChildRuntimeContextError, match="single-use"):
        session.__enter__()


def test_entry_observer_records_only_real_one_shot_hook_firing() -> None:
    _, _, _, context = _inputs()
    hook_backend = ExplicitHookBackend()
    observer = OneShotChildEntrypointObserver(hook_backend)

    observer.arm(context)

    assert hook_backend.boundaries == (
        context.run.start_addr,
        context.run.start_addr + 1,
    )
    assert observer.reached(context.ownership.launch_id) is False
    assert hook_backend.callback is not None
    assert hook_backend.callback(object(), 0x1234, 1) is True
    assert observer.reached(context.ownership.launch_id) is False
    assert hook_backend.callback(object(), context.run.start_addr, 1) is True
    assert observer.reached(context.ownership.launch_id) is True
    assert hook_backend.hook.disabled is True


def test_entry_observer_disarm_is_idempotent_and_retains_evidence() -> None:
    _, _, _, context = _inputs()
    hook_backend = ExplicitHookBackend()
    observer = OneShotChildEntrypointObserver(hook_backend)
    observer.arm(context)

    observer.disarm(context.ownership.launch_id)
    observer.disarm(context.ownership.launch_id)

    assert hook_backend.hook.disabled is True
    assert observer.reached(context.ownership.launch_id) is False


def test_entry_observer_rejects_missing_entrypoint_and_duplicate_evidence() -> None:
    _, _, _, context = _inputs()
    hook_backend = ExplicitHookBackend()
    observer = OneShotChildEntrypointObserver(hook_backend)
    original_start = context.run.start_addr
    context.run.start_addr = None

    with pytest.raises(ChildEntrypointObservationError, match="entry-point"):
        observer.arm(context)

    context.run.start_addr = original_start
    observer.arm(context)
    assert hook_backend.callback is not None
    hook_backend.callback(object(), original_start, 1)

    with pytest.raises(ChildEntrypointObservationError, match="already observed"):
        observer.arm(context)
