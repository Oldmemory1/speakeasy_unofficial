from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any

from speakeasy.windows.child_execution.budget import ExecutionBudgetFactory
from speakeasy.windows.child_execution.models import (
    BudgetUsage,
    ChildEventOwnership,
    ChildExecutionState,
    ChildLaunchRequest,
    ChildOutcome,
    ChildProcessContext,
    ChildTargetSource,
    ChildTerminationReason,
    ExecutionBudget,
    LoadedChildImage,
    ResolvedChildTarget,
    TargetPayloadRef,
)
from speakeasy.windows.child_execution.runner import (
    ChildBudgetHooks,
    ChildExecutionBackendResult,
    ChildExecutionRunner,
)
from speakeasy.windows.child_execution.runtime_context import (
    ChildRuntimeContextManager,
    OneShotChildEntrypointObserver,
    ParentRuntimeContext,
)
from speakeasy.windows.child_execution.runtime_loader import (
    ChildImageRuntimeLoader,
)
from speakeasy.windows.loaders import (
    LoadedImage,
    MemoryRegion,
    PeLoader,
    SectionEntry,
)


class ProcessStub:
    """Process object with only the public fields required by contracts."""

    def __init__(self, pid: int, path: str) -> None:
        self.id = pid
        self.pid = pid
        self.path = path
        self.cmdline = path
        self.threads: list[ThreadStub] = []


class ThreadStub:
    """Thread object with only the public contract fields."""

    def __init__(self, tid: int) -> None:
        self.id = tid
        self.tid = tid


class ModuleStub:
    """Runtime module returned by the explicit image mapper."""

    def __init__(self, base: int) -> None:
        self.base = base
        self.image_size = 0x5000
        self.emu_path = r"C:\fixtures\child.exe"


class RunStub:
    """Run object binding the child process and thread."""

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


class HookStub:
    """Hook handle recording one-shot disables."""

    def __init__(self) -> None:
        self.disabled = False

    def disable(self) -> None:
        """Disable the hook."""

        self.disabled = True


class HookBackend:
    """Explicit code-hook registration fake."""

    def __init__(self) -> None:
        self.callback: Callable[[object, int, int], bool] | None = None
        self.hook = HookStub()

    def add_code_hook(
        self,
        callback: Callable[[object, int, int], bool],
        *,
        begin: int,
        end: int,
    ) -> HookStub:
        """Register the callback without patching engine state."""

        assert end == begin + 1
        self.callback = callback
        return self.hook


class Materializer:
    """Materialize only after recording exact child bytes."""

    def __init__(self, image: LoadedImage) -> None:
        self.image = image
        self.data: bytes | None = None

    def materialize(
        self,
        data: bytes,
        *,
        emu_path: str,
        display_name: str,
    ) -> LoadedImage:
        """Return the unmapped image for the exact payload."""

        self.data = data
        assert emu_path == r"C:\fixtures\child.exe"
        assert display_name == "child"
        return self.image


class Mapper:
    """Map an already-materialized image without executing it."""

    def __init__(self, module: ModuleStub) -> None:
        self.module = module

    def map_child_image(
        self,
        image: LoadedImage,
        *,
        request: ChildLaunchRequest,
    ) -> ModuleStub:
        """Return a deterministic non-primary mapped module."""

        assert request.launch_id == "child-000001"
        assert image.loader is not None
        return self.module


class ContextBackend:
    """Explicit parent snapshot and child context backend."""

    def __init__(self) -> None:
        self.parent = ParentRuntimeContext(
            process=ProcessStub(100, r"C:\root.exe"),
            thread=ThreadStub(101),
            run=None,
        )
        self.restored: list[ParentRuntimeContext] = []

    def capture_parent(self) -> ParentRuntimeContext:
        """Return the immutable parent snapshot."""

        return self.parent

    def activate(
        self,
        request: ChildLaunchRequest,
        image: LoadedChildImage,
        ownership: ChildEventOwnership,
    ) -> ChildProcessContext:
        """Create the child process/thread/run context."""

        process = ProcessStub(ownership.child_pid, image.module.emu_path)
        thread = ThreadStub(201)
        run = RunStub(process, thread, image.entrypoint_address)
        return ChildProcessContext(
            process=process,
            thread=thread,
            module=image.module,
            run=run,
            ownership=ownership,
        )

    def restore_parent(self, parent: ParentRuntimeContext) -> None:
        """Record one parent restoration."""

        self.restored.append(parent)


class Backend:
    """Queue one child run and fire one real-simulated entry hook."""

    def __init__(self, hook_backend: HookBackend) -> None:
        self._hook_backend = hook_backend

    def run(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
        image: LoadedChildImage,
        context: ChildProcessContext,
        budget_hooks: ChildBudgetHooks,
    ) -> ChildExecutionBackendResult:
        """Execute only the public hook contract and return run evidence."""

        assert target.resolved
        assert image.primary is False
        assert context.ownership.launch_id == request.launch_id
        callback = self._hook_backend.callback
        assert callback is not None
        callback(object(), image.entrypoint_address, 1)
        assert budget_hooks.observe_api()
        assert budget_hooks.observe_instructions(3)
        return ChildExecutionBackendResult(run_indexes=(17,))


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
        command_sha256=hashlib.sha256(b"command").hexdigest(),
        parent_budget=ExecutionBudget(
            timeout_seconds=37.5,
            max_api_count=977,
            max_instructions=123_456,
        ),
    )


def _target(data: bytes) -> ResolvedChildTarget:
    digest = hashlib.sha256(data).hexdigest()
    return ResolvedChildTarget(
        source=ChildTargetSource.FIXTURE,
        normalized_path=r"C:\fixtures\child.exe",
        payload_ref=TargetPayloadRef(
            source=ChildTargetSource.FIXTURE,
            sha256=digest,
            size=len(data),
            emu_path=r"C:\fixtures\child.exe",
            data=data,
        ),
        sha256=digest,
        size=len(data),
        file_format="pe",
        arch="x86",
        module_type="exe",
        entrypoint_rva=0x1000,
        resolved=True,
        reason=None,
    )


def _image() -> LoadedImage:
    return LoadedImage(
        arch=0,
        module_type="exe",
        name="child",
        emu_path=r"C:\fixtures\child.exe",
        image_base=0x300000,
        image_size=0x5000,
        regions=[
            MemoryRegion(
                base=0x300000,
                data=b"MZ",
                name="pe_image",
                perms=1,
            )
        ],
        imports=[],
        exports=[],
        default_export_mode="intercepted",
        entry_points=[0x301000],
        loader=PeLoader(data=b"MZ"),
        sections=[
            SectionEntry(
                name=".text",
                virtual_address=0x1000,
                virtual_size=0x200,
                perms=1,
            )
        ],
    )


def test_loader_context_observer_and_runner_compose_without_root_pollution() -> None:
    data = b"MZ" + b"\x00" * 30
    request = _request()
    target = _target(data)
    ownership = ChildEventOwnership(
        root_sample_sha256=request.root_sample_sha256,
        launch_id=request.launch_id,
        parent_pid=request.parent_pid,
        child_pid=200,
        depth=request.depth,
    )
    root_metadata: dict[str, Any] = {
        "sha256": request.root_sample_sha256,
        "path": r"C:\root.exe",
        "image_base": 0x400000,
    }
    root_snapshot = root_metadata.copy()
    hook_backend = HookBackend()
    observer = OneShotChildEntrypointObserver(hook_backend)
    materializer = Materializer(_image())
    loader = ChildImageRuntimeLoader(materializer, Mapper(ModuleStub(0x300000)))
    context_backend = ContextBackend()
    runner = ChildExecutionRunner(
        backend=Backend(hook_backend),
        entrypoint_observer=observer,
        budget_factory=ExecutionBudgetFactory(),
        clock=lambda: 0.0,
    )

    image = loader.load(request, target)
    usage = BudgetUsage()
    with ChildRuntimeContextManager(context_backend).enter(
        request,
        image,
        ownership,
    ) as context:
        result = runner.run(
            request,
            target,
            image,
            context,
            request.parent_budget,
            usage,
        )

    assert materializer.data == data
    assert image.primary is False
    assert image.image_base == 0x300000
    assert result.state is ChildExecutionState.COMPLETED
    assert result.outcome is ChildOutcome.OK
    assert result.termination_reason is ChildTerminationReason.NORMAL_EXIT
    assert result.run_indexes == (17,)
    assert result.ownership == ownership
    assert observer.reached(request.launch_id) is True
    assert hook_backend.hook.disabled is True
    assert usage.api_count_used == 1
    assert usage.instructions_used == 3
    assert context_backend.restored == [context_backend.parent]
    assert root_metadata == root_snapshot
