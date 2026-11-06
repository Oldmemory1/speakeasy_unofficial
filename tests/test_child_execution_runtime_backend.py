from __future__ import annotations

from types import SimpleNamespace

import pytest

from speakeasy.windows.child_execution import (
    ChildEventOwnership,
    ChildExecutionOptions,
    ChildLaunchRequest,
    ChildTargetSource,
    ExecutionBudget,
    LoadedChildImage,
    create_engine_child_scheduler,
)
from speakeasy.windows.child_execution.runtime_backend import (
    EngineChildRuntimeContextBackend,
)


class ThreadStub:
    """Thread identity used by the context backend."""

    def __init__(self, tid: int) -> None:
        """Store one thread identifier."""

        self.id = tid
        self.tid = tid
        self.process: ProcessStub | None = None


class ProcessStub:
    """Process identity and threads used by the context backend."""

    def __init__(self, pid: int, path: str) -> None:
        """Store one process identity."""

        self.id = pid
        self.pid = pid
        self.path = path
        self.cmdline = path
        self.threads = [ThreadStub(pid + 1)]
        self.threads[0].process = self
        self.pe: object | None = None


class EmulatorStub:
    """Public context surface used by the restore verifier."""

    def __init__(self) -> None:
        """Create distinct parent and child contexts."""

        self.parent_process = ProcessStub(100, r"C:\root.exe")
        self.parent_thread = ThreadStub(101)
        self.parent_run = SimpleNamespace(start_addr=0x401000)
        self.child_process = ProcessStub(202, r"C:\child.exe")
        self.child_process.threads = [ThreadStub(203)]
        self.child_process.threads[0].process = self.child_process
        self.curr_process = self.parent_process
        self.curr_thread = self.parent_thread
        self.curr_run = self.parent_run
        self.curr_mod = "parent-module"
        self.child_processes = [self.child_process]
        self.processes = [self.parent_process]

    def get_current_process(self) -> ProcessStub:
        """Return the active process."""

        return self.curr_process

    def get_current_thread(self) -> ThreadStub:
        """Return the active thread."""

        return self.curr_thread

    def get_current_run(self) -> object:
        """Return the active run."""

        return self.curr_run

    def set_current_process(self, process: ProcessStub) -> None:
        """Set the active process."""

        self.curr_process = process

    def set_current_thread(self, thread: ThreadStub) -> None:
        """Set the active thread."""

        self.curr_thread = thread

    def get_module_from_addr(self, address: int) -> str:
        """Return one deterministic parent module label."""

        assert address == 0x401000
        return "parent-module"


def _request() -> ChildLaunchRequest:
    """Build one depth-one request for context activation."""

    return ChildLaunchRequest(
        launch_id="child-000001",
        root_sample_sha256="a" * 64,
        parent_launch_id=None,
        source_api="ShellExecute",
        parent_pid=100,
        parent_tid=101,
        depth=1,
        target=r"C:\child.exe",
        normalized_target=r"C:\child.exe",
        working_directory=r"C:\Windows",
        command_line="",
        command_sha256="b" * 64,
        parent_budget=ExecutionBudget(
            timeout_seconds=10.0,
            max_api_count=100,
            max_instructions=1000,
        ),
    )


def test_context_backend_restores_exact_parent_handles() -> None:
    """Activation switches to child handles and restoration is verified."""

    emulator = EmulatorStub()
    backend = EngineChildRuntimeContextBackend(emulator)
    request = _request()
    ownership = ChildEventOwnership(
        root_sample_sha256=request.root_sample_sha256,
        launch_id=request.launch_id,
        parent_pid=request.parent_pid,
        child_pid=202,
        depth=1,
    )
    image = LoadedChildImage(
        request_launch_id=request.launch_id,
        module=SimpleNamespace(
            base=0x500000,
            image_size=0x1000,
            emu_path=r"C:\child.exe",
        ),
        image_base=0x500000,
        entrypoint_address=0x501000,
    )
    parent = backend.capture_parent()

    context = backend.activate(request, image, ownership)

    assert emulator.curr_process is emulator.child_process
    assert emulator.curr_thread is emulator.child_process.threads[0]
    assert context.run.start_addr == image.entrypoint_address
    assert emulator.curr_mod is image.module

    backend.restore_parent(parent)
    backend.restore_parent(parent)

    assert emulator.curr_process is emulator.parent_process
    assert emulator.curr_thread is emulator.parent_thread
    assert emulator.curr_run is emulator.parent_run
    assert emulator.curr_mod == "parent-module"


def test_runtime_factory_rejects_disabled_options() -> None:
    """The concrete engine scheduler is never built for disabled mode."""

    with pytest.raises(ValueError, match="explicitly enabled"):
        create_engine_child_scheduler(
            SimpleNamespace(emu=object()),
            ChildExecutionOptions(enabled=False),
        )


def test_mira_scope_uses_only_self_sources() -> None:
    """The explicit factory input retains the self-only source contract."""

    options = ChildExecutionOptions(
        enabled=True,
        max_depth=1,
        max_children_per_root=1,
        allowed_sources=(ChildTargetSource.SELF,),
    )

    scheduler = create_engine_child_scheduler(
        SimpleNamespace(
            emu=SimpleNamespace(
                add_code_hook=lambda *args, **kwargs: None,
            )
        ),
        options,
    )

    assert scheduler is not None
    assert options.allowed_sources == (ChildTargetSource.SELF,)
