from __future__ import annotations

from types import SimpleNamespace

import pytest

from speakeasy.windows.child_execution import (
    ChildEventOwnership,
    ChildExecutionOptions,
    ChildLaunchRequest,
    ChildTargetSource,
    ChildTerminationReason,
    ExecutionBudget,
    LoadedChildImage,
    create_engine_child_scheduler,
)
from speakeasy.windows.child_execution.runner import (
    ChildExecutionRuntimeError,
)
from speakeasy.windows.child_execution.runtime_backend import (
    EngineChildExecutionBackend,
    EngineChildRuntimeContextBackend,
)
from speakeasy.windows.win32 import Win32Emulator


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
        self.peb_processes: list[ProcessStub] = []
        self.current_process_at_peb_allocation: list[ProcessStub] = []

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

    def alloc_peb(self, process: ProcessStub) -> None:
        """Record explicit child PEB allocation before context switching."""

        self.peb_processes.append(process)
        self.current_process_at_peb_allocation.append(self.curr_process)

    def get_module_from_addr(self, address: int) -> str:
        """Return one deterministic parent module label."""

        assert address == 0x401000
        return "parent-module"


class PebProcessStub:
    """Minimal explicit process seam for PEB allocation."""

    def __init__(self) -> None:
        """Create an inactive PEB owned by a distinct process."""

        self.base = 0x500000
        self.is_peb_active = False
        self.peb_ldr_data = SimpleNamespace(address=0, sizeof=lambda: 0x400)
        self.peb = SimpleNamespace(
            address=0x600000,
            object=SimpleNamespace(
                ImageBaseAddress=0,
                OSMajorVersion=0,
                OSMinorVersion=0,
                OSBuildNumber=0,
            ),
            write_back=lambda: None,
        )
        self.ldr_addresses: list[int] = []

    def set_peb_ldr_address(self, address: int) -> None:
        """Record the LDR address selected for this process."""

        self.ldr_addresses.append(address)
        self.peb_ldr_data.address = address

    def init_peb(self, modules: list[str]) -> None:
        """Record explicit module projection into this process PEB."""

        self.peb_modules = list(modules)


class PebAllocatorHarness(Win32Emulator):
    """Expose PEB allocation without constructing an emulator engine."""

    def __init__(self) -> None:
        """Initialize only the seams consumed by ``alloc_peb``."""

        self.config = SimpleNamespace(
            os_ver=SimpleNamespace(major=10, minor=0, build=19045)
        )
        self.init_peb_calls: list[tuple[list[str], PebProcessStub | None]] = []
        self.protected_ranges: list[int] = []

    def get_valid_ranges(self, size: int) -> tuple[int, int]:
        """Return one deterministic LDR range."""

        assert size == 0x400
        return 0x700000, size

    def mem_reserve(self, size: int, *, base: int, tag: str) -> None:
        """Record reservation without allocating host emulator memory."""

        del size, tag
        self.protected_ranges.append(base)

    def _ensure_core_dlls_loaded(self) -> None:
        """Keep the unit seam independent of configured system modules."""

    def mem_map_reserve(self, address: int) -> None:
        """Record LDR commitment without invoking Unicorn."""

        self.protected_ranges.append(address)

    def _ordered_peb_modules(self) -> list[str]:
        """Return one explicit child module marker."""

        return ["child.exe"]

    def init_peb(
        self,
        user_mods: list[str],
        proc: PebProcessStub | None = None,
    ) -> object:
        """Record which process receives the projected module list."""

        self.init_peb_calls.append((user_mods, proc))
        if proc is None:
            raise AssertionError("alloc_peb must pass its process explicitly")
        return proc.peb


class PebBindingHarness(Win32Emulator):
    """Expose the current-TEB binding side effect of PEB initialization."""

    def __init__(self) -> None:
        """Initialize one current parent and a bounded memory-write seam."""

        self.curr_process = PebProcessStub()
        self.peb_addr = 0x1234
        self.memory_writes: list[tuple[int, bytes]] = []

    def get_current_process(self) -> PebProcessStub:
        """Return the process whose current TEB is active."""

        return self.curr_process

    def get_ptr_size(self) -> int:
        """Return one x86 pointer width."""

        return 4

    def mem_write(self, address: int, data: bytes) -> None:
        """Record writes to the emulated current-PEB pointer."""

        self.memory_writes.append((address, bytes(data)))


class FailingExecutionHook:
    """No-op instruction hook for the synthetic failed child run."""

    def disable(self) -> None:
        """Disable the hook without changing synthetic execution state."""


class FailingExecutionEmulator:
    """Set one child run error after recording its run and API count."""

    def __init__(self, process: ProcessStub, thread: ThreadStub) -> None:
        """Initialize the public execution surface used by the backend."""

        self.curr_process = process
        self.curr_thread = thread
        self.run_queue: list[object] = []
        self.runs: list[object] = []
        self.instruction_budget_exhausted = False

    def add_code_hook(self, _callback: object, *, begin: int, end: int) -> FailingExecutionHook:
        """Return a no-op hook for the requested child image range."""

        assert begin == 0x270000
        assert end == 0x272000
        return FailingExecutionHook()

    def add_run(self, run: object) -> None:
        """Record the child run before execution."""

        self.run_queue.append(run)
        self.runs.append(run)

    def start(self) -> None:
        """Attach one authoritative failed-run evidence record."""

        run = self.runs[-1]
        run.num_apis = 3  # type: ignore[attr-defined]
        run.error = SimpleNamespace(  # type: ignore[attr-defined]
            type="Invalid memory mapping (UC_ERR_MAP)",
            pc=0x271710,
            address=0x14,
            access_type="read",
            api_name="kernel32.LeaveCriticalSection",
        )

    def stop(self) -> None:
        """Record the synthetic stop request."""


class BudgetHooksStub:
    """Count child-only budget observations passed to the backend."""

    def __init__(self) -> None:
        """Initialize independent counters."""

        self.api_calls = 0
        self.instructions = 0

    def observe_api(self) -> bool:
        """Record one API call."""

        self.api_calls += 1
        return True

    def observe_instructions(self, count: int = 1) -> bool:
        """Record one instruction batch."""

        self.instructions += count
        return True

    def should_continue(self) -> bool:
        """Allow synthetic execution to continue."""

        return True


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

    assert emulator.peb_processes == [emulator.child_process]
    assert emulator.current_process_at_peb_allocation == [emulator.parent_process]
    assert emulator.child_process.base == image.image_base
    assert emulator.child_process.pe is image.module
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


def test_alloc_peb_initializes_the_supplied_process_explicitly() -> None:
    """PEB population must not depend on the emulator's current process."""

    emulator = PebAllocatorHarness()
    process = PebProcessStub()

    peb = emulator.alloc_peb(process)

    assert peb is process.peb
    assert process.is_peb_active is True
    assert process.peb.object.ImageBaseAddress == process.base
    assert process.ldr_addresses == [0x700000]
    assert emulator.init_peb_calls == [(["child.exe"], process)]


def test_init_peb_does_not_rebind_a_non_current_process_to_current_teb() -> None:
    """Preparing a child PEB must not overwrite the active parent TEB pointer."""

    emulator = PebBindingHarness()
    child = PebProcessStub()

    peb = emulator.init_peb(["child.exe"], proc=child)

    assert peb is child.peb
    assert child.peb_modules == ["child.exe"]
    assert emulator.memory_writes == []


def test_init_peb_binds_the_current_process_to_the_current_teb() -> None:
    """Current-process initialization retains the legacy TEB binding."""

    emulator = PebBindingHarness()

    peb = emulator.init_peb(["parent.exe"], proc=emulator.curr_process)

    assert peb is emulator.curr_process.peb
    assert emulator.memory_writes == [(0x1234, (0x600000).to_bytes(4, "little"))]


def test_execution_backend_preserves_run_facts_when_child_faults() -> None:
    """A failed child run retains its own index, usage, PC, and fault address."""

    request = _request()
    process = ProcessStub(request.parent_pid + 1, r"C:\child.exe")
    thread = process.threads[0]
    context = SimpleNamespace(
        process=process,
        thread=thread,
        run=SimpleNamespace(
            start_addr=0x271000,
            num_apis=0,
            error=None,
        ),
    )
    image = LoadedChildImage(
        request_launch_id=request.launch_id,
        module=SimpleNamespace(
            base=0x270000,
            image_size=0x2000,
            emu_path=r"C:\child.exe",
        ),
        image_base=0x270000,
        entrypoint_address=0x271000,
    )
    emulator = FailingExecutionEmulator(process, thread)
    hooks = BudgetHooksStub()

    with pytest.raises(ChildExecutionRuntimeError) as exc_info:
        EngineChildExecutionBackend(emulator).run(
            request,
            SimpleNamespace(),
            image,
            context,
            hooks,
        )

    failure = exc_info.value
    assert failure.termination_reason.value == "invalid_memory"
    assert failure.run_indexes == (0,)
    assert failure.pc == 0x271710
    assert failure.fault_address == 0x14
    assert failure.access_type == "read"
    assert hooks.api_calls == 3


@pytest.mark.parametrize(
    ("error_type", "expected"),
    (
        ("invalid_read", ChildTerminationReason.INVALID_MEMORY),
        ("invalid_write", ChildTerminationReason.INVALID_MEMORY),
        (
            "invalid_protect_write",
            ChildTerminationReason.INVALID_MEMORY,
        ),
        ("Invalid memory mapping (UC_ERR_MAP)", ChildTerminationReason.INVALID_MEMORY),
        ("invalid_fetch", ChildTerminationReason.INVALID_FETCH),
        ("unsupported_api", ChildTerminationReason.INTERNAL_ERROR),
    ),
)
def test_run_error_termination_reason_preserves_fault_category(
    error_type: str,
    expected: ChildTerminationReason,
) -> None:
    """Child reports distinguish memory faults from fetch and internal errors."""

    assert (
        EngineChildExecutionBackend._termination_for_run_error(
            SimpleNamespace(type=error_type)
        )
        is expected
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
