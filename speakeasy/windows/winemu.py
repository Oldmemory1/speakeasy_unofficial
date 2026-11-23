# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import inspect
import io
import logging
import multiprocessing.synchronize
import ntpath
import os
import random
import struct
import threading
import time
import traceback
from abc import abstractmethod
from collections import deque
from collections.abc import Callable, Generator, Sequence
from dataclasses import dataclass
from enum import Enum
from functools import wraps
from types import MethodType
from typing import TYPE_CHECKING, Any, ClassVar, Concatenate, ParamSpec, TypeVar

import capstone as cs
import pefile
import unicorn as uc

import speakeasy.windows.common as winemu
import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy import common
from speakeasy.binemu import BinaryEmulator
from speakeasy.config import parse_start_time
from speakeasy.errors import FileSystemEmuError, OutOfMemoryError, WindowsEmuError
from speakeasy.gdb import GdbServer, ResumeAction, StopReason
from speakeasy.memmgr import MemMap
from speakeasy.profiler import ApiCallbackFrame, GuestCallbackFrame, MemAccess, ProcessEntryContext, Run
from speakeasy.profiler_events import ApiArg, ApiArgType, EventType, NetTrafficProtocol, NetTrafficType, TracePosition
from speakeasy.report import AccessType, ApiLoop, Arch, ErrorInfo, ErrorType, FileType, RegionInfo, RunType
from speakeasy.struct import EmuStruct
from speakeasy.windows import (
    api_resolution,
    api_trace_diagnostics,
    bool_semantics,
    cpu_exceptions,
    guest_callbacks,
    handle_semantics,
    hardware_breakpoints,
    mapped_imports,
    module_trace_diagnostics,
    objman,
    seh,
    seh32,
    seh64,
    thread_context,
    unwind,
)
from speakeasy.windows.api_image import ApiModuleLoader
from speakeasy.windows.api_registry import ApiEntry, ApiRegistry, module_name, symbol_ref
from speakeasy.windows.child_execution import (
    ChildExecutionDispatcher,
    ChildExecutionRegistry,
    ChildExecutionRequest,
    ChildLaunchRequest,
    ChildSchedulerProtocol,
    ExecutionBudget,
    ParentExecutionSnapshot,
    ProcessCreationResult,
    ProcessLaunchSpec,
)
from speakeasy.windows.cryptman import CryptoManager
from speakeasy.windows.dep_policy import (
    ImageDepPolicy,
    dep_opt_out,
    image_page_exec_allowed,
)
from speakeasy.windows.driveman import DriveManager
from speakeasy.windows.fast_fail import (
    FAST_FAIL_INTERRUPT_VECTOR,
    STATUS_STACK_BUFFER_OVERRUN,
    TERMINATION_KIND,
    requires_kernel_bootstrap_recovery,
)
from speakeasy.windows.fileman import File, FileManager
from speakeasy.windows.guest_call import GuestCallChain
from speakeasy.windows.handles import (
    CURRENT_PROCESS_HANDLE,
    CURRENT_THREAD_HANDLE,
    HANDLE_MASK,
    HandleTable,
)
from speakeasy.windows.import_sentinel import find_import_sentinel, import_probe_prefix
from speakeasy.windows.ioman import IoManager
from speakeasy.windows.loaders import (
    LoadState,
    PeLoader,
    RuntimeModule,
    get_prot_string,
    is_dep_enabled,
    relocate_image,
)
from speakeasy.windows.module_loader import ModuleLoader
from speakeasy.windows.netman import NetworkManager
from speakeasy.windows.objman import HandleAllocator
from speakeasy.windows.page_protection import (
    emu_perms_to_win_protect,
    image_protection_for_emu_perms,
    is_virtual_alloc_view,
    win_protect_to_emu_perms,
)
from speakeasy.windows.process_memory import (
    ERROR_INVALID_ADDRESS,
    ERROR_INVALID_PARAMETER,
    MAX_SHADOW_REGION_SIZE,
    SHADOW_MATERIALIZED_TAG_PREFIX,
    ProcessAddressSpace,
    ProcessMemoryError,
)
from speakeasy.windows.regman import WINDOWS_CURRENT_VERSION_KEY, RegistryManager, RegKey, get_program_files_values
from speakeasy.windows.system_modules import (
    SystemModuleDecoyLoader,
    is_synthesizable_system_module,
)
from speakeasy.windows.tls import TlsManager
from speakeasy.windows.veh import VectoredExceptionRegistry, VehDispatchState
from speakeasy.windows.x86_interrupts import OverflowTrapKind, classify_overflow_trap
from speakeasy.winenv.api import sigdb, sigfmt
from speakeasy.winenv.api.api import NO_CONTEXT, ApiContext, HandlerArgs
from speakeasy.winenv.api.winapi import WindowsApi
from speakeasy.winenv.defs.nt import ddk

if TYPE_CHECKING:
    from speakeasy.speakeasy import Speakeasy

# The maximum number of exports of a module that the emulator runs when it emulates all exports
MAX_EXPORTS_TO_EMULATE = 10

# The signal number that the GDB server reports for memory faults
GDB_SIGSEGV = 11

# The first bytes of the VEX and EVEX prefixes. On x86, these bytes also start les, lds and bound.
VEX_PREFIXES = (0xC4, 0xC5, 0x62)
LEGACY_VEX_PREFIX_MNEMONICS = ("les", "lds", "bound")

# The maximum size of the static TLS data that the emulator copies for each thread
TLS_TEMPLATE_MAX = 0x1000000

# The registers that a callee must preserve. The emulator restores them after the guest callbacks of an API.
NONVOLATILE_X86 = (_arch.X86_REG_EBX, _arch.X86_REG_EBP, _arch.X86_REG_ESI, _arch.X86_REG_EDI)
NONVOLATILE_AMD64 = (
    _arch.AMD64_REG_RBX,
    _arch.AMD64_REG_RBP,
    _arch.AMD64_REG_RSI,
    _arch.AMD64_REG_RDI,
    _arch.AMD64_REG_R12,
    _arch.AMD64_REG_R13,
    _arch.AMD64_REG_R14,
    _arch.AMD64_REG_R15,
)

REPORT_ARCHES = {_arch.ARCH_X86: Arch.X86, _arch.ARCH_AMD64: Arch.X64}

# Trampoline used to defer UC_MEM_READ_PROT / UC_MEM_FETCH_PROT dispatch.
# Unicorn 2.1.4 crashes when uc_mem_map is called from those two callbacks, so
# the callback only snapshots the fault and points EIP here; the resulting
# invalid fetch builds the exception structures outside the PROT callback.
DEFERRED_DISPATCH_ADDR = winemu.EMU_RETURN_ADDR + 2

# The local child-execution budget describes an unlimited API-call count with a large finite number.
UNLIMITED_API_CALLS = (1 << 63) - 1


@dataclass
class DeferredProtectedFault:
    """Snapshot of a protected read/fetch fault awaiting exception dispatch.

    Attributes:
        error_type: Fatal error type used only when no guest handler accepts.
        access_type: "read", "write" or "fetch" for the recorded error.
        fault_pc: PC of the faulting instruction at snapshot time.
        address: Faulting memory address.
        context: CPU context captured before the fault was resumed.
        dep_exec_allowed: True when the process image opted out of DEP and the
            faulting page is writable (a writable ``VirtualAlloc`` view or a
            writable image-section page). Such a fault is not delivered to
            the guest exception chain; the deferred handler grants execution
            to the page and resumes the faulting instruction instead.
    """

    error_type: str
    access_type: str
    fault_pc: int
    address: int
    context: Any
    dep_exec_allowed: bool = False


class _DeferredFaultError(guest_callbacks.CallbackError):
    """The unhandled error of a deferred protected fault, with the fault's original error value.

    ``get_error_info`` accepts the local error values as strings, and the
    protected-read value (``invalid_prot_read``) predates the ``ErrorType``
    enum, so the error of a declined handler chain keeps the value that the
    non-dispatched path records.
    """

    def __init__(self, kind: str | ErrorType, address: int, access_type: str | None, pc: int | None):
        Exception.__init__(self, f"{kind} at 0x{address:x}")
        if isinstance(kind, str):
            try:
                kind = ErrorType(kind)
            except ValueError:
                pass
        self.kind = kind
        self.address = address
        self.access_type = access_type
        self.pc = pc
        self.details: dict[str, Any] = {}


@dataclass(frozen=True)
class MaterializedShadowRegion:
    """One per-process shadow region that was given physical backing.

    Attributes:
        base: Page-aligned mapping base (equal to the shadow region base).
        size: Mapping size in bytes.
        tag: Tag prefix used for the created emulator mapping. Release only
            frees mappings whose tag still starts with this value.
    """

    base: int
    size: int
    tag: str


def _normalize_mod_name(name: str) -> str:
    return os.path.splitext(name)[0].lower()


# Windows loader entry-register convention for a process's first thread:
# x86 passes the entry address in EAX and the PEB in EBX; x64 uses RCX/RDX.
# Each value is an (architecture register id, saved CONTEXT field name) pair,
# ordered as (entry, PEB).
_PROCESS_ENTRY_CONTEXT_REGS: dict[int, tuple[tuple[int, str], tuple[int, str]]] = {
    _arch.ARCH_X86: ((_arch.X86_REG_EAX, "Eax"), (_arch.X86_REG_EBX, "Ebx")),
    _arch.ARCH_AMD64: ((_arch.AMD64_REG_RCX, "Rcx"), (_arch.AMD64_REG_RDX, "Rdx")),
}


def _complete_pending_api_callback(emu: Any) -> None:
    """Complete a pending callback transition on ``emu``.

    The local API callback frames (``run.api_callbacks``) come first. A v2.1.0
    generator guest callback (``run.guest_callbacks``) returns to the same
    reserved sentinel (``API_CALLBACK_HANDLER_ADDR`` is
    ``GUEST_CALLBACK_RETURN_ADDR``); when no local frame is pending, continue
    that guest callback instead of reporting a missing callback. Continuing it
    resumes the handler generator, so the intercepted API call completes with
    the callback's ``complete``/return value, as ``setup_callback`` implements
    it.
    """
    run = emu.get_current_run()
    if run is not None and not run.api_callbacks:
        guest_frames = getattr(run, "guest_callbacks", None)
        continue_guest_callback = getattr(emu, "_continue_guest_callback", None)
        if guest_frames and callable(continue_guest_callback):
            continue_guest_callback()
            return
    if not run or not run.api_callbacks:
        error = emu.get_error_info(
            "callback_return_without_callback",
            emu.get_pc(),
            access_type="fetch",
        )
        emu.curr_run.error = error
        end_run = getattr(emu, "end_run", None)
        if callable(end_run):
            end_run(error)
        else:
            # The callback bookkeeping of a run that has no run loop (the
            # control-flow contract) is completed by the caller's hook.
            emu.on_run_complete()
        return

    frame = run.api_callbacks.pop()
    if isinstance(frame, tuple):
        # Compatibility with runs created by integrations that still enqueue
        # the historical (return address, function, arguments) tuple.
        ret_addr, _function, args = frame
        emu.do_call_return(len(args), ret_addr)
        return

    arch = emu.get_arch()
    if arch == _arch.ARCH_X86:
        return_register = _arch.X86_REG_EAX
    elif arch == _arch.ARCH_AMD64:
        return_register = _arch.AMD64_REG_RAX
    else:
        raise WindowsEmuError(f"Unsupported architecture: {arch}")

    callback_result = int(emu.reg_read(return_register))

    if isinstance(frame, GuestCallChain):
        # A handler asked the engine to run an ordered list of guest
        # functions. Resume at the next function, or finish the intercepted
        # API call with the chain's result (cdecl: the guest caller cleans
        # its own argument slots).
        if frame.advance(emu, callback_result):
            # The chain is still pending: the next guest function must return
            # to the same sentinel and be completed the same way.
            run.api_callbacks.append(frame)
            return
        emu.do_call_return(
            frame.cleanup_argc,
            frame.ret_addr,
            frame.api_return(),
            conv=frame.conv,
        )
        return

    if not isinstance(frame, ApiCallbackFrame):
        raise WindowsEmuError(f"Unsupported API callback frame: {type(frame).__name__}")

    api_return = frame.resolve_api_return(callback_result)
    emu.do_call_return(frame.cleanup_argc, frame.ret_addr, api_return)


def attach_handler_observation(error: ErrorInfo, ctx: Any) -> None:
    """Fold a handler's read-only observation into an API error report.

    FX-003 handlers attach page-protection evidence to
    ``ctx["_api_observation"]`` before a risky operation. If the handler then
    raises (for example ``lstrcpyA`` writing to an unmapped destination), the
    exception path never reaches ``log_api``, so the evidence would otherwise
    be dropped. This merge keeps it in ``ErrorInfo.diagnostics``.

    Reporting-only: the exception type/message, run termination and any other
    behaviour are unchanged. Missing or non-dict observations are ignored.
    """
    if error is None or not isinstance(ctx, dict):
        return
    observation = ctx.get("_api_observation")
    if not isinstance(observation, dict):
        return
    try:
        diagnostics = error.diagnostics if isinstance(error.diagnostics, dict) else {}
        merged = dict(diagnostics)
        merged["api_observation"] = observation
        error.diagnostics = merged
    except Exception:
        logger.debug("fx-003 diagnostic: handler observation merge failed", exc_info=True)


logger = logging.getLogger(__name__)


@dataclass
class _ExecutionBudget:
    limit: float
    elapsed: float = 0.0
    exhausted: bool = False

    def add(self, seconds: float) -> bool:
        """Add seconds to the elapsed time. Return True if the elapsed time is at or past the limit."""
        self.elapsed += seconds
        if self.limit <= 0 or self.elapsed < self.limit:
            return False
        if not self.exhausted:
            logger.error("* Total execution time of %d sec(s) reached.", self.limit)
        self.exhausted = True
        return True


@dataclass(frozen=True)
class SuspendedApiCall:
    """
    The guest called an API. The run loop calls the handler of the API next.

    The stack pointer, the return address and the code of the API are the values when the guest fetched the token.
    If a debugger changes one of them, the emulator drops the exit, and the guest runs the code of the API again.
    """

    entry: ApiEntry
    stack_pointer: int
    return_address: bytes | None
    code: bytes | None


@dataclass(frozen=True)
class RunReturn:
    """The guest returned to the return hook or the exit hook. The run is complete."""


@dataclass(frozen=True)
class CallbackReturn:
    """A guest callback returned to ``GUEST_CALLBACK_RETURN_ADDR``. The API handler that called it continues."""


@dataclass(frozen=True)
class RunEnd:
    """
    A fault, an API handler, a hook or the user ended the run. See ``WindowsEmulator.end_run``.

    The run loop completes the run after Unicorn stops, also if Unicorn raises an error. If ``stop_emulation`` is
    set, the loop then ends the emulation and does not start the next run.
    """

    stop_emulation: bool = False


@dataclass(frozen=True)
class ExecRecovery:
    """
    The guest fetched code from a guest PE page without execute permission.

    The run loop sets the protection of the page to ``perms`` and runs the code again.
    """

    page: int
    perms: int


@dataclass(frozen=True)
class RaisedCpuException:
    """A CPU exception that the run loop sends to the exception handlers of the guest."""

    exception: cpu_exceptions.CpuException
    error_type: ErrorType  # the error of the run if no handler takes the exception
    interrupt_num: int | None = None
    access_type: str | None = None
    rax: int | None = None  # the run loop restores RAX before dispatch, because the IN instruction writes it
    # (page, perms) of a guard page. The run loop restores perms on the page before dispatch.
    guard_page: tuple[int, int] | None = None


# The reason why Unicorn stopped. A hook records the exit and stops Unicorn, or _get_exit_at_pc gets the exit from
# the PC after Unicorn stops. Then the run loop handles the exit. If two hooks record an exit, the emulator keeps the
# first.
NativeExit = SuspendedApiCall | RunReturn | CallbackReturn | RunEnd | ExecRecovery | RaisedCpuException


@dataclass
class _ApiCallState:
    """State of the guest when it calls an API, before the API runs."""

    dll: str
    name: str
    frame: GuestCallbackFrame
    run: Run | None
    pc: int
    sp: int
    return_address: int
    # The address of the call, or None if the emulator does not know it.
    call_pc: int | None

    @property
    def api_name(self) -> str:
        return f"{self.dll}.{self.name}"


S = TypeVar("S", bound="WindowsEmulator | Speakeasy")
P = ParamSpec("P")
R = TypeVar("R")


def execution_scope(func: Callable[Concatenate[S, P], R]) -> Callable[Concatenate[S, P], R]:
    """
    Apply one ``limits.total_time`` limit to all emulation in a call of the decorated method.

    A nested call of a decorated method uses the limit of the outer call.
    """

    @wraps(func)
    def wrapped(self: S, *args: P.args, **kwargs: P.kwargs) -> R:
        emu = self if isinstance(self, WindowsEmulator) else self.emu
        if emu is None or emu._execution_budget is not None:
            return func(self, *args, **kwargs)
        emu._execution_budget = _ExecutionBudget(emu.config.limits.total_time)
        try:
            return func(self, *args, **kwargs)
        finally:
            emu._execution_budget = None

    return wrapped


def _module_type_from_path(path: str, default: str = "dll") -> str:
    ext = ntpath.splitext(path)[1].lower()
    if ext == ".exe":
        return "exe"
    if ext == ".sys":
        return "driver"
    if ext == ".dll":
        return "dll"
    return default


def get_page_protection_runs(page_perms: dict[int, int], page_size: int) -> list[tuple[int, int, int]]:
    """Merge the permissions of single pages into (base, size, perms) ranges of adjacent pages with equal perms."""
    runs: list[tuple[int, int, int]] = []
    for page_base in sorted(page_perms):
        perms = page_perms[page_base]
        if runs:
            run_base, run_size, run_perms = runs[-1]
            if run_perms == perms and run_base + run_size == page_base:
                runs[-1] = (run_base, run_size + page_size, perms)
                continue
        runs.append((page_base, page_size, perms))
    return runs


class LimitKind(str, Enum):
    """A limit that ends a run. The value is the type of the error of the run, and the kind of the debugger stop."""

    PER_RUN_TIME_LIMIT = "per_run_time_limit"
    TOTAL_TIME_LIMIT = "total_time_limit"
    INSTRUCTION_LIMIT = "instruction_limit"


@dataclass
class _SehRepeat:
    """
    The last fault that the guest SEH handlers took, and how many times in a row it occurred.

    A handler that does not fix a fault can make an infinite loop, so the emulator dispatches the same fault at most
    ``MAX_REPEAT`` times in a row. The illegal-instruction replay uses the full limit; the memory-fault replay passes
    one less, as the local FX-002 accounting does.
    """

    MAX_REPEAT: ClassVar[int] = 4

    # (pc, faulting address) of the last fault, or None.
    fault: tuple[int, int | None] | None = None
    count: int = 0
    # A guest handler continued at the pc of the fault. The deferred work hook clears the count when pc leaves it.
    resume_pc: int | None = None

    def reset(self) -> None:
        self.fault = None
        self.count = 0
        self.resume_pc = None

    def record(self, fault: tuple[int, int | None], limit: int | None = None) -> bool:
        """Count the fault. Return False after ``limit`` dispatches of the same fault in a row.

        The limit defaults to ``MAX_REPEAT``.
        """
        self.resume_pc = None
        if fault == self.fault:
            self.count += 1
            return self.count <= (self.MAX_REPEAT if limit is None else limit)
        self.fault = fault
        self.count = 1
        return True


@dataclass
class RunLimits:
    """The time and instruction limits of one call of the run loop, and the instruction count of the call."""

    # When the call started, from time.monotonic().
    started: float
    # The execution time of the run before the call started.
    spent: float
    # The time limit of the run in seconds, or 0 for no limit.
    timeout: float
    # When the call must stop, from time.monotonic(), or None for no time limit.
    deadline: float | None
    # TOTAL_TIME_LIMIT if the total execution time gives the deadline, otherwise PER_RUN_TIME_LIMIT.
    deadline_kind: LimitKind
    # The total execution time of all runs, or None for no total limit.
    total_budget: _ExecutionBudget | None
    # The instruction limit of the run, or 0 or less for no limit.
    budget: int
    # The instructions that the run can still execute, or -1 for no limit.
    remaining: int
    # The address of the last instruction that the accounting hook counted, or None.
    last_executed: int | None = None

    @classmethod
    def from_run(cls, run: Run, timeout: float, budget: int, total_budget: _ExecutionBudget | None) -> "RunLimits":
        """Get the limits that apply to ``run`` from now. The deadline is the nearer of the two time limits."""
        started = time.monotonic()
        spent = run.execution_elapsed
        deadline = started + max(timeout - spent, 0) if timeout > 0 else None
        deadline_kind = LimitKind.PER_RUN_TIME_LIMIT
        if total_budget is not None and total_budget.limit > 0:
            total_deadline = started + max(total_budget.limit - total_budget.elapsed, 0)
            if deadline is None or total_deadline < deadline:
                deadline = total_deadline
                deadline_kind = LimitKind.TOTAL_TIME_LIMIT
        remaining = max(budget - run.budget_instructions, 0) if budget > 0 else -1
        return cls(started, spent, timeout, deadline, deadline_kind, total_budget, budget, remaining)

    def get_reached_limit(self) -> LimitKind | None:
        """Get the kind of the limit that the run reached, or None if it reached no limit."""
        if self.deadline is not None and time.monotonic() >= self.deadline:
            return self.deadline_kind
        if self.budget > 0 and self.remaining <= 0:
            return LimitKind.INSTRUCTION_LIMIT
        return None

    def is_total_time_reached(self) -> bool:
        """Get whether the run reached the total execution time of all runs."""
        return (
            self.deadline_kind == LimitKind.TOTAL_TIME_LIMIT
            and self.deadline is not None
            and time.monotonic() >= self.deadline
        )

    def get_native_timeout(self) -> float:
        """Get the timeout for the next start of Unicorn: the time to the deadline, or 0 for no deadline."""
        return max(self.deadline - time.monotonic(), 0.000001) if self.deadline is not None else 0

    def get_native_count(self) -> int:
        """
        Get the instruction count for the next start of Unicorn, or 0 for no limit.

        The count stops Unicorn at the instruction limit, so that the tracing
        hooks do not see an instruction after the limit. The accounting hook
        counts the instructions of all starts of Unicorn in one call.
        """
        return self.remaining if self.budget > 0 else 0


@dataclass(frozen=True)
class RegionPart:
    """
    One memory region of the report: a memory map, or the headers or one section of a module image in it.

    ``module`` is the file name of the module for a part of an image. ``section`` is ``headers`` or the
    section name, or ``None`` for the full image.
    """

    mm: MemMap
    base: int
    size: int
    perms: int
    tag: str | None
    module: str | None = None
    section: str | None = None

    def to_region_info(self) -> RegionInfo:
        return RegionInfo(
            base=self.base,
            size=self.size,
            permissions=get_prot_string(self.perms),
            tag=self.tag,
            module=self.module,
            section=self.section,
        )

    def contains(self, address: int) -> bool:
        return self.base <= address < self.base + self.size


class WindowsEmulator(BinaryEmulator):
    """
    Base class of the user mode and kernel mode emulators.

    It adds processes, threads, modules, runs, API calls and SEH to BinaryEmulator. Win32Emulator sets ``peb_addr``
    to the address of the PEB pointer in the TEB (``fs:[0x30]`` or ``gs:[0x60]``).
    """

    _X64_EXEC_ADDR_MASK = (1 << 52) - 1

    _execution_budget: _ExecutionBudget | None = None
    peb_addr: int
    api: WindowsApi

    @abstractmethod
    def alloc_peb(self, proc: Any) -> None:
        """Allocate memory for the Process Environment Block (PEB)."""
        ...

    @abstractmethod
    def init_processes(self, processes: list[Any]) -> None:
        """Create the processes of the config."""
        ...

    def __init__(self, config, *, exit_event=None, debug=False, gdb_port=None, gdb_host=None):
        super().__init__(config)

        self.debug: bool = debug
        self.gdb_port: int | None = gdb_port
        self.gdb_host: str | None = gdb_host
        self.arch: int = 0
        self.modules: list[Any] = []
        self.module_change_listeners: list[Callable[[], None]] = []
        self.is_machine_ready: bool = False
        self.curr_run: Run | None = None
        self.api_ctx: ApiContext = NO_CONTEXT
        self._should_stop_on_faults: bool = False
        self._pending_fault_stop: StopReason | None = None
        self.curr_mod: Any | None = None
        self.runs: list[Run] = []
        self.input: dict[str, Any] | None = None
        self.exit_event: threading.Event | multiprocessing.synchronize.Event | None = exit_event
        self.max_runs: int = 100
        self.symbols: dict[int, tuple[str, str]] = {}
        self.ansi_strings: list[str] = []
        self.unicode_strings: list[str] = []
        self.run_queue: list[Run] = []
        self.suspended_runs: list[Run] = []
        self.is_reserved_range_unmapped: bool = True
        self.curr_process: Any | None = None
        self.om: objman.ObjectManager | None = None
        self._sigdb: sigdb.SignatureDatabase | None = None
        self._sigfmt: sigfmt.ArgFormatter | None = None
        self.api_registry: ApiRegistry = ApiRegistry(self)
        self._native_exit: NativeExit | None = None
        # The API entry that the last block jumped to, and the start and size of that block.
        self._api_call_site: tuple[int, tuple[int, int]] | None = None
        self._last_block: tuple[int, int] | None = None
        # A capstone engine with operand details, for the instruction that a memory fault names.
        self._fault_disasm_eng: cs.Cs | None = None
        self.call_site_hook: Any | None = None
        # Maps each guard page to the protection that its first access restores. Guard pages have no access.
        self.guard_pages: dict[int, int] = {}
        self.hardware_breakpoints = hardware_breakpoints.HardwareBreakpoints(self)
        self.module_loader: ModuleLoader = ModuleLoader(self)
        self._active_api_frame: GuestCallbackFrame | None = None
        self.mem_trace_hooks: list[Any] = []
        self.coverage_hook: Any | None = None
        self.debug_hook: Any | None = None
        self.is_kernel_mode: bool = False
        self.virtual_mem_base: int = 0x50000

        # Code hook for work that must wait until the next instruction: unmap the reserved range,
        # and clear the SEH repeat count. The emulator enables the hook only when there is such work.
        self.deferred_work_hook: Any | None = None

        # Only the run loop writes these two fields. To end a run, call end_run.
        # _run_completed: the result of curr_run is recorded, and the next run is not prepared yet.
        self._run_completed: bool = False
        self.is_emu_complete: bool = False
        self.processes: list[Any] = []
        # The processes that the guest creates with CreateProcess. self.processes does not include them.
        self.child_processes: list[Any] = []
        self.curr_thread: Any | None = None
        self.prev_pc: int = 0
        # The state of the kernel, and of a user mode emulator before a process exists. Each process has its own
        # copy of these fields. BinaryEmulator.env has the environment.
        self.cd: str = ""
        self.heap_allocs: list[tuple[int, int, str]] = []
        self.unhandled_exception_filter: int = 0
        self.function_tables: list[unwind.FunctionTable] = []
        self._seh_repeat: _SehRepeat = _SehRepeat()

        self.fs_addr: int = 0
        self.gs_addr: int = 0

        self.return_hook: int = winemu.EMU_RETURN_ADDR
        self.exit_hook: int = winemu.EXIT_RETURN_ADDR
        # A jump in kernel32 to the return hook. The EXE entry point and thread start routines return to it.
        self.thread_return_addr: int | None = None
        self._parse_config(config)

        self.wintypes = windefs
        self.handle_allocator: HandleAllocator = HandleAllocator(
            p.pid for p in self.config.processes if p.pid is not None
        )
        # The handles of the kernel, and of a user-mode emulator before a process exists
        self.handles: HandleTable = HandleTable(self.handle_allocator, self.dec_ref, self.get_pseudo_handle_object)
        self.regman: RegistryManager = RegistryManager(
            self.get_handle_table, self.config.registry, os_ver=self.config.system.os_ver, emu=self
        )
        self.fileman: FileManager = FileManager(config, self)
        self.netman: NetworkManager = NetworkManager(self.handle_allocator, config=self.config.network, emu=self)
        self.driveman: DriveManager = DriveManager(config=self.config.system.drives)
        self.cryptman: CryptoManager = CryptoManager(self.handle_allocator)
        self.rng: random.Random = random.Random(self.config.system.random_seed)
        self.start_time: int = winemu.get_filetime(parse_start_time(self.config.system.start_time))
        self._user_shared_data_bases: list[int] = []
        self._io_manager: Any | None = None

        # Local extensions: input identity for child execution, DEP/deferred-fault state, the
        # vectored exception registry, the import-sentinel table, TLS and child execution.
        self._root_pe_data: bytes | None = None
        self._root_emu_path: str = ""
        self._root_sample_sha256: str | None = None
        self._dyn_code_caller_pc: int | None = None
        self.instruction_budget_exhausted: bool = False
        self.veh_registry: VectoredExceptionRegistry = VectoredExceptionRegistry()
        self._deferred_protected_fault: DeferredProtectedFault | None = None
        self._seh_deferred_fault: DeferredProtectedFault | None = None
        self._next_sentinel: int = winemu.IMPORT_HOOK_ADDR
        self.import_table: dict[int, tuple[str, str]] = {}
        self.global_data: dict[Any, Any] = {}
        self._api_trace_tail: list[dict[str, Any]] = []
        self._last_api_trace: dict[str, Any] | None = None
        self.curr_exception_code: int = 0
        self._pending_cpu_exception: cpu_exceptions.CpuException | None = None
        self.restart_curr_run: bool = False
        self.tls: TlsManager = TlsManager()
        self.child_execution: ChildExecutionRegistry = ChildExecutionRegistry(self)
        self.child_scheduler: ChildSchedulerProtocol | None = None
        self.child_dispatcher: ChildExecutionDispatcher | None = None

    @property
    def veh_handlers(self) -> list[int]:
        """Guest VEH addresses in Windows dispatch order (read-only view).

        The registry is the source of truth; ``win32`` maintains it through
        ``add_vectored_exception_handler`` / ``remove_vectored_exception_handler``.
        """
        return self.veh_registry.dispatch_order()

    @property
    def run_complete(self) -> bool:
        """Get whether the current run is complete (local lifecycle view of ``_run_completed``)."""
        return self._run_completed

    @run_complete.setter
    def run_complete(self, value: bool) -> None:
        self._run_completed = bool(value)

    @property
    def emu_complete(self) -> bool:
        """Get whether the emulation is complete (local lifecycle view of ``is_emu_complete``)."""
        return self.is_emu_complete

    @emu_complete.setter
    def emu_complete(self, value: bool) -> None:
        self.is_emu_complete = bool(value)

    @property
    def kernel_mode(self) -> bool:
        """Get whether the emulator runs in kernel mode (local name for ``is_kernel_mode``)."""
        return self.is_kernel_mode

    @kernel_mode.setter
    def kernel_mode(self, value: bool) -> None:
        self.is_kernel_mode = bool(value)

    def _parse_config(self, config):
        super()._parse_config(config)
        self.cd = self.config.process.current_dir

    def _exceptions_dispatch_enabled(self) -> bool:
        """Get whether CPU exceptions go to the guest VEH/SEH handlers.

        The v2.1.0 schema names the switch ``exceptions.dispatch``; the local
        extension keeps ``exceptions.dispatch_handlers``. Both must allow the
        dispatch when both are present.
        """
        exceptions = self.config.exceptions
        if not getattr(exceptions, "dispatch", True):
            return False
        handlers = getattr(exceptions, "dispatch_handlers", None)
        return True if handlers is None else bool(handlers)

    def init_machine(self, arch):
        """
        Create the Unicorn engine, the disassembler and the API layer for ``arch``.

        Then create the Windows structures and the modules of the machine. Load images after this. The container image
        of a DLL or shellcode input is not part of the machine. Win32Emulator.load_container loads it.

        Raises:
            WindowsEmuError: if the machine is already initialized, or arch is not x86 or amd64.
        """
        if self.arch:
            raise WindowsEmuError("the machine is already initialized")
        if arch not in (_arch.ARCH_X86, _arch.ARCH_AMD64):
            raise WindowsEmuError(f"unsupported architecture: {arch}")
        self.arch = arch
        self.set_ptr_size(arch)
        self.env.setdefault("processor_architecture", "AMD64" if arch == _arch.ARCH_AMD64 else "x86")
        if arch == _arch.ARCH_AMD64:
            program_files = self.env.get("programfiles", "C:\\Program Files")
            self.env.setdefault("programfiles(x86)", f"{program_files} (x86)")
            self.env.setdefault("commonprogramfiles(x86)", f"{program_files} (x86)\\Common Files")
            self.env.setdefault("programw6432", program_files)
        self.regman.add_default_values(
            WINDOWS_CURRENT_VERSION_KEY, get_program_files_values(self.env, arch == _arch.ARCH_AMD64)
        )
        if self.emu_eng and not self.emu_eng.emu:
            self.emu_eng.init_engine(_arch.ARCH_X86, arch)
        self.disasm_eng = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64 if arch == _arch.ARCH_AMD64 else cs.CS_MODE_32)
        self.api = WindowsApi(self)

        with self.allocations_from(winemu.MACHINE_BASE):
            self.init_machine_structures()
            self.is_machine_ready = True
            for entry in tuple(self.api_registry.entries.values()):
                if entry.export.kind == "data":
                    self._initialize_api_data(entry)

    @abstractmethod
    def init_machine_structures(self) -> None:
        """Create the object manager, segments, shared data and modules of the machine."""

    def get_object_manager(self, reason: str) -> objman.ObjectManager:
        """
        Get the object manager of the machine.

        Raises:
            WindowsEmuError: if the machine structures are not initialized yet.
        """
        if self.om is None:
            raise WindowsEmuError(f"{reason} requires initialized object services")
        return self.om

    def on_run_complete(self):
        """
        Record the result of the current run. Only the run loop calls this, from ``_complete_run``.

        A subclass can add runs to the queue here. The run loop starts the next run after this.
        """
        raise NotImplementedError()

    @property
    def end_requested(self) -> bool:
        """Get whether a fault, an API handler, a hook or the user ended the current run with ``end_run``."""
        return isinstance(self._native_exit, RunEnd)

    @property
    def is_run_complete(self) -> bool:
        """Get whether the current run ended: ``end_run`` was called, or the run loop completed the run."""
        return self._run_completed or self.end_requested

    def end_run(self, error: ErrorInfo | None = None, *, stop_emulation: bool = False) -> None:
        """
        End the current run, with ``error`` as its error. API handlers and hooks use this to end a run.

        The run loop completes the run after the handler or the hook returns and Unicorn stops. Then it starts the
        next run, or, if ``stop_emulation`` is set, it ends the emulation. If the run already ended, keep its error.
        """
        if self.end_requested:
            if stop_emulation:
                self._native_exit = RunEnd(stop_emulation=True)
            return
        if error is not None:
            self._set_run_error(error)
        # An end replaces other native exits, such as a CPU exception that a hook raised before.
        self._native_exit = RunEnd(stop_emulation=stop_emulation)
        self.emu_eng.stop()

    def stop(self) -> None:
        """End the current run and the emulation. The runs in the queue do not run."""
        self._cancel_execution_runs()
        self.end_run(stop_emulation=True)
        super().stop()

    def end_run_on_fault(self):
        """
        End the current run after a handled memory fault.

        With a debugger attached, stop Unicorn at the fault, and end the run after the debugger resumes.
        A fault at a PC in the reserved range, such as the return hook, is not a fault of the guest, so it does not
        stop the debugger.
        """
        pc = self.get_pc()
        in_reserved = winemu.EMU_RESERVED <= pc < winemu.EMU_RESERVED + winemu.EMU_RESERVE_SIZE
        if not self._should_stop_on_faults or in_reserved:
            # The run loop goes to the next run only after Unicorn stops, also if Unicorn raises an error
            # after the stop. Otherwise the rest of the fault can change the next run.
            self.end_run()
            return
        self._pending_fault_stop = StopReason(signal=GDB_SIGSEGV, kind="exception", address=pc)
        self.emu_eng.stop()

    def enable_deferred_work_hook(self, address: int | None = None):
        """
        Add the deferred work hook, so that it runs at the next instruction.

        Unicorn does not add a new hook to code that it translated before, so drop the translation at ``address``,
        where the guest continues. The default is the current PC.
        """
        if not self.deferred_work_hook:
            self.deferred_work_hook = self.add_code_hook(cb=self._hook_code_deferred_work)
        if address is None:
            address = self.get_pc()
        self.emu_eng.invalidate_translations(address, address + 1)

    def disable_deferred_work_hook(self):
        """Remove the deferred work hook, so that Unicorn does not call Python for each instruction."""
        if self.deferred_work_hook:
            self.remove_hook(self.deferred_work_hook)
            self.deferred_work_hook = None

    def set_mem_tracing_hooks(self):
        if not self.config.memory.accesses:
            return

        if len(self.mem_trace_hooks) > 0:
            return

        logger.debug("installing memory tracing hooks")
        self.mem_trace_hooks = [
            self.add_code_hook(cb=self._hook_code_tracing),
            self.add_mem_read_hook(cb=self._hook_mem_read),
            self.add_mem_write_hook(cb=self._hook_mem_write),
        ]

    def set_call_site_hook(self):
        if self.call_site_hook:
            return
        self.call_site_hook = self.add_block_hook(cb=self._hook_block_call_site)

    def set_coverage_hooks(self):
        if not self.config.code.coverage:
            return

        if self.coverage_hook:
            return

        logger.debug("installing coverage hooks")
        self.coverage_hook = self.add_code_hook(cb=self._hook_code_coverage)

    def set_debug_hooks(self):
        if not self.debug:
            return

        if self.debug_hook:
            return

        self.debug_hook = self.add_code_hook(cb=self._hook_code_debug)

    def cast(self, obj, bytez):
        """Create a formatted structure from bytes."""
        if not isinstance(obj, EmuStruct):
            raise WindowsEmuError("Invalid object for cast")
        return obj.cast(bytez)

    def file_open(self, path, *, create=False, truncate=False, disposition=None, access=None):
        """Open an emulated file using the file manager."""
        return self.fileman.file_open(path, create, truncate=truncate, disposition=disposition, access=access)

    def pipe_open(self, path, mode, num_instances, out_size, in_size):
        """Open an emulated named pipe."""
        return self.fileman.pipe_open(path, mode, num_instances, out_size, in_size)

    def does_file_exist(self, path):
        """Get whether the emulated file at path exists."""
        return self.fileman.does_file_exist(path)

    def file_create_mapping(self, hfile, name, size, prot):
        """Create a memory mapping for an emulated file."""
        return self.fileman.file_create_mapping(hfile, name, size, prot)

    def file_get(self, handle):
        """Get a file object from a handle."""
        return self.fileman.get_file_from_handle(handle)

    def file_delete(self, path):
        """Delete a file."""
        return self.fileman.delete_file(path)

    def get_file_manager(self):
        """Get the file emulation manager."""
        return self.fileman

    def get_network_manager(self):
        """Get the network emulation manager."""
        return self.netman

    def get_crypt_manager(self):
        """Get the crypto manager."""
        return self.cryptman

    def get_drive_manager(self):
        """Get the drive manager."""
        return self.driveman

    def dev_ioctl(self, arch, dev, ioctl, inbuf):
        rv = ddk.STATUS_INVALID_DEVICE_REQUEST
        outbuf = b""

        if not dev or not hasattr(dev, "driver"):
            return rv, outbuf

        parent = dev.driver
        if not parent:
            return rv, outbuf

        if self._io_manager is None:
            self._io_manager = IoManager()

        return self._io_manager.dev_ioctl(arch, dev, ioctl, inbuf)

    def reg_open_key(self, path, *, create=False, disposition=None, access=None):
        """Open a key of the emulated registry. If create is set, create the key if it does not exist."""
        return self.regman.open_key(path, create, disposition=disposition, access=access)

    def reg_get_subkeys(self, hkey):
        """Get subkeys for a given registry key."""
        return self.regman.get_subkeys(hkey)

    def reg_get_key(self, handle: int = 0, path: str = "") -> RegKey | None:
        """Get registry key by path or handle."""
        if path:
            return self.regman.get_key_from_path(path)
        return self.regman.get_key_from_handle(handle)

    def get_trace_position(self) -> TracePosition:
        """
        Get the position of the current run, thread, process and program counter, for a report event.

        While the code of an API call runs, the program counter is the address of the call, or None if the
        emulator does not know it, for example in a thread that starts at the API.
        """
        run = self.get_current_run()
        thread = self.get_current_thread()
        proc = self.get_current_process()
        tick = self.get_tick(run)
        tid = thread.tid if thread else 0
        pid = proc.id if proc else 0
        frame = self._active_api_frame
        if frame is not None:
            pc = frame.call_pc
        else:
            try:
                pc = self.get_pc()
            except Exception:
                pc = None
        return TracePosition(tick=tick, tid=tid, pid=pid, pc=pc)

    def record_file_event(
        self, path, event_type: EventType, data=None, handle=0, disposition=None, access=None, buffer=0, size=None
    ):
        """Record a file or directory event in the report."""
        logger.debug("%s: %s", event_type.value, path)
        if self.profiler:
            self.profiler.record_file_access_event(
                self.get_current_run(),
                self.get_trace_position(),
                path,
                event_type,
                data,
                handle,
                disposition,
                access,
                buffer,
                size,
            )

    def record_registry_event(
        self,
        path,
        event_type: EventType,
        value_name=None,
        data=None,
        handle=0,
        disposition=None,
        access=None,
        buffer=0,
        size=None,
    ):
        """Record a registry key or value event in the report."""
        logger.debug("%s: %s", event_type.value, path)
        if self.profiler:
            self.profiler.record_registry_access_event(
                self.get_current_run(),
                self.get_trace_position(),
                path,
                event_type,
                value_name,
                data,
                handle,
                disposition,
                access,
                buffer,
                size,
            )

    def record_dns_event(self, domain, ip=""):
        """Record a DNS name lookup in the report."""
        logger.debug("dns: %s -> %s", domain, ip)
        if self.profiler:
            self.profiler.record_dns_event(self.get_current_run(), self.get_trace_position(), domain, ip)

    def record_network_event(
        self,
        server,
        port,
        typ: NetTrafficType | None = None,
        proto: NetTrafficProtocol = NetTrafficProtocol.UNKNOWN,
        data=b"",
        method="",
    ):
        """Record socket activity in the report."""
        logger.debug("net: %s:%d %s", server, port, proto.value)
        if self.profiler:
            self.profiler.record_network_event(
                self.get_current_run(),
                self.get_trace_position(),
                server,
                port,
                typ=typ,
                proto=proto,
                data=data,
                method=method,
            )

    def record_http_event(self, server, port, headers="", body=b"", secure=False):
        """Record an HTTP request in the report."""
        logger.debug("http: %s:%d", server, port)
        if self.profiler:
            self.profiler.record_http_event(
                self.get_current_run(),
                self.get_trace_position(),
                server,
                port,
                headers=headers,
                body=body,
                secure=secure,
            )

    def _unmap_reserved_range(self):
        """Unmap the reserved range, so that a return to the return hook or the exit hook faults."""
        if not self.is_reserved_range_unmapped:
            self.mem_unmap(winemu.EMU_RETURN_ADDR, winemu.EMU_RESERVE_SIZE)
            self.is_reserved_range_unmapped = True

    def _map_reserved_range(self):
        """
        Map the reserved memory range, so that Unicorn can complete an access to it.

        The deferred work hook or the next run unmaps it again.
        """
        if self.is_reserved_range_unmapped:
            self.emu_eng.mem_map(winemu.EMU_RETURN_ADDR, winemu.EMU_RESERVE_SIZE)
        self.is_reserved_range_unmapped = False

    def get_valid_ranges(self, size, addr=None):
        """
        Get a free range for an allocation outside the reserved range.

        The emulator keeps the reserved range unmapped, so that a return to the return hook faults.
        """
        base, total = super().get_valid_ranges(size, addr=addr)
        if base < winemu.EMU_RESERVED_END and base + total > winemu.EMU_RESERVED:
            base, total = super().get_valid_ranges(size, addr=winemu.EMU_RESERVED_END)
        return base, total

    def add_run(self, run):
        """Add a run to the emulation run queue."""
        self.run_queue.append(run)

    def _complete_run(self) -> None:
        """
        Record the result of the current run. Only the run loop calls this. Then it calls ``_start_next_run``.

        If ``stop`` ended the run, also end the emulation.
        """
        run = self.curr_run
        stop_emulation = isinstance(self._native_exit, RunEnd) and self._native_exit.stop_emulation
        self._native_exit = None
        self._run_completed = True
        self._end_dyn_code_watches()
        self.on_run_complete()
        if run is not None:
            self._finish_run_initializers(run)
        if stop_emulation:
            # on_run_complete can add runs, for example the routines of a driver after DriverEntry.
            self._cancel_execution_runs()
            self.on_emu_complete()

    def _start_next_run(self) -> Run | None:
        """
        Prepare the next run from the queue. Only the run loop calls this, after ``_complete_run``.

        Return the prepared run. If the queue is empty or the emulation is complete, complete the emulation and
        return None.
        """
        if self.is_emu_complete or not self.run_queue:
            self.on_emu_complete()
            return None
        run = self.run_queue.pop(0)
        self.reset_stack(self.stack_base)
        self.reset_cpu_context()
        mm = self.get_address_map(self.stack_base - 1)
        self.mem_write(mm.base, b"\x00" * mm.size)
        prepared: Run = self._prepare_run_context(run)
        return prepared

    def _queue_startup_initializers(self):
        """
        Add a run for each DllMain and TLS callback of the DLLs that the process loaded at start.

        Put these runs before the first run in the queue.
        """
        if self.is_kernel_mode or not self.run_queue:
            return
        queued = []
        for routine in self.module_loader.collect_initializers():
            run = Run()
            if routine.is_entry_point:
                run.type = RunType.DEPENDENCY_DLL_ENTRY
            else:
                run.type = RunType.DEPENDENCY_TLS_CALLBACK
            run.name = routine.module.name
            run.start_addr = routine.address
            run.args = routine.args
            run.thread = self.run_queue[0].thread or self.curr_thread
            run.process_context = self.curr_process
            run.guest_initialization = routine
            queued.append(run)
        self.run_queue[:0] = queued

    def _finish_run_initializers(self, run):
        """
        Undo the loads that the run did not complete.

        If the run is a startup initializer and it failed, set the state of its module to INIT_ERROR, and remove the
        other startup initializers of the module from the queue.
        """
        for frame in run.guest_callbacks:
            self.module_loader.rollback_guest_load(frame)
        run.guest_callbacks.clear()
        routine = run.guest_initialization
        if routine is None or self.module_loader.finish_initializer(
            routine, self.get_return_val(), faulted=run.error is not None
        ):
            return
        run.error = run.error or ErrorInfo(type=ErrorType.DLL_INITIALIZATION_FAILED, pc=self.get_pc())
        logger.warning(
            "guest initializer failed for %s in process %s: %s", routine.module.name, routine.pid, run.error.type.value
        )
        # Keep the module mapped, because bound import slots can point into it.
        routine.module.load_states[routine.pid] = LoadState.INIT_ERROR
        self.run_queue[:] = [
            queued
            for queued in self.run_queue
            if not (
                (pending := queued.guest_initialization) is not None
                and pending.module is routine.module
                and pending.pid == routine.pid
            )
        ]

    def call(self, addr, params=None) -> None:
        """Add a run that starts at addr. If the queue is empty, start the emulation."""
        self.reset_stack(self.stack_base)
        self.reset_cpu_context()
        mm = self.get_address_map(self.stack_base - 1)
        self.mem_write(mm.base, b"\x00" * mm.size)
        run = Run()
        run.type = RunType.CALL
        run.start_addr = addr
        run.args = params or []

        if not self.run_queue:
            self.add_run(run)
            self.start()
        else:
            self.add_run(run)

    def _prepare_run_context(self, run):
        """Set the registers, the stack, the process and the thread for run. Do not start Unicorn."""
        logger.info("* exec: %s", run.get_label())

        self.curr_run = run
        self._run_completed = False
        self._seh_repeat.reset()
        self._deferred_protected_fault = None
        self._seh_deferred_fault = None
        # FX-016 diagnostics: keep the last-API trace scoped to one run so an
        # error report never cites an API call from a previous run.
        self._api_trace_tail = []
        self._last_api_trace = None
        self.curr_mod = self.get_module_from_addr(run.start_addr)
        if self.profiler:
            self.profiler.add_run(run)

        self.runs.append(self.curr_run)

        stk_ptr = self.get_stack_ptr()
        if self.ptr_size == 8:
            # Win64 callees expect RSP + 8 to be 16-byte aligned at entry
            stk_ptr &= ~0xF
            if max(len(run.args) - 4, 0) % 2:
                stk_ptr -= 8

        self.set_func_args(stk_ptr, self.get_run_return_address(run), *run.args, conv=_arch.CALL_CONV_STDCALL)
        for reg, value in run.registers.items():
            self.reg_write(reg, value)
        stk_ptr = self.get_stack_ptr()
        stk_map = self.get_address_map(stk_ptr)

        self.curr_run.stack = MemAccess(base=stk_map.base, size=stk_map.size)

        if run.process_context:
            if run.process_context != self.get_current_process():
                self.alloc_peb(run.process_context)
            self.set_current_process(run.process_context)
        if run.thread:
            self.set_current_thread(run.thread)
        elif not self.is_kernel_mode:
            thread = objman.Thread(self, stack_base=self.stack_base)
            self.get_object_manager("thread registration").add_object(thread)
            if self.curr_process:
                thread.process = self.curr_process
                self.curr_process.threads.append(thread)
            run.thread = thread
            self.set_current_thread(thread)

        if not self.is_kernel_mode:
            thread = self.get_current_thread()
            if thread:
                thread.exit_code = None
                if self.curr_process is not None:
                    self.init_teb(thread, self.curr_process.peb)
                self.init_tls(thread)

        # Every run starts with the reserved range unmapped: a fetch from it must fault, so
        # that an import sentinel dispatches and a return to the return hook ends the run.
        # The range is mapped only to complete an access that the emulator is handling, and
        # a run that ends during that handling (for example a handler that exits a thread)
        # leaves it mapped. Unmap it here so that the next run cannot execute the mapped
        # sentinel page, including a run that does not start in the reserved range.
        self._unmap_reserved_range()

        self.set_pc(run.start_addr)
        if run.entry_context is not None:
            # A top-level EXE starts with the Windows loader entry registers.
            self.apply_process_entry_context(run.entry_context)
            self.set_thread_entry_context(self.get_current_thread(), run.entry_context)
        return run

    def get_run_return_address(self, run: Run) -> int:
        """Get the return address that the code of run returns to. A return to it ends the run."""
        return self.return_hook

    def mem_cast(self, obj, addr):
        """Read a structure of the type of obj from guest memory at addr."""
        size = obj.sizeof()
        struct_bytes = self.mem_read(addr, size)
        return self.cast(obj, struct_bytes)

    def setup_user_shared_data(self):
        """Map KUSER_SHARED_DATA at its user mode address and its kernel mode address, and write its data."""
        aliases = []
        if self.get_arch() == _arch.ARCH_X86:
            aliases.append(0xFFDF0000)
        elif self.get_arch() == _arch.ARCH_AMD64:
            aliases.append(0xFFFFF78000000000)

        # On x64, Unicorn truncates the address of a guest memory access to 52 bits, so a read from the kernel
        # address goes to the truncated address. Map the page there too.
        mirrors = {a & self._X64_EXEC_ADDR_MASK for a in aliases if a & self._X64_EXEC_ADDR_MASK != a}

        # The user mode address is the same on x86 and x64.
        bases = [0x7FFE0000] + aliases + list(mirrors)

        kuser_tag = "emu.struct.KUSER_SHARED_DATA"

        data = self._build_user_shared_data()
        self._user_shared_data_bases = []
        for base in bases:
            mm = self.get_address_map(base)
            if mm and not (mm.tag or "").startswith(kuser_tag):
                # Another mapping uses this address. A second map fails and stops the kernel mode load, and
                # a write changes the data of the other mapping.
                continue
            if not mm:
                self.mem_map(self.page_size, base=base, tag=kuser_tag)
            self.mem_write(base, data)
            self._user_shared_data_bases.append(base)

    def update_user_shared_time(self, tick_ms: int) -> None:
        """Write the time fields for the tick count tick_ms to each mapped copy of KUSER_SHARED_DATA."""
        data = bytearray(0x400)
        self._pack_user_shared_time(data, tick_ms)
        for base in self._user_shared_data_bases:
            self.mem_write(base + 0x008, bytes(data[0x008:0x020]))
            self.mem_write(base + 0x320, bytes(data[0x320:0x32C]))

    def _pack_user_shared_time(self, data: bytearray, tick_ms: int) -> None:
        # InterruptTime (offset 0x008): KSYSTEM_TIME {LowPart, High1Time, High2Time}
        interrupt_100ns = tick_ms * 10000
        struct.pack_into(
            "<IiI", data, 0x008, interrupt_100ns & 0xFFFFFFFF, interrupt_100ns >> 32, interrupt_100ns >> 32
        )
        # SystemTime (offset 0x014): KSYSTEM_TIME
        now_100ns = self.start_time + (tick_ms - winemu.START_TICK_COUNT) * 10000
        struct.pack_into("<IiI", data, 0x014, now_100ns & 0xFFFFFFFF, now_100ns >> 32, now_100ns >> 32)
        # TickCount (offset 0x320): KSYSTEM_TIME
        struct.pack_into("<IiI", data, 0x320, tick_ms & 0xFFFFFFFF, tick_ms >> 32, tick_ms >> 32)

    def get_native_machine(self) -> int:
        """Get the IMAGE_FILE_MACHINE value of the emulated host, which matches the guest architecture."""
        if self.get_arch() == _arch.ARCH_AMD64:
            return windefs.IMAGE_FILE_MACHINE_AMD64
        return windefs.IMAGE_FILE_MACHINE_I386

    def _build_user_shared_data(self):
        data = bytearray(0x400)
        # TickCountMultiplier (offset 0x004) is 1.0 in 8.24 fixed point, so TickCount counts milliseconds.
        struct.pack_into("<I", data, 0x004, 1 << 24)
        self._pack_user_shared_time(data, winemu.START_TICK_COUNT)
        # ImageNumberLow, ImageNumberHigh (offset 0x02C)
        machine = self.get_native_machine()
        struct.pack_into("<HH", data, 0x02C, machine, machine)
        # NtSystemRoot (offset 0x030): WCHAR[260] that ends with a NUL, without a trailing backslash, as in C:\Windows
        root = self.get_system_root().rstrip("\\")[:259].encode("utf-16le")
        data[0x030 : 0x030 + len(root)] = root
        # NtBuildNumber (offset 0x260), a reserved field before Windows 10
        struct.pack_into("<I", data, 0x260, self.config.system.os_ver.build or 0)
        # NtProductType (offset 0x264): NtProductWinNt, and ProductTypeIsValid (offset 0x268): TRUE
        struct.pack_into("<IB", data, 0x264, 1, 1)
        # NtMajorVersion (offset 0x26C), NtMinorVersion (offset 0x270)
        struct.pack_into("<II", data, 0x26C, self.config.system.os_ver.major or 0, self.config.system.os_ver.minor or 0)
        # QpcFrequency (offset 0x3B8)
        struct.pack_into("<q", data, 0x3B8, 10_000_000)

        return bytes(data)

    def _execute_current_run(self, address, timeout=0, count=-1, debugger=None):
        """
        Run the current run from address until it ends, it reaches a limit, or the debugger stops.

        Unicorn runs guest code until a hook records a native exit and stops Unicorn.
        Then the loop handles the exit, for example it calls the handler of an API, and starts Unicorn again.
        """
        address = self._drop_stale_exit(address)
        origin_run = self.curr_run
        assert origin_run is not None
        budget = self.config.limits.instructions if debugger is not None else count
        limits = RunLimits.from_run(origin_run, timeout, budget, self._execution_budget)
        if limits.budget > 0:
            hook = self._add_accounting_hook(limits, origin_run, debugger)
        elif self.counts_instructions() and not self.config.memory.accesses:
            # The report positions need the instruction count, and no other hook counts.
            hook = self._add_counting_hook(debugger)
        else:
            hook = None
        stepping = debugger is not None and count == 1

        try:
            while not self.is_emu_complete and not self._run_completed:
                if self.exit_event and self.exit_event.is_set():
                    self.emu_eng.stop()
                    return
                if self._native_exit is None:
                    reached = limits.get_reached_limit()
                    if reached is not None:
                        self._stop_at_limit(reached, limits, origin_run, debugger)
                        return
                    if not self._start_unicorn(address, limits, origin_run, debugger, stepping):
                        return
                    if self._native_exit is None:
                        self._native_exit = self._get_exit_at_pc()
                    if not isinstance(self._native_exit, RaisedCpuException):
                        if debugger is not None and debugger.has_pending_stop():
                            return
                        if self._native_exit is None:
                            self._stop_without_exit(limits, origin_run, debugger)
                            return
                        continue
                if not self._handle_exit(limits, origin_run, debugger):
                    return
                address = self.get_pc()
                if self._pending_fault_stop is not None:
                    return
                if debugger is not None and (debugger.has_pending_stop() or stepping):
                    return
        finally:
            self._finish_current_run_execution(limits, origin_run, debugger)
            if hook is not None:
                self.remove_hook(hook)

    def _start_unicorn(
        self, address: int, limits: RunLimits, origin_run: Run, debugger: GdbServer | None, stepping: bool
    ) -> bool:
        """
        Run guest code in Unicorn from address until it stops, and raise the CPU exception of a ``hlt`` that ran.

        Return False if a fault stops the debugger.

        Raises:
            uc.UcError: if Unicorn fails and no native exit explains the failure.
        """
        # A block of an earlier start of Unicorn did not jump to the code of this start.
        self._last_block = None
        try:
            native_timeout = limits.get_native_timeout()
            native_count = limits.get_native_count()
            if stepping:
                native_count = 1
                registers = self.get_register_state()
                counted = (limits.remaining, origin_run.budget_instructions, origin_run.instr_cnt)
                if limits.budget <= 0:
                    # There is no accounting hook, so record the instruction of the step here.
                    limits.last_executed = address
            self.emu_eng.start(address, timeout=native_timeout, count=native_count)
            if stepping and self._step_had_no_effect(registers, debugger):
                # When an instruction writes to the page of its own code, Unicorn
                # translates the page again and runs the instruction again. This
                # uses up the count of 1. Undo the counts of the first start, so
                # that the second start counts the instruction once.
                limits.remaining, origin_run.budget_instructions, origin_run.instr_cnt = counted
                self.emu_eng.start(address, timeout=native_timeout, count=2)
        except uc.UcError as exc:
            if self._pending_fault_stop is not None:
                return False
            if not self._exit_explains_error(exc):
                raise
        if self._stopped_at_hlt(limits.deadline, limits.last_executed, native_count, debugger):
            self.raise_cpu_exception(
                cpu_exceptions.privileged_instruction(self.get_pc() - 1), ErrorType.PRIVILEGED_INSTRUCTION
            )
        return True

    def _exit_explains_error(self, exc: uc.UcError) -> bool:
        """Get whether the native exit is the cause of the Unicorn error. Then the run loop handles the exit."""
        match self._native_exit:
            case None:
                return False
            case RaisedCpuException() | RunEnd():
                return True
            case ExecRecovery() if exc.errno == uc.UC_ERR_FETCH_PROT:
                return True
        return bool(exc.errno == uc.UC_ERR_FETCH_UNMAPPED)

    def _record_exit(self, native_exit: NativeExit) -> None:
        """Record native_exit and stop Unicorn. If an exit is already recorded, keep that exit."""
        if self._native_exit is None:
            self._native_exit = native_exit
        self.emu_eng.stop()

    def _get_exit_at_pc(self) -> NativeExit | None:
        """
        Get the exit at the address where Unicorn stopped, if no hook recorded one.

        The exit is the call of an API, the return of a guest callback, or the return of the run.
        """
        pc = self.get_pc()
        entry = self.api_registry.traps.get(pc)
        if entry is not None:
            return self._get_suspended_api_call(entry)
        run = self.curr_run
        if pc == winemu.GUEST_CALLBACK_RETURN_ADDR and run is not None and run.guest_callbacks:
            return CallbackReturn()
        if pc in (self.return_hook, self.exit_hook):
            return RunReturn()
        return None

    def _add_accounting_hook(self, limits: RunLimits, origin_run: Run, debugger: GdbServer | None):
        """Add a code hook that counts each instruction and stops Unicorn at the instruction limit."""

        def account_instruction(_emu, address, _size):
            if debugger is not None and debugger.has_pending_stop():
                return
            if limits.remaining <= 0:
                self.emu_eng.stop()
                return
            limits.remaining -= 1
            limits.last_executed = address
            origin_run.budget_instructions += 1
            if not self.config.memory.accesses:
                run = self.curr_run
                if run is not None:
                    run.instr_cnt += 1

        return self.add_code_hook(account_instruction)

    def _add_counting_hook(self, debugger: GdbServer | None):
        """
        Add a code hook that counts each instruction of the current run.

        A count of the instructions of each block in the block hook costs less, but it is wrong when a fault stops a
        block before its end.
        """

        def count_instruction(_emu, _address, _size):
            if debugger is not None and debugger.has_pending_stop():
                return
            run = self.curr_run
            if run is not None:
                run.instr_cnt += 1

        return self.add_code_hook(count_instruction)

    def _finish_current_run_execution(self, limits: RunLimits, origin_run: Run, debugger: GdbServer | None) -> None:
        """
        Add the time of the call to origin_run and to the total execution time.

        End the run if the exit event stopped it, and cancel all runs if the total time ran out.
        """
        elapsed = time.monotonic() - limits.started
        origin_run.execution_elapsed = limits.spent + elapsed
        stopped = self.exit_event is not None and self.exit_event.is_set()
        if stopped and debugger is None and not self.is_run_complete:
            if origin_run.error is None:
                origin_run.error = self._get_limit_error_info(ErrorType.PER_RUN_TIME_LIMIT)
            self._cancel_execution_runs()
        total_budget = limits.total_budget
        if total_budget is not None and total_budget.add(elapsed):
            self._cancel_execution_runs()
            if not self.is_run_complete and origin_run.error is None:
                origin_run.error = self._get_limit_error_info(ErrorType.TOTAL_TIME_LIMIT)
            if debugger is not None:
                debugger._request_stop(StopReason(kind=LimitKind.TOTAL_TIME_LIMIT.value, address=self.get_pc()))

    def _handle_exit(self, limits: RunLimits, origin_run: Run, debugger: GdbServer | None) -> bool:
        """
        Handle the native exit.

        Return False if the run loop must return, because the debugger stops, a limit is reached, or the run ended.
        """
        native_exit = self._native_exit
        match native_exit:
            case RaisedCpuException():
                self._native_exit = None
                self._dispatch_cpu_exception(native_exit)
                return True
            case SuspendedApiCall():
                reached = limits.get_reached_limit()
                if reached is not None:
                    self._stop_at_limit(reached, limits, origin_run, debugger)
                    return False
                if debugger is not None and debugger.has_pending_stop():
                    return False
                return self._dispatch_api_entry(native_exit.entry, limits, origin_run, debugger)
        if debugger is not None and debugger.has_pending_stop():
            return False
        if limits.is_total_time_reached():
            self._stop_at_limit(LimitKind.TOTAL_TIME_LIMIT, limits, origin_run, debugger)
            return False
        if isinstance(native_exit, (RunReturn, RunEnd)):
            self._complete_run()
            return False
        self._native_exit = None
        match native_exit:
            case ExecRecovery(page=page, perms=perms):
                self.mem_protect(page, self.page_size, perms)
            case CallbackReturn():
                self._continue_guest_callback()
        return True

    def _dispatch_api_entry(
        self, entry: ApiEntry, limits: RunLimits, origin_run: Run, debugger: GdbServer | None
    ) -> bool:
        """
        Call the handler of the API that the guest called, and complete the run if the handler ended it.

        Return False if the call of the run loop must return, because the debugger stops at an API with no
        implementation, a fault stops the debugger, or the total execution time ran out.
        """
        # With a debugger, an API without an implementation stops the debugger at the API, and the run continues.
        if debugger is not None and isinstance(
            self.resolve_api_implementation(entry.dll, entry.name), api_resolution.UnsupportedImplementation
        ):
            self.set_pc(entry.address)
            debugger._request_stop(StopReason(kind="unsupported_api", address=entry.address))
            return False
        self._native_exit = None
        site, self._api_call_site = self._api_call_site, None
        self.prev_pc = self._get_last_instruction(*site[1]) if site is not None and site[0] == entry.address else 0
        self.dispatch_api_call(entry.dll, entry.name)
        if self._pending_fault_stop is not None:
            return False
        if self.end_requested:
            if limits.is_total_time_reached():
                self._stop_at_limit(LimitKind.TOTAL_TIME_LIMIT, limits, origin_run, debugger)
                return False
            self._complete_run()
        return True

    def _stop_without_exit(self, limits: RunLimits, origin_run: Run, debugger: GdbServer | None) -> None:
        """
        Stop origin_run after Unicorn stopped with no native exit.

        If a limit is reached, stop at the limit. Otherwise, end the run with an ``engine_stopped`` error, if the run is
        not complete and no debugger is attached.
        """
        reached = limits.get_reached_limit()
        if reached is not None:
            self._stop_at_limit(reached, limits, origin_run, debugger)
        elif debugger is None and not self.is_run_complete:
            logger.error("0x%x: Emulation engine stopped", self.get_pc())
            origin_run.error = self.get_error_info(ErrorType.ENGINE_STOPPED, self.get_pc())
            self._complete_run()

    def _stop_at_limit(self, kind: LimitKind, limits: RunLimits, origin_run: Run, debugger: GdbServer | None) -> None:
        """
        Stop origin_run at the limit of the given kind.

        Without a debugger, the limit becomes the error of the run and the run ends. With a debugger, the debugger
        stops.
        """
        if isinstance(self._native_exit, SuspendedApiCall):
            self.set_pc(self._native_exit.entry.address)
        if kind == LimitKind.PER_RUN_TIME_LIMIT:
            # Each debugger resume of a timed out run stops at once; log only the first stop.
            if limits.spent < limits.timeout:
                logger.error("* Timeout of %d sec(s) reached.", limits.timeout)
        elif kind == LimitKind.TOTAL_TIME_LIMIT:
            assert limits.total_budget is not None
            logger.error("* Total execution time of %d sec(s) reached.", limits.total_budget.limit)
            limits.total_budget.exhausted = True
            self._cancel_execution_runs()
            # If the run already has an error, such as a fault, keep that error.
            if not self._run_completed and origin_run.error is None:
                origin_run.error = self._get_limit_error_info(ErrorType(kind.value))
        else:
            self.instruction_budget_exhausted = True
            logger.error("* Instruction limit of %d reached.", limits.budget)
        if debugger is not None:
            debugger._request_stop(StopReason(kind=kind.value, address=self.get_pc()))
        elif not self._run_completed:
            if origin_run.error is None:
                origin_run.error = self._get_limit_error_info(
                    ErrorType(kind.value),
                    limit=limits.budget if kind == LimitKind.INSTRUCTION_LIMIT else None,
                )
            self._complete_run()

    def _drop_stale_exit(self, address: int) -> int:
        """
        Drop the native exit that a debugger made stale while the target was stopped.

        Returns:
            The address where execution continues.
        """
        native_exit = self._native_exit
        if isinstance(native_exit, SuspendedApiCall):
            entry = native_exit.entry
            if address not in (entry.address, entry.trap):
                # The debugger changed PC, so the guest does not call the API.
                self._native_exit = None
            elif self._get_suspended_api_call(entry) != native_exit:
                # The debugger changed the stack or the code of the API. Run the
                # code of the API again, so that the changes take effect.
                self._native_exit = None
                address = entry.address
                self.set_pc(address)
        elif isinstance(native_exit, (RunReturn, CallbackReturn, RunEnd)) and address not in (
            winemu.GUEST_CALLBACK_RETURN_ADDR,
            self.return_hook,
            self.exit_hook,
        ):
            self._native_exit = None
        return address

    def _take_pending_fault_stop(self) -> StopReason | None:
        """Get the fault stop that a hook set during the last run, and clear it."""
        stop, self._pending_fault_stop = self._pending_fault_stop, None
        return stop

    def _cancel_execution_runs(self, prepared=None):
        """
        Remove the runs in the queue, the suspended runs and the run ``prepared``.

        Clear the ``INITIALIZING`` state of the DllMain and TLS callbacks of these runs.
        """
        canceled = [*self.run_queue, *self.suspended_runs]
        if prepared is not None:
            canceled.append(prepared)
        self.module_loader.cancel_initializers(
            run.guest_initialization for run in canceled if run.guest_initialization is not None
        )
        self.run_queue.clear()
        self.suspended_runs.clear()

    def resume(self, addr, count=-1) -> None:
        """
        Continue the current run at addr, without the GDB server.

        The current run continues also if it ended before. With the GDB server, use ``start``.
        """
        if self.curr_run is None:
            self.curr_run = Run()
        self.is_emu_complete = False
        self._run_completed = False
        if self.end_requested:
            self._native_exit = None
        timeout = 0 if self.gdb_port is not None else self.config.limits.per_run_time
        self._execute_current_run(addr, timeout=timeout, count=count)

    @execution_scope
    def start(self) -> None:
        """Add the runs of the startup initializers, then run all runs in the queue."""
        total_budget = self._execution_budget
        assert total_budget is not None
        if total_budget.exhausted:
            self._cancel_execution_runs()
            return
        self._queue_startup_initializers()
        try:
            run = self.run_queue.pop(0)
        except IndexError:
            return

        # An exit that a stop() before the emulation recorded does not end the first run.
        self._native_exit = None
        self.is_emu_complete = False
        self.set_hooks()
        self._unmap_reserved_range()

        # Prepare the first run before the GDB server starts, so that the first
        # stop shows the registers of the run.
        self._prepare_run_context(run)

        completed = True
        if self.gdb_port is not None:
            if self.gdb_host is None:
                raise WindowsEmuError("A GDB bind host is required when gdb_port is set")
            with GdbServer(self, self.gdb_port, self.gdb_host) as debugger:
                debug_action = debugger.command_loop()
                if debug_action.kill:
                    completed = True
                elif debug_action.detach:
                    debugger.close()
                    completed = self._execute_runs()
                else:
                    completed = self._execute_runs(debugger, debug_action)
        else:
            completed = self._execute_runs()

        if completed:
            self.on_emu_complete()

    def _execute_runs(
        self,
        debugger: GdbServer | None = None,
        debug_action: ResumeAction = ResumeAction(),
    ) -> bool:
        """
        Run the current run and the runs in the queue, with or without a GDB session.

        Return False if the user or the exit event stopped the emulation.
        """
        total_budget = self._execution_budget
        assert total_budget is not None
        detached_resume_addr: int | None = None
        terminal_signal = 0
        self._should_stop_on_faults = debugger is not None
        self._pending_fault_stop = None

        if self.profiler:
            self.profiler.start_clock()

        while True:
            try:
                executing_run = self.curr_run
                if executing_run is None:
                    break
                if debugger is not None:
                    resume_addr = self.get_pc()
                else:
                    start_addr = detached_resume_addr or executing_run.start_addr
                    if start_addr is None:
                        raise WindowsEmuError("the run has no start address")
                    resume_addr = start_addr
                    detached_resume_addr = None
                instruction_count = 1 if debugger is not None and debug_action.step else self.config.limits.instructions
                should_execute = debugger is None or debugger.begin_run(debug_action)
                if should_execute:
                    self._execute_current_run(
                        resume_addr, timeout=self.config.limits.per_run_time, count=instruction_count, debugger=debugger
                    )
                if debugger is None and total_budget.exhausted:
                    self._end_at_total_budget()
                    break
                completed = self._run_completed
                if completed and not total_budget.exhausted:
                    self._start_next_run()
                if debugger is not None:
                    stop_reason = debugger.finish_run(debug_action)
                    if stop_reason is not None and stop_reason.kind == "step" and self.is_emu_complete:
                        # A step that ends emulation gets the final stop instead.
                        stop_reason = None
                    fault_stop = self._take_pending_fault_stop()
                    if fault_stop is not None:
                        stop_reason = fault_stop
                        terminal_signal = fault_stop.signal
                    if stop_reason is not None:
                        debug_action = debugger.command_loop(stop_reason)
                        if debug_action.kill and not total_budget.exhausted:
                            return True
                        if debug_action.detach:
                            self._detach_debugger(debugger)
                            debugger = None
                        if total_budget.exhausted:
                            self._end_at_total_budget(debugger if not debug_action.kill else None)
                            return True
                        if fault_stop is not None:
                            self._complete_run()
                            if self._start_next_run() is None:
                                break
                            terminal_signal = 0
                        if debugger is None:
                            detached_resume_addr = self.get_pc()
                        continue
                if completed and not self.is_emu_complete:
                    continue
            except KeyboardInterrupt:
                logger.error("* User exited.")
                if debugger is not None:
                    debugger.notify_signal(2)
                return False
            except Exception as e:
                if self.exit_event and self.exit_event.is_set():
                    return False
                stack_trace = traceback.format_exc()

                if isinstance(e, uc.UcError) and e.errno == uc.UC_ERR_INSN_INVALID:
                    pc = self.get_pc()
                    error = self.get_error_info(self._get_invalid_instruction_error(pc), pc, traceback=stack_trace)
                elif isinstance(e, uc.UcError) and e.errno == uc.UC_ERR_MAP:
                    # UC_ERR_MAP does not expose the faulting address; recover the
                    # memory operand of the faulting instruction for the report.
                    error_pc = self.get_pc()
                    fault_address, access_type = self._resolve_uc_map_fault(str(e), error_pc)
                    error = self.get_error_info(
                        ErrorType.INTERNAL_ERROR,
                        fault_address if fault_address is not None else error_pc,
                        traceback=stack_trace,
                        access_type=access_type,
                        message=str(e) or type(e).__name__,
                    )
                else:
                    error = self.get_error_info(
                        ErrorType.INTERNAL_ERROR,
                        self.get_pc(),
                        traceback=stack_trace,
                        message=str(e) or type(e).__name__,
                    )
                self._set_run_error(error)
                terminal_signal = GDB_SIGSEGV

                if debugger is not None:
                    # finish_run keeps a pending Ctrl-C. Then report the fault
                    # while the registers of the fault are available.
                    debugger.finish_run(debug_action)
                    debug_action = debugger.command_loop(
                        StopReason(signal=terminal_signal, kind="exception", address=self.get_pc())
                    )
                    if debug_action.kill:
                        return True
                    if debug_action.detach:
                        self._detach_debugger(debugger)
                        debugger = None

                if not self._run_completed:
                    self._complete_run()
                if self._start_next_run() is None:
                    break
                terminal_signal = 0
                continue
            break

        if debugger is not None:
            if terminal_signal:
                debugger.notify_signal(terminal_signal)
            else:
                # Stop once more while the memory is mapped, so that the client
                # can read the final state before the exit reply.
                debug_action = debugger.command_loop(StopReason(kind="exit"))
                if debug_action.kill:
                    return True
                if debug_action.detach:
                    debugger.close()
                    return True
                debugger.notify_exit(0)
        return True

    def _end_at_total_budget(self, debugger: GdbServer | None = None) -> None:
        """
        Cancel the runs that are left and end the emulation, because the total time limit is reached.

        Args:
            debugger: the GDB session to send the exit reply to, if the client still waits for one.
        """
        self._cancel_execution_runs()
        if not self._run_completed:
            self._complete_run()
        if debugger is not None:
            debugger.notify_exit(0)
        self.on_emu_complete()

    def _detach_debugger(self, debugger: GdbServer) -> None:
        """Close the GDB session, so that the runs continue without a debugger."""
        debugger.close()
        self._should_stop_on_faults = False

    def get_current_run(self):
        """Get the current run that is being emulated."""
        return self.curr_run

    def get_current_module(self):
        """Get the currently running module."""
        return self.curr_mod

    def get_dropped_files(self) -> list[File]:
        """Get all files written by the sample from the file manager."""
        return self.fileman.get_dropped_files()

    def set_hooks(self):
        """Add the hooks in the hook lists to Unicorn."""
        super().set_hooks()

    def get_processes(self):
        """Get the process list. It does not include the child processes."""
        return self.processes

    def open_process(self, pid: int) -> int:
        """Open a handle to the process with the ID pid. Return 0 if no process has the ID."""
        proc = self.get_process_by_id(pid)
        if proc is None:
            return 0
        if not self.get_object_from_addr(proc.address):
            self.add_object(proc)
        hnd: int = self.get_object_handle(proc)
        return hnd

    def get_process_by_id(self, pid: int) -> Any | None:
        """Resolve a PID in the emulated Windows process namespace.

        Search order: configured/modeled processes from :meth:`get_processes`,
        then the currently executing process installed by
        :meth:`set_current_process`. The executing process is addressable by
        PID even though the top-level ``Process`` created by ``run_module()``
        is not materialized in the configured table.

        Args:
            pid: Process identifier to resolve.

        Returns:
            The matching ``Process`` object, or ``None`` when *pid* is neither
            the current process nor present in ``get_processes()``. Callers map
            ``None`` to their API-specific failure code; this method never
            allocates, clones or fabricates a process.

        Side effects:
            Calls ``get_processes()``, which lazily initializes the configured
            process table exactly as the existing enumeration APIs do.
        """
        for proc in self.get_processes():
            if proc.pid == pid:
                return proc
        current = self.get_current_process()
        if current is not None and current.pid == pid:
            return current
        return None

    def get_process_address_space(self, process: Any) -> ProcessAddressSpace | None:
        """Return the shadow VA view for a non-current process.

        Args:
            process: Process object from ``get_current_process`` or
                ``get_object_from_handle``.

        Returns:
            ``None`` when *process* is ``None`` or is the current process: its
            memory lives in the emulator's global address space and callers
            must keep using the existing global ``mem_read``/``mem_write``/
            ``mem_map`` APIs. For any other process a lazily created
            :class:`ProcessAddressSpace` is returned and cached on the process
            object. The view is seeded from ``process.pe_data`` (raw PE file
            bytes) when present; otherwise a loaded ``process.pe`` module is
            projected from the emulator's mapped image bytes and section
            protections (FX-012-extended). A process with neither field keeps
            an empty view because there is no initial image layout to model.

        Raises:
            ProcessMemoryError: if ``process.pe_data`` starts with ``MZ`` but
                cannot be parsed as a PE, or if ``process.pe`` exists but has no
                loadable image (missing base/size/sections) or its mapped bytes
                cannot be read. The error is explicit; a failed seed is never
                cached as an empty view.

        Side effects:
            Creates and caches ``process.address_space`` on success. Never maps
            or changes Unicorn memory; model-only children stay non-executable.
        """
        if process is None or process is self.curr_process:
            return None
        return self._ensure_process_address_space(process)

    def get_executing_process_address_space(self, process: Any) -> ProcessAddressSpace:
        """Return the shadow VA view used to project an executing child's writes.

        This is the executor-only companion of
        :meth:`get_process_address_space`. API handlers must keep treating the
        current process as the global emulator view, but a child execution
        backend runs the child in that same shared memory and therefore needs
        the child's per-process view as the projection target for observed
        runtime writes (FX12-extended-rv1). The view is seeded by exactly the
        same rules as :meth:`get_process_address_space`.

        Args:
            process: Non-``None`` process that is currently executing in the
                shared emulator memory. The caller is responsible for having
                installed it as the emulator's current process.

        Returns:
            The cached or newly seeded :class:`ProcessAddressSpace`.

        Raises:
            ProcessMemoryError: ``ERROR_INVALID_PARAMETER`` when no process is
                supplied; otherwise the same explicit seeding failures as
                :meth:`get_process_address_space`.

        Side effects:
            Creates and caches ``process.address_space`` on first use. Never
            maps or changes Unicorn memory and never changes the current
            process.
        """
        if process is None:
            raise ProcessMemoryError(ERROR_INVALID_PARAMETER, "no process supplied")
        return self._ensure_process_address_space(process)

    def _ensure_process_address_space(self, process: Any) -> ProcessAddressSpace:
        """Return the cached process view, seeding it on first use.

        Args:
            process: Non-``None`` process owning the view.

        Returns:
            The existing or newly seeded :class:`ProcessAddressSpace`.

        Raises:
            ProcessMemoryError: Propagated from :meth:`_seed_process_shadow`.
                A failed seed is never cached.
        """
        space = getattr(process, "address_space", None)
        if space is None:
            space = ProcessAddressSpace(
                pid=int(getattr(process, "pid", getattr(process, "id", 0))),
                pointer_bits=self.get_ptr_size() * 8,
                page_size=self.page_size,
            )
            self._seed_process_shadow(space, process)
            process.address_space = space
        return space

    def _seed_process_shadow(self, space: ProcessAddressSpace, process: Any) -> None:
        """Initialize ``space`` from the process's initial image.

        ``pe_data`` (raw file bytes) is parsed with the PE section table. A
        pe-only process (``pe`` set, ``pe_data`` unset) is seeded from the
        already mapped image bytes plus per-section Win32 protections, because
        the loader has no raw file bytes attached to that process object.

        Raises:
            ProcessMemoryError: explicit failure instead of leaving the view
                empty when the process has a module that cannot be projected.
        """
        data = getattr(process, "pe_data", None)
        if isinstance(data, (bytes, bytearray, memoryview)) and data and bytes(data[:2]) == b"MZ":
            space.map_pe_image(bytes(data))
            return

        module = getattr(process, "pe", None)
        if module is None:
            return

        image_base = int(getattr(module, "base", 0) or 0)
        image_size = int(getattr(module, "image_size", 0) or 0)
        sections = tuple(getattr(module, "sections", ()) or ())
        if image_base <= 0 or image_size <= 0 or not sections:
            raise ProcessMemoryError(
                ERROR_INVALID_PARAMETER, "process module has no loadable image layout"
            )

        try:
            image_bytes = self.mem_read(image_base, image_size)
        except Exception as err:  # engine read failure: report it, never fake zeros
            raise ProcessMemoryError(
                ERROR_INVALID_ADDRESS,
                f"process image at 0x{image_base:x} is not readable in the emulator: {err}",
            ) from err

        protections = self._image_page_protections(image_base, image_size, sections)
        space.map_loaded_image(image_base, image_size, image_bytes, protections)

    def _image_page_protections(self, image_base: int, image_size: int, sections: Any) -> dict[int, int]:
        """Return the Win32 protection of every page in a loaded image span.

        Headers are ``PAGE_READONLY``; sections use
        :func:`image_protection_for_emu_perms` (writable image sections become
        write-copy); pages not covered by a header/section are ``PAGE_NOACCESS``,
        matching the image view that :meth:`ProcessAddressSpace.map_pe_image`
        builds from raw bytes.

        Args:
            image_base: Page-aligned runtime image base.
            image_size: PE ``SizeOfImage``.
            sections: Loader ``SectionEntry`` objects with ``virtual_address``,
                ``virtual_size`` and emulator ``perms``.
        """
        page_size = self.page_size
        start = image_base & ~(page_size - 1)
        end = (image_base + image_size + page_size - 1) & ~(page_size - 1)
        protections = {page: windefs.PAGE_NOACCESS for page in range(start, end, page_size)}

        first_section_rva = min(int(section.virtual_address) for section in sections)
        headers_end = min(image_base + first_section_rva, image_base + image_size)
        for page in range(start, headers_end, page_size):
            protections[page] = windefs.PAGE_READONLY

        image_end = image_base + image_size
        for section in sections:
            section_start = image_base + int(section.virtual_address)
            section_end = min(section_start + int(section.virtual_size), image_end)
            if section_end <= section_start:
                continue
            protect = image_protection_for_emu_perms(int(section.perms))
            aligned_start = section_start & ~(page_size - 1)
            aligned_end = (section_end + page_size - 1) & ~(page_size - 1)
            for page in range(aligned_start, aligned_end, page_size):
                if page in protections:
                    protections[page] = protect
        return protections

    @staticmethod
    def _shadow_materialized_tag(pid: int) -> str:
        """Return the tag prefix for one process's materialized shadow maps."""

        return f"{SHADOW_MATERIALIZED_TAG_PREFIX}pid{int(pid)}"

    def materialize_process_shadow(
        self, process: Any
    ) -> tuple[MaterializedShadowRegion, ...]:
        """Give a non-current process's shadow regions physical backing.

        A model-only child has a bookkeeping :class:`ProcessAddressSpace` but no
        emulator mappings, so an executing child cannot write to a
        ``VirtualAllocEx`` reservation.  This executor-only operation maps each
        non-image shadow region at its exact base for the duration of one child
        run, seeds it with the shadow bytes, and applies the shadow's committed
        and reserved page protections (reserved/decommitted pages become
        ``PERM_MEM_NONE`` + ``PAGE_NOACCESS``, so a guest write faults exactly
        like Windows).

        Image regions are never materialized: the executing child already has
        its own (possibly relocated) runtime image mapping and the shadow image
        lives at the preferred ``ImageBase`` where another image may reside.

        Args:
            process: Process owning the shadow view.  It must expose
                ``address_space`` (:class:`ProcessAddressSpace`).

        Returns:
            One :class:`MaterializedShadowRegion` per created mapping, in shadow
            region order.  The caller must pass this tuple to
            :meth:`release_materialized_process_shadow` in a ``finally`` block.

        Raises:
            ProcessMemoryError: ``ERROR_INVALID_PARAMETER`` when the process has
                no usable shadow view or a region page is missing;
                ``ERROR_INVALID_ADDRESS`` for an oversized/misaligned region, an
                occupied base, or a relocation by the allocator.  Any failure
                releases every mapping created by this call; no global mapping
                leaks and no bytes are fabricated.

        Side effects:
            Creates emulator mappings tagged ``emu.child_shadow.pid<pid>`` with
            ``process=process`` and writes shadow bytes/protections into them.
            Image mappings and other components' memory are never modified.
        """

        space = getattr(process, "address_space", None)
        if not isinstance(space, ProcessAddressSpace):
            raise ProcessMemoryError(
                ERROR_INVALID_PARAMETER, "process has no shadow address space to materialize"
            )
        page_size = int(self.page_size or 0)
        if page_size <= 0:
            raise ProcessMemoryError(ERROR_INVALID_PARAMETER, "emulator page size is unavailable")
        pid = int(getattr(process, "pid", getattr(process, "id", 0)))
        tag = self._shadow_materialized_tag(pid)

        created: list[MaterializedShadowRegion] = []
        try:
            for region in space.regions:
                if region.is_image or int(region.size) <= 0:
                    continue
                base = int(region.base)
                size = int(region.size)
                if size > MAX_SHADOW_REGION_SIZE:
                    raise ProcessMemoryError(
                        ERROR_INVALID_ADDRESS,
                        f"shadow region at 0x{base:x} is too large to materialize",
                    )
                if base % page_size or size % page_size:
                    raise ProcessMemoryError(
                        ERROR_INVALID_ADDRESS,
                        f"shadow region at 0x{base:x} is not page aligned",
                    )
                if self.get_address_map(base) is not None:
                    raise ProcessMemoryError(
                        ERROR_INVALID_ADDRESS,
                        f"address 0x{base:x} is already mapped in the emulator",
                    )
                mapped = self.mem_map(
                    size,
                    base=base,
                    tag=tag,
                    flags=int(region.protect),
                    perms=common.PERM_MEM_RW,
                    process=process,
                )
                if int(mapped) != base:
                    # get_valid_ranges searches forward when the exact base is
                    # occupied.  Never relocate a shadow reservation silently.
                    try:
                        self.mem_free(int(mapped))
                    except Exception:
                        pass
                    raise ProcessMemoryError(
                        ERROR_INVALID_ADDRESS,
                        f"materialization relocated 0x{base:x} to 0x{int(mapped):x}",
                    )
                created.append(MaterializedShadowRegion(base=base, size=size, tag=tag))
                self.mem_write(base, bytes(region.data))
                self._apply_materialized_shadow_protections(space, base, size, page_size)
        except Exception as exc:
            try:
                self.release_materialized_process_shadow(tuple(created))
            except Exception:
                pass
            if isinstance(exc, ProcessMemoryError):
                raise
            raise ProcessMemoryError(
                ERROR_INVALID_ADDRESS,
                f"cannot materialize child shadow: {type(exc).__name__}: {exc}",
            ) from exc
        return tuple(created)

    def _apply_materialized_shadow_protections(
        self,
        space: ProcessAddressSpace,
        base: int,
        size: int,
        page_size: int,
    ) -> None:
        """Apply shadow committed/reserved page protections to one mapping."""

        plan: list[tuple[int, int, int]] = []
        for page in range(base, base + size, page_size):
            snapshot = space.query(page)
            if snapshot is None:
                raise ProcessMemoryError(
                    ERROR_INVALID_PARAMETER,
                    f"shadow page 0x{page:x} disappeared during materialization",
                )
            if snapshot["state"] == windefs.MEM_COMMIT:
                protect = int(snapshot["protect"])
                plan.append((page, win_protect_to_emu_perms(protect), protect))
            else:
                plan.append((page, common.PERM_MEM_NONE, windefs.PAGE_NOACCESS))

        runs: list[list[int]] = []
        for page, perms, protect in plan:
            if runs and runs[-1][1] == page and runs[-1][2] == perms and runs[-1][3] == protect:
                runs[-1][1] = page + page_size
            else:
                runs.append([page, page + page_size, perms, protect])
        for run_start, run_end, perms, protect in runs:
            self.mem_protect(run_start, run_end - run_start, perms, win_protect=protect)

    def release_materialized_process_shadow(
        self, regions: Sequence[MaterializedShadowRegion]
    ) -> None:
        """Remove every mapping created by :meth:`materialize_process_shadow`.

        A missing mapping is normal: the executing child may have freed it (or
        the engine may already have unmapped it).  A mapping at the recorded
        base whose tag no longer starts with ``region.tag`` belongs to another
        component and is never freed; that is an explicit error.

        Args:
            regions: Tuple returned by :meth:`materialize_process_shadow`.

        Raises:
            ProcessMemoryError: ``ERROR_INVALID_ADDRESS`` when a base is owned
                by a different mapping or a release did not remove our mapping.
                All supplied regions are still visited so one failure does not
                leak the remaining mappings.
        """

        errors: list[ProcessMemoryError] = []
        for region in regions:
            base = int(region.base)
            mm = self.get_address_map(base)
            if mm is None:
                continue
            if not str(getattr(mm, "tag", "")).startswith(region.tag):
                errors.append(
                    ProcessMemoryError(
                        ERROR_INVALID_ADDRESS,
                        f"mapping at 0x{base:x} is not owned by child shadow {region.tag}",
                    )
                )
                continue
            try:
                self.mem_free(base)
            except Exception as exc:
                errors.append(
                    ProcessMemoryError(
                        ERROR_INVALID_ADDRESS,
                        f"cannot release child shadow mapping at 0x{base:x}: {exc}",
                    )
                )
                continue
            if self.get_address_map(base) is not None:
                errors.append(
                    ProcessMemoryError(
                        ERROR_INVALID_ADDRESS,
                        f"child shadow mapping at 0x{base:x} survived release",
                    )
                )
        if errors:
            raise errors[0]

    def capture_process_runtime_write(self, process: Any, base: int, data: bytes) -> int:
        """Project bytes observed in a process's own runtime memory.

        Model path for :class:`ProcessAddressSpace`: child execution is
        ``model_only`` in the current engine, so production code does not call
        this yet. A future child execution backend that runs a child in the
        shared emulator reports each observed write here; the target process's
        shadow overlay then reflects the runtime bytes while the parent's
        global mappings stay unchanged. Tests drive this interface with
        controlled writes and never claim a child executed.

        Args:
            process: Non-current process that owns the write.
            base: Address in that process's own view.
            data: Bytes observed at ``base``.

        Returns:
            Number of bytes written to the shadow overlay.

        Raises:
            ProcessMemoryError: ``ERROR_INVALID_PARAMETER`` when no process is
            supplied or the target is the current/global process; page errors
            from :meth:`ProcessAddressSpace.capture_runtime_write`.
        """
        if process is None:
            raise ProcessMemoryError(ERROR_INVALID_PARAMETER, "no process supplied")
        space = self.get_process_address_space(process)
        if space is None:
            raise ProcessMemoryError(
                ERROR_INVALID_PARAMETER, "current process memory is the global emulator view"
            )
        return space.capture_runtime_write(base, data)

    def set_thread_entry_context(self, thread: Any, context: ProcessEntryContext) -> None:
        """Write process-entry values into a thread's saved CPU context.

        Applies the Windows loader convention for a process's first thread:
        x86 ``EAX=entry``/``EBX=PEB``; x64 ``RCX=entry``/``RDX=PEB``. Only
        ``thread.ctx`` is modified; the live guest CPU and the program counter
        are untouched. No-op when *thread* has no saved context or when the
        emulator architecture has no process-entry convention.

        Args:
            thread: Thread object whose saved ``CONTEXT`` should be updated.
            context: Entry address and PEB address for the process.
        """
        rules = _PROCESS_ENTRY_CONTEXT_REGS.get(self.get_arch())
        if rules is None or thread is None or thread.ctx is None:
            return
        (_, entry_field), (_, peb_field) = rules
        setattr(thread.ctx, entry_field, context.entry)
        setattr(thread.ctx, peb_field, context.peb)

    def apply_process_entry_context(self, context: ProcessEntryContext) -> None:
        """Write process-entry values to the live guest CPU registers.

        Applies the same architecture rule as
        :meth:`set_thread_entry_context`: x86 ``EAX=entry``/``EBX=PEB``;
        x64 ``RCX=entry``/``RDX=PEB``. The program counter and stack pointer
        are not modified. No-op when the emulator architecture has no
        process-entry convention.

        Args:
            context: Entry address and PEB address for the process.
        """
        rules = _PROCESS_ENTRY_CONTEXT_REGS.get(self.get_arch())
        if rules is None:
            return
        (entry_reg, _), (peb_reg, _) = rules
        self.reg_write(entry_reg, context.entry)
        self.reg_write(peb_reg, context.peb)


    def kill_process(self, proc):
        """Remove proc from the process list."""
        try:
            self.processes.remove(proc)
        except ValueError:
            pass

    def get_current_thread(self):
        """Get the current thread."""
        return self.curr_thread

    def set_last_error(self, code):
        """Set the last error code for the current thread."""
        if self.curr_thread:
            self.curr_thread.last_error = code

    def get_last_error(self):
        """Get the last error code for the current thread."""
        if self.curr_thread:
            return self.curr_thread.last_error

    def heap_alloc(self, size, heap="None"):
        """Map a block for a heap, and record it in the heap allocations. Return 0 if there is no free memory."""
        try:
            addr = self.mem_map(size, base=None, tag=f"api.heap.{heap}")
        except OutOfMemoryError:
            return 0
        self.get_heap_allocs().append((addr, size, heap))
        return addr

    def pool_alloc(self, pooltype, size, tag="None") -> int:
        """
        Allocate memory in the emulated pool.

        Raises:
            WindowsEmuError: if the emulator runs in user mode, which has no pool.
        """
        raise WindowsEmuError("pool allocations need kernel mode")

    def exit_process(self) -> None:
        """
        Signal that the current process ends.

        Raises:
            WindowsEmuError: if the emulator runs in kernel mode, which has no process to end.
        """
        raise WindowsEmuError("process exit needs user mode")

    def get_current_process(self):
        """Get the current process."""
        return self.curr_process

    def set_current_process(self, process):
        """Set the current process."""
        self.curr_process = process

    def set_current_thread(self, thread):
        """Set the current thread."""
        self.curr_thread = thread
        self.hardware_breakpoints.update()

    def set_debug_registers(self, thread, ctx):
        """Give thread the debug registers of ctx, which arm its hardware breakpoints."""
        thread_context.set_debug_registers(thread, ctx)
        if thread is self.get_current_thread():
            self.hardware_breakpoints.update()

    def _setup_gdt(self, arch):
        """
        Map the GDT and the TEB segment, and load the segment registers.

        The guest reads the TEB through FS on x86 and through GS on x64.
        """
        GDT_SIZE = 0x1000
        SEG_SIZE = 0x1000
        ENTRY_SIZE = 0x8
        num_gdt_entries = 31
        fs_addr = 0
        gs_addr = 0
        gdt_addr = None

        # The format of a descriptor: https://wiki.osdev.org/Global_Descriptor_Table

        def _make_entry(index, base, access, limit=0xFFFFF000):
            access = access | (winemu.GDT_ACCESS_BITS.PresentBit | winemu.GDT_ACCESS_BITS.DirectionConformingBit)
            entry = 0xFFFF & limit
            entry |= (0xFFFFFF & base) << 16
            entry |= (0xFF & access) << 40
            entry |= (0xFF & (limit >> 16)) << 48
            entry |= (0xFF & winemu.GDT_ACCESS_BITS.ProtMode32) << 52
            entry |= (0xFF & (base >> 24)) << 56
            entry = entry.to_bytes(8, "little")

            offset = index * ENTRY_SIZE
            self.mem_write(gdt_addr + offset, entry)

        def _create_selector(index, flags):
            return flags | (index << 3)

        # x86 user mode uses the selectors of native 32-bit Windows: CS 0x1B, DS and ES 0x23, FS 0x3B.
        # SS is a ring 0 selector, because Unicorn runs the guest at CPL 0 and rejects an RPL 3 SS.
        native_x86 = arch == _arch.ARCH_X86 and not self.is_kernel_mode
        data_index, code_index, fs_index = (4, 3, 7) if native_x86 else (16, 17, 19)

        gdt_addr, gdt_size = self.get_valid_ranges(GDT_SIZE)
        self.mem_map(gdt_size, base=gdt_addr, tag="emu.gdt")
        seg_addr, seg_size = self.get_valid_ranges(SEG_SIZE)
        self.mem_map(seg_size, base=seg_addr, tag="emu.segment.gdt")

        access = winemu.GDT_ACCESS_BITS.Data | winemu.GDT_ACCESS_BITS.DataWritable | winemu.GDT_ACCESS_BITS.Ring3
        _make_entry(data_index, 0, access)

        access = winemu.GDT_ACCESS_BITS.Code | winemu.GDT_ACCESS_BITS.CodeReadable | winemu.GDT_ACCESS_BITS.Ring3
        _make_entry(code_index, 0, access)

        access = winemu.GDT_ACCESS_BITS.Data | winemu.GDT_ACCESS_BITS.DataWritable | winemu.GDT_ACCESS_BITS.Ring0
        _make_entry(18, 0, access)

        self.reg_write(_arch.X86_REG_GDTR, (0, gdt_addr, num_gdt_entries * ENTRY_SIZE - 1, 0x0))
        selector = _create_selector(data_index, winemu.GDT_FLAGS.Ring3)
        self.reg_write(_arch.X86_REG_DS, selector)
        if native_x86:
            self.reg_write(_arch.X86_REG_ES, selector)
        selector = _create_selector(code_index, winemu.GDT_FLAGS.Ring3)
        self.reg_write(_arch.X86_REG_CS, selector)
        selector = _create_selector(18, winemu.GDT_FLAGS.Ring0)
        self.reg_write(_arch.X86_REG_SS, selector)

        teb_addr = None if self.is_kernel_mode else winemu.TEB_ADDRESS
        if arch == _arch.ARCH_X86:
            # The guest reads the TEB through FS, for example the PEB pointer at fs:[0x30]
            fs_addr, fs_size = self.get_valid_ranges(SEG_SIZE, addr=teb_addr)
            self.mem_map(fs_size, base=fs_addr, tag="emu.segment.fs")

            access = winemu.GDT_ACCESS_BITS.Data | winemu.GDT_ACCESS_BITS.DataWritable | winemu.GDT_ACCESS_BITS.Ring3
            _make_entry(fs_index, fs_addr, access)

            selector = _create_selector(fs_index, winemu.GDT_FLAGS.Ring3)
            self.reg_write(_arch.X86_REG_FS, selector)

        elif arch == _arch.ARCH_AMD64:
            # The guest reads the TEB through GS, for example the PEB pointer at gs:[0x60]
            gs_addr, gs_size = self.get_valid_ranges(SEG_SIZE, addr=teb_addr)
            self.mem_map(gs_size, base=gs_addr, tag="emu.segment.gs")

            access = winemu.GDT_ACCESS_BITS.Data | winemu.GDT_ACCESS_BITS.DataWritable | winemu.GDT_ACCESS_BITS.Ring3
            _make_entry(15, gs_addr, access, limit=SEG_SIZE)

            selector = _create_selector(15, winemu.GDT_FLAGS.Ring3)
            self.reg_write(_arch.X86_REG_GS, selector)

        self.fs_addr = fs_addr
        self.gs_addr = gs_addr

        return fs_addr, gs_addr

    def init_peb(self, user_mods, proc=None):
        """Initialize the PEB of proc or of the current process. For the current process, write the PEB pointer."""
        p = proc
        if not p:
            p = self.curr_process
        p.init_peb(user_mods)
        if p is self.get_current_process():
            self.mem_write(self.peb_addr, p.peb.address.to_bytes(self.get_ptr_size(), "little"))
        return p.peb

    def init_teb(self, thread, peb):
        """Initialize the TEB of thread at the base of the FS or GS segment."""
        if self.get_arch() == _arch.ARCH_X86:
            thread.init_teb(self.fs_addr, peb.address)
        elif self.get_arch() == _arch.ARCH_AMD64:
            thread.init_teb(self.gs_addr, peb.address)

    def init_tls(self, thread):
        """
        Initialize implicit thread local storage for a thread.

        Each module with an ``IMAGE_TLS_DIRECTORY`` received a TLS index at load
        time. Here the :class:`TlsManager` allocates this thread's pointer array
        and its writable copy of every registered template. The returned array is
        published through ``TEB->ThreadLocalStoragePointer``; the read-only image
        template itself is never written.
        """
        init_thread = self.tls.init_thread
        # v2.1.0 gives every registered module a writable block, even when its
        # template and zero fill are empty (a callback-only TLS directory). The
        # TLS manager keeps the Wine zero-size rule as its default and exposes
        # the v2.1.0 policy as an explicit ``allocate_empty`` keyword; pass it
        # only when the installed manager declares the keyword, so this file
        # works with both TLS manager interfaces.
        try:
            parameters = inspect.signature(init_thread).parameters
        except (TypeError, ValueError):
            parameters = {}
        if "allocate_empty" in parameters:
            tls_array = init_thread(self, thread, allocate_empty=True)
        else:
            tls_array = init_thread(self, thread)
        if tls_array is None:
            return
        if thread.teb is None:
            raise WindowsEmuError("init_tls called before init_teb")
        thread.teb.object.ThreadLocalStoragePointer = tls_array
        thread.teb.write_back()

    def read_tls_template(self, tls_dirp: int) -> bytes:
        """
        Get the static TLS data of a module from its IMAGE_TLS_DIRECTORY at tls_dirp.

        Set the TLS index of the module to 0. A directory with an invalid or too large range gives empty data.
        """
        ptrsz = self.get_ptr_size()
        fmt = "<4QI" if ptrsz == 8 else "<5I"
        try:
            start, end, index_addr, _, zero_fill = struct.unpack(fmt, self.mem_read(tls_dirp, struct.calcsize(fmt)))
        except Exception:
            return b""
        size = end - start if start <= end else 0
        if size + zero_fill > TLS_TEMPLATE_MAX:
            size, zero_fill = 0, 0
        data = b""
        if size:
            try:
                data = self.mem_read(start, size)
            except Exception:
                data = b""
        if index_addr:
            try:
                self.mem_write(index_addr, b"\0\0\0\0")
            except Exception:
                pass
        return data + bytes(zero_fill)

    def load_pe(self, path=None, data=None):
        """Parse a PE file or buffer without loading it into the emulator."""
        if not data:
            if path is None:
                raise WindowsEmuError("No PE data to parse")
            if not os.path.exists(path):
                raise WindowsEmuError(f"File: {path} not found")

        try:
            return winemu._PeParser(path=path, data=data)
        except pefile.PEFormatError as e:
            raise WindowsEmuError(f"Invalid PE: {e}") from e

    def get_mod_from_addr(self, addr):
        if self.curr_mod and self.curr_mod.base <= addr < self.curr_mod.base + self.curr_mod.image_size:
            return self.curr_mod
        return self.get_module_from_addr(addr)

    def ensure_pe_import_hooks(self, base_addr):
        """
        Bind the imports of a PE that the guest mapped itself, for example by process hollowing.

        Bind each valid IAT slot, and skip the invalid slots. If OriginalFirstThunk is zero, the IAT can have
        addresses that this method bound in an earlier call. The emulator records its bindings, so that it skips
        these slots and does not read their addresses as RVAs.
        """
        ptr_size = self.get_ptr_size()
        import_errors = (ValueError, struct.error, uc.UcError, WindowsEmuError)

        def read(address, size):
            try:
                return self.mem_read(address, size)
            except uc.UcError as error:
                raise ValueError(str(error)) from error

        pending = []
        try:
            for slot in mapped_imports.get_import_slots(read, base_addr, ptr_size):
                bindings = self.module_loader.import_bindings
                if bindings.get(slot.iat) == slot.current:
                    continue
                if slot.iat in bindings and (not slot.has_ilt or slot.current != slot.thunk):
                    # The guest changed an entry that the emulator bound. Keep the value of
                    # the guest, unless the guest wrote back the original value from the ILT.
                    continue
                if slot.is_bound_externally:
                    continue
                try:
                    reference = slot.get_reference()
                    address = self.get_proc(slot.dll, reference)
                    if not address:
                        raise WindowsEmuError(f"unresolved import {slot.dll}!{reference}")
                    if not 0 <= address < 1 << (ptr_size * 8):
                        raise ValueError("import address does not fit pointer size")
                except import_errors as error:
                    logger.warning("skipping injected PE import slot at %#x: %s", slot.iat, error)
                    continue
                pending.append((slot.iat, address))

            for iat, address in pending:
                self.mem_write(iat, address.to_bytes(ptr_size, "little"))
            self.module_loader.import_bindings.update(pending)
        except import_errors:
            logger.warning("invalid injected PE import table at %#x", base_addr, exc_info=True)

    def get_mod_by_name(self, name):
        name_lower = name.lower()
        for mod in self.modules:
            mod_name = ntpath.basename(mod.emu_path)
            base_name = os.path.splitext(mod_name)[0]
            if base_name.lower() == name_lower:
                return mod
            if mod.name and mod.name.lower() == name_lower:
                return mod
        return None

    def get_peb_modules(self):
        return [mod for mod in self.modules if mod.visible_in_peb]

    def _set_input_metadata(self, path, data):
        if not self.profiler:
            return
        pe = winemu._PeParser(path=path, data=data, fast_load=True)
        file_type = None
        if pe.is_driver():
            file_type = FileType.DRIVER
        elif pe.is_dll():
            file_type = FileType.DLL
        elif pe.is_exe():
            file_type = FileType.EXE
        self.input = {
            "path": pe.path or None,
            "sha256": pe.hash,
            "size": pe.file_size,
            "arch": REPORT_ARCHES.get(pe.arch),
            "file_type": file_type,
            "emu_version": self.get_emu_version(),
            "os_run": self.get_osver_string(),
        }
        self.profiler.add_input_metadata(self.input)

    def get_mem_strings(self):
        """
        Get ansi and unicode strings from emulated memory.

        In the image of a guest module, get only the strings that contain a byte that changed after the load.
        """
        ansi_strings, unicode_strings = super().get_mem_strings()
        for mod in self.modules:
            loaded = mod.loaded_data
            if loaded is None:
                continue
            # The guest can unmap its image and allocate new memory at the same base. That memory is not the image.
            mmap = self.get_address_map(mod.base)
            if mmap is None or mmap.base != mod.base or not (mmap.tag or "").startswith("emu.module."):
                continue
            data = bytes(self.mem_read(mod.base, len(loaded)))
            if data == loaded:
                continue
            for off, s in self.get_ansi_strings(data):
                if data[off : off + len(s)] != loaded[off : off + len(s)]:
                    ansi_strings.append((off, s))
            for off, s in self.get_unicode_strings(data):
                if data[off : off + 2 * len(s)] != loaded[off : off + 2 * len(s)]:
                    unicode_strings.append((off, s))
        return (list(dict.fromkeys(ansi_strings)), list(dict.fromkeys(unicode_strings)))

    def load_image(self, image, base: int | None = None, *, is_input: bool = False) -> RuntimeModule:
        """
        Load an image and its dependencies.

        Set is_input for the input image. The input image is the first module in modules, and the emulator
        allocates the stack only for the input image.
        """
        return self.module_loader.load_image(image, base, is_input=is_input)

    def _load_image(self, image, base=None, *, is_input=False):
        """
        Map an image at base, or at its preferred base, or at the next free range after it.

        An image with preferred base 0 loads at any free address.

        Raises:
            ValueError: if the image cannot move to the free base, for example because it has no relocation data.
            WindowsEmuError: if the machine is not initialized, or the image does not match the machine.
        """
        if not self.arch:
            raise WindowsEmuError("the machine is not initialized: call init_machine before loading images")
        if image.arch in (_arch.ARCH_X86, _arch.ARCH_AMD64) and self.arch != image.arch:
            raise WindowsEmuError("module architecture does not match the emulated process")
        if image.source == "synthetic" and not image.image_base:
            raise WindowsEmuError("synthetic image addresses must be finalized before mapping")

        # A synthesized decoy materializes its regions, exports and image base as absolute
        # addresses (SystemModuleDecoyLoader contract), unlike the RVA-based guest PE images.
        is_decoy_image = isinstance(getattr(image, "loader", None), SystemModuleDecoyLoader)
        if not is_decoy_image:
            for region in image.regions:
                if region.base < 0 or region.base + len(region.data) > image.image_size:
                    raise WindowsEmuError("module region is outside its image span")
            requested_base = base or image.image_base
            if requested_base:
                base, _ = self.get_valid_ranges(image.image_size, addr=requested_base)
                if base != requested_base:
                    logger.debug("module %s: base %#x is in use, loading at %#x", image.name, requested_base, base)
                image = relocate_image(image, base)
        else:
            requested_base = image.image_base
            if base is not None and base != image.image_base:
                raise WindowsEmuError("a synthesized decoy image cannot move after it was built")
        # The emulator maps an image before its process exists, so the input EXE decides the DEP state for all
        # processes. Set it before the map of the input image.
        if is_input and image.source == "guest_pe" and image.module_type == "exe" and not self.is_kernel_mode:
            self.dep_enabled = is_dep_enabled(image)
        # Only PE loader images are image views (SEC_IMAGE) with write-copy protection semantics.
        # Shellcode and raw blobs are private memory. Synthetic modules keep the protection of
        # their sections, so that a jump into their data faults.
        is_pe_image = isinstance(getattr(image, "loader", None), PeLoader)
        # FX-001 keeps the local deferred image-page rule authoritative: the image mappings
        # request exactly their section permissions, and the only image-page execution
        # relaxation is the deferred DEP grant for writable pages of an NXCOMPAT-clear image.
        dep = False
        base = self.mem_map(
            image.image_size,
            base=image.image_base if is_decoy_image else (base or None),
            tag=f"emu.module.{image.name}",
            process=self.get_current_process() if self.is_kernel_mode else None,
            dep=dep,
            image=is_pe_image,
        )
        if is_decoy_image:
            if base != image.image_base:
                raise WindowsEmuError("a synthesized decoy image was relocated by the memory manager")
        elif not requested_base:
            image = relocate_image(image, base)
        for region in image.regions:
            self.mem_write(region.base, region.data)

        mod = RuntimeModule(image)
        if is_input:
            self.modules.insert(0, mod)
            if self.profiler:
                for problem in image.problems:
                    self.profiler.record_error_event(ErrorInfo(type=ErrorType.INVALID_IMAGE, context_summary=problem))
        else:
            self.modules.append(mod)
        self.api_registry.register_module(mod)
        if is_input and image.source == "guest_pe" and not self.stack_base and image.stack_size:
            self.stack_base, _stack_addr = self.alloc_stack(self.config.runs.stack_size or image.stack_size)

        if image.module_type in ("exe", "dll"):
            tls_directory = mod.get_tls_directory()
            if tls_directory is not None:
                self.tls.register_module(self, tls_directory, module_name=mod.get_base_name())

        ptr_size = self.get_ptr_size()
        for imp in image.imports:
            try:
                if not mod.base <= imp.iat_address <= mod.base + mod.image_size - ptr_size:
                    raise WindowsEmuError("import IAT slot outside image")
                address = self._resolve_import_target(imp.dll_name, imp.func_name)
                if not address:
                    raise WindowsEmuError(f"unresolved import {imp.dll_name}!{imp.func_name}")
                encoded = address.to_bytes(ptr_size, "little")
            except (ValueError, OverflowError, uc.UcError, WindowsEmuError) as error:
                logger.warning("skipping import %s!%s in %s: %s", imp.dll_name, imp.func_name, image.name, error)
                continue
            self.mem_write(imp.iat_address, encoded)
            self.module_loader.import_bindings[imp.iat_address] = address

        # Data exports (for example msvcrt._acmdln) are variables, not code: bind the
        # actual data address instead of the dispatch sentinel written above.
        if self.api:
            for imp in image.imports:
                dll_name = imp.dll_name
                alt_dll = winemu.normalize_dll_name(dll_name)
                _api_mod, eh = self.api.get_data_export_handler(dll_name, imp.func_name)
                if not eh and alt_dll:
                    _api_mod, eh = self.api.get_data_export_handler(alt_dll, imp.func_name)
                if not eh:
                    continue
                try:
                    old_sentinel = int.from_bytes(self.mem_read(imp.iat_address, ptr_size), "little")
                except uc.UcError:
                    continue
                entry = self._synthetic_data_export_entry(_api_mod, imp.func_name)
                if entry is not None:
                    # The handler module gives the export its own storage slot in the
                    # synthetic image's .data section. Initialize that slot and bind the
                    # IAT to it, as v2.1.0 does through get_proc/resolve_export, so a
                    # data initializer never writes through a null storage pointer.
                    self._initialize_api_data(entry)
                    data_ptr = entry.address
                else:
                    # No synthetic data export: keep the local cell allocation of the
                    # data handler (B03 _wcmdln/_environ identity contract).
                    data_ptr = self.handle_import_data(dll_name, imp.func_name)
                sym = f"{dll_name}.{imp.func_name}"
                self.global_data[imp.iat_address] = [sym, data_ptr]
                if data_ptr is not None:
                    self.mem_write(imp.iat_address, data_ptr.to_bytes(ptr_size, "little"))
                self.import_table.pop(old_sentinel, None)

        # FX-013-extended: a synthesized module may expose the API surface that
        # another handler module implements (kernelbase -> kernel32). Register
        # each handler-backed export under the implementing handler module, so
        # a guest that resolves the export by hand and calls its address
        # dispatches through that module's handler.
        if self.api:
            mod_base_name_no_ext = _normalize_mod_name(ntpath.basename(image.emu_path))
            handler_module_name = mod_base_name_no_ext
            if isinstance(getattr(image, "loader", None), SystemModuleDecoyLoader):
                handler_module_name = image.loader.api_handler_module or handler_module_name
            is_synthesized = image.source == "synthetic" or isinstance(
                getattr(image, "loader", None), SystemModuleDecoyLoader
            )
            for exp in image.exports:
                if not exp.name:
                    continue
                _api_mod, func_attrs = self.api.get_export_func_handler(handler_module_name, exp.name)
                if not func_attrs:
                    _api_mod, func_attrs = self.normalize_import_miss(handler_module_name, exp.name)
                symbol_module_name = handler_module_name
                if not func_attrs and is_synthesized:
                    # The module's own handler does not implement the export:
                    # resolve it through the same alias/host chain as an API
                    # call (kernelbase facade -> kernel32 handler).
                    _api_mod, func_attrs = self.get_api_handler(handler_module_name, exp.name)
                    handler_name = getattr(_api_mod, "name", None)
                    if func_attrs and isinstance(handler_name, str) and handler_name:
                        symbol_module_name = handler_name
                if func_attrs:
                    self.symbols[exp.address] = (symbol_module_name, exp.name)

        for entry in tuple(self.api_registry.entries.values()):
            if entry.export.kind == "data":
                self._initialize_api_data(entry)

        if image.sections and image.module_type != "shellcode":
            first_rva = min(section.virtual_address for section in image.sections)
            if first_rva:
                self.mem_protect(
                    mod.base,
                    (first_rva + self.page_size - 1) & ~(self.page_size - 1),
                    common.PERM_MEM_READ,
                    dep=dep,
                    win_protect=image_protection_for_emu_perms(common.PERM_MEM_READ),
                )
            page_perms: dict[int, int] = {}
            for section in image.sections:
                start = (mod.base + section.virtual_address) & ~(self.page_size - 1)
                end = (mod.base + section.virtual_address + section.virtual_size + self.page_size - 1) & ~(
                    self.page_size - 1
                )
                # Sections can be smaller than a page, and two sections can share a page. Merge the
                # permissions of each page, so that a small read-only section does not remove the
                # write or execute permission of an earlier section on the same page.
                for page in range(start, end, self.page_size):
                    page_perms[page] = page_perms.get(page, 0) | section.perms
            # Each mem_protect call of Unicorn splits a region, and the cost of a call grows with the
            # number of regions. So protect each range of adjacent pages with equal perms in one call.
            for start, length, perms in get_page_protection_runs(page_perms, self.page_size):
                try:
                    self.mem_protect(
                        start,
                        length,
                        perms,
                        dep=dep,
                        win_protect=image_protection_for_emu_perms(perms),
                    )
                except Exception:
                    logger.debug("failed to protect image section range at %#x", start, exc_info=True)

        if image.source in ("guest_pe", "guest_shellcode") and self.profiler and self.config.memory.strings:
            mod.loaded_data = bytes(self.mem_read(mod.base, mod.image_size))
            if image.regions:
                raw = image.regions[0].data
                self.profiler.strings["ansi"] = [a[1] for a in self.get_ansi_strings(raw)]
                self.profiler.strings["unicode"] = [u[1] for u in self.get_unicode_strings(raw)]
        process = self.get_current_process()
        is_before_peb = process is None or not process.is_peb_active
        if not self.is_kernel_mode and is_before_peb and mod.visible_in_peb and mod.is_dll():
            self.module_loader.shared_peb_modules.add(mod.base)
        self._add_module_to_current_peb(mod)
        return mod

    def get_system_root(self):
        """Get the path of the "SYSTEMROOT" environment variable."""
        sysroot = self.get_env().get("systemroot", "C:\\Windows")
        if not sysroot.endswith("\\"):
            sysroot += "\\"
        return sysroot

    def get_cd(self):
        """Get the path of the current directory of the current process."""
        state = self._get_process_state()
        if not state.cd:
            state.cd = state.env.get("cd", "C:\\WINDOWS\\system32")
            if not state.cd.endswith("\\"):
                state.cd += "\\"
        return state.cd

    def set_cd(self, cd):
        """Set the path of the current directory of the current process."""
        self._get_process_state().cd = cd

    def get_env(self):
        """Get the environment variables of the current process, by lower-case name."""
        return self._get_process_state().env

    def set_env(self, var, val):
        return self.get_env().update({var.lower(): val})

    def get_object_from_addr(self, addr):
        om = self.get_object_manager("object lookup by address")
        return om.get_object_from_addr(addr)

    def get_object_from_id(self, id):
        om = self.get_object_manager("object lookup by id")
        return om.get_object_from_id(id)

    def get_object_from_name(self, name):
        om = self.get_object_manager("object lookup by name")
        return om.get_object_from_name(name)

    def get_object_from_handle(self, handle):
        om = self.get_object_manager("object lookup by handle")
        return om.get_object_from_handle(handle)

    def get_object_handle(self, obj):
        om = self.get_object_manager("object handle lookup")
        obj = om.objects.get(obj.address)
        if obj:
            return om.new_handle(obj)

    def get_handle_table(self) -> HandleTable:
        """Get the handle table of the current process, or the table of the emulator if no process exists."""
        proc = self.get_current_process()
        return proc.handles if proc is not None else self.handles

    def _get_process_state(self) -> "objman.Process | WindowsEmulator":
        """Get the current process, or the emulator if no process exists, for the state that each process has."""
        proc = self.get_current_process()
        return proc if proc is not None else self

    def get_veh_handlers(self) -> list[int]:
        """Get the vectored exception handlers in the order that the dispatcher calls them."""
        return self.veh_registry.dispatch_order()

    def get_unhandled_exception_handler(self) -> int:
        """Get the filter that SetUnhandledExceptionFilter set for the current process, or 0."""
        return self._get_process_state().unhandled_exception_filter

    def get_function_tables(self) -> list[unwind.FunctionTable]:
        """Get the function tables that the current process registered at runtime."""
        return self._get_process_state().function_tables

    def get_heap_allocs(self) -> list[tuple[int, int, str]]:
        """Get the address, size and heap name of each block that heap_alloc returned in the current process."""
        return self._get_process_state().heap_allocs

    def get_pseudo_handle_object(self, handle: int) -> Any:
        """Get the current process for the pseudo handle -1, the current thread for -2, else None."""
        handle &= HANDLE_MASK
        if handle == CURRENT_PROCESS_HANDLE:
            return self.get_current_process()
        if handle == CURRENT_THREAD_HANDLE:
            return self.get_current_thread()
        return None

    def add_object(self, obj):
        om = self.get_object_manager("object registration")
        om.add_object(obj)

    def new_object(self, otype):
        om = self.get_object_manager("object creation")
        return om.new_object(otype)

    def create_process(self, path=None, cmdline=None, image=None, *, child=False, cd=""):
        """
        Create a process with one thread for the program in path, or in cmdline if path is empty.

        Add the process to child_processes if child is set, else to processes. An empty cd gives the process the
        current directory of the current process.

        Raises:
            IsADirectoryError: if the program path is a directory.
            FileSystemEmuError: if there is no program name, if the path ends in a separator, or if the configuration
                names a host file that does not exist.
        """
        om = self.get_object_manager("process creation")

        if path:
            file_path = path.strip().strip('"')
        else:
            # As CreateProcess does: a quoted program name ends at the next quote, any other at white space
            head = (cmdline or "").lstrip()
            if head.startswith('"'):
                file_path = head[1:].partition('"')[0]
            else:
                file_path = head.split(maxsplit=1)[0] if head else ""
        if not file_path:
            raise FileSystemEmuError("process creation needs a program name")
        if self.fileman.is_directory(file_path):
            raise IsADirectoryError(file_path)
        if file_path.endswith(("\\", "/")):
            raise FileSystemEmuError(f"process creation needs a file name: {file_path}")

        mod_data = self.get_module_data_from_emu_file(file_path)

        # Give the values to the constructor, because it writes them into the PEB ProcessParameters.
        p = om.add_object(objman.Process(self, path=file_path, cmdline=cmdline or "", cd=cd))

        # A program such as cmd.exe has placeholder data in the default config. It gets a synthetic module, so that
        # the guest sees an image base, for example to hollow the process.
        if mod_data and mod_data.startswith(b"MZ"):
            p.pe_data = mod_data
        else:
            new_mod = self.load_module_by_name(file_path, emu_path=file_path)
            p.pe = new_mod

        t = om.new_object(objman.Thread)
        t.process = p

        peb_addr = p.peb.address
        mod_base = 0
        if p.pe:
            mod_base = getattr(p.pe, "base", 0) or 0
        if mod_base:
            p.peb.object.ImageBaseAddress = mod_base
            p.peb.write_back()

        ep_addr = 0
        if p.pe:
            ep_addr = (getattr(p.pe, "base", 0) or 0) + (getattr(p.pe, "ep", 0) or 0)

        if t.ctx and self.get_arch() == _arch.ARCH_AMD64:
            t.ctx.Rip = 0
            t.ctx.Rcx = ep_addr
            t.ctx.Rdx = peb_addr
        elif t.ctx and self.get_arch() == _arch.ARCH_X86:
            t.ctx.Eip = 0
            t.ctx.Eax = ep_addr
            t.ctx.Ebx = peb_addr

        p.threads.append(t)

        if child:
            self.child_processes.append(p)
        else:
            self.processes.append(p)

        return p

    def register_child_fixture(self, path: str, data: bytes) -> None:
        """Register exact child bytes for model-only target resolution."""

        self.child_execution.register_fixture(path, data)

    def set_child_scheduler(
        self,
        scheduler: ChildSchedulerProtocol | None,
    ) -> None:
        """Install the sole production child queue/drain implementation.

        Args:
            scheduler: Scheduler implementing ``ChildSchedulerProtocol``, or
                ``None`` to keep child execution disabled while preserving
                model-only request recording.

        Returns:
            ``None``.

        Side effects:
            Replaces the engine's explicit scheduler reference. It does not
            create, load, enqueue, or execute a child.
        """

        self.child_scheduler = scheduler

    def set_child_dispatcher(
        self,
        dispatcher: ChildExecutionDispatcher | None,
    ) -> None:
        """Install the explicit dispatcher that owns child request handling.

        Args:
            dispatcher: Dispatcher implementing ``ChildExecutionDispatcher``,
                or ``None`` to use the legacy model-only registry path.

        Returns:
            ``None``.

        Side effects:
            Replaces the engine's dispatcher reference. It does not submit
            work, create processes, or execute child code.
        """

        self.child_dispatcher = dispatcher

    def create_child_execution_request(
        self,
        source_api: str,
        path: str | None,
        cmdline: str | None,
        cwd: str | None = None,
    ) -> ChildExecutionRequest:
        """Record a child request without queuing its entry point."""

        return self.child_execution.create_request(
            source_api=source_api,
            path=path,
            command_line=cmdline,
            cwd=cwd,
        )

    def request_process_execution(
        self,
        source_api: str,
        path: str | None,
        cmdline: str | None,
        cwd: str | None = None,
    ) -> tuple[
        Any | None,
        ChildExecutionRequest | ChildLaunchRequest,
        ProcessCreationResult,
    ]:
        """Request one child launch and return authoritative creation facts.

        Args:
            source_api: Process-launch API that produced the request.
            path: Explicit target path, if supplied by the API.
            cmdline: Complete command line supplied by the API.
            cwd: Optional emulated working directory.

        Returns:
            A tuple of the created process (or ``None``), its launch request,
            and a ``ProcessCreationResult``. The creation result is the sole
            source for success, reason, and created PID/TID decisions.

        Side effects:
            In the legacy registry path, creates a process only for an
            admitted request and marks that request's creation fields. In the
            dispatcher path, delegates all request handling to the dispatcher.
            It never creates a fallback process for an unavailable target.
        """

        if self.child_dispatcher is None:
            request = self.create_child_execution_request(
                source_api,
                path,
                cmdline,
                cwd=cwd,
            )
            if not request.eligible:
                return (
                    None,
                    request,
                    ProcessCreationResult(
                        process=None,
                        created_pid=None,
                        created_tid=None,
                        created=False,
                        reason=(
                            request.rejection_reason
                            or request.skip_reason
                            or "child_request_rejected"
                        ),
                    ),
                )

            process = self.create_process(
                path=path,
                cmdline=cmdline,
                child=True,
            )
            request.mark_process_created(process)
            thread = process.threads[0] if process.threads else None
            return (
                process,
                request,
                ProcessCreationResult(
                    process=process,
                    created_pid=int(getattr(process, "pid", process.id)),
                    created_tid=(
                        int(thread.tid) if thread is not None else None
                    ),
                    created=True,
                ),
            )

        parent = self.curr_process
        parent_thread = self.curr_thread
        parent_context = ParentExecutionSnapshot(
            root_sample_sha256=self._root_sample_sha256 or "",
            pid=int(getattr(parent, "pid", getattr(parent, "id", 0))),
            tid=(
                int(parent_thread.tid)
                if parent_thread is not None
                else None
            ),
            cwd=cwd or self.cd,
            budget=self._child_execution_budget(),
        )
        outcome = self.child_dispatcher.submit(
            ProcessLaunchSpec(
                source_api=source_api,
                target=path,
                command_line=cmdline or "",
                working_directory=cwd,
                creation_flags=0,
                requested_show_command=None,
            ),
            parent_context=parent_context,
        )
        return outcome.creation.process, outcome.request, outcome.creation

    def request_child_process(
        self,
        source_api: str,
        path: str | None,
        cmdline: str | None,
        cwd: str | None = None,
    ) -> tuple[Any, ChildExecutionRequest | ChildLaunchRequest]:
        """Return the legacy process/request pair for non-WinExec callers.

        Args:
            source_api: Process-launch API that owns the request.
            path: Explicit target path supplied by the API, if any.
            cmdline: Complete child command line, if any.
            cwd: Emulated working directory, if supplied by the API.

        Returns:
            The created process or a compatibility fallback process, together
            with the request evidence. Callers that require authoritative
            success and PID facts must use :meth:`request_process_execution`.

        Side effects:
            May create a process object in ``child_processes`` for legacy
            handler compatibility. It never adds a run to ``run_queue``; the
            fallback process must not be treated as evidence of creation.
        """

        process, request, creation = self.request_process_execution(
            source_api,
            path,
            cmdline,
            cwd=cwd,
        )
        if creation.created and process is not None:
            return process, request

        # Preserve the legacy API-handler object contract for unavailable or
        # rejected targets. The dispatcher report remains authoritative and
        # still records the request as unresolved/rejected.
        process = self.create_process(path=path, cmdline=cmdline, child=True)
        return process, request

    def _child_execution_budget(self) -> ExecutionBudget:
        """Build the parent/child execution budget from the v2.1.0 ``limits`` schema.

        A limit of 0 in the config means "disabled", which the local
        ``ExecutionBudget`` cannot represent: it requires a positive wall-clock
        and API-call limit. Disabled limits therefore become an infinite
        wall-clock time, the largest finite API-call count, and the local ``-1``
        instruction sentinel.
        """
        limits = self.config.limits
        per_run_time = float(limits.per_run_time)
        api_calls = int(limits.api_calls)
        instructions = int(limits.instructions)
        return ExecutionBudget(
            timeout_seconds=per_run_time if per_run_time > 0 else float("inf"),
            max_api_count=api_calls if api_calls > 0 else UNLIMITED_API_CALLS,
            max_instructions=-1 if instructions == 0 else instructions,
        )

    def create_thread(self, addr, ctx, proc_obj, name=None, *, is_suspended=False):
        """
        Create a thread of proc_obj and a run that starts at addr.

        Add the run to the queue, or to the suspended runs if is_suspended is set. Return the handle and the thread,
        or (0, None) if the queue has max_runs runs.
        """
        om = self.get_object_manager("thread creation")

        if len(self.run_queue) >= self.max_runs:
            return 0, None

        thread = om.new_object(objman.Thread)
        thread.process = proc_obj
        hnd = om.new_handle(thread)

        run = Run()
        run.type = RunType.THREAD
        run.name = name
        run.start_addr = addr
        run.instr_cnt = 0
        run.args = (ctx,)
        run.process_context = proc_obj
        run.thread = thread

        if not is_suspended:
            self.run_queue.append(run)
        else:
            thread.suspend_count = 1
            self.suspended_runs.append(run)

        return hnd, thread

    def resume_thread(self, thread):
        """Move the suspended run of thread to the queue. Return False if thread has no suspended run."""
        for r in self.suspended_runs:
            if r.thread == thread:
                _run = self.suspended_runs.pop(self.suspended_runs.index(r))
                self.run_queue.append(_run)
                return True
        return False

    def get_process_peb(self, process):
        return process.peb

    def add_callback(self, mod_name, func_name):
        """
        Get the address of an entry for the handler mod_name!func_name in the speakeasy_callbacks module.

        The guest calls such a function through a pointer that a handler wrote, for example in a function table or a
        vtable, not through an import.
        """
        module = self.get_mod_by_name("speakeasy_callbacks")
        if module is None:
            base, _ = self.get_valid_ranges(0x20000, addr=0x6E000000)
            image = ApiModuleLoader(
                name="speakeasy_callbacks",
                arch=self.arch,
                base=base,
                emu_path="speakeasy_callbacks.dll",
                signature_db=self.get_signature_db(),
            ).make_image()
            image.visible_in_peb = False
            module = self.load_image(image)
        entry = self.api_registry.dynamic(module, mod_name + "!" + func_name)
        entry.binding_module = mod_name
        entry.binding_name = func_name
        return entry.address

    def _synthetic_data_export_entry(self, handler: Any, func_name: str) -> ApiEntry | None:
        """Get the registry entry that holds the storage of an imported data export.

        A synthetic handler module gives each data export a slot of its image's
        ``.data`` section. That slot is the variable's storage: the data initializer
        writes at it, and the importer and the matching ``__p__*`` accessor must see
        the same address. Return None when the handler module has no such export, so
        the caller keeps the local allocation path of the handler.

        Args:
            handler: The API handler module that implements the data initializer.
            func_name: Name of the imported variable.
        """
        module_name = getattr(handler, "name", None)
        if not isinstance(module_name, str) or not module_name:
            return None
        module = self.get_mod_by_name(module_name)
        if module is None or module._image.source != "synthetic":
            return None
        entry = self.api_registry.lookup(module, func_name)
        if entry is None or entry.export.kind != "data":
            return None
        return entry

    def _initialize_api_data(self, entry):
        if not self.is_machine_ready:
            return
        if entry.dll == "ntoskrnl" and not self.is_kernel_mode:
            return
        if entry.initialized or entry.module._image.source != "synthetic":
            return
        mod, handler = self.api.get_data_export_handler(entry.dll, entry.name)
        if handler:
            address = self.api.call_data_func(mod, handler, entry.address)
            if address and address != entry.address:
                raise WindowsEmuError(f"data initializer for {entry.symbol} ignored its provided storage")
            if not address:
                return
        entry.initialized = True

    def resolve_export(self, module, reference, *, allow_dynamic=False, _seen=None, strict=False):
        reference = symbol_ref(reference)
        if isinstance(reference, int):
            if not 0 < reference <= 0xFFFF:
                return 0
        elif not isinstance(reference, str) or not reference or "\x00" in reference or len(reference) > 4096:
            return 0
        entry = self.api_registry.lookup(module, reference)
        if entry is None:
            if strict:
                return 0
            hooks = self.get_api_hooks(module.name, str(reference))
            eligible = allow_dynamic or self.config.apis.stubs or hooks
            # A function in the signature database resolves even if the module does not
            # export it, because other Windows builds export it.
            eligible = eligible or (isinstance(reference, str) and self.has_api_signature(module.name, reference))
            # A synthetic module without exports gives a dynamic entry for each name.
            eligible = eligible or (module._image.source == "synthetic" and not module.get_exports())
            if not eligible or module._image.source != "synthetic" or module is getattr(self, "container_image", None):
                return 0
            try:
                entry = self.api_registry.dynamic(module, reference)
            except WindowsEmuError:
                logger.debug("cannot allocate API entry for %s!%s", module.name, reference, exc_info=True)
                return 0
        forwarder = entry.export.forwarder
        if module._image.source != "synthetic":
            # Windows decides a forwarder by the export directory range in the mapped header.
            directory = self._get_export_directory(module)
            if directory is not None:
                rva, size = directory
                forwarder = (forwarder or "") if rva <= entry.address - module.base < rva + size else None
        if forwarder is not None:
            seen = set() if _seen is None else _seen
            key = (id(module), reference)
            if key in seen or len(seen) >= 32:
                return 0
            seen.add(key)
            target = forwarder
            if module._image.source != "synthetic":
                # Windows reads the forwarder from the mapped image when it resolves it.
                try:
                    target = self.read_mem_string(entry.address, 1, max_chars=4096)
                except Exception:
                    return 0
            if "." not in target:
                return 0
            dll, name = target.rsplit(".", 1)
            target_name = winemu.normalize_dll_name(module_name(dll))
            target_module = self.get_mod_by_name(target_name)
            if target_module is None:
                target_module = self.load_module_by_name(target_name)
            ref = int(name[1:]) if name.startswith("#") and name[1:].isdigit() else name
            return self.resolve_export(target_module, ref, _seen=seen, strict=True)
        if entry.export.kind == "data":
            self._initialize_api_data(entry)
        return entry.address

    def _get_export_directory(self, module):
        """Read the (RVA, size) of the export directory from the mapped header, or None if the read fails."""
        try:
            nt = module.base + struct.unpack("<I", self.mem_read(module.base + 0x3C, 4))[0]
            magic = struct.unpack("<H", self.mem_read(nt + 0x18, 2))[0]
            directories = nt + 0x18 + (112 if magic == 0x20B else 96)
            if not struct.unpack("<I", self.mem_read(directories - 4, 4))[0]:
                return 0, 0
            return struct.unpack("<II", self.mem_read(directories, 8))
        except (uc.UcError, struct.error):
            return None

    def get_import_host(self, dll: str, name: str | int) -> str:
        """
        Get the module that handles an import of dll!name.

        When the functions of an API set are in more than one module, use the first module that has a handler for the
        name.
        """
        hosts = winemu.get_dll_hosts(module_name(dll))
        if len(hosts) > 1 and isinstance(name, str):
            for host in hosts:
                if self.get_api_handler(host, name)[1] or self.api.get_data_export_handler(host, name)[1]:
                    return host
        return hosts[0]

    def _alloc_sentinel(self) -> int:
        """Allocate the next import-dispatch sentinel address in the reserved range.

        A sentinel is a guest-visible pointer, so its whole pointer-sized slot
        must stay inside ``[EMU_RESERVED, EMU_RESERVED_END)``. The reserved
        range has a fixed capacity; when it is exhausted this returns 0 and the
        allocation state does not change, so the sentinels that were already
        handed out keep their addresses.
        """
        ptr_size = self.get_ptr_size()
        addr = self._next_sentinel
        if addr < winemu.EMU_RESERVED or addr + ptr_size > winemu.EMU_RESERVED_END:
            return 0
        self._next_sentinel = addr + ptr_size
        return addr

    def _alloc_import_sentinel(self, mod_name: str, func_name: str) -> int:
        """Get or create the import sentinel that dispatches ``mod_name!func_name``.

        Returns 0 when the reserved sentinel range is exhausted. An entry that
        already exists for the same symbol keeps its address and is still
        returned, so exhaustion never moves an earlier sentinel.
        """
        mod_name = _normalize_mod_name(mod_name)
        for addr, (mod, fn) in self.import_table.items():
            if mod_name == mod and func_name == fn:
                return addr
        sentinel = self._alloc_sentinel()
        if not sentinel:
            return 0
        self.import_table[sentinel] = (mod_name, func_name)
        return sentinel

    def get_proc(self, mod_name, func_name):
        """
        Get a pointer for a supplied function name, similar to how the
        ``GetProcAddress`` API functions work.

        A function that a loaded API module exports resolves to its registry entry
        address (the synthetic stub that jumps to the API token). A name that the
        module does not export resolves to an import sentinel in the reserved range;
        the invalid fetch of the sentinel dispatches through the handler/signature
        path. An unknown module that ``modules.stubs`` allows keeps an empty API
        module, whose dynamic entries live in the module image; that fixed-size
        arena refuses with 0 once it is exhausted.
        """
        if isinstance(func_name, int):
            if not 0 < func_name <= 0xFFFF:
                return 0
            func_name = f"ordinal_{func_name}"
        host = self.get_import_host(mod_name, func_name)
        module = self.get_mod_by_name(host)
        if module is None:
            module = self.load_module_by_name(host)
        if module is not None:
            if (
                module._image.source == "synthetic"
                and not module.get_exports()
                and module is not getattr(self, "container_image", None)
            ):
                # A synthetic module without exports has no export table to
                # extend: each name becomes a dynamic entry of the module's
                # ``.dyn`` arena, as in upstream. When that arena is exhausted
                # the lookup refuses with 0 instead of falling back to an
                # import sentinel, which would report a callable address for an
                # entry that could not be allocated and defer the failure from
                # lookup time to call time.
                return self.resolve_export(module, func_name, allow_dynamic=True)
            address = self.resolve_export(module, func_name, allow_dynamic=False)
            if address:
                return address
        return self._alloc_import_sentinel(host, func_name)

    def _resolve_import_target(self, dll_name: str, func_name: str) -> int:
        """Resolve one import of an image to the address that the IAT receives.

        A real PE target executes its own code, so the IAT gets the export's mapped
        address, and a missing export leaves the slot unbound (0) as the Windows
        loader does. A handler/signature target (synthetic module or decoy) has no
        real code; a name import of it gets an import sentinel that dispatches
        through the engine (the FX-013 name contract), while an ordinal import
        follows the module's mapped export table exactly as
        ``GetProcAddress(ordinal)`` does.
        """
        host = self.get_import_host(dll_name, func_name)
        module = self.get_mod_by_name(host)
        if module is None:
            module = self.load_module_by_name(host)
        if module is not None:
            if isinstance(getattr(module, "loader", None), PeLoader):
                # A real guest PE executes its own code: bind the export's
                # mapped address, and leave the IAT slot untouched when the
                # export is missing (0), as the Windows loader does. Never
                # invent a handler sentinel for a guest PE.
                return self.resolve_export(module, func_name, strict=True)
            # FX-013 keeps name imports of handler-backed modules on dispatch
            # sentinels, but an ordinal import follows the mapped export table
            # exactly as GetProcAddress(ordinal) does.
            if (
                isinstance(func_name, str)
                and func_name.startswith("ordinal_")
                and func_name[8:].isdigit()
                and any(exp.ordinal == int(func_name[8:]) for exp in module.get_exports())
            ):
                return self.resolve_export(module, int(func_name[8:]))
        return self._alloc_import_sentinel(host, func_name)

    def handle_import_data(self, mod_name, sym, data_ptr=0):
        """
        Data that is imported (e.g. KeTickCount) is handled with an initializer function.
        Call it here if there is a handler for the imported variable.
        """
        module, func = self.api.get_data_export_handler(mod_name, sym)  # type: ignore[union-attr]
        if not func:
            alt_dll = winemu.normalize_dll_name(mod_name)
            if alt_dll:
                module, func = self.api.get_data_export_handler(alt_dll, sym)  # type: ignore[union-attr]
        if not func:
            module, func = self.api.get_export_func_handler(mod_name, sym)  # type: ignore[union-attr]
            if not func:
                module, func = self.normalize_import_miss(mod_name, sym)
            if not func:
                return None

            proc_addr = self.get_proc(mod_name, sym)
            return proc_addr

        data_addr = self.api.call_data_func(module, func, data_ptr)  # type: ignore[union-attr]
        return data_addr

    def normalize_import_miss(self, dll, name):
        """
        This function attempts to fold as many function handlers together as possible.
        For example, ntdll functions will be handled by the ntoskrnl handlers, multiple versions
        of the C runtime are folded together, and Zw/Nt functions use the same handler.
        """
        alt_imp_api = ""
        alt_imp_dll = ""
        mod, func_attrs = None, None

        # Handle ANSI vs UNICODE functions
        if name.endswith("A") or name.endswith("W"):
            alt_imp_api = name[:-1]

        # Handle Zw*/Nt* function overlap
        if dll.lower().startswith("ntoskrnl"):
            if name.startswith("Zw"):
                alt_imp_api = f"Nt{name[2:]}"
            elif name.startswith("Nt"):
                name = "Zw" + name[2:]
                alt_imp_api = f"Zw{name[2:]}"

        alt_imp_dll = winemu.normalize_dll_name(dll)

        # Bridge ntdll funcs to ntoskrnl if supported
        if dll.lower().startswith("ntdll"):
            alt_imp_dll = "ntoskrnl"
            mod, func_attrs = self.api.get_export_func_handler(alt_imp_dll, name)  # type: ignore[union-attr]
            if not func_attrs:
                if name.startswith("Zw"):
                    alt_imp_api = f"Nt{name[2:]}"
                elif name.startswith("Nt"):
                    name = "Zw" + name[2:]
                    alt_imp_api = f"Zw{name[2:]}"
                mod, func_attrs = self.api.get_export_func_handler(alt_imp_dll, alt_imp_api)  # type: ignore[union-attr]
            return mod, func_attrs

        if alt_imp_api:
            mod, func_attrs = self.api.get_export_func_handler(dll, alt_imp_api)  # type: ignore[union-attr]
        if not func_attrs and alt_imp_dll:
            mod, func_attrs = self.api.get_export_func_handler(alt_imp_dll, name)  # type: ignore[union-attr]
        if not func_attrs and alt_imp_dll and alt_imp_api:
            mod, func_attrs = self.api.get_export_func_handler(alt_imp_dll, alt_imp_api)  # type: ignore[union-attr]
        return mod, func_attrs

    def get_guest_module_file_data(self, guest_path: str) -> bytes | None:
        """Return image bytes for a file materialized in the emulated filesystem.

        ``LoadLibrary`` sees files a sample created, unpacked or opened, not
        only host-native paths and API-handler modules. Matching is exact
        (case-insensitive) against ``FileManager`` files; relative paths are
        resolved against ``config.process.current_dir`` the same way file I/O does.

        Returns ``None`` when no emulated file matches *guest_path*, and
        ``b""`` when the file exists but is empty. Configured ``filesystem``
        by-extension/default stubs are deliberately not treated as module
        files: they are I/O decoys, not images. The emulated-input-image alias
        used by file I/O is not reused here because loading the sample itself
        as a module would be wrong.

        LoadLibrary reads the whole on-disk image regardless of where the
        guest's shared ``File`` pointer currently sits, and the pointer is
        restored before returning: loading a module must not move a
        guest-observable file position.
        """
        if not guest_path:
            return None

        guest_file = self.fileman.get_file_from_path(guest_path)
        if guest_file is None or getattr(guest_file, "is_dir", False):
            return None
        # A configured by_ext/default filesystem stub is an I/O decoy, not an
        # image. get_module_data_from_emu_file() registers such a File on the
        # first lookup, so a later lookup must still reject it.
        if getattr(guest_file, "config", None) and getattr(guest_file.config, "mode", None):
            return None
        pointer = guest_file.tell()
        try:
            data = guest_file.get_contents()
        finally:
            guest_file.seek(0 if pointer is None else pointer, io.SEEK_SET)
        if not data:
            return b""
        return bytes(data)

    def get_module_by_handle(self, handle: int) -> RuntimeModule | None:
        """Return the loaded module addressed by an HMODULE/HINSTANCE value.

        Windows defines an HMODULE as the module's load base
        (``handle_semantics.HMODULE_HANDLE_APIS``), and this engine stores the
        mapped base in ``RuntimeModule.base``, so base equality is the module
        handle equivalence. ``0`` (NULL) and unknown handles return ``None``;
        no address inside the module is accepted because Windows does not
        define a module handle as an interior pointer.
        """
        if not handle:
            return None
        for mod in self.modules:
            if mod.base == handle:
                return mod
        return None

    def resolve_module_export(self, mod: RuntimeModule, func_name: str, *, _seen: set | None = None) -> int:
        """Return the guest-callable address of an export in *mod*.

        Modules loaded from a real PE image (``PeLoader``: native path,
        configured user module or a guest file) expose actual executable code;
        returning the export's mapped address lets the guest run the module's
        own code, matching Windows ``GetProcAddress`` semantics.

        Handler-backed modules (``ApiModuleLoader``) and decoy modules expose
        JIT stubs, so their exports resolve to an import sentinel that
        dispatches through the API implementation.

        A forwarder export is followed to the module that implements its
        destination, as Windows ``GetProcAddress`` does: a synthetic module can
        forward to a handler-backed module (``kernel32.GetTickCount``) or to a
        loaded PE. A cycle, a destination module that cannot be loaded, a
        destination export that is absent, or a chain longer than 32 hops
        resolves to 0, which is what Windows returns for a broken forwarder.

        Args:
            mod: the loaded module whose export table is queried.
            func_name: the exported name.
            _seen: the ``(id(module), reference)`` pairs already followed in
                this resolution chain, for cycle detection.

        Raises:
            KeyError: if *func_name* is not present in *mod*'s export table;
                callers must use their missing-export policy first. A missing
                destination export of a forwarder returns 0 instead.
        """
        entry = mod.get_export_by_name(func_name)
        if entry is None:
            raise KeyError(f"{mod.get_base_name()}!{func_name} is not exported")

        # Windows finds a forwarder by the export directory range in the mapped
        # header of a real image; a synthetic image records it in the entry.
        forwarder = entry.forwarder
        if mod._image.source != "synthetic":
            directory = self._get_export_directory(mod)
            if directory is not None:
                rva, size = directory
                forwarder = (forwarder or "") if rva <= entry.address - mod.base < rva + size else None
        if forwarder is not None:
            seen = set() if _seen is None else _seen
            key = (id(mod), func_name)
            if key in seen or len(seen) >= 32:
                return 0
            seen.add(key)
            target = forwarder
            if mod._image.source != "synthetic":
                # Windows reads the forwarder from the mapped image when it resolves it.
                try:
                    target = self.read_mem_string(entry.address, 1, max_chars=4096)
                except (uc.UcError, ValueError):
                    return 0
            return self._resolve_forwarded_export(target, seen)

        loader = getattr(mod, "loader", None)
        if isinstance(loader, PeLoader):
            return entry.address

        module_name, _ = os.path.splitext(mod.get_base_name())
        if isinstance(loader, SystemModuleDecoyLoader) and loader.api_handler_module:
            # FX-013-extended: the decoy's standard exports are implemented
            # by the declared handler module (kernelbase -> kernel32). Key the
            # dispatch sentinel to that module so calling it reaches the
            # handler instead of an unbacked "kernelbase" miss.
            module_name = loader.api_handler_module
        return self._alloc_import_sentinel(module_name, func_name)

    def _resolve_forwarded_export(self, forwarder: str, seen: set) -> int:
        """Resolve one forwarder target of ``resolve_module_export``.

        ``forwarder`` is the ``dll.export`` (or ``dll.#ordinal``) string of the
        export directory and ``seen`` holds the ``(id(module), reference)``
        pairs that the chain already followed. Returns 0 for a malformed
        string, a destination module or export that cannot be resolved, and for
        a cycle; those are the Windows ``GetProcAddress`` failure cases of a
        broken forwarder.
        """
        if not isinstance(forwarder, str) or "\x00" in forwarder or "." not in forwarder:
            return 0
        dll, name = forwarder.rsplit(".", 1)
        if not dll or not name:
            return 0
        target_name = winemu.normalize_dll_name(module_name(dll))
        target_module = self.get_mod_by_name(target_name)
        if target_module is None:
            try:
                target_module = self.load_module_by_name(target_name)
            except (OSError, ValueError, struct.error, uc.UcError, WindowsEmuError) as error:
                logger.debug("cannot load forwarder target %r: %s", forwarder, error, exc_info=True)
                return 0
        if target_module is None:
            return 0

        reference = int(name[1:]) if name.startswith("#") and name[1:].isdigit() else name
        if not isinstance(reference, str):
            # An ordinal target keeps GetProcAddress's ordinal policy: the
            # mapped export address, or 0 when the module has no such ordinal.
            return self.resolve_export(target_module, reference, _seen=seen, strict=True)
        if not isinstance(getattr(target_module, "loader", None), PeLoader):
            # GetProcAddress keys a handler-backed export's dispatch sentinel to
            # the module that implements it through the API-alias chain
            # (kernelbase facade -> kernel32 surface). The forwarded export must
            # resolve through the same module, or the guest's call would miss as
            # an unbacked export of the forwarding module.
            target_module = self._handler_sentinel_module(target_module, reference)
        try:
            return self.resolve_module_export(target_module, reference, _seen=seen)
        except KeyError:
            logger.debug("forwarder %r names an export the target module does not have", forwarder)
            return 0

    def _handler_sentinel_module(self, mod: RuntimeModule, func_name: str) -> RuntimeModule:
        """Return the module whose API handler implements ``mod!func_name``.

        Mirrors the handler-module lookup that ``kernel32.GetProcAddress`` uses
        for its non-``PeLoader`` branch: a synthesized module can expose an API
        surface that another handler module implements (kernelbase -> kernel32),
        and the dispatch sentinel must be keyed to that implementing module.
        This read-only lookup returns *mod* when *mod* has no handler, the
        handler is *mod* itself, or the implementing module does not expose the
        name.
        """
        base_name, _ = os.path.splitext(mod.get_base_name())
        handler, func_attrs = self.get_api_handler(base_name, func_name)
        handler_name = getattr(handler, "name", None)
        if handler is None or func_attrs is None or not isinstance(handler_name, str) or not handler_name:
            return mod
        if handler_name.lower() == base_name.lower():
            return mod
        handler_module = self.get_mod_by_name(handler_name)
        if handler_module is None or handler_module.get_export_by_name(func_name) is None:
            return mod
        return handler_module

    def handle_import_func(self, dll, name):
        """Dispatch an API import call intercepted at its sentinel address.

        The guest fetched the sentinel that ``get_proc`` returned. Resolve the
        call site and run the implementation of ``dll!name`` through the normal
        API dispatch (handler, user hook, signature or stub).
        """
        self.curr_mod = self.get_mod_from_addr(self.get_pc()) or self.curr_mod
        site, self._api_call_site = self._api_call_site, None
        call_pc = 0
        if site is not None and site[0] == self.get_pc() and self._last_block is not None:
            call_pc = self._get_last_instruction(*site[1])
        if not call_pc:
            # The sentinel fetch faults before a block hook runs at its address,
            # so use the block that transferred control to the sentinel.
            call_pc = self._get_sentinel_call_site()
        if not call_pc:
            call_pc = self.prev_pc
        if not call_pc:
            call_pc = self.get_ret_address()
        self.prev_pc = call_pc
        self.dispatch_api_call(_normalize_mod_name(dll), name)

    def _intercept_api_trap(self, access, address, size):
        """
        Record the native exit of a fetch from a return address or an API token, and fault other token accesses.

        Return True if the access is one of these, so that the other hooks for invalid memory do not run.
        """
        if self.emu_eng.mem_access.get(access) == common.INVALID_MEM_EXEC:
            if address in (self.return_hook, self.exit_hook) and self.curr_run:
                self._record_exit(RunReturn())
                return True
            if address == winemu.GUEST_CALLBACK_RETURN_ADDR and self.curr_run and self.curr_run.guest_callbacks:
                self._record_exit(CallbackReturn())
                return True
            entry = self.api_registry.traps.get(address)
            if entry is not None:
                self._record_exit(self._get_suspended_api_call(entry))
                return True
        if self.api_registry.overlaps_traps(address, size):
            kind = {
                common.INVALID_MEM_READ: "read",
                common.INVALID_MEM_WRITE: "write",
                common.INVALID_MEM_EXEC: "fetch",
            }.get(self.emu_eng.mem_access.get(access, common.INVALID_MEM_READ), "read")
            self._raise_memory_fault(address, kind)
            return True
        return False

    def _raise_memory_fault(self, address, access_type):
        """From a Unicorn hook: raise the access violation of an access to unmapped memory."""
        pc = address if access_type == "fetch" else self._get_faulting_instruction_pc(address, access_type)
        exception = cpu_exceptions.memory_fault(pc, address, access_type)
        self.raise_cpu_exception(exception, ErrorType(f"invalid_{access_type}"), access_type=access_type)
        return False

    def raise_cpu_exception(self, exception, error_type: ErrorType, **details):
        """From a Unicorn hook: record the exception as a native exit and stop Unicorn. Then the run loop sends it."""
        self._record_exit(RaisedCpuException(exception, error_type, **details))

    def _dispatch_cpu_exception(self, raised: RaisedCpuException) -> None:
        exception = raised.exception
        if raised.rax is not None:
            self.reg_write(
                _arch.AMD64_REG_RAX if self.get_arch() == _arch.ARCH_AMD64 else _arch.X86_REG_EAX, raised.rax
            )
        if raised.guard_page is not None:
            page, perms = raised.guard_page
            self.mem_protect(page, self.page_size, perms)
        self.set_pc(exception.pc)
        self.prev_pc = exception.pc
        faulting_address = exception.params[1] if raised.access_type else None
        error = guest_callbacks.CallbackError(
            raised.error_type,
            exception.address if faulting_address is None else faulting_address,
            raised.access_type,
            pc=exception.pc,
            interrupt_num=raised.interrupt_num,
        )
        if self._exceptions_dispatch_enabled() and self.dispatch_seh(
            exception.code, faulting_address, exception=exception, error=error
        ):
            return
        guest_callbacks.fail(self, error)

    def _can_raise_api_fault(self):
        return not self.is_kernel_mode and self._exceptions_dispatch_enabled()

    def _raise_api_fault(self, frame, access_type, address):
        """
        Raise an access violation in the caller of an API, because the handler of the API accessed a bad pointer.

        On Windows, the code of the API raises this access violation.

        Return False if the dispatch fails before it calls guest code.
        """
        params = (cpu_exceptions.ACCESS_CODES[access_type], address)
        try:
            dispatch_exception = self.exception_dispatcher().dispatch_exception
            fault = seh.raise_in_caller(self, ddk.STATUS_ACCESS_VIOLATION, 0, params, dispatch_exception)
            guest_callbacks.start(self, frame, fault)
        except guest_callbacks.CallbackError:
            self.get_current_run().guest_callbacks.remove(frame)
            return False
        return True

    def set_guard_pages(self, address, size, perms):
        """Remove all access from the pages. The first access restores perms and raises a guard page exception."""
        base = address & ~(self.page_size - 1)
        end = (address + size + self.page_size - 1) & ~(self.page_size - 1)
        for page in range(base, end, self.page_size):
            self.guard_pages[page] = perms
        self.mem_protect(base, end - base, common.PERM_MEM_NONE)

    def clear_guard_pages(self, address, size):
        for page in range(address & ~(self.page_size - 1), address + size, self.page_size):
            self.guard_pages.pop(page, None)

    def protect_pages(self, address, size, perms, guard=False):
        """
        Change the protection of a page-aligned range, as ``VirtualProtect`` does. ``guard`` sets guard pages.

        A ``MemMap`` has one protection, so each allocation that the range touches gets ``perms`` in the memory
        layout, also when the range covers only part of it.
        """
        self.mem_protect(address, size, perms)
        self.clear_guard_pages(address, size)
        if guard:
            self.set_guard_pages(address, size, perms)
        for mm in self.get_mem_maps():
            if mm.base < address + size and address < mm.base + mm.size:
                mm.prot = perms

    def _raise_protection_fault(self, address, access_type):
        """From a Unicorn hook: raise the exception for an access that page protections deny."""
        page = address & ~(self.page_size - 1)
        pc = address if access_type == "fetch" else self._get_faulting_instruction_pc(address, access_type)
        perms = self.guard_pages.pop(page, None)
        if perms is not None:
            exception = cpu_exceptions.memory_fault(
                pc, address, access_type, code=cpu_exceptions.STATUS_GUARD_PAGE_VIOLATION
            )
            self.raise_cpu_exception(
                exception, ErrorType.GUARD_PAGE_VIOLATION, access_type=access_type, guard_page=(page, perms)
            )
        else:
            exception = cpu_exceptions.memory_fault(pc, address, access_type)
            self.raise_cpu_exception(exception, ErrorType(f"invalid_protect_{access_type}"), access_type=access_type)
        return False

    def _step_had_no_effect(self, registers, debugger):
        """Get whether a single step did not change the registers, and no stop or exit is pending."""
        if debugger.has_pending_stop() or self._native_exit is not None:
            return False
        return self._pending_fault_stop is None and self.get_register_state() == registers

    def _stopped_at_hlt(self, deadline, last_executed, counted, debugger):
        """
        Get whether Unicorn stopped because the guest ran ``hlt``, which user mode cannot run.

        Unicorn stops without an error after ``hlt``, and also for other reasons. So report a ``hlt`` only if it ran:
        it is the last instruction that the accounting hook counted or that a debugger step ran, or nothing else
        stopped Unicorn.

        Unicorn has no better way to report ``hlt``. Of the x86 instructions, Unicorn hooks only ``in``, ``out``,
        ``syscall``, ``sysenter`` and ``cpuid``. ``hlt`` raises no interrupt, and a code hook on each instruction
        makes all emulation slower.
        """
        if self.is_kernel_mode or not self._exceptions_dispatch_enabled():
            return False
        if self._native_exit is not None:
            return False
        if deadline is not None and time.monotonic() >= deadline:
            return False
        if debugger is not None and debugger.has_pending_stop():
            return False
        pc = self.get_pc()
        if last_executed is not None:
            if last_executed != pc - 1:
                return False
        elif counted or (self.exit_event and self.exit_event.is_set()):
            return False
        try:
            return self.mem_read(pc - 1, 1) == b"\xf4"
        except uc.UcError:
            return False

    def _hook_invalid_instruction(self, emu):
        if not self._exceptions_dispatch_enabled():
            return False
        pc = self.get_pc()
        exception = cpu_exceptions.from_invalid_instruction(pc, self.mem_read(pc, 1))
        self.raise_cpu_exception(exception, self._get_invalid_instruction_error(pc))
        return False

    def _get_invalid_instruction_error(self, pc: int) -> ErrorType:
        """
        Get the error type of the instruction at pc, which Unicorn cannot run.

        Unicorn runs the VEX forms of the SSE instructions with 128-bit registers, but not the 256-bit forms, the
        EVEX forms or the instructions that AVX, AVX2 and FMA add. A valid VEX or EVEX instruction is an
        ``unsupported_cpu_feature``, because a CPU with AVX runs it.
        """
        engine = cs.Cs(cs.CS_ARCH_X86, self.disasm_eng.mode)
        engine.detail = True
        try:
            insn = next(engine.disasm(self.mem_read(pc, _arch.DISASM_SIZE), pc, 1), None)
        except uc.UcError:
            return ErrorType.INVALID_INSTRUCTION
        if insn and insn.opcode[0] in VEX_PREFIXES and insn.mnemonic not in LEGACY_VEX_PREFIX_MNEMONICS:
            return ErrorType.UNSUPPORTED_CPU_FEATURE
        return ErrorType.INVALID_INSTRUCTION

    def _hook_in_instruction(self, emu, port, size):
        rax = self.get_return_val()
        self.raise_cpu_exception(
            cpu_exceptions.privileged_instruction(self.get_pc()), ErrorType.PRIVILEGED_INSTRUCTION, rax=rax
        )
        return rax & 0xFFFFFFFF

    def _hook_out_instruction(self, emu, port, size, value):
        self.raise_cpu_exception(cpu_exceptions.privileged_instruction(self.get_pc()), ErrorType.PRIVILEGED_INSTRUCTION)

    def _get_suspended_api_call(self, entry: ApiEntry) -> SuspendedApiCall:
        sp = self.get_stack_ptr()
        try:
            return_address = self.mem_read(sp, self.ptr_size)
        except uc.UcError:
            return_address = None
        try:
            code = self.mem_read(entry.address, 16)
        except uc.UcError:
            code = None
        return SuspendedApiCall(entry, sp, return_address, code)

    def _handle_invalid_fetch(self, emu, address, size, value):
        """Handle a fetch from unmapped memory, a reserved sentinel or an import sentinel."""
        if address == self.return_hook or address == self.exit_hook:
            self._map_reserved_range()
            return True

        # A handler that returned with do_call_return can point PC at a reserved
        # control-flow sentinel. Consume the transition before Unicorn retries it.
        if self._dispatch_control_return():
            self._map_reserved_range()
            return True

        if address == DEFERRED_DISPATCH_ADDR:
            if self._run_deferred_protected_fault():
                # Map the reserved sentinel page before returning; otherwise
                # Unicorn retries the handled fetch and raises UC_ERR_MAP.
                self._map_reserved_range()
                return True

        # The fetch is the rest of an instruction that crosses into the next page. The fault at its start ends the run.
        if isinstance(self._native_exit, RunEnd) or self._pending_fault_stop is not None:
            return False

        # An import sentinel dispatches to the implementation of the import.
        impfunc = self.import_table.get(address)
        if impfunc:
            dll_name, func_name = impfunc
            # The sentinel lives in the reserved range, which stays unmapped so
            # that a return to the return/exit hooks faults. Unicorn 2.1.4 only
            # accepts a handled UC_MEM_FETCH_UNMAPPED callback (return True)
            # when the faulting range is mapped afterwards; otherwise
            # uc_emu_start raises UC_ERR_MAP. Map it for the dispatch and let
            # the deferred-work hook unmap it again at the return address.
            self._map_reserved_range()
            self.handle_import_func(dll_name, func_name)
            return True

        return self._raise_memory_fault(address, "fetch")

    def _resolve_module_offset(self, addr: int) -> tuple[str, int] | None:
        """Return the file name of the loaded module that contains addr and the offset of addr in it, or None."""
        mod = self.get_module_from_addr(addr)
        if mod:
            return mod.get_base_name() or mod.name or "unknown", addr - mod.base
        return None

    def _format_module_offset(self, addr: int) -> str:
        """Return 'module+0xoffset' for an address inside a loaded module, or the address in hex."""
        resolved = self._resolve_module_offset(addr)
        if resolved is None:
            return hex(addr)
        name, offset = resolved
        return f"{name}+{offset:#x}"

    def _get_image_module(self, mm: MemMap) -> RuntimeModule | None:
        """Get the module whose image is the memory map ``mm``, or None."""
        if not (mm.tag or "").startswith("emu.module."):
            return None
        mod: RuntimeModule
        for mod in self.modules:
            if mod.base == mm.base and mod.image_size > 0:
                return mod
        return None

    def _get_full_region_part(self, mm: MemMap) -> RegionPart:
        """Get the region of the full memory map: the full image for a module image."""
        mod = self._get_image_module(mm)
        if mod is None:
            return RegionPart(mm, mm.base, mm.size, mm.prot, mm.get_tag_without_address())
        return RegionPart(mm, mm.base, mm.size, mm.prot, "emu.module", mod.get_base_name() or mod.name)

    def get_region_parts(self, mm: MemMap) -> list[RegionPart]:
        """
        Get the regions of the report in the memory map ``mm``.

        A module image with sections gives one region for the headers and one region for each section.
        Another memory map gives one region.
        """
        mod = self._get_image_module(mm)
        if mod is None or not mod.sections:
            return [self._get_full_region_part(mm)]
        name = mod.get_base_name() or mod.name
        parts = []
        headers_size = min(sect.virtual_address for sect in mod.sections)
        if headers_size:
            parts.append(RegionPart(mm, mm.base, headers_size, common.PERM_MEM_READ, "emu.module", name, "headers"))
        for sect in mod.sections:
            parts.append(
                RegionPart(
                    mm, mm.base + sect.virtual_address, sect.virtual_size, sect.perms, "emu.module", name, sect.name
                )
            )
        return parts

    def _find_region_part(self, address: int) -> tuple[RegionPart, bool] | None:
        """
        Get the region of the report that contains ``address``, and whether ``address`` is in its range.

        For an address in a module image outside the headers and the sections, get the full image and False.
        Return None if ``address`` is not mapped.
        """
        mm = self.get_address_map(address)
        if mm is None:
            return None
        for part in self.get_region_parts(mm):
            if part.contains(address):
                return part, True
        return self._get_full_region_part(mm), False

    def get_region_part(self, address: int) -> RegionPart | None:
        """
        Get the region of the report that contains ``address``, or None if ``address`` is not mapped.

        For an address in a module image outside the headers and the sections, get the full image.
        """
        found = self._find_region_part(address)
        return found[0] if found else None

    def get_region_base(self, address: int) -> int | None:
        """Get the base of the region of the report that contains ``address``, or None if it is not mapped."""
        part = self.get_region_part(address)
        return part.base if part else None

    def _resolve_region_info(self, addr: int) -> RegionInfo | None:
        """Return a RegionInfo for the region containing addr, or None if unmapped."""
        part = self.get_region_part(addr)
        return part.to_region_info() if part else None

    def _find_nearby_regions(self, addr: int, count: int = 2) -> list[RegionInfo]:
        """Return up to ``count`` memory regions nearest to an unmapped address."""
        distances = []
        for mm in self.get_mem_maps():
            for part in self.get_region_parts(mm):
                end = part.base + part.size - 1
                if addr < part.base:
                    dist = part.base - addr
                elif addr > end:
                    dist = addr - end
                else:
                    continue
                distances.append((dist, part))
        distances.sort(key=lambda x: x[0])
        return [part.to_region_info() for _, part in distances[:count]]

    @staticmethod
    def _describe_region(region: RegionInfo) -> str:
        """Get a short name of a region for a summary, such as ``sample.exe .text`` or ``api.VirtualAlloc``."""
        if region.module:
            return f"{region.module} {region.section}" if region.section else region.module
        return region.tag or "untagged"

    def _build_context_summary(
        self,
        desc: str,
        pc: int,
        address: int,
        access_type: str | None,
        pc_module: str | None,
        address_region: RegionInfo | None,
        nearby_regions: list[RegionInfo] | None,
    ) -> str:
        """
        Build a one-line summary of an error for the report.

        Examples:
            read of unmapped 0x12345678 from sample.exe+0x8d14; nearest: heap [0x12340000-0x12340fff]
            write of 0x401500 from sample.exe+0x2000; in .text [0x401000-0x405fff]
            fetch at 0xdeadbeef from pc=0xdeadbeef
        """
        parts = []
        access_str = access_type or desc
        if address != pc:
            parts.append(f"{access_str} of {'unmapped ' if not address_region else ''}0x{address:x}")
        else:
            parts.append(f"{access_str} at 0x{address:x}")
        if pc_module:
            parts.append(f"from {pc_module}")
        else:
            parts.append(f"from pc=0x{pc:x}")
        if address_region:
            ri = address_region
            parts.append(f"in {self._describe_region(ri)} [0x{ri.base:x}-0x{ri.base + ri.size - 1:x}]")
        elif nearby_regions:
            nearest = nearby_regions[0]
            parts.append(
                f"nearest: {self._describe_region(nearest)} [0x{nearest.base:x}-0x{nearest.base + nearest.size - 1:x}]"
            )
        return "; ".join(parts)

    def _resolve_uc_map_fault(
        self,
        description: str,
        pc: int,
    ) -> tuple[int | None, str | None]:
        """Resolve the memory operand address for an Unicorn map fault.

        ``UcError(UC_ERR_MAP)`` does not expose the access address.  The
        register state and faulting instruction are still available, so this
        helper reconstructs a simple base/index/displacement operand.  It
        intentionally skips segmented operands, whose effective address needs
        the descriptor base that is not exposed by the public register state.

        Args:
            description: Exception string captured from the engine.
            pc: Program counter of the faulting instruction.

        Returns:
            A ``(fault_address, access_type)`` pair, or ``(None, None)`` when
            the instruction cannot be decoded safely.

        Side effects:
            Reads guest memory and registers. It does not map memory or alter
            execution state.
        """

        folded = description.casefold()
        if "uc_err_map" not in folded and "invalid memory mapping" not in folded:
            return None, None

        try:
            import capstone
            import capstone.x86_const as x86

            mode = (
                capstone.CS_MODE_64
                if self.get_arch() == _arch.ARCH_AMD64
                else capstone.CS_MODE_32
            )
            decoder = capstone.Cs(capstone.CS_ARCH_X86, mode)
            decoder.detail = True
            code = bytes(self.mem_read(pc, 16))
            instruction = next(decoder.disasm(code, pc, count=1))
            registers = self.get_register_state()
            mask = (1 << (self.get_ptr_size() * 8)) - 1
        except Exception:
            return None, None

        candidates: list[tuple[int, str | None]] = []
        try:
            for operand in instruction.operands:
                if operand.type != capstone.CS_OP_MEM:
                    continue
                if operand.mem.segment != x86.X86_REG_INVALID:
                    continue

                if operand.mem.base == x86.X86_REG_RIP:
                    base = instruction.address + instruction.size
                elif operand.mem.base == x86.X86_REG_INVALID:
                    base = 0
                else:
                    base_name = instruction.reg_name(operand.mem.base)
                    base = int(registers[base_name], 0)

                if operand.mem.index == x86.X86_REG_INVALID:
                    index = 0
                else:
                    index_name = instruction.reg_name(operand.mem.index)
                    index = int(registers[index_name], 0)

                address = (
                    base
                    + index * operand.mem.scale
                    + operand.mem.disp
                ) & mask
                access_type = None
                if operand.access & capstone.CS_AC_WRITE:
                    access_type = "write"
                elif operand.access & capstone.CS_AC_READ:
                    access_type = "read"
                candidates.append((address, access_type))
        except (KeyError, TypeError, ValueError):
            return None, None

        for address, access_type in candidates:
            if self._resolve_region_info(address) is None:
                return address, access_type
        return candidates[0] if candidates else (None, None)


    def _get_error_pc(self) -> int:
        """
        Get the pc of an error at the current position.

        While the code of an API call runs, the pc is the address of the call, the same as in its API event.
        """
        frame = self._active_api_frame
        if frame is not None and frame.call_pc is not None:
            return frame.call_pc
        return self.get_pc()

    def _get_limit_error_info(
        self, error_type: ErrorType, limit: int | None = None, last_api: str | None = None, loop: ApiLoop | None = None
    ) -> ErrorInfo:
        """Get the error of a limit that stopped the run of the current thread."""
        return ErrorInfo(
            type=error_type,
            pc=self._get_error_pc(),
            tid=self.curr_thread.tid if self.curr_thread else None,
            pid=self.curr_process.id if self.curr_process else None,
            limit=limit,
            last_api=last_api,
            loop=loop,
        )

    def get_error_info(
        self,
        desc: ErrorType | str,
        address: int,
        traceback: str | None = None,
        access_type: str | None = None,
        api_name: str | None = None,
        message: str | None = None,
        pc: int | None = None,
        pc_override: int | None = None,
    ) -> ErrorInfo:
        """
        Get the state of the emulator for an error.

        For an error at an API call, give the API name, and the return address as address.
        For an ``internal_error``, give the text of the Python exception as message.
        Give pc when the error is at an instruction other than the current pc. While the code of an API call runs, the
        current pc is the address of the call. ``pc_override`` is the local name for the same override.
        """
        run = self.get_current_run()
        if pc_override is not None:
            pc = pc_override
        if pc is None:
            pc = self._get_error_pc()

        try:
            mnem, op, instr = self.get_disasm(pc, _arch.DISASM_SIZE)
        except Exception:
            logger.debug("cannot disassemble 0x%x", pc, exc_info=True)
            instr = None

        registers = self.get_register_state()
        stack = self.get_stack_trace()
        pc_module, pc_offset = self._resolve_module_offset(pc) or (None, None)
        address_region = self._resolve_region_info(address)
        nearby_regions = self._find_nearby_regions(address) if not address_region else None
        tid = self.curr_thread.tid if self.curr_thread else None
        pid = self.curr_process.id if self.curr_process else None

        label_value = desc.value if isinstance(desc, ErrorType) else desc
        label = f"{label_value}: {message}" if message else label_value
        if api_name:
            summary = f"{label} {api_name} called from {self._format_module_offset(address)}"
        else:
            summary = self._build_context_summary(
                label,
                pc,
                address,
                access_type,
                self._format_module_offset(pc) if pc_module else None,
                address_region,
                nearby_regions,
            )

        # FX-016 diagnostics: record the fakeout-page marker and the last API
        # call's caller/return context alongside the fault registers. Failure
        # to collect diagnostics must not affect error reporting or dispatch.
        diagnostics = None
        try:
            last_api = getattr(self, "_last_api_trace", None)
            api_tail = getattr(self, "_api_trace_tail", None)
            diagnostics = api_trace_diagnostics.error_diagnostics(
                self,
                description=desc,
                address=address,
                access_type=access_type,
                pc=pc,
                pc_module=pc_module,
                last_api=last_api if isinstance(last_api, dict) else None,
                api_tail=list(api_tail) if isinstance(api_tail, list) else None,
            )
            marker = api_trace_diagnostics.summary_marker(
                desc,
                address,
                last_api if isinstance(last_api, dict) else None,
            )
            if marker:
                summary = f"{summary}; {marker}"
        except Exception:
            logger.debug("api trace diagnostic: error diagnostics failed", exc_info=True)
            diagnostics = None

        logger.error(
            "0x%x: %s: Caught error: %s\n  summary: %s\n  instr: %s\n  regs: %s",
            pc,
            run.get_label(),
            label,
            summary,
            instr,
            "  ".join(f"{k}={v:#x}" for k, v in registers.items()),
        )

        return ErrorInfo(
            type=desc,
            pc=pc,
            address=address,
            access_type=AccessType(access_type) if access_type else None,
            instruction=instr,
            registers=registers,
            stack=stack,
            pc_module=pc_module,
            pc_offset=pc_offset,
            address_region=address_region,
            nearby_regions=nearby_regions,
            tid=tid,
            pid=pid,
            context_summary=summary,
            traceback=traceback,
            message=message,
            diagnostics=diagnostics,
        )

    def get_api_handler(self, dll: str, name: str) -> tuple[Any, Any]:
        """
        Get the module and attributes of the handler for dll!name.

        If there is no handler for the name, try the names from get_handler_candidates. Return (None, None) if no
        handler is found.
        """
        for cand_dll, cand_name in ((dll, name), *api_resolution.get_handler_candidates(dll, name)):
            mod, func_attrs = self.api.get_export_func_handler(cand_dll, cand_name)
            if func_attrs:
                return mod, func_attrs
        return None, None

    def read_unicode_string(self, addr):
        """Read string data from a UNICODE_STRING object located at the specified address."""
        us = windefs.UNICODE_STRING(self.get_ptr_size())
        us = self.mem_cast(us, addr)

        return self.read_mem_string(us.Buffer, width=2)

    @staticmethod
    def format_api_arg(arg: ApiArg) -> str:
        """Render a single API argument the way it appears in the API trace."""
        text = arg.display
        if arg.type == ApiArgType.STR or (arg.name is None and arg.type == ApiArgType.TEXT):
            text = sigfmt.quote_string(text)
        return f"{arg.name}: {text}" if arg.name is not None else text

    def log_api(
        self,
        pc: int | None,
        imp_api: str,
        rv: int | None,
        args: list[ApiArg],
        *,
        run=None,
        return_address: int | None = None,
        argv: list[Any] | tuple[Any, ...] | None = None,
        display: list[str] | None = None,
        event_context: Any | None = None,
        observation: dict[str, Any] | None = None,
    ) -> None:
        """Log an API call and record it in the report.

        ``argv`` are the raw argument slots (used by the FX-016 provenance), ``event_context``
        is the handler context that may carry the FX-003/FX-004 observation, and ``observation``
        overrides that observation explicitly.
        """
        call_str = f"{imp_api}({', '.join(self.format_api_arg(arg) for arg in args)})"

        rv = self.get_machine_word(rv)
        rv_str = hex(rv) if rv is not None else None
        logger.info("%s: %s -> %s", hex(pc) if pc is not None else "?", repr(call_str), rv_str)

        # FX-016 diagnostics: persist the caller/return address, API-return registers,
        # calling module, bounded stack window and pointer mappings. A diagnostic failure
        # must never affect API handling or reporting.
        provenance = None
        try:
            provenance = api_trace_diagnostics.api_provenance(
                self,
                api_name=imp_api,
                argv=argv,
                ret=rv,
                call_pc=pc,
                display=display,
            )
            compact = api_trace_diagnostics.compact_trace(provenance)
            if compact is not None:
                tail = getattr(self, "_api_trace_tail", None)
                if not isinstance(tail, list):
                    tail = []
                    self._api_trace_tail = tail
                tail.append(compact)
                if len(tail) > api_trace_diagnostics.MAX_TAIL_ENTRIES:
                    del tail[: -api_trace_diagnostics.MAX_TAIL_ENTRIES]
                self._last_api_trace = compact
        except Exception:
            logger.debug("api trace diagnostic: provenance failed for %s", imp_api, exc_info=True)
            provenance = None

        if observation is None:
            if isinstance(event_context, dict):
                observation = event_context.get("_api_observation")
            else:
                observation = getattr(event_context, "_api_observation", None)
        if not isinstance(observation, dict):
            observation = None

        run = self.curr_run if run is None else run
        if self.profiler and run:
            tick = self.get_tick(run)
            thread = run.thread or self.curr_thread
            process = run.process_context or (thread.process if thread else None) or self.curr_process
            tid = thread.tid if thread else 0
            pid = process.id if process else 0
            pos = TracePosition(tick=tick, tid=tid, pid=pid, pc=pc)
            frame = self._active_api_frame
            if frame is not None and not any(item is frame for item in run.guest_callbacks):
                frame = None
            event = self.profiler.record_api_event(
                run,
                pos,
                imp_api,
                rv,
                args,
                deduplicate=frame is None,
                return_address=return_address,
                observation=observation,
                provenance=provenance,
            )
            if frame is not None:
                frame.event = event

    def get_signature_db(self) -> sigdb.SignatureDatabase:
        """Get the API signature database used to emulate imports without a handler."""
        if self._sigdb is None:
            self._sigdb = sigdb.get_default_database()
        return self._sigdb

    def _get_signature_arch(self) -> str:
        return sigdb.ARCH_X86 if self.get_arch() == _arch.ARCH_X86 else sigdb.ARCH_X64

    def _lookup_api_declaration(self, dll: str, name: str) -> sigdb.FuncSig | None:
        """
        Get the declaration of dll!name, also a declaration that lookup_api_signature rejects.

        Raises:
            WindowsEmuError: if the signature database fails.
        """
        db = self.get_signature_db()
        arch = self._get_signature_arch()
        try:
            sig = db.get_functions(dll, arch).get(name)
            if sig is None:
                alt_dll = winemu.normalize_dll_name(dll)
                if alt_dll.lower() != dll.lower():
                    sig = db.get_functions(alt_dll, arch).get(name)
            if sig is None:
                sig = self._lookup_api_set_declaration(dll, name)
        except Exception as exc:
            raise WindowsEmuError(f"signature provider failed for {dll}!{name}: {exc}") from exc
        return sig

    def _lookup_api_set_declaration(self, dll: str, name: str) -> sigdb.FuncSig | None:
        """Get a declaration that the signature database has under an API set whose host is ``dll``."""
        db = self.get_signature_db()
        arch = self._get_signature_arch()
        sig = db.lookup(dll, name, arch)
        if sig is None or not sig.dll.lower().startswith(("api-ms-win-", "ext-ms-win-")):
            return None
        if winemu.normalize_dll_name(sig.dll).lower() != winemu.normalize_dll_name(dll).lower():
            return None
        return db.get_functions(sig.dll, arch).get(name)

    def lookup_api_signature(self, dll: str, name: str) -> sigdb.FuncSig | None:
        sig = self._lookup_api_declaration(dll, name)
        if sig is not None and not sig.supports_emulation(self.get_ptr_size()):
            logger.debug("signature for %s.%s cannot be emulated safely", dll, name)
            return None
        return sig

    def _can_stub_unknown_api(self, dll: str, name: str) -> bool:
        # A function with a declaration that the emulator cannot use is not
        # unknown, so it does not get a stub. The local functions_always_exist
        # extension treats every unresolved import as an existing stub too.
        stubs = self.config.apis.stubs or self.config.modules.functions_always_exist
        return stubs and self._lookup_api_declaration(dll, name) is None

    def has_api_signature(self, dll: str, name: str) -> bool:
        return self.lookup_api_signature(dll, name) is not None

    def get_handler_signature(self, dll: str, name: str, argc: int) -> sigdb.FuncSig | None:
        """
        Get the signature that names the arguments of a call to a handler.

        Return None if the function is unknown or variadic, or if its declaration does not use exactly the ``argc``
        slots that the handler reads.
        """
        try:
            sig = self.get_signature_db().lookup(dll, name, self._get_signature_arch())
        except Exception:
            logger.debug("handler argument signature unavailable for %s!%s", dll, name, exc_info=True)
            return None
        if sig is None or sig.skip or sig.variadic or sig.slot_count(self.get_ptr_size()) != argc:
            return None
        return sig

    def get_signature_formatter(self) -> sigfmt.ArgFormatter:
        """
        Get the formatter that renders API arguments from their signatures for the report.

        The formatter renders strings, enums, flags and struct contents.
        """
        if self._sigfmt is None:
            xmm = (_arch.X86_REG_XMM0, _arch.X86_REG_XMM1, _arch.X86_REG_XMM2, _arch.X86_REG_XMM3)
            self._sigfmt = sigfmt.ArgFormatter(
                self.get_signature_db(),
                self.get_ptr_size(),
                self.mem_read,
                read_xmm=lambda index: self.reg_read(xmm[index]),
            )
        return self._sigfmt

    def _render_signature_arg(self, param: sigdb.ParamSig, value: int, index: int) -> sigfmt.RenderedArg:
        try:
            return self.get_signature_formatter().render_param(param, value, index)
        except Exception:
            logger.debug("failed to render %s (%s)", param.name, param.code, exc_info=True)
            return sigfmt.RenderedArg(hex(value), ApiArgType.INT)

    def _render_signature_args(self, sig: sigdb.FuncSig, argv: list[int]) -> list[sigfmt.RenderedArg]:
        values = sig.values_from_slots(argv, self.get_ptr_size())
        return [self._render_signature_arg(param, value, i) for i, (param, value) in enumerate(zip(sig.params, values))]

    # The maximum number of bytes that the emulator zeroes for one Out parameter
    MAX_OUT_ZERO_FILL = 0x1000

    def _read_uint_for_signature(self, addr: int, size: int) -> int | None:
        try:
            return int.from_bytes(self.mem_read(addr, size), "little")
        except Exception:
            return None

    def _get_writable_size(self, addr: int, size: int) -> int:
        """Get the number of bytes at ``addr``, up to ``size``, that the guest can write without a fault."""
        write = self.emu_eng.perms[common.PERM_MEM_WRITE]
        regions = self.get_mem_regions()
        end = addr
        while end < addr + size:
            last = next((last for first, last, perms in regions if first <= end <= last and perms & write), None)
            if last is None:
                break
            end = last + 1
        return min(end, addr + size) - addr

    def _zero_fill_out_params(self, sig: sigdb.FuncSig, values: list[int], ptr_size: int) -> None:
        """
        Zero the buffers of the Out parameters that are not also In parameters.

        A call from a signature returns success but writes no data. So the caller reads zeros, such as empty strings,
        NULL handles and zero counts, and not old stack data. A string buffer gets only a terminator. The fill is at
        most MAX_OUT_ZERO_FILL bytes, and it stops at the first page that the guest cannot write, because the size
        can come from a count that the guest gives.
        """
        db = self.get_signature_db()
        for index, (param, value) in enumerate(zip(sig.params, values)):
            if not param.is_out or param.is_in or not value:
                continue
            size = sigdb.out_buffer_size(sig, index, values, ptr_size, db.lookup_struct, self._read_uint_for_signature)
            if not size or size < 0:
                continue
            if param.kind in sigdb.STRING_KINDS or (param.kind == "a" and param.pointee in ("u8", "u16")):
                # An empty string needs only its terminator. The database codes PSTR and PWSTR Out buffers as
                # a:u8 and a:u16, so a byte or WCHAR buffer also gets only one zero element.
                size = min(size, param.elem_size(ptr_size) or 1)
            # mem_write ignores page protection, so stop before a page that the guest cannot write
            size = self._get_writable_size(value, min(size, self.MAX_OUT_ZERO_FILL))
            if size:
                self.mem_write(value, b"\x00" * size)

    def _default_return_for_signature(self, sig: sigdb.FuncSig) -> int | None:
        """Get a plausible return value for a call that is emulated from its signature.

        BOOL returns are semantic, not just typed: a predicate and a status change both
        spell ``b``/``B``, but neither may be claimed when the emulator has no state behind
        it. Both classes therefore return FALSE (``bool_semantics``).

        Handle returns are domain-sensitive: only the kernel-object domain may receive a
        fresh ``ObjectManager.allocate_handle()`` value; data, GUI, module and unknown
        domains return NULL rather than a fabricated kernel handle.
        """
        kind = sig.ret_kind
        if kind == "v":
            return None
        if kind in sigdb.BOOL_KINDS:
            return bool_semantics.default_bool_return(sig)
        if kind == "h":
            allocate = self.om.allocate_handle if self.om is not None else None
            rv = handle_semantics.signature_handle_return(sig.dll, sig.name, allocate)
            if rv == 0:
                logger.debug("%s: %s return domain is not a kernel handle; returning NULL", sig.name, sig.dll)
            return rv
        # For status codes (HRESULT, NTSTATUS, WIN32_ERROR), 0 is success. For
        # counts and pointers, 0 means no data.
        return 0

    def _apply_signature_last_error(self, sig: sigdb.FuncSig, rv: int | None) -> None:
        """Set LastError for a call emulated from its signature alone.

        BOOL signatures follow the signature-library policy: a ``status_bool`` returning
        FALSE reports ``ERROR_CALL_NOT_IMPLEMENTED`` because the emulator did not perform
        the state change; a ``predicate_bool`` leaves LastError untouched. All other
        signatures keep the previous behaviour: APIs that declare SetLastError report
        ERROR_SUCCESS for the "nothing happened" value.
        """
        set_last_error = getattr(self, "set_last_error", None)
        if not set_last_error:
            return
        if sig.ret_kind in sigdb.BOOL_KINDS:
            if rv == 0:
                error = bool_semantics.last_error_for_default(sig)
                if error is not None:
                    set_last_error(error)
            return
        if sig.set_last_error:
            set_last_error(0)

    def _handle_api_from_signature(self, dll: str, name: str, sig: sigdb.FuncSig, call_pc: int | None) -> int | None:
        """
        Run an API that has no handler from its signature.

        Read the arguments, log the call, zero the Out buffers, and return a success value for the return type. Remove
        the arguments from the stack as the calling convention requires.
        """
        imp_api = f"{dll}.{name}"
        ptr_size = self.get_ptr_size()
        conv = _arch.CALL_CONV_CDECL if sig.conv == sigdb.CONV_CDECL else _arch.CALL_CONV_STDCALL
        argc = sig.slot_count(ptr_size)

        argv = self.get_func_argv(conv, argc)
        values = sig.values_from_slots(argv, ptr_size)
        args = sigfmt.get_call_args(sig, ptr_size, self._render_signature_args(sig, argv), argv)

        rv = self._default_return_for_signature(sig)
        logger.debug(
            "%s: no handler for %s; emulating from %s signature (%d params, %s, argc=%d)",
            hex(call_pc) if call_pc is not None else "?",
            imp_api,
            sig.source,
            len(sig.params),
            sig.conv,
            argc,
        )

        self._zero_fill_out_params(sig, values, ptr_size)
        self._apply_signature_last_error(sig, rv)

        # FX-004 diagnostics: a signature-emulated unload API (LdrUnloadDll) gets
        # an explicit observation (arguments, return value, module table). Other
        # signature-emulated APIs return None and report as before.
        observation = module_trace_diagnostics.signature_call_observation(self, dll, name, sig, argv, rv, call_pc)
        event_context = {"func_name": imp_api, "_api_observation": observation} if observation is not None else None

        ret = self.get_ret_address()
        self.log_api(
            call_pc,
            imp_api,
            rv,
            args,
            return_address=ret,
            argv=argv,
            event_context=event_context,
        )
        self.do_call_return(argc, ret, rv, conv=conv)
        self._dispatch_control_return()
        if not self.is_run_complete:
            self.enable_deferred_work_hook()
        return rv

    def get_api_args(self) -> list[ApiArg]:
        """
        Get the arguments of the hooked API call in progress, as the report shows them.

        An API hook calls this after it calls the original handler to see the
        values the handler decoded, such as the strings behind pointer arguments.
        Outside an API hook the list is empty.
        """
        return self.api_ctx.args.get_report_args()

    def resolve_api_implementation(self, dll: str, name: str) -> api_resolution.ApiImplementation:
        """
        Find the code to run for dll!name.

        Look in this order: a handler, user hooks, the signature database, a stub.
        """
        mod, func_attrs = self.get_api_handler(dll, name)
        if func_attrs:
            handler_name, func, argc, conv, _ = func_attrs
            if name.startswith("ordinal_"):
                name = handler_name
            return api_resolution.HandlerImplementation(mod, name, func, argc, conv)
        hooks = self.get_api_hooks(dll, name)
        if hooks:
            return api_resolution.UserHookImplementation(hooks)
        sig = self.lookup_api_signature(dll, name)
        if sig is not None:
            return api_resolution.SignatureImplementation(sig)
        if self._can_stub_unknown_api(dll, name):
            return api_resolution.StubImplementation()
        return api_resolution.UnsupportedImplementation()

    def dispatch_api_call(self, dll: str, name: str) -> None:
        """
        Run the code for the API that the guest called.

        End the run if the code changed the stack pointer but did not return.
        """
        frame = GuestCallbackFrame(self.get_stack_ptr(), self.get_ret_address(), call_pc=self.prev_pc or None)
        previous = self._active_api_frame
        self._active_api_frame = frame
        origin_run = self.curr_run
        entry_pc = self.get_pc()
        try:
            self._call_api_implementation(dll, name, frame)
            if (
                origin_run is not None
                and self.curr_run is origin_run
                and not self.is_run_complete
                and not self.is_emu_complete
                and self.get_pc() == entry_pc
                and self.get_stack_ptr() != frame.stack_pointer
                and self._native_exit is None
                and not origin_run.guest_callbacks
            ):
                origin_run.error = self.get_error_info(ErrorType.API_HANDLER_DID_NOT_RETURN, entry_pc)
                origin_run.error.api_name = f"{dll}.{name}"
                logger.error("API handler %s.%s changed SP without returning", dll, name)
                self.end_run_on_fault()
        except uc.UcError as e:
            # The API code accessed unmapped memory when it read the arguments or wrote the results
            kind, address, access_type, _ = guest_callbacks.get_handler_fault(self, e, entry_pc)
            if access_type is None or self._should_stop_on_faults:
                raise
            logger.error("0x%x: %s in the call of %s.%s", entry_pc, kind.value, dll, name)
            guest_callbacks.fail(self, guest_callbacks.CallbackError(kind, address, access_type))
        finally:
            self._active_api_frame = previous

    def _call_api_implementation(self, dll: str, name: str, frame: GuestCallbackFrame) -> None:
        """Find the code for the API and run it. Then check the API count limit."""
        ret = self.get_ret_address()
        call = _ApiCallState(
            dll=dll,
            name=name,
            frame=frame,
            run=self.curr_run,
            pc=self.get_pc(),
            sp=self.get_stack_ptr(),
            return_address=ret,
            call_pc=frame.call_pc,
        )
        impl = self.resolve_api_implementation(dll, name)
        api_name = call.api_name
        match impl:
            case api_resolution.HandlerImplementation():
                api_name = f"{dll}.{impl.name}"
                if not self._handle_api_with_handler(call, impl):
                    return
            case api_resolution.UserHookImplementation():
                self._handle_api_hook(call, impl.hooks)
            case api_resolution.SignatureImplementation():
                self._handle_api_from_signature(dll, name, impl.sig, call.call_pc)
            case api_resolution.StubImplementation():
                self._handle_api_stub(call)
            case api_resolution.UnsupportedImplementation():
                self._handle_unsupported_api(call)
        self._check_api_limit(call.run, api_name)

    def _handle_api_with_handler(self, call: _ApiCallState, impl: api_resolution.HandlerImplementation) -> bool:
        """
        Run the handler of the API, or the user hooks for the API.

        Return False if the handler failed, and the run ended or a guest exception started.
        """
        dll, name = call.dll, impl.name
        imp_api = f"{dll}.{name}"
        frame = call.frame
        frame.argc = impl.argc
        frame.convention = impl.conv
        argv = self.get_func_argv(impl.conv, impl.argc)

        # Render the arguments before the handler runs, while the memory
        # they point to still holds what the caller passed.
        sig = self.get_handler_signature(dll, name, impl.argc)
        if sig is not None:
            rendered = self._render_signature_args(sig, argv)
            args = HandlerArgs.from_signature(sig, self.get_ptr_size(), rendered, argv)
        else:
            args = HandlerArgs.from_slots(argv)
        ctx = ApiContext(func_name=imp_api, args=args)

        hooks = self.get_api_hooks(dll, name)
        if hooks:
            hooked_func = MethodType(impl.func, impl.module)
            orig = lambda args: hooked_func(self, args, ctx)  # noqa
            # All hooks run in the order of get_api_hooks. The return value of the last hook is the result.
            prev_ctx, self.api_ctx = self.api_ctx, ctx
            try:
                for hook in hooks:
                    rv = hook.cb(hook.emu, imp_api, orig, argv)
            finally:
                self.api_ctx = prev_ctx
        else:
            try:
                rv = self.api.call_api_func(impl.module, impl.func, argv, ctx=ctx)
            except Exception as e:
                if self._should_stop_on_faults:
                    # _execute_runs reports the fault to the debugger before it ends the run.
                    raise
                desc, address, access_type, message = guest_callbacks.get_handler_fault(self, e, self.get_pc())
                if access_type and self._can_raise_api_fault():
                    self.log_api(
                        call.call_pc,
                        imp_api,
                        None,
                        ctx.args.get_report_args(),
                        run=call.run,
                        return_address=call.return_address,
                    )
                    if self._raise_api_fault(frame, access_type, address):
                        return False
                logger.exception("0x%x: Error while calling API handler for %s:", call.return_address, imp_api)
                error = self.get_error_info(
                    desc, address, traceback=traceback.format_exc(), access_type=access_type, message=message
                )
                attach_handler_observation(error, ctx)
                self.end_run(error)
                return False

        if isinstance(rv, Generator):
            rv = guest_callbacks.start_api_handler(self, frame, rv)
        elif isinstance(rv, guest_callbacks.Resume):
            guest_callbacks.transfer(self, rv.context)
            rv = None

        ret = self.get_ret_address()
        pc = self.get_pc()
        frame.result = rv
        mm = self.get_address_map(ret)

        # The return address is in memory that VirtualAlloc or ZwAllocateVirtualMemory allocated.
        if mm and mm.tag and any(name in mm.tag.lower() for name in ("virtualalloc", "allocatevirtualmemory")):
            self._fire_dyn_code_hooks(ret)

        self.log_api(
            call.call_pc,
            imp_api,
            rv,
            ctx.args.get_report_args(),
            run=call.run,
            return_address=call.return_address,
            argv=argv,
            event_context=ctx,
        )

        if (
            self.curr_run is call.run
            and not self.is_run_complete
            and ret == call.return_address
            and pc == call.pc
            and self.get_stack_ptr() == call.sp
        ):
            self.do_call_return(impl.argc, ret, rv, conv=impl.conv)
            self._dispatch_control_return()

        if not self.is_run_complete:
            self.enable_deferred_work_hook()
        return True

    def _handle_api_hook(self, call: _ApiCallState, hooks: list[common.ApiHook]) -> None:
        """
        Run the user hook of an API that has no handler.

        The hook can give the argument count and the calling convention, but a wildcard hook
        (module ``*``, API ``*``, argc 0, stdcall) does not know them. When the signature
        database declares the API, the declared ``argc``/``call_conv`` win, and the hook gets
        an ``orig`` callable that performs the engine's own signature emulation (zero-filled
        Out parameters and the signature-policy default return value).
        """
        if len(hooks) > 1:
            logger.warning(
                "%d hooks registered for unsupported API %s; only the last registered hook will be called",
                len(hooks),
                call.api_name,
            )
        hook = hooks[-1]
        sig = self.lookup_api_signature(call.dll, call.name)
        ptr_size = self.get_ptr_size()
        if sig is not None:
            conv = _arch.CALL_CONV_CDECL if sig.conv == sigdb.CONV_CDECL else _arch.CALL_CONV_STDCALL
            argc = sig.slot_count(ptr_size)
        else:
            if hook.call_conv is None:
                hook.call_conv = _arch.CALL_CONV_STDCALL
            conv = hook.call_conv
            argc = hook.argc

        argv = self.get_func_argv(conv, argc)
        call.frame.argc = argc
        call.frame.convention = conv

        orig = None
        if sig is not None:
            # Default implementation for the hook == what the engine would have
            # done on its own: zero-fill the out parameters and return the
            # signature-policy default value.
            values = sig.values_from_slots(argv, ptr_size)
            self._zero_fill_out_params(sig, values, ptr_size)
            if sig.ret_kind in sigdb.BOOL_KINDS:
                # BOOL defaults have no allocation side effects, so the value and
                # its LastError policy are applied eagerly.
                default_rv = self._default_return_for_signature(sig)
                self._apply_signature_last_error(sig, default_rv)

                def orig(args, _rv=default_rv):
                    return _rv

            else:
                self._apply_signature_last_error(sig, None)

                def orig(args, _sig=sig):
                    return self._default_return_for_signature(_sig)

        rv = hook.cb(hook.emu, call.api_name, orig, argv)
        call.frame.result = rv
        ret = self.get_ret_address()
        # FX-004 diagnostics: the wildcard-hook path is how the sample pipeline
        # dispatches handler-less APIs, so the unload observation must be
        # attached here too (None for other APIs).
        observation = module_trace_diagnostics.signature_call_observation(
            self, call.dll, call.name, sig, argv, rv, call.call_pc
        )
        event_context = (
            {"func_name": call.api_name, "_api_observation": observation} if observation is not None else None
        )
        self.log_api(
            call.call_pc,
            call.api_name,
            rv,
            sigfmt.get_slot_args(argv),
            run=call.run,
            return_address=call.return_address,
            argv=argv,
            event_context=event_context,
        )
        if (
            self.curr_run is call.run
            and self.get_pc() == call.pc
            and ret == call.return_address
            and self.get_stack_ptr() == call.sp
        ):
            self.do_call_return(argc, ret, rv, conv=conv)
            self._dispatch_control_return()
        if not self.is_run_complete:
            self.enable_deferred_work_hook()

    def _handle_api_stub(self, call: _ApiCallState) -> None:
        """
        Return 1 from an unknown API so that execution can continue.

        The argument count and the calling convention are not known, so guess stdcall with four arguments.
        """
        logger.warning("Stubbed unknown API %s with return 1", call.api_name)
        conv = _arch.CALL_CONV_STDCALL
        argc = 4
        argv = self.get_func_argv(conv, argc)
        call.frame.argc = argc
        call.frame.convention = conv
        call.frame.result = 1
        self.log_api(
            call.call_pc,
            call.api_name,
            1,
            sigfmt.get_slot_args(argv),
            run=call.run,
            return_address=call.return_address,
            argv=argv,
        )
        self.do_call_return(argc, call.return_address, 1, conv=conv)
        self._dispatch_control_return()

    def _handle_unsupported_api(self, call: _ApiCallState) -> None:
        """End the run with an ``unsupported_api`` error."""
        error = self.get_error_info(ErrorType.UNSUPPORTED_API, call.return_address, api_name=call.api_name)
        logger.error("Unsupported API: %s (ret: 0x%x)", call.api_name, call.return_address)
        self.log_api(call.call_pc, call.api_name, None, [], run=call.run, return_address=call.return_address)
        error.api_name = call.api_name
        self.end_run(error)

    def _check_api_limit(self, origin_run, imp_api):
        run = self.get_current_run()
        if run is not origin_run or not run or self.end_requested:
            return
        limit = self.config.limits.api_calls
        if limit > 0 and run.get_api_count() > limit:
            logger.info("* Maximum number of API calls reached. Stopping current run.")
            self.end_run(
                self._get_limit_error_info(
                    ErrorType.API_CALL_LIMIT,
                    limit=limit,
                    last_api=imp_api,
                )
            )
            return
        limit = self.config.limits.api_loop_calls
        if limit and run.api_loop.calls >= limit:
            logger.info("* %d API calls with no new call site. Stopping current run.", limit)
            self.end_run(
                self._get_limit_error_info(
                    ErrorType.API_LOOP_LIMIT,
                    limit=limit,
                    last_api=imp_api,
                    loop=run.api_loop.get_loop(),
                )
            )

    def start_guest_callback(self, frame, function, args, sp=None):
        """Call function with args as a guest callback of frame, on the stack of frame or below sp."""
        if frame.saved_registers is None:
            registers = NONVOLATILE_AMD64 if self.get_arch() == _arch.ARCH_AMD64 else NONVOLATILE_X86
            frame.saved_registers = tuple((register, self.reg_read(register)) for register in registers)
        frame.function = function
        sp = frame.stack_pointer if sp is None else sp
        if self.ptr_size == 8:
            # Win64 callees expect RSP + 8 to be 16-byte aligned at entry, and
            # each argument after the fourth uses one 8-byte stack slot.
            sp &= ~0xF
            if max(len(args) - 4, 0) % 2:
                sp -= 8
        self.set_func_args(sp, winemu.GUEST_CALLBACK_RETURN_ADDR, *args, conv=_arch.CALL_CONV_STDCALL)
        self.set_pc(function)

    def _continue_guest_callback(self):
        """
        Continue the API handler after one of its guest callbacks returned.

        Resume the handler generator, start the next pending callback of the frame, or return from the API.
        """
        run = self.get_current_run()
        # Drop the frames of nested callbacks that the guest left without a return
        while len(run.guest_callbacks) > 1 and run.guest_callbacks[-1].stack_pointer < self.get_stack_ptr():
            run.guest_callbacks.pop()
        frame = run.guest_callbacks[-1]
        if frame.handler is not None:
            guest_callbacks.resume(self, frame)
            return
        routine = frame.initializers.get(frame.function)
        if routine is not None and not self.module_loader.finish_initializer(routine, self.get_return_val()):
            self._fail_library_initializer(frame, routine)
        self.set_stack_ptr(frame.stack_pointer)
        if frame.pending:
            function, args = frame.pending.pop(0)
            self.start_guest_callback(frame, function, args)
        else:
            run.guest_callbacks.pop()
            if frame.event is not None:
                frame.event.return_value = self.get_machine_word(frame.result)
            self.restore_caller_registers(frame)
            self.do_call_return(frame.argc, frame.return_address, frame.result, conv=frame.convention)

    def _fail_library_initializer(self, frame, routine):
        """
        Make the load call of the frame fail, and undo the loads that it made.

        Windows does this when a DllMain returns FALSE.
        """
        frame.result = frame.failure_result
        for address, data in frame.failure_writes:
            self.mem_write(address, data)
        self.set_last_error(1114)  # ERROR_DLL_INIT_FAILED
        self.module_loader.remove_failed_module_from_peb(routine.module, routine.pid)
        self.module_loader.rollback_guest_load(frame)

    def restore_caller_registers(self, frame):
        """Restore the nonvolatile registers that the guest callbacks of frame can change. Windows keeps them."""
        for register, value in frame.saved_registers or ():
            self.reg_write(register, value)

    def _hook_mem_unmapped(self, emu, access, address, size, value):
        """Handle an access to unmapped memory, or an access that the page protection denies."""
        try:
            access = self.emu_eng.mem_access.get(access)
            logger.debug("mem_unmapped: access=%s addr=0x%x size=0x%x", access, address, size)
            if access != common.INVALID_MEM_EXEC:
                self.prev_pc = self.get_pc()

            self.enable_deferred_work_hook()

            if access == common.INVALID_MEM_EXEC:
                return self._handle_invalid_fetch(emu, address, size, value)

            if access == common.INVALID_MEM_READ:
                return self._handle_invalid_read(emu, address, size, value)

            if access == common.INVAL_PERM_MEM_EXEC:
                if address & ~(self.page_size - 1) in self.guard_pages:
                    return self._raise_protection_fault(address, "fetch")
                return self._handle_prot_fetch(emu, address, size, value)
            if access == common.INVAL_PERM_MEM_READ and not self.is_kernel_mode:
                return self._handle_prot_read(emu, address, size, value)
            if access == common.INVALID_MEM_WRITE:
                return self._handle_invalid_write(emu, address, size, value)
            if access == common.INVAL_PERM_MEM_WRITE:
                return self._handle_prot_write(emu, address, size, value)
        except Exception as e:
            return self._end_run_on_hook_error("Invalid memory exception", e)

    def _handle_prot_write(self, emu, address, size, value):
        """Deliver a write to a mapped read-only page to the guest chain.

        Windows/Wine raise ``STATUS_ACCESS_VIOLATION`` for a protection fault
        just like an unmapped access, so VEH/SEH/UEF handlers get a chance to
        change the page protection, skip the instruction, or terminate
        normally. Only when no guest handler takes over is the original
        ``invalid_protect_write`` error recorded (with PC/address/instruction
        and access_type preserved).
        """
        guarded = address & ~(self.page_size - 1) in self.guard_pages
        if not guarded and size <= 8 and self._unprotect_resource_write(address):
            # Unicorn drops a store that a protection hook handles, so do the store here.
            self.mem_write(address, (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little"))
            return True
        if not self.is_kernel_mode and guarded:
            return self._raise_protection_fault(address, "write")
        if not self.is_kernel_mode and self._exceptions_dispatch_enabled():
            return self._defer_protected_fault("invalid_protect_write", "write", address)

        error = self.get_error_info(ErrorType.INVALID_PROTECT_WRITE, address, access_type="write")
        self._set_run_error(error)
        self.end_run_on_fault()
        return True

    def _handle_prot_read(self, emu, address, size, value):
        """Deliver a read from a mapped no-access page to the guest chain.

        A guard page raises its own exception on the first read, like the
        execute and write paths. The exception dispatch is deferred through
        ``DEFERRED_DISPATCH_ADDR`` because Unicorn 2.1.4 crashes when exception
        structures are mapped from inside a ``UC_MEM_READ_PROT`` callback. Only
        an unhandled fault becomes ``invalid_prot_read``, with
        PC/address/instruction/access_type kept.
        """
        if not self.is_kernel_mode and (address & ~(self.page_size - 1)) in self.guard_pages:
            return self._raise_protection_fault(address, "read")
        if self._exceptions_dispatch_enabled():
            return self._defer_protected_fault("invalid_prot_read", "read", address)

        error = self.get_error_info(ErrorType.INVALID_PROTECT_READ, address, access_type="read")
        self._set_run_error(error)
        self.end_run_on_fault()
        return True

    def _defer_protected_fault(self, error_type, access_type, address, *, dep_exec_allowed: bool = False):
        """Snapshot a protected read/fetch fault and defer its dispatch.

        Unicorn 2.1.4 segfaults when ``uc_mem_map`` is invoked from a
        UC_MEM_READ_PROT or UC_MEM_FETCH_PROT callback. Redirect EIP to the
        reserved trampoline; the resulting invalid fetch runs the normal
        exception dispatch outside the PROT callback.

        ``dep_exec_allowed`` marks a fault that the process DEP opt-out
        permits: instead of delivering STATUS_ACCESS_VIOLATION, the deferred
        handler grants execute permission to the writable faulting page and
        resumes the instruction.

        Side effects: stores ``_deferred_protected_fault`` and changes EIP.
        Returns True so the memory hook treats the fault as handled.
        """
        if self._deferred_protected_fault is not None:
            # A UC_MEM_FETCH_PROT episode can invoke the hook repeatedly while
            # the engine finishes decoding the non-executable page. Keep the
            # first (real) fault snapshot and re-point EIP at the trampoline.
            self.set_pc(DEFERRED_DISPATCH_ADDR)
            return True

        self._deferred_protected_fault = DeferredProtectedFault(
            error_type=error_type,
            access_type=access_type,
            fault_pc=(
                address if access_type == "fetch" else self._get_faulting_instruction_pc(address, access_type)
            ),
            address=address,
            context=self.get_thread_context(),
            dep_exec_allowed=dep_exec_allowed,
        )
        logger.debug(
            "deferring protected %s fault: pc=0x%x addr=0x%x",
            access_type,
            self.get_pc(),
            address,
        )
        self.set_pc(DEFERRED_DISPATCH_ADDR)
        return True

    def _run_deferred_protected_fault(self):
        """Dispatch a protected read/fetch fault captured by _defer_protected_fault.

        Restores the fault-time context, then delivers STATUS_ACCESS_VIOLATION
        to VEH/SEH/UEF. When no guest handler accepts, the caller's original
        fatal error is recorded with the preserved PC/address/access_type.

        A fault marked ``dep_exec_allowed`` (process image opted out of DEP and
        the page is writable) is not an exception: grant execute permission to
        the page and resume the faulting instruction.

        Returns:
            True when the deferred sentinel was consumed; False when no
            deferred fault is pending (defensive path).
        """
        fault = self._deferred_protected_fault
        if fault is None:
            logger.warning("deferred protected-fault sentinel hit with no pending fault")
            return False
        self._deferred_protected_fault = None
        logger.debug(
            "dispatching deferred protected %s fault: fault_pc=0x%x addr=0x%x current_pc=0x%x",
            fault.access_type,
            fault.fault_pc,
            fault.address,
            self.get_pc(),
        )

        self.load_thread_context(fault.context)
        self.set_pc(fault.fault_pc)
        self.prev_pc = fault.fault_pc

        if fault.dep_exec_allowed:
            if self._grant_dep_exec_fetch(fault.address):
                logger.debug(
                    "DEP opt-out: granted execute on writable page 0x%x, resuming pc=0x%x",
                    fault.address,
                    fault.fault_pc,
                )
                return True
            # The page is no longer writable/mapped (the guest may have
            # changed it between the fault and this deferred handler); fall
            # back to the normal guest exception chain.
            logger.debug(
                "DEP opt-out grant no longer applies to 0x%x; dispatching the fault",
                fault.address,
            )

        exception = cpu_exceptions.memory_fault(fault.fault_pc, fault.address, fault.access_type)
        # A declining handler chain keeps the original protected-fault error,
        # as the non-dispatched path records it.
        error = _DeferredFaultError(fault.error_type, fault.address, fault.access_type, fault.fault_pc)
        if self.dispatch_seh(
            ddk.STATUS_ACCESS_VIOLATION,
            fault.address,
            deferred_fault=fault,
            exception=exception,
            error=error,
        ):
            return True

        self._finalize_unhandled_deferred_fault(fault)
        return True

    def _process_image_dep_policy(self) -> ImageDepPolicy | None:
        """Return the current process image's DEP/NXCOMPAT policy.

        Windows/Wine derive process DEP from the main image's Optional Header
        ``DllCharacteristics`` (Wine ``loader.c:1585-1591``). The policy is
        read from ``Process.pe`` (the module loaded as the process image), not
        from whichever module happens to be executing: DEP is process-wide.

        Returns:
            The image policy, or ``None`` when there is no current process, the
            process has no PE image, or the image loader has no PE header
            (shellcode/synthesized/decoy modules). ``None`` keeps DEP enabled.
        """
        process = self.get_current_process()
        image_module = getattr(process, "pe", None) if process is not None else None
        if image_module is None:
            return None
        getter = getattr(image_module, "get_dep_policy", None)
        if getter is None:
            return None
        return getter()

    def _dep_exec_fetch_allowed(self, address: int) -> bool:
        """Return True when the image DEP opt-out permits fetching ``address``.

        Applicable only when the process image explicitly cleared NXCOMPAT.
        Two page classes are covered:

        * writable private ``VirtualAlloc`` views, i.e. a page returned by
          ``VirtualAlloc(..., PAGE_READWRITE)`` that the guest then executes;
        * writable image-section pages (``PAGE_WRITECOPY``), the class packed
          samples decrypt code into before jumping to it.

        Read-only image sections (``.rdata``/resources), no-access pages,
        stack pages and other private mappings keep their existing
        protections.
        """
        policy = self._process_image_dep_policy()
        if not dep_opt_out(policy):
            return False
        mm = self.get_address_map(address)
        if mm is None:
            return False
        perms = self.get_address_perms(address)
        if perms is None:
            return False
        if mm.is_image:
            return image_page_exec_allowed(
                policy,
                is_image_page=True,
                page_readable=bool(perms & common.PERM_MEM_READ),
                page_writable=bool(perms & common.PERM_MEM_WRITE),
            )
        if not is_virtual_alloc_view(mm):
            return False
        return bool(perms & common.PERM_MEM_WRITE)

    def _grant_dep_exec_fetch(self, address: int) -> bool:
        """Add execute permission to the faulting page when DEP permits it.

        Called outside the Unicorn UC_MEM_FETCH_PROT callback (through the
        deferred trampoline). Only the faulting page is changed; the Win32
        protection the guest observes is preserved (a ``PAGE_WRITECOPY`` image
        page or a ``PAGE_READWRITE`` VirtualAlloc page keeps its recorded
        value), matching Wine's model where force-exec affects the host
        protection but not the recorded ``VPROT``.
        """
        page_size = self.page_size or 0x1000
        page = address & ~(page_size - 1)
        mm = self.get_address_map(page)
        if mm is None:
            return False
        is_image_page = bool(mm.is_image)
        if not is_image_page and not is_virtual_alloc_view(mm):
            return False
        perms = self.get_address_perms(page)
        if perms is None:
            return False
        if is_image_page:
            if not (perms & common.PERM_MEM_READ and perms & common.PERM_MEM_WRITE):
                return False
        elif not (perms & common.PERM_MEM_WRITE):
            return False
        if perms & common.PERM_MEM_EXEC:
            return True

        win_protect = self.get_address_win_protection(page)
        if win_protect is None:
            win_protect = emu_perms_to_win_protect(perms)
        try:
            self.mem_protect(
                page,
                page_size,
                perms | common.PERM_MEM_EXEC,
                win_protect=win_protect,
            )
        except Exception:
            logger.exception("DEP opt-out: failed to grant execute on page 0x%x", page)
            return False
        return True

    def _finalize_unhandled_deferred_fault(self, fault: DeferredProtectedFault) -> None:
        """Record the original protected read/fetch error and end the run.

        Called only after VEH, SEH and the unhandled-exception filter all
        declined a deferred protected fault. Callers restore the fault-time
        context and PC before dispatch, so the recorded ``ErrorInfo`` keeps the
        original type, PC, address, access type and instruction.
        """
        self._seh_deferred_fault = None
        error = self.get_error_info(
            fault.error_type,
            fault.address,
            access_type=fault.access_type,
            pc_override=fault.fault_pc,
        )
        self._set_run_error(error)
        logger.debug(
            "deferred %s fault unhandled: recorded %s pc=0x%x addr=0x%x",
            fault.access_type,
            fault.error_type,
            fault.fault_pc,
            fault.address,
        )
        self.end_run_on_fault()

    def _protected_access_still_faults(self, fault: DeferredProtectedFault) -> bool:
        """Return True if the faulted access would fault again right now.

        A guest handler that leaves ``CONTEXT.Eip`` on the faulting instruction
        and restores enough page protection (for example PAGE_READWRITE for a
        write) can retry the instruction; a handler that changed nothing has
        declined. A fetch fault needs execute permission, so a handler that
        only makes the page writable has not resolved it.
        """
        required = {
            "read": common.PERM_MEM_READ,
            "write": common.PERM_MEM_WRITE,
            "fetch": common.PERM_MEM_EXEC,
        }.get(fault.access_type)
        if required is None:
            return True
        perms = self.get_address_perms(fault.address)
        if perms is None:
            return True
        return (perms & required) == 0

    def _unset_emu_hooks(self) -> None:
        """Map the reserved sentinel range so a handled reserved access can complete."""
        self._map_reserved_range()

    def _dispatch_guest_exception(
        self,
        exception: cpu_exceptions.CpuException,
        faulting_address: int | None,
        *,
        deferred_fault: DeferredProtectedFault | None = None,
        error: guest_callbacks.CallbackError | None = None,
    ) -> bool:
        """Offer a CPU exception to the guest VEH, SEH and top-level filter.

        ``error`` is the error to end the run with when no handler takes the
        exception, so a declining VEH/SEH chain keeps the identity of the
        original fault (its type, pc, address and interrupt number) instead of
        a generic ``unhandled_exception``.

        Returns True when control was transferred to guest code, or when a
        deferred protected access may be retried after its handler restored the
        required page protection. False means no handler took the exception, so
        the caller keeps its original fatal error.
        """
        if not self._exceptions_dispatch_enabled():
            return False
        # Local FX-002 accounting: the illegal-instruction replay allowed
        # ``MAX_REPEAT`` handler runs (its own counter stopped the next trap),
        # while the memory-fault replay stopped on the fourth dispatch.
        replay_limit = self._seh_repeat.MAX_REPEAT
        if exception.code != ddk.STATUS_ILLEGAL_INSTRUCTION:
            replay_limit -= 1
        if not self._seh_repeat.record((self.get_pc(), faulting_address), replay_limit):
            return False
        try:
            rv = self.exception_dispatcher().dispatch_fault(self, exception, error)
        except guest_callbacks.CallbackError:
            rv = False
        if rv:
            return True
        if deferred_fault is not None and not self._protected_access_still_faults(deferred_fault):
            # A handler restored the protection the access needs and left PC at
            # the faulting instruction: retry it instead of resuming nothing.
            return True
        return False

    def dispatch_seh(
        self,
        except_code,
        faulting_address=None,
        *,
        deferred_fault=None,
        exception=None,
        error=None,
    ):
        """Deliver a CPU exception to the guest exception chain.

        Windows order is VEH, then the SEH chain, then the unhandled-exception
        filter. ``exception`` is the original ``cpu_exceptions.CpuException``
        when the caller has it; a protected-fault snapshot builds one from
        ``faulting_address`` instead. ``error`` is the error of the run when no
        handler takes the exception.

        Returns:
            True only when a guest handler took the exception (or a deferred
            protected access may be retried); False when no handler exists.
        """
        self._seh_deferred_fault = deferred_fault
        if exception is None:
            pc = self.get_pc()
            address = pc if faulting_address is None else faulting_address
            exception = cpu_exceptions.memory_fault(pc, address, "read")
        return self._dispatch_guest_exception(
            exception, faulting_address, deferred_fault=deferred_fault, error=error
        )

    def continue_seh(self) -> None:
        """Reset the SEH repeat state after a legacy SEH return sentinel.

        The upstream dispatch runs guest handlers as guest callbacks and does not use
        ``SEH_RETURN_ADDR``; keeping this entry point preserves the local control-flow
        contract without re-running a dispatch.
        """
        self._seh_repeat.reset()

    def _get_exception_list(self) -> int:
        """Get the exception registration list of the current thread, or 0."""
        thread = self.get_current_thread()
        if not thread:
            return 0
        teb = thread.get_teb()
        return int(teb.object.NtTib.ExceptionList)

    def enable_code_hook(self) -> None:
        """Run the deferred-work hook at the next instruction (local deferred exception dispatch)."""
        self.enable_deferred_work_hook()

    def disable_code_hook(self) -> None:
        """Remove the deferred-work hook."""
        self.disable_deferred_work_hook()

    def _dispatch_control_return(self) -> bool:
        """Consume an internal control-flow return before it is fetched by Unicorn.

        API handlers run in Python and set the guest PC with do_call_return(). If that
        return address is one of the reserved control sentinels, the mapped sentinel page
        would otherwise be fetched and its zero bytes executed. Complete the
        SEH/callback transition directly instead.

        ``API_CALLBACK_HANDLER_ADDR`` is also the v2.1.0
        ``GUEST_CALLBACK_RETURN_ADDR``. A pending local ``run.api_callbacks`` frame is
        completed first; otherwise a live ``run.guest_callbacks`` frame is continued
        (the API was tail-called from guest callback code, as user32 CallWindowProc ->
        DefWindowProc does). With neither frame the run ends with
        ``callback_return_without_callback``.
        """
        pc = self.get_pc()
        if pc == winemu.SEH_RETURN_ADDR:
            self.continue_seh()
            if self.run_complete and not self.emu_complete:
                self.on_run_complete()
            return True

        if pc == winemu.API_CALLBACK_HANDLER_ADDR:
            _complete_pending_api_callback(self)
            return True

        return False

    def _complete_api_callback(self) -> None:
        """Complete a guest callback and restore the intercepted API return."""
        _complete_pending_api_callback(self)

    def _unprotect_resource_write(self, address: int) -> bool:
        """
        Make the resource pages of an image writable when the guest writes into its resource data.

        The unhandled exception filter of Windows does the same for an access violation in resource data.
        """
        module = self.get_mod_from_addr(address)
        image = getattr(module, "_image", None)
        if image is None or image.resource_directory is None:
            return False
        start, size = image.resource_directory
        if not start <= address < start + size:
            return False
        base = start & ~0xFFF
        end = min((start + size + 0xFFF) & ~0xFFF, module.base + module.image_size)
        self.mem_protect(base, end - base, common.PERM_MEM_RW)
        return True

    def get_symbol_from_address(self, address) -> str | None:
        """Get the symbol at address as "dll.name", or None."""
        symbol = self.api_registry.symbol(address)
        if symbol is not None:
            return symbol
        if self.api_registry.overlaps_traps(address):
            return None
        auxiliary = self.symbols.get(address)
        return "{}.{}".format(*auxiliary) if auxiliary else None

    def get_symbols(self) -> dict[int, tuple[str, str]]:
        """
        Get a copy of the symbols as {address: (dll, name)}.

        If two symbols have the same address, the API registry entry wins.
        The result does not include forwarder strings or API tokens.
        """
        symbols = {
            address: value
            for address, value in self.symbols.items()
            if not self.api_registry.overlaps_traps(address)
            and not (
                address in self.api_registry.entries and self.api_registry.entries[address].export.forwarder is not None
            )
        }
        symbols.update(
            (address, (entry.dll, entry.name))
            for address, entry in self.api_registry.entries.items()
            if entry.export.forwarder is None
        )
        return symbols

    def get_api_symbols(self) -> dict[int, str]:
        """Get a copy of the symbols of get_symbols as {address: "dll.name"}."""
        return {address: "{}.{}".format(*value) for address, value in self.get_symbols().items()}

    def _set_run_error(self, error: ErrorInfo) -> None:
        """Save error as the error of the current run, if a run is active."""
        if self.curr_run is not None:
            self.curr_run.error = error

    def _end_run_on_hook_error(self, description: str, exception: Exception) -> bool:
        """Log the current exception, save it as the error of the run, and end the emulation."""
        logger.exception(description)
        error = self.get_error_info(
            ErrorType.INTERNAL_ERROR,
            self.get_pc(),
            traceback=traceback.format_exc(),
            message=str(exception) or type(exception).__name__,
        )
        self._set_run_error(error)
        self.stop()
        return False

    def _get_exact_symbol(self, address: int) -> str | None:
        """Get the symbol whose address is ``address`` as "dll.name", or None. An address inside an API is no symbol."""
        entry = self.api_registry.entries.get(address)
        if entry is not None:
            return entry.symbol
        if self.api_registry.overlaps_traps(address):
            return None
        auxiliary = self.symbols.get(address)
        return "{}.{}".format(*auxiliary) if auxiliary else None

    def _count_symbol_access(self, run: Run, counter: str, address: int) -> None:
        """Count a read, write or execute at the address of a symbol. counter is "reads", "writes" or "execs"."""
        access = run.sym_access.get(address)
        if access is None:
            symbol = self._get_exact_symbol(address)
            if symbol is None:
                return
            access = run.sym_access[address] = MemAccess(sym=symbol)
        setattr(access, counter, getattr(access, counter) + 1)

    def _get_cached_region_access(self, address: int, cache: deque[tuple[int, int, MemAccess]]) -> MemAccess | None:
        """
        Get the access counts of the region of the report that contains address.

        Look in cache first. Return None if address is not mapped. An access in a module image outside
        the headers and the sections counts for the region at the image base, which is the headers.
        """
        for start, end, cached in cache:
            if start <= address < end:
                return cached
        run = self.curr_run
        assert run is not None
        found = self._find_region_part(address)
        if found is None:
            return None
        part, in_range = found
        access = run.region_access.get(part.base)
        if access is None:
            access = run.region_access[part.base] = MemAccess(base=part.base, size=part.size)
        if in_range:
            cache.appendleft((part.base, part.base + part.size, access))
        return access

    def _hook_mem_read(self, emu, access, address, size, value):
        """Count the reads of each symbol, section and memory map."""
        try:
            run = self.curr_run
            if run is None:
                return True
            self._count_symbol_access(run, "reads", address)
            region = self._get_cached_region_access(address, run.read_cache)
            if region is None:
                return False
            region.reads += 1
            return True
        except Exception as e:
            return self._end_run_on_hook_error("Exception during memory read", e)

    def _hook_mem_write(self, emu, access, address, size, value):
        """Count the writes of each symbol, section and memory map."""
        try:
            run = self.curr_run
            if run is None:
                return True
            self._count_symbol_access(run, "writes", address)
            region = self._get_cached_region_access(address, run.write_cache)
            if region is None:
                return False
            region.writes += 1
            return True
        except Exception as e:
            return self._end_run_on_hook_error("Exception during memory write", e)

    def _handle_invalid_read(self, emu, address, size, value):
        """Handle a read from unmapped memory."""
        if winemu.EMU_RESERVED <= address < winemu.EMU_RESERVED_END:
            self._unset_emu_hooks()
            # Some samples inspect API prologues through an imported function
            # pointer. Serve those data reads from the zero-filled sentinel page
            # while leaving subsequent fetches unmapped for import interception.
            sentinel = find_import_sentinel(
                self.import_table,
                address,
                size,
                self.get_ptr_size(),
            )
            if sentinel is not None:
                prefix = import_probe_prefix(self.get_arch())
                if prefix:
                    self.mem_write(sentinel, prefix)
            return True

        return self._raise_memory_fault(address, "read")

    def _handle_prot_fetch(self, emu, address, size, value):
        """Handle a fetch from memory without execute permission."""
        # A process image that explicitly opted out of DEP (NXCOMPAT clear) runs
        # with no-exec enforcement disabled for writable pages. The deferred
        # grant stays the only image-page relaxation path (FX-001); read-only,
        # no-access and non-writable pages keep their protections.
        if not self._should_stop_on_faults and self._dep_exec_fetch_allowed(address):
            return self._defer_protected_fault(
                "invalid_protect_fetch",
                "fetch",
                address,
                dep_exec_allowed=True,
            )

        # A fetch from a mapped but non-executable page is an access violation,
        # not a silent success: deliver it to VEH/SEH/UEF and only record the
        # protected-fetch error when nobody handles it. Dispatch is deferred
        # because Unicorn 2.1.4 crashes when exception structures are mapped
        # from inside UC_MEM_FETCH_PROT.
        if not self._should_stop_on_faults and self._exceptions_dispatch_enabled():
            return self._defer_protected_fault("invalid_protect_fetch", "fetch", address)

        error = self.get_error_info(ErrorType.INVALID_PROTECT_FETCH, address, access_type="fetch")
        self._set_run_error(error)
        self.end_run_on_fault()
        return False

    def _handle_invalid_write(self, emu, address, size, value):
        """Handle a write to unmapped memory."""
        if winemu.EMU_RESERVED <= address < winemu.EMU_RESERVED_END:
            return self._complete_reserved_access(address, size, "write")

        return self._raise_memory_fault(address, "write")

    def _complete_reserved_access(self, address, size, access_type):
        """Map the reserved range for an access to it. An access past its end faults at the first unmapped byte."""
        self._map_reserved_range()
        first = guest_callbacks.get_first_unmapped(self, address, size)
        if first != address:
            self._unmap_reserved_range()
            return self._raise_memory_fault(first, access_type)
        return True

    def _hook_code_deferred_work(self, emu, addr, size):
        """
        Code hook that runs at the next instruction after an API call or a fault.

        Record the exit at a return address in the reserved range, and unmap the reserved range. Remove the hook when
        there is no more work.
        """
        try:
            # Local deferred CPU-exception dispatch (interrupts that the x86 SEH
            # chain must see) is completed at the next instruction.
            if self.curr_exception_code:
                code = self.curr_exception_code
                self.curr_exception_code = 0
                exception = self._pending_cpu_exception
                self._pending_cpu_exception = None
                if exception is not None and self.dispatch_seh(code, None, exception=exception):
                    self._unmap_reserved_range()
                    return True
                error = self.get_error_info(ErrorType.UNHANDLED_EXCEPTION, self.prev_pc or self.get_pc())
                self._set_run_error(error)
                self.end_run_on_fault()
                return False

            # An access to the reserved range maps it until this hook runs. Unicorn does not call this hook in code that
            # it translated without the hook, so a return to a reserved address can run before the range is unmapped.
            native_exit = self._get_exit_at_pc()
            if native_exit is not None:
                self._record_exit(native_exit)
                return False

            # A guest exception handler continued at the fault address. Clear the repeat count of the fault
            # when PC leaves that address.
            if self._seh_repeat.resume_pc is not None and addr != self._seh_repeat.resume_pc:
                self._seh_repeat.reset()

            self._unmap_reserved_range()
            if self._seh_repeat.resume_pc is None:
                self.disable_deferred_work_hook()
            return True
        except Exception as e:
            return self._end_run_on_hook_error("Exception during code hook (deferred work)", e)

    def _hook_code_coverage(self, emu, addr, size):
        """Record the address of each instruction that runs, for coverage."""
        try:
            if self.curr_run is not None:
                self.curr_run.coverage.add(addr)
            return True
        except Exception as e:
            return self._end_run_on_hook_error("Exception during code hook (coverage)", e)

    def _hook_block_call_site(self, emu, addr, size):
        """
        Record the block that jumps to an API entry, and take a snapshot of a changed dynamic code region.

        The last instruction of the block before the API entry is the call site.
        """
        entry = self.api_registry.entries.get(addr)
        is_call_target = (entry is not None and entry.trap is not None) or addr in self.import_table
        if is_call_target and self._last_block is not None:
            self._api_call_site = (addr, self._last_block)
        dyn_code = self._dyn_code_watches
        if dyn_code.changed:
            # Take a snapshot of a changed region when control comes into it from outside. A decoder loop in the
            # region writes the region on each pass, but each of its blocks comes after a block in the region.
            prev = dyn_code.prev_block
            for watch in dyn_code.changed.values():
                end = watch.base + watch.size
                if watch.base <= addr < end and not watch.base <= prev < end:
                    try:
                        self._snapshot_changed_dyn_code(watch, addr)
                    except Exception as e:
                        return self._end_run_on_hook_error("Exception during block hook (dynamic code)", e)
                    break
            dyn_code.prev_block = addr
        self._last_block = (addr, size)
        return True

    def _get_last_instruction(self, block: int, size: int) -> int:
        """Get the address of the last instruction of a block, or 0 if the block does not decode to its end."""
        try:
            code = self.mem_read(block, size)
        except uc.UcError:
            return 0
        for address, insn_size, _, _ in self.disasm_eng.disasm_lite(bytes(code), block):
            if address + insn_size == block + size:
                return int(address)
        return 0

    def _get_sentinel_call_site(self) -> int:
        """Get the address of the call or jump that reached an import sentinel, or 0.

        An import sentinel is unmapped, so its fetch faults before Unicorn translates a block at the sentinel and the
        block hook records no API call site for it. The last executed block is then the caller, and its last
        instruction is the call or jump. Return 0 when that instruction is not a control transfer.
        """
        if self._last_block is None:
            return 0
        address = self._get_last_instruction(*self._last_block)
        if not address:
            return 0
        try:
            mnemonic, _, _ = self.get_disasm(address, _arch.DISASM_SIZE)
        except Exception:
            return 0
        return address if mnemonic.startswith(("call", "jmp", "lcall", "ljmp")) else 0

    def _get_fault_disassembler(self) -> cs.Cs:
        """Get the capstone engine with operand details, which decodes the instruction of a memory fault."""
        if self._fault_disasm_eng is None:
            engine = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64 if self.get_arch() == _arch.ARCH_AMD64 else cs.CS_MODE_32)
            engine.detail = True
            self._fault_disasm_eng = engine
        return self._fault_disasm_eng

    @staticmethod
    def _operand_address(insn, operand, registers: dict[str, int], mask: int) -> int | None:
        """Get the effective address of a memory operand, or None when a register is unknown."""
        import capstone.x86_const as x86

        base = operand.mem.base
        index = operand.mem.index
        try:
            if base == x86.X86_REG_RIP:
                value = insn.address + insn.size
            elif base == x86.X86_REG_INVALID:
                value = 0
            else:
                value = registers[insn.reg_name(base)]
            if index != x86.X86_REG_INVALID:
                value += registers[insn.reg_name(index)] * operand.mem.scale
        except KeyError:
            return None
        return (value + operand.mem.disp) & mask

    def _get_faulting_instruction_pc(self, address: int, access_type: str | None) -> int:
        """Get the pc of the instruction that accesses ``address``, or the pc that Unicorn reports.

        Unicorn reports the start of the translated block in a memory-fault hook when the block was translated
        without a per-instruction hook. The faulting instruction is one of the instructions of that block, so find
        the memory operand that covers the faulted address. Only the fault path calls this, so the disassembly does
        not slow down normal execution.
        """
        pc = self.get_pc()
        if access_type not in ("read", "write"):
            return pc
        page_left = self.page_size - (pc & (self.page_size - 1)) if self.page_size else 0x100
        try:
            code = bytes(self.mem_read(pc, min(0x100, page_left)))
        except uc.UcError:
            return pc
        import capstone.x86_const as x86

        required = cs.CS_AC_WRITE if access_type == "write" else cs.CS_AC_READ
        mask = (1 << (self.get_ptr_size() * 8)) - 1
        registers = self.get_register_state()
        try:
            for insn in self._get_fault_disassembler().disasm(code, pc):
                for operand in insn.operands:
                    if operand.type != cs.CS_OP_MEM:
                        continue
                    if operand.mem.segment in (x86.X86_REG_FS, x86.X86_REG_GS):
                        # A segmented access needs the descriptor base, which the register state does not give.
                        continue
                    if not operand.access & required:
                        continue
                    ea = self._operand_address(insn, operand, registers, mask)
                    if ea is None:
                        continue
                    if ea <= (address & mask) < ea + max(operand.size, 1):
                        return int(insn.address)
                if (
                    insn.group(cs.CS_GRP_JUMP)
                    or insn.group(cs.CS_GRP_CALL)
                    or insn.group(cs.CS_GRP_RET)
                    or insn.group(cs.CS_GRP_IRET)
                    or insn.group(cs.CS_GRP_INT)
                ):
                    break
        except (cs.CsError, KeyError, TypeError, ValueError):
            return pc
        return pc

    def _hook_code_tracing(self, emu, addr, size):
        """Count the instructions, and the executes of each symbol, section and memory map."""
        try:
            if logger.isEnabledFor(logging.DEBUG):
                disasm = self.get_disasm(addr, size)[2]
                logger.debug("exec: 0x%x %s", addr, disasm)

            self._dyn_code_caller_pc = self.prev_pc if self.prev_pc and self.prev_pc != addr else None
            self.prev_pc = addr
            run = self.curr_run
            if run is None:
                return True
            self._count_symbol_access(run, "execs", addr)
            run.instr_cnt += 1
            region = self._get_cached_region_access(addr, run.exec_cache)
            if region is None:
                return False
            region.execs += 1
            return True
        except Exception as e:
            return self._end_run_on_hook_error("Exception during code hook (tracing)", e)

    def _hook_code_debug(self, emu, addr, size):
        """Log the disassembly and the registers of each instruction in debug mode."""
        x = self.get_disasm(addr, size)[2]
        if self.get_arch() == _arch.ARCH_AMD64:
            regs: tuple[str, ...] = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9")
        else:
            regs = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        vals = " : ".join(f"{r}=0x{self.reg_read(r):x}" for r in regs)
        logger.debug("0x%x: %s, %s", addr, x, vals)
        return True

    def get_native_module_path(self, mod_name=""):
        """Get the path of a DLL with this name in a configured module directory."""
        modules = self.config.modules
        if self.get_arch() == _arch.ARCH_AMD64:
            directories = (
                modules.directory_x64,
                modules.module_directory_x64,
            )
            packaged = os.path.join(os.path.dirname(__file__), os.pardir, "winenv", "decoys", "amd64")
        else:
            directories = (
                modules.directory_x86,
                modules.module_directory_x86,
            )
            packaged = os.path.join(os.path.dirname(__file__), os.pardir, "winenv", "decoys", "x86")
        mod_name = mod_name.lower()
        for directory in (*directories, packaged):
            path = common.normalize_package_path(directory or "")
            if not os.path.isdir(path):
                continue
            for fn in os.listdir(path):
                if os.path.splitext(fn.lower())[0] == mod_name:
                    return os.path.join(path, fn)
        return None
    def _add_module_to_current_peb(self, module):
        if self.is_kernel_mode or not module.visible_in_peb or module.is_driver():
            return
        process = self.get_current_process()
        if process is None or not self.get_address_map(process.peb_ldr_data.address):
            return
        if process.initializing_peb:
            return
        if module.is_exe() and module is not process.pe and module.base != process.base:
            return
        process.add_module_to_peb(module)

    def load_library(self, mod_name):
        original_modules = list(self.modules)
        original_peb_modules = self.module_loader.snapshot_peb_modules()
        name = winemu.normalize_dll_name(module_name(mod_name))
        module = self.get_mod_by_name(name)
        data = None
        if module is None:
            # FX-013: a guest-visible file that has already been materialized in
            # the emulated filesystem is a real load candidate. Packers unpack a
            # DLL to disk and then LoadLibraryA the path; a host-native/handler
            # lookup cannot see that file.
            guest_image = self.get_guest_module_file_data(mod_name)
            if guest_image is not None:
                if not guest_image:
                    logger.info("LoadLibrary: guest file %r exists but is empty", mod_name)
                    return 0
                try:
                    module = self.load_module_by_name(
                        name, emu_path=self.fileman.get_full_path(mod_name), data=guest_image
                    )
                except (WindowsEmuError, ValueError, pefile.PEFormatError) as error:
                    logger.info("LoadLibrary: guest file %r is not a loadable PE: %s", mod_name, error)
                    return 0
            else:
                data = self.get_module_data_from_emu_file(mod_name)
        if module is None and data and data.startswith(b"MZ"):
            try:
                module = self.load_module_by_name(name, emu_path=self.fileman.get_full_path(mod_name), data=data)
            except (WindowsEmuError, ValueError, pefile.PEFormatError) as error:
                logger.warning("failed to load %s: %s", mod_name, error)
                return 0
        elif module is None:
            known = self.get_native_module_path(name) or self.api.load_api_handler(name)
            known = known or self.get_signature_db().get_functions(name, self._get_signature_arch())
            known = known or is_synthesizable_system_module(name, self.config.modules.synthesized_system_modules)
            if not known and not self.config.modules.stubs:
                logger.info("LoadLibrary: unknown module %r and stubs are disabled", mod_name)
                return 0
            try:
                module = self.load_module_by_name(name)
            except WindowsEmuError as error:
                logger.warning("failed to load %s: %s", name, error)
                return 0
        self._add_module_to_current_peb(module)
        new_modules = [m for m in self.modules if m not in original_modules]
        # Each module that the load maps gets a module_load event, its dependencies included.
        profiler = self.get_profiler()
        if profiler and self.curr_run is not None:
            pos = self.get_trace_position()
            for mod in new_modules:
                name = mod.get_base_name() or mod.name
                profiler.record_module_load_event(self.curr_run, pos, name, mod.emu_path, mod.base, mod.image_size)
        frame = self._active_api_frame
        if frame is not None and not self.is_kernel_mode:
            # Keep the earliest snapshot for each process across reentrant loads.
            tracked = {process.id for process, _ in frame.peb_module_snapshot}
            frame.peb_module_snapshot.extend(item for item in original_peb_modules if item[0].id not in tracked)
            frame.created_modules.extend(new_modules)
            # Queue the initializers on the API frame so that
            # _continue_guest_callback() consults frame.initializers: a DllMain
            # that returns FALSE then fails the LoadLibrary/LdrLoadDll call and
            # rolls the load back (v2.1.0 frame model). A generator handler
            # (setup_callback) drains frame.pending itself and never records an
            # initializer result, so it cannot fail the load.
            guests = self.get_current_run().guest_callbacks
            for routine in self.module_loader.collect_initializers():
                frame.initializers[routine.address] = routine
                if any(item is frame for item in guests):
                    frame.pending.append((routine.address, tuple(routine.args)))
                else:
                    self.start_guest_callback(frame, routine.address, routine.args)
                    guests.append(frame)
        return module.base
    def load_module_by_name(self, name, emu_path=None, base=None, native_path=None, data=None, image_data=None):
        """
        Load the module name, or get it if it is loaded.

        Load the module from data, else from the module directory, else as a synthetic API module.
        ``image_data`` is the local name for raw PE file content of a module that only exists in
        the emulated filesystem; it takes precedence over host-side loader selection.
        """
        name = module_name(name)
        existing = self.get_mod_by_name(name)
        if existing is not None:
            self._add_module_to_current_peb(existing)
            return existing
        if not emu_path:
            emu_path = (self.config.process.current_dir or r"C:\Windows\system32") + "\\" + name + ".dll"
        native_path = native_path or self.get_native_module_path(mod_name=name)
        if image_data is not None and data is not None:
            raise WindowsEmuError("load_module_by_name got both data and image_data")
        if image_data is not None:
            data = image_data
        if base is None and not native_path and data is None:
            base = 0x6F000000
        handler = self.api.load_api_handler(name)
        if handler and name == "ntdll":
            nt_handler = self.api.load_api_handler("ntoskrnl")
            if nt_handler:
                handler._nt_handler = nt_handler

        def _make_image(load_base):
            """Build the module image at ``load_base`` with the selected loader."""
            if data is not None:
                return PeLoader(data=data, base_override=load_base, emu_path=emu_path).make_image()
            if native_path:
                return PeLoader(path=native_path, base_override=load_base, emu_path=emu_path).make_image()
            if handler is not None:
                return ApiModuleLoader(
                    name=name,
                    api=handler,
                    arch=self.get_arch(),
                    base=load_base,
                    emu_path=emu_path,
                    signature_db=self.get_signature_db(),
                ).make_image()
            if is_synthesizable_system_module(name, self.config.modules.synthesized_system_modules):
                # FX-014: a known system DLL without an API handler gets a decoy PE
                # with an export table instead of a generic placeholder.
                return SystemModuleDecoyLoader(
                    name=name,
                    arch=self.get_arch(),
                    base=load_base,
                    emu_path=emu_path,
                ).make_image()
            return ApiModuleLoader(
                name=name,
                api=None,
                arch=self.get_arch(),
                base=load_base,
                emu_path=emu_path,
                signature_db=self.get_signature_db(),
            ).make_image()

        image = _make_image(base)
        # Synthesized images have no relocation data. When the preferred module
        # base is already occupied, rebuild the image at a free base instead of
        # failing the load (the local fixG behaviour).
        if data is None and self._module_image_conflicts(image):
            span = self._module_image_span(image)
            free_base, _ = self.get_valid_ranges(span, addr=base or 0x6F000000)
            base = free_base
            image = _make_image(base)
        image.name = name
        # A caller-supplied image keeps its PE-header module type (DLL vs EXE);
        # path-derived types only substitute for host-side modules.
        if data is None:
            image.module_type = _module_type_from_path(emu_path)
        module = self.load_image(image, base)
        if (
            image.source == "guest_pe"
            and not isinstance(getattr(image, "loader", None), SystemModuleDecoyLoader)
            and module.is_dll()
            and not self.is_kernel_mode
        ):
            self.module_loader.guest_dependencies.append(module)
        return module

    @staticmethod
    def _image_region_base(image, region) -> int:
        """Get the absolute base of a region: decoys are absolute, guest images are RVAs."""
        if isinstance(getattr(image, "loader", None), SystemModuleDecoyLoader):
            return region.base
        return image.image_base + region.base

    def _module_image_conflicts(self, image) -> bool:
        """Return True when a module image would land on mapped memory."""
        if image.image_base and self.get_address_map(image.image_base) is not None:
            return True
        for region in image.regions:
            start = self._image_region_base(image, region)
            end = start + len(region.data)
            if self.get_address_map(start) or self.get_address_map(max(start, end - 1)):
                return True
        return False

    def _module_image_span(self, image) -> int:
        """Return the span that covers all regions of a module image."""
        starts = [self._image_region_base(image, region) for region in image.regions]
        ends = [start + len(region.data) for start, region in zip(starts, image.regions)]
        return max(max(ends) - min(starts), image.image_size) if starts else image.image_size

    def get_module_data_from_emu_file(self, file_path):
        """
        Get the contents of the file at file_path in the emulated file system, or None if there is no file.

        Raises:
            FileSystemEmuError: if the configuration names a host file that does not exist.
        """
        mod_file = self.fileman.get_file_by_path(file_path)
        if not mod_file:
            return None

        # get_contents keeps the file pointer of the guest.
        return mod_file.get_contents()

    def init_sys_modules(self, modules_config):
        return self._init_module_group(modules_config)

    def init_user_modules(self, modules_config):
        return self._init_module_group(modules_config, default_base=0x6F000000)

    def _init_module_group(self, modules_config, default_base=None):
        rtmods = []
        for modconf in modules_config:
            name = modconf.name or "unknown"
            base = modconf.base_addr or default_base
            path = modconf.path or name + ".dll"
            rtmods.append(self.load_module_by_name(name, emu_path=path, base=base))
        return rtmods

    def get_thread_context(self, thread=None):
        """Get the saved CONTEXT of thread, or the CONTEXT of the CPU if thread is None."""
        if thread:
            return thread.get_context()
        if self.get_arch() == _arch.ARCH_AMD64:
            ctx = self.wintypes.CONTEXT64(self.get_ptr_size())
            ctx.ContextFlags = thread_context.CONTEXT_ALL_AMD64
            registers = thread_context.CPU_REGISTERS_AMD64
        else:
            ctx = self.wintypes.CONTEXT(self.get_ptr_size())
            ctx.ContextFlags = thread_context.CONTEXT_ALL_I386
            registers = thread_context.CPU_REGISTERS_I386
        for name, reg in registers.items():
            setattr(ctx, name, self.reg_read(reg))
        thread = self.get_current_thread()
        if thread is not None:
            thread_context.get_debug_registers(thread, ctx)
        return ctx

    def load_thread_context(self, ctx):
        """Write ctx to the CPU registers, and its debug registers to the current thread."""
        if self.get_arch() == _arch.ARCH_AMD64:
            registers = thread_context.CPU_REGISTERS_AMD64
        else:
            registers = thread_context.CPU_REGISTERS_I386
        for name, reg in registers.items():
            self.reg_write(reg, getattr(ctx, name))
        thread = self.get_current_thread()
        if thread is not None and thread_context.has(ctx.ContextFlags, thread_context.CONTEXT_DEBUG_REGISTERS):
            self.set_debug_registers(thread, ctx)
        if ctx.EFlags & hardware_breakpoints.RESUME_FLAG:
            self.reg_write(_arch.X86_REG_EFLAGS, ctx.EFlags & ~hardware_breakpoints.RESUME_FLAG)
            self.hardware_breakpoints.resume_at(thread_context.instruction_pointer(ctx))

    def record_exception(self, code, pc, handler, registers, faulting_address=None):
        """
        Log an exception at pc that is offered to a guest handler, and record it in the report.

        pc is None for an exception that an API raises when the emulator does not know the address of the call.
        """
        instr = None
        pc_module = pc_offset = None
        if pc is not None:
            try:
                _, _, instr = self.get_disasm(pc, _arch.DISASM_SIZE)
            except Exception:
                logger.debug("cannot disassemble 0x%x", pc, exc_info=True)
            pc_module, pc_offset = self._resolve_module_offset(pc) or (None, None)
        handler_desc = f"0x{handler:x}"
        if self._resolve_module_offset(handler):
            handler_desc += f" ({self._format_module_offset(handler)})"
        logger.info(
            '%s: Exception caught: code=0x%x handler=%s instr="%s"\n  pc: %s\n  regs: %s',
            hex(pc) if pc is not None else "?",
            code,
            handler_desc,
            instr,
            self._format_module_offset(pc) if pc is not None else "?",
            "  ".join(f"{k}={v:#x}" for k, v in registers.items()),
        )
        if self.profiler:
            pos = self.get_trace_position()
            pos.pc = pc
            self.profiler.record_exception_event(
                self.get_current_run(),
                pos,
                instr,
                code,
                handler,
                registers,
                address=faulting_address,
                pc_module=pc_module,
                pc_offset=pc_offset,
                stack=self.get_stack_trace(),
            )

    @property
    def active_api_frame(self) -> GuestCallbackFrame | None:
        """The frame of the API call that the emulator runs, or None."""
        return self._active_api_frame

    def exception_dispatcher(self):
        """Get the SEH dispatch module of the architecture."""
        return seh64 if self.get_arch() == _arch.ARCH_AMD64 else seh32

    def note_seh_resume(self, pc):
        """
        Record that a guest exception handler continues execution at pc.

        If pc is not the address of the last fault, clear the repeat count. If pc is the address of the fault, keep the
        count until the deferred work hook sees PC move away.
        """
        fault = self._seh_repeat.fault
        if fault is None:
            return
        if pc == fault[0]:
            self._seh_repeat.resume_pc = pc
            self.enable_deferred_work_hook(pc)
        else:
            self._seh_repeat.reset()

    def _new_object_handle(self, otype, name):
        """
        Create an object of type otype with one handle.

        The handle takes the reference of the object manager, so the last close of a handle removes the object.
        """
        om = self.get_object_manager("object creation")
        obj = om.new_object(otype)
        obj.name = name
        hnd = om.new_handle(obj)
        om.dec_ref(obj)
        return hnd, obj

    def create_event(self, name=""):
        """Create a kernel event object."""
        return self._new_object_handle(objman.Event, name)

    def dec_ref(self, obj):
        """Decrement the reference count of obj."""
        om = self.get_object_manager("object dereference")
        return om.dec_ref(obj)

    def create_mutant(self, name=""):
        """Create a kernel mutant object."""
        if name == 0:
            name = ""
        return self._new_object_handle(objman.Mutant, name)

    def create_semaphore(self, name=""):
        """Create a kernel semaphore object."""
        return self._new_object_handle(objman.Semaphore, name)

    def _hook_interrupt(self, emu, intnum):
        """Handle a software interrupt."""
        # `into` (0xCE) raises vector 4 only when OF=1; an explicit `int 4`
        # always raises it. Unicorn reports both through this hook.
        if intnum == 4 and self.get_arch() == _arch.ARCH_X86:
            previous_pc = getattr(self, "prev_pc", None)
            if isinstance(previous_pc, int) and previous_pc > 0:
                try:
                    opcode_prefix = bytes(self.mem_read(previous_pc, 2))
                    eflags = self.reg_read(_arch.X86_REG_EFLAGS)
                    trap_kind = classify_overflow_trap(opcode_prefix, eflags=eflags)
                except Exception:
                    trap_kind = OverflowTrapKind.UNKNOWN
                if trap_kind is OverflowTrapKind.INTO_NOT_TAKEN:
                    return True

        # __fastfail is a process-termination contract (Windows 8 and later): it
        # must not become a recoverable SEH exception or a normal API return.
        if intnum == FAST_FAIL_INTERRUPT_VECTOR:
            if self.get_arch() == _arch.ARCH_AMD64:
                fast_fail_code = self.reg_read(_arch.AMD64_REG_RCX) & 0xFFFFFFFF
                fast_fail_data = self.reg_read(_arch.AMD64_REG_RDX)
            else:
                fast_fail_code = self.reg_read(_arch.X86_REG_ECX)
                fast_fail_data = self.reg_read(_arch.X86_REG_EDX)

            if requires_kernel_bootstrap_recovery(fast_fail_code, kernel_mode=self.kernel_mode):
                # Windows initializes this cookie before entering driver code.
                # Complete the missing bootstrap transition without reporting a
                # guest fast-fail termination or dispatching an SEH exception.
                logger.debug("recovering kernel GS cookie initialization")
                hook_ref = [None]

                def _tmp_hook(emu, addr, size):
                    ret = self.pop_stack()
                    self.set_pc(ret)
                    hook_ref[0].disable()

                hook_ref[0] = self.add_code_hook(cb=_tmp_hook)
                return True

            # Unicorn advances EIP/RIP past `int 0x29` before invoking the
            # interrupt hook. Record the trapping instruction rather than the
            # following instruction so the report points at the fast-fail site.
            interrupt_pc = max(self.get_pc() - 2, 0)
            error = self.get_error_info("fast_fail", interrupt_pc, pc_override=interrupt_pc)
            error.interrupt_num = intnum
            error.termination_kind = TERMINATION_KIND
            error.status_code = STATUS_STACK_BUFFER_OVERRUN
            error.fast_fail_code = fast_fail_code
            error.fast_fail_data = fast_fail_data
            self.curr_run.error = error  # type: ignore[union-attr]
            self.restart_curr_run = False
            self.run_complete = True
            # __fastfail terminates the process, not just the current run.
            # Stop the engine so queued threads or entrypoints cannot resume.
            self.stop()
            return True

        # Local x86 SEH chain: defer the dispatch to the next instruction so the
        # guest exception structures are built outside the interrupt callback.
        exception_list = self._get_exception_list() if not self.kernel_mode else 0
        exceptions = self.config.exceptions
        dispatch_enabled = bool(getattr(exceptions, "dispatch", True)) and bool(
            getattr(exceptions, "dispatch_handlers", True)
        )
        if exception_list and dispatch_enabled:
            pc_now = self.get_pc()
            exception = None
            if intnum in (3, 0x2D):
                exception = cpu_exceptions.CpuException(ddk.STATUS_BREAKPOINT, pc_now, pc_now, (0,))
            elif intnum == 0:
                exception = cpu_exceptions.CpuException(ddk.STATUS_INTEGER_DIVIDE_BY_ZERO, pc_now, pc_now)
            elif intnum == 1:
                eflags = self.reg_read(_arch.X86_REG_EFLAGS)
                # Remove the trap flag
                self.reg_write(_arch.X86_REG_EFLAGS, eflags & 0xFFFFFEFF)
                exception = cpu_exceptions.CpuException(ddk.STATUS_SINGLE_STEP, pc_now, pc_now)
            elif intnum == 4:
                exception = cpu_exceptions.CpuException(ddk.STATUS_INTEGER_OVERFLOW, pc_now, pc_now)
            if exception is not None:
                self.curr_exception_code = exception.code
                self._pending_cpu_exception = exception
                self.prev_pc = pc_now
                self.enable_code_hook()
                return True

        if getattr(self, "emu_eng", None) is None:
            # The interrupt-contract surface has no engine to decode or raise
            # through; report the interrupt through the local error path.
            pc = self.get_pc()
            error = self.get_error_info("unhandled_interrupt", pc)
            error.interrupt_num = intnum
            self.curr_run.error = error  # type: ignore[union-attr]
            self.restart_curr_run = True
            self.on_run_complete()
            return False

        self.emu_eng.clear_exception_state()
        pc = self.get_pc()
        try:
            code_bytes = self.mem_read(pc - 2, 2)
        except uc.UcError:
            # an `int3` or `into` at the start of a region has nothing mapped before it
            try:
                code_bytes = self.mem_read(pc - 1, 1)
            except uc.UcError:
                code_bytes = b""
        if (
            not self.is_kernel_mode
            and self._exceptions_dispatch_enabled()
            and intnum not in cpu_exceptions.SYSTEM_GATES[self.get_arch()]
        ):
            trap_flag = bool(self.reg_read(_arch.X86_REG_EFLAGS) & seh.TRAP_FLAG)
            exception = cpu_exceptions.from_interrupt(intnum, pc, code_bytes, self.get_return_val(), trap_flag)
            if exception is None:
                self.set_pc(cpu_exceptions.skip_debug_service(pc))
            else:
                self.raise_cpu_exception(exception, ErrorType.UNHANDLED_INTERRUPT, interrupt_num=intnum)
            return True

        pc = cpu_exceptions.get_interrupt_instruction(intnum, pc, code_bytes)
        logger.debug("interrupt: intnum=0x%x", intnum)
        logger.error("0x%x: Unhandled interrupt: intnum=0x%x", pc, intnum)
        error = self.get_error_info(ErrorType.UNHANDLED_INTERRUPT, pc, pc=pc)
        error.interrupt_num = intnum
        self._set_run_error(error)
        self.end_run_on_fault()
        return False
