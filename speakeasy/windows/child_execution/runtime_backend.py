"""Concrete child runtime adapters for the Windows emulator.

The adapters in this module are deliberately limited to the child-execution
package.  They compose the existing loader, context manager, observer, runner,
and scheduler through public emulator operations and never install global
hooks or alter detector behavior.
"""

from __future__ import annotations

import time
from typing import Any

from speakeasy.profiler import Run

from .budget import ExecutionBudgetFactory
from .models import (
    ChildEventOwnership,
    ChildFailureKind,
    ChildLaunchRequest,
    ChildProcessContext,
    ChildTerminationReason,
    EmulatedProcessProtocol,
    LoadedChildImage,
)
from .runner import (
    ChildBudgetHooks,
    ChildExecutionBackendResult,
    ChildExecutionRunner,
    ChildExecutionRuntimeError,
)
from .runtime_context import (
    ChildRuntimeContextBackend,
    ChildRuntimeContextError,
    ChildRuntimeContextManager,
    OneShotChildEntrypointObserver,
    ParentRuntimeContext,
)
from .runtime_loader import (
    ChildImageRuntimeLoader,
    EngineChildImageBaseAllocator,
    EngineChildImageMapper,
    PeChildImageMaterializer,
)
from .scheduler import ChildExecutionScheduler


class EngineChildRuntimeContextBackend(ChildRuntimeContextBackend):
    """Switch child process, thread, module, and run context in one emulator.

    Args:
        emulator: Windows emulator exposing public current-context setters,
            process collections, and the existing run-queue API.

    The backend captures and restores only the emulator's public current
    process/thread/run handles and initializes the child PEB through the
    emulator's explicit-process ``alloc_peb`` operation. It does not schedule
    or execute child code during activation.
    """

    def __init__(self, emulator: Any) -> None:
        self._emulator = emulator

    def capture_parent(self) -> ParentRuntimeContext:
        """Capture the current parent process, thread, and run handles.

        Returns:
            An immutable snapshot used for unconditional restoration.

        Side effects:
            None.  The emulator's current context is only read.
        """

        return ParentRuntimeContext(
            process=self._emulator.get_current_process(),
            thread=self._emulator.get_current_thread(),
            run=self._emulator.get_current_run(),
        )

    def activate(
        self,
        request: ChildLaunchRequest,
        image: LoadedChildImage,
        ownership: ChildEventOwnership,
    ) -> ChildProcessContext:
        """Activate the existing child process and prepare its entry run.

        Args:
            request: Immutable child launch identity.
            image: Already mapped non-primary child image.
            ownership: Expected child process identity.

        Returns:
            Active child process/thread/module/run context.  The run is not
            queued until :class:`EngineChildExecutionBackend` starts it.

        Side effects:
            Binds and initializes the child process PEB, then sets the
            emulator's current process, thread, module, and run to the
            child-owned values. It does not execute instructions.

        Raises:
            ChildRuntimeContextError: If the child process or thread created by
                the dispatcher cannot be found or violates launch identity.
        """

        process = self._find_process(ownership.child_pid)
        if process is None:
            raise ChildRuntimeContextError(f"child process {ownership.child_pid} is not available")
        if process.pid != ownership.child_pid:
            raise ChildRuntimeContextError("child process id does not match event ownership")
        threads = getattr(process, "threads", ())
        if not threads:
            raise ChildRuntimeContextError("child process has no thread created by the dispatcher")
        thread = threads[0]

        run = Run()
        run.type = "child.module_entry"
        run.start_addr = image.entrypoint_address
        run.args = ()
        run.process_context = process
        run.thread = thread

        # The child process is a dispatcher-owned object.  Bind its image to
        # the exact mapped child module before allocating the PEB.  This avoids
        # inheriting the compatibility module or image base used merely to
        # create the process object.
        process.pe = image.module
        process.base = image.module.base
        process.path = request.normalized_target
        process.cmdline = request.command_line
        thread.process = process
        self._emulator.alloc_peb(process)

        self._emulator.set_current_process(process)
        self._emulator.set_current_thread(thread)
        self._emulator.curr_run = run
        self._emulator.curr_mod = image.module
        return ChildProcessContext(
            process=process,
            thread=thread,
            module=image.module,
            run=run,
            ownership=ownership,
        )

    def restore_parent(self, parent: ParentRuntimeContext) -> None:
        """Restore the exact process, thread, module, and run captured earlier.

        Args:
            parent: Snapshot returned by :meth:`capture_parent`.

        Returns:
            ``None``.

        Side effects:
            Replaces the emulator's current context.  This method is idempotent
            and may safely run after partial child activation.  It verifies
            the restored handles before returning.

        Raises:
            ChildRuntimeContextError: If any current handle does not match the
                captured parent snapshot after restoration.
        """

        self._emulator.set_current_process(parent.process)
        self._emulator.set_current_thread(parent.thread)
        self._emulator.curr_run = parent.run
        parent_run = parent.run
        start_addr = getattr(parent_run, "start_addr", None)
        self._emulator.curr_mod = (
            self._emulator.get_module_from_addr(start_addr) if isinstance(start_addr, int) and start_addr > 0 else None
        )
        if self._emulator.get_current_process() is not parent.process:
            raise ChildRuntimeContextError("parent process restoration did not take effect")
        if self._emulator.get_current_thread() is not parent.thread:
            raise ChildRuntimeContextError("parent thread restoration did not take effect")
        if self._emulator.get_current_run() is not parent.run:
            raise ChildRuntimeContextError("parent run restoration did not take effect")

    def _find_process(self, pid: int) -> EmulatedProcessProtocol | None:
        """Return the unique child process with ``pid``.

        Args:
            pid: Expected child process identifier.

        Returns:
            The matching process object, or ``None``.

        Side effects:
            None.  Process collections are read but not modified.
        """

        collections = (
            getattr(self._emulator, "child_processes", ()),
            getattr(self._emulator, "processes", ()),
        )
        seen: set[int] = set()
        for processes in collections:
            for process in processes:
                if id(process) in seen:
                    continue
                seen.add(id(process))
                if int(getattr(process, "pid", 0)) == pid:
                    return process
        return None


class EngineChildEntrypointHookBackend:
    """Adapt the emulator's public code-hook API for one-shot observation.

    Args:
        emulator: Windows emulator exposing ``add_code_hook``.
    """

    def __init__(self, emulator: Any) -> None:
        self._emulator = emulator

    def add_code_hook(self, callback: Any, *, begin: int, end: int) -> Any:
        """Register one code-range callback.

        Args:
            callback: Callback receiving ``(emulator, address, size)``.
            begin: Inclusive watched entry-point address.
            end: Exclusive watched range end.

        Returns:
            Hook handle with the emulator's public ``disable`` method.

        Side effects:
            Registers one hook for the duration of one child run.
        """

        return self._emulator.add_code_hook(callback, begin=begin, end=end)


class EngineChildExecutionBackend:
    """Execute one prepared child run through the emulator run queue.

    Args:
        emulator: Windows emulator exposing run-queue, start, run history,
            current-context, and instruction-budget state.

    The backend executes exactly the run prepared by the context manager.  It
    restores the parent instruction-budget flag after the child and never
    changes parent process or run history.
    """

    def __init__(self, emulator: Any) -> None:
        self._emulator = emulator

    def run(
        self,
        request: ChildLaunchRequest,
        target: Any,
        image: LoadedChildImage,
        context: ChildProcessContext,
        budget_hooks: ChildBudgetHooks,
    ) -> ChildExecutionBackendResult:
        """Queue and execute one child entry point.

        Args:
            request: Child launch identity.
            target: Resolved target evidence used to load ``image``.
            image: Mapped non-primary child image.
            context: Active child context from the runtime context manager.
            budget_hooks: Child-only API and instruction accounting callbacks.

        Returns:
            The child report run index and normal-stop evidence.

        Side effects:
            Appends the prepared run to the emulator queue and executes it.
            The child's API and instruction counts are observed only through
            ``budget_hooks``.  The parent's instruction-budget flag is restored
            before returning.

        Raises:
            ChildExecutionRuntimeError: If the run cannot be queued, the
                emulator reports an execution error, or budget accounting is
                rejected.
        """

        del target
        if not request.launch_id:
            raise ChildExecutionRuntimeError(
                "child launch id is missing",
                kind=ChildFailureKind.RUNTIME,
                termination_reason=ChildTerminationReason.INTERNAL_ERROR,
            )
        if image.request_launch_id != request.launch_id:
            raise ChildExecutionRuntimeError(
                "child image does not belong to this launch",
                kind=ChildFailureKind.LOAD,
                termination_reason=ChildTerminationReason.LOAD_ERROR,
            )
        if context.run.start_addr != image.entrypoint_address:
            raise ChildExecutionRuntimeError(
                "child context entry point does not match the loaded image",
                kind=ChildFailureKind.CONTEXT,
                termination_reason=ChildTerminationReason.ENTRYPOINT_OUT_OF_RANGE,
            )
        if self._emulator.curr_process is not context.process:
            raise ChildExecutionRuntimeError(
                "child process context is not active",
                kind=ChildFailureKind.CONTEXT,
                termination_reason=ChildTerminationReason.INTERNAL_ERROR,
            )
        if self._emulator.curr_thread is not context.thread:
            raise ChildExecutionRuntimeError(
                "child thread context is not active",
                kind=ChildFailureKind.CONTEXT,
                termination_reason=ChildTerminationReason.INTERNAL_ERROR,
            )
        if self._emulator.run_queue:
            raise ChildExecutionRuntimeError(
                "child execution requires an empty parent run queue",
                kind=ChildFailureKind.RUNTIME,
                termination_reason=ChildTerminationReason.INTERNAL_ERROR,
            )

        start_index = len(self._emulator.runs)
        parent_budget_exhausted = bool(getattr(self._emulator, "instruction_budget_exhausted", False))
        self._emulator.instruction_budget_exhausted = False
        instruction_budget_hit = False

        def observe_instruction(
            _emulator: Any,
            _address: int,
            _size: int,
        ) -> bool:
            """Count one child instruction and stop at the child-owned limit."""

            nonlocal instruction_budget_hit
            if budget_hooks.observe_instructions(1):
                return True
            instruction_budget_hit = True
            self._emulator.stop()
            return False

        instruction_hook = self._emulator.add_code_hook(
            observe_instruction,
            begin=image.image_base,
            end=image.image_base + image.module.image_size,
        )
        try:
            self._emulator.add_run(context.run)
            self._emulator.start()
        finally:
            instruction_hook.disable()
            child_budget_exhausted = bool(getattr(self._emulator, "instruction_budget_exhausted", False))
            self._emulator.instruction_budget_exhausted = parent_budget_exhausted

        try:
            api_count = max(0, int(getattr(context.run, "num_apis", 0)))
            for _ in range(api_count):
                if not budget_hooks.observe_api():
                    break
            if child_budget_exhausted and not instruction_budget_hit:
                # The engine stopped exactly at its configured instruction
                # count.  One additional observation records the authoritative
                # child-local budget fact without changing parent accounting.
                budget_hooks.observe_instructions(1)
        except Exception as exc:
            raise ChildExecutionRuntimeError(
                f"child budget observation failed: {type(exc).__name__}: {exc}",
                kind=ChildFailureKind.BUDGET,
                termination_reason=ChildTerminationReason.INTERNAL_ERROR,
            ) from exc

        run_indexes = tuple(
            index for index in range(start_index, len(self._emulator.runs)) if self._emulator.runs[index] is context.run
        )
        run_error = getattr(context.run, "error", None)
        if run_error is not None:
            pc = getattr(run_error, "pc", None)
            fault_address = getattr(run_error, "address", None)
            access_type = getattr(run_error, "access_type", None)
            if access_type is None:
                fault_address = None
            error_type = str(
                getattr(run_error, "type", "unknown child runtime error")
            )
            raise ChildExecutionRuntimeError(
                f"child run failed: {error_type}",
                kind=ChildFailureKind.RUNTIME,
                termination_reason=self._termination_for_run_error(run_error),
                run_indexes=run_indexes,
                pc=pc,
                fault_address=fault_address,
                access_type=access_type,
                api_name=getattr(run_error, "api_name", None),
            )
        if not run_indexes:
            raise ChildExecutionRuntimeError(
                "child entry-point run was not recorded",
                kind=ChildFailureKind.RUNTIME,
                termination_reason=ChildTerminationReason.INVALID_FETCH,
            )
        return ChildExecutionBackendResult(run_indexes=run_indexes)

    @staticmethod
    def _termination_for_run_error(
        run_error: Any,
    ) -> ChildTerminationReason:
        """Map one engine run error to a stable child termination reason.

        Args:
            run_error: Emulator ``ErrorInfo``-compatible failure record.

        Returns:
            A child-local terminal reason that preserves the underlying fault
            category instead of treating every execution exception as an
            invalid instruction fetch.

        Side effects:
            None.
        """

        error_type = str(getattr(run_error, "type", "")).casefold()
        if any(
            marker in error_type
            for marker in (
                "invalid memory mapping",
                "uc_err_map",
                "invalid_read",
                "invalid_write",
                "invalid_protect_write",
                "access violation",
            )
        ):
            return ChildTerminationReason.INVALID_MEMORY
        if "invalid fetch" in error_type or "invalid_fetch" in error_type:
            return ChildTerminationReason.INVALID_FETCH
        return ChildTerminationReason.INTERNAL_ERROR


def create_engine_child_scheduler(
    engine: Any,
    options: Any,
) -> ChildExecutionScheduler:
    """Build the production scheduler for one explicitly enabled engine.

    Args:
        engine: Speakeasy wrapper whose ``emu`` is a Windows emulator.
        options: Explicit child-execution options supplied by the caller.
            The adapter itself does not read environment variables.

    Returns:
        A scheduler wired to the concrete engine runtime adapters.

    Side effects:
        Instantiates loader, context, observer, runner, and scheduler objects.
        It does not install hooks, queue runs, or execute child code.

    Raises:
        ValueError: If ``options`` is already known to be disabled.
    """

    if not bool(getattr(options, "enabled", False)):
        raise ValueError("engine child scheduler requires explicitly enabled options")
    emulator = engine.emu
    loader = ChildImageRuntimeLoader(
        PeChildImageMaterializer(EngineChildImageBaseAllocator(emulator)),
        EngineChildImageMapper(emulator),
    )
    context_manager = ChildRuntimeContextManager(EngineChildRuntimeContextBackend(emulator))
    runner = ChildExecutionRunner(
        backend=EngineChildExecutionBackend(emulator),
        entrypoint_observer=OneShotChildEntrypointObserver(EngineChildEntrypointHookBackend(emulator)),
        budget_factory=ExecutionBudgetFactory(),
        clock=time.monotonic,
    )
    return ChildExecutionScheduler(
        loader=loader,
        context_manager=context_manager,
        runner=runner,
        budget_factory=ExecutionBudgetFactory(),
    )


__all__ = [
    "EngineChildEntrypointHookBackend",
    "EngineChildExecutionBackend",
    "EngineChildRuntimeContextBackend",
    "create_engine_child_scheduler",
]
