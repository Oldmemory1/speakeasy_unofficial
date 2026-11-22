"""Concrete child runtime adapters for the Windows emulator.

The adapters in this module are deliberately limited to the child-execution
package.  They compose the existing loader, context manager, observer, runner,
and scheduler through public emulator operations and never install global
hooks or alter detector behavior.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from speakeasy.profiler import Run
from speakeasy.windows.process_memory import ProcessAddressSpace, ProcessMemoryError

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


@dataclass(frozen=True)
class _RuntimeImageBackfill:
    """Prepared projection of one executing child's runtime image pages.

    Attributes:
        address_space: The child process's per-process shadow view.
        runtime_base: Address where the child image is mapped in the shared
            emulator memory. It may differ from the shadow image base because
            the loader relocates the child image away from its preferred base.
        image_size: Child PE ``SizeOfImage`` in bytes.
        page_size: Emulator page size used to slice the runtime snapshot.
        before: Runtime image bytes captured before the child run.
    """

    address_space: ProcessAddressSpace
    runtime_base: int
    image_size: int
    page_size: int
    before: bytes


class EngineChildExecutionBackend:
    """Execute one prepared child run through the emulator run queue.

    Args:
        emulator: Windows emulator exposing run-queue, start, run history,
            current-context, instruction-budget state, page size, and the
            executor-only ``get_executing_process_address_space`` view.

    The backend executes exactly the run prepared by the context manager.  It
    restores the parent instruction-budget flag after the child and never
    changes parent process or run history.  After the child runs, pages of its
    mapped image whose runtime bytes changed are projected into the child's
    per-process shadow view (``AddressSpace / per_process_isolation``); the
    parent's global view is never modified (FX12-extended-rv1).
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
            before returning.  When a shadow view is available, pages of the
            child's runtime image that changed during the run are projected
            into that view; the parent's global memory is never modified.

        Raises:
            ChildExecutionRuntimeError: If the run cannot be queued, the
                emulator reports an execution error, budget accounting is
                rejected, or an observed runtime write cannot be projected into
                the child's shadow view.
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

        # FX12-extended-rv1: the child executes in the emulator's shared
        # memory, so the per-process shadow view is the projection target for
        # its runtime writes.  Preparing the snapshot before the run and
        # diffing afterwards captures CPU writes and engine/API-handler writes
        # without intercepting unrelated memory traffic.
        backfill = self._prepare_runtime_image_backfill(context.process, image)

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
            backfill_error: ChildExecutionRuntimeError | None = None
            try:
                self._backfill_runtime_image(backfill)
            except ChildExecutionRuntimeError as exc:
                # A failed projection must never mask an execution error that
                # is already propagating; it is reported below when the run
                # itself completed.
                backfill_error = exc

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
        if backfill_error is not None:
            raise ChildExecutionRuntimeError(
                str(backfill_error),
                kind=backfill_error.kind,
                termination_reason=backfill_error.termination_reason,
                run_indexes=run_indexes,
            ) from backfill_error
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

    def _prepare_runtime_image_backfill(
        self,
        process: Any,
        image: LoadedChildImage,
    ) -> _RuntimeImageBackfill:
        """Ensure the child's shadow view and snapshot its runtime image.

        Args:
            process: Child process installed as the emulator's current process.
            image: Mapped non-primary child image about to execute.

        Returns:
            The projection target and the pre-execution runtime image bytes.

        Raises:
            ChildExecutionRuntimeError: If the child shadow view cannot be
                seeded (``ProcessMemoryError``) or the runtime image cannot be
                read.  Both are explicit failures; no bytes are fabricated.

        Side effects:
            Creates and caches the child's shadow view when it does not exist
            yet.  This is the same bookkeeping view ``ReadProcessMemory``
            would create; it never maps Unicorn memory and never executes
            code.
        """

        try:
            space = self._emulator.get_executing_process_address_space(process)
        except ProcessMemoryError as exc:
            raise ChildExecutionRuntimeError(
                f"cannot prepare child shadow view: Win32 error {exc.win_error}: {exc}",
                kind=ChildFailureKind.RUNTIME,
                termination_reason=ChildTerminationReason.INVALID_MEMORY,
            ) from exc

        runtime_base = int(image.image_base)
        image_size = int(image.module.image_size)
        page_size = int(self._emulator.page_size or 0)
        if page_size <= 0:
            raise ChildExecutionRuntimeError(
                "child runtime page size is unavailable",
                kind=ChildFailureKind.RUNTIME,
                termination_reason=ChildTerminationReason.INTERNAL_ERROR,
            )
        return _RuntimeImageBackfill(
            address_space=space,
            runtime_base=runtime_base,
            image_size=image_size,
            page_size=page_size,
            before=self._read_runtime_image_bytes(runtime_base, image_size),
        )

    def _read_runtime_image_bytes(self, base: int, size: int) -> bytes:
        """Read exactly ``size`` runtime image bytes from shared memory.

        Args:
            base: Runtime image base in the emulator's shared memory.
            size: Child PE ``SizeOfImage``.

        Returns:
            The current runtime image bytes.

        Raises:
            ChildExecutionRuntimeError: ``INVALID_MEMORY`` when the image size
                is not positive or the engine cannot read the mapped image.
        """

        if size <= 0:
            raise ChildExecutionRuntimeError(
                "child runtime image has no size",
                kind=ChildFailureKind.RUNTIME,
                termination_reason=ChildTerminationReason.INVALID_MEMORY,
            )
        try:
            data = bytes(self._emulator.mem_read(base, size))
        except Exception as exc:
            raise ChildExecutionRuntimeError(
                f"cannot read child runtime image at 0x{base:x}: "
                f"{type(exc).__name__}: {exc}",
                kind=ChildFailureKind.RUNTIME,
                termination_reason=ChildTerminationReason.INVALID_MEMORY,
            ) from exc
        if len(data) != size:
            raise ChildExecutionRuntimeError(
                f"short child runtime image read at 0x{base:x}: "
                f"{len(data)} of {size} bytes",
                kind=ChildFailureKind.RUNTIME,
                termination_reason=ChildTerminationReason.INVALID_MEMORY,
            )
        return data

    def _backfill_runtime_image(self, backfill: _RuntimeImageBackfill) -> int:
        """Project changed runtime image pages into the child shadow view.

        Only pages whose runtime bytes changed between the pre-run snapshot
        and the post-run image are projected, so a child run that performs no
        writes backfills nothing.  If the shadow view exists but cannot
        describe the runtime image (no/duplicate image region or a size
        mismatch), or a changed page is unmapped/decommitted in the shadow, the
        failure is explicit instead of silently succeeding.

        Args:
            backfill: Prepared projection target and pre-run image snapshot.

        Returns:
            Number of pages projected.

        Raises:
            ChildExecutionRuntimeError: ``INVALID_MEMORY`` for a shadow view
                that cannot describe the runtime image or a page that the
                shadow refuses (``ProcessMemoryError``).
        """

        after = self._read_runtime_image_bytes(backfill.runtime_base, backfill.image_size)
        changed: list[tuple[int, bytes]] = []
        for offset in range(0, backfill.image_size, backfill.page_size):
            page_before = backfill.before[offset : offset + backfill.page_size]
            page_after = after[offset : offset + backfill.page_size]
            if page_before != page_after:
                changed.append((offset, page_after))
        if not changed:
            return 0

        shadow_base = self._shadow_image_base(backfill.address_space, backfill.image_size)
        projected = 0
        for offset, data in changed:
            try:
                backfill.address_space.capture_runtime_write(shadow_base + offset, data)
            except ProcessMemoryError as exc:
                raise ChildExecutionRuntimeError(
                    f"cannot backfill child runtime write at shadow address "
                    f"0x{shadow_base + offset:x}: Win32 error {exc.win_error}: {exc}",
                    kind=ChildFailureKind.RUNTIME,
                    termination_reason=ChildTerminationReason.INVALID_MEMORY,
                ) from exc
            projected += 1
        return projected

    @staticmethod
    def _shadow_image_base(space: ProcessAddressSpace, image_size: int) -> int:
        """Return the shadow image-region base matching one runtime image.

        Args:
            space: Child process's per-process shadow view.
            image_size: Runtime PE ``SizeOfImage``.

        Returns:
            The base of the single image region in the shadow view.

        Raises:
            ChildExecutionRuntimeError: ``INVALID_MEMORY`` when the view holds
                no image region, more than one image region, or an image region
                whose size differs from the runtime image.  Runtime page
                offsets cannot be projected unambiguously in those cases.
        """

        image_regions = [region for region in space.regions if region.is_image]
        if len(image_regions) != 1:
            raise ChildExecutionRuntimeError(
                f"child shadow view has {len(image_regions)} image regions; "
                "exactly one is required for runtime backfill",
                kind=ChildFailureKind.RUNTIME,
                termination_reason=ChildTerminationReason.INVALID_MEMORY,
            )
        region = image_regions[0]
        if int(region.size) != image_size:
            raise ChildExecutionRuntimeError(
                f"child shadow image size 0x{int(region.size):x} does not match "
                f"runtime image size 0x{image_size:x}",
                kind=ChildFailureKind.RUNTIME,
                termination_reason=ChildTerminationReason.INVALID_MEMORY,
            )
        return int(region.base)


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
