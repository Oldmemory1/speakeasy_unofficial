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
from speakeasy.windows.page_protection import (
    emulator_page_win_protection,
    is_virtual_alloc_view,
)
from speakeasy.windows.process_memory import (
    MAX_SHADOW_REGION_SIZE,
    MEM_RELEASE,
    SHADOW_MATERIALIZED_TAG_PREFIX,
    ProcessAddressSpace,
    ProcessMemoryError,
)

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
class _ChildMapSpan:
    """One page-aligned span of child-attributed runtime mappings.

    Attributes:
        base: Page-aligned span base.
        size: Page-aligned span size.
        tag: Diagnostic tag of the first mapping in the span.
        sample_addresses: ``(page, address)`` pairs where ``address`` is mapped
            inside ``page``.  Used to sample the effective Win32 protection even
            when a heap mapping starts mid-page.
        allocation_protect: Win32 allocation protection for adoption: the
            private ``VirtualAlloc`` ``flProtect`` when present, otherwise the
            first page's effective protection.
    """

    base: int
    size: int
    tag: str
    sample_addresses: tuple[tuple[int, int], ...]
    allocation_protect: int


@dataclass(frozen=True)
class _RuntimeRangeSnapshot:
    """Prepared projection source for one runtime range.

    Attributes:
        base: Runtime address of the range in the shared emulator.
        size: Range size in bytes.
        page_size: Emulator page size used to slice the snapshot.
        before: Pre-run runtime bytes; ``None`` means the range did not exist.
        kind: ``"image"``, ``"child_mapping"`` or ``"shadow_materialized"``.
        shadow_base: Shadow-view address the range projects onto.
        tag: Diagnostic label of the runtime mapping/region.
    """

    base: int
    size: int
    page_size: int
    before: bytes | None
    kind: str
    shadow_base: int
    tag: str


@dataclass(frozen=True)
class _RuntimeBackfill:
    """Prepared projection and materialization state for one child run.

    Attributes:
        address_space: The child process's per-process shadow view.
        process: Child process that owns the runtime mappings.
        image_base: Runtime base of the child's mapped image.
        image_size: Runtime PE ``SizeOfImage``.
        page_size: Emulator page size.
        ranges: Runtime ranges snapshotted before the run.
        materialized: Mappings created by ``materialize_process_shadow`` that
            must be released after the run.
    """

    address_space: ProcessAddressSpace
    process: Any
    image_base: int
    image_size: int
    page_size: int
    ranges: tuple[_RuntimeRangeSnapshot, ...]
    materialized: tuple[Any, ...]


class EngineChildExecutionBackend:
    """Execute one prepared child run through the emulator run queue.

    Args:
        emulator: Windows emulator exposing run-queue, start, run history,
            current-context, instruction-budget state, page size, and the
            executor-only ``get_executing_process_address_space`` view.

    The backend executes exactly the run prepared by the context manager.  It
    restores the parent instruction-budget flag after the child and never
    changes parent process or run history.  Before the run it snapshots the
    child's mapped image, every child-attributed runtime mapping outside the
    image, and (phase B) materializes non-image shadow reservations at their
    exact bases.  After the run it projects changed bytes and runtime ``PAGE_*``
    protections into the child's per-process shadow view and releases every
    materialized mapping; the parent's global view is never modified
    (FX12-extended-rv2, following FX12-extended-rv1).
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

        # FX12-extended-rv2: the child executes in the emulator's shared
        # memory, so the per-process shadow view is the projection target for
        # its runtime writes.  Preparation snapshots the runtime image, every
        # child-attributed mapping outside it, and materializes non-image
        # shadow reservations for the duration of the run.  Post-run diffing
        # captures CPU and API-handler writes without intercepting unrelated
        # memory traffic; materialized mappings are always released.
        backfill = self._prepare_runtime_backfill(context.process, image)

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

        instruction_hook: Any | None = None
        try:
            instruction_hook = self._emulator.add_code_hook(
                observe_instruction,
                begin=image.image_base,
                end=image.image_base + image.module.image_size,
            )
            self._emulator.add_run(context.run)
            self._emulator.start()
        finally:
            if instruction_hook is not None:
                instruction_hook.disable()
            child_budget_exhausted = bool(getattr(self._emulator, "instruction_budget_exhausted", False))
            self._emulator.instruction_budget_exhausted = parent_budget_exhausted
            backfill_error: ChildExecutionRuntimeError | None = None
            try:
                self._backfill_runtime_memory(backfill)
            except ChildExecutionRuntimeError as exc:
                # A failed projection must never mask an execution error that
                # is already propagating; it is reported below when the run
                # itself completed.
                backfill_error = exc
            finally:
                if backfill.materialized:
                    try:
                        self._emulator.release_materialized_process_shadow(
                            backfill.materialized
                        )
                    except ProcessMemoryError as exc:
                        if backfill_error is None:
                            backfill_error = ChildExecutionRuntimeError(
                                f"cannot release materialized child shadow: "
                                f"Win32 error {exc.win_error}: {exc}",
                                kind=ChildFailureKind.RUNTIME,
                                termination_reason=ChildTerminationReason.INVALID_MEMORY,
                            )

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

    def _prepare_runtime_backfill(
        self,
        process: Any,
        image: LoadedChildImage,
    ) -> _RuntimeBackfill:
        """Ensure the child's shadow view and snapshot every runtime range.

        Preparation covers three kinds of runtime state:

        * the mapped child image (``kind="image"``), projected at the shadow
          image base so relocated children map by page offset;
        * every child-attributed runtime mapping outside the image span
          (``kind="child_mapping"``), including ``VirtualAlloc`` and heap maps;
        * each non-image shadow region materialized for this run
          (``kind="shadow_materialized"``).

        Image regions are never materialized.  The parent's mappings and the
        global stack/PEB are excluded (their ``MemMap.process`` is not the
        child), so engine bookkeeping is never projected as child writes.

        Args:
            process: Child process installed as the emulator's current process.
            image: Mapped non-primary child image about to execute.

        Returns:
            The projection target, pre-execution snapshots, and materialized
            mappings that must be released after the run.

        Raises:
            ChildExecutionRuntimeError: ``INVALID_MEMORY`` when the shadow view
                cannot be seeded, a range cannot be read, a range is oversized,
                the aggregate snapshot exceeds ``MAX_SHADOW_REGION_SIZE``, or
                materialization fails explicitly (for example a Win32 487
                collision).  No bytes are fabricated.

        Side effects:
            Creates and caches the child's shadow view when it does not exist
            yet, and creates temporary emulator mappings for non-image shadow
            regions.  Those mappings are released by the caller in ``finally``.
        """

        try:
            space = self._emulator.get_executing_process_address_space(process)
        except ProcessMemoryError as exc:
            raise ChildExecutionRuntimeError(
                f"cannot prepare child shadow view: Win32 error {exc.win_error}: {exc}",
                kind=ChildFailureKind.RUNTIME,
                termination_reason=ChildTerminationReason.INVALID_MEMORY,
            ) from exc

        image_base = int(image.image_base)
        image_size = int(image.module.image_size)
        page_size = int(self._emulator.page_size or 0)
        if page_size <= 0:
            raise ChildExecutionRuntimeError(
                "child runtime page size is unavailable",
                kind=ChildFailureKind.RUNTIME,
                termination_reason=ChildTerminationReason.INTERNAL_ERROR,
            )
        if image_size <= 0:
            raise self._memory_error("child runtime image has no size")

        shadow_base = self._shadow_image_base(space, image_size)
        image_before = self._read_runtime_bytes(image_base, image_size, "runtime image")
        ranges: list[_RuntimeRangeSnapshot] = [
            _RuntimeRangeSnapshot(
                base=image_base,
                size=image_size,
                page_size=page_size,
                before=image_before,
                kind="image",
                shadow_base=shadow_base,
                tag=str(getattr(image.module, "emu_path", "")),
            )
        ]

        total_size = image_size
        spans = self._child_map_spans(process, image_base, image_size, page_size)
        for span in spans:
            total_size += span.size
            if total_size > MAX_SHADOW_REGION_SIZE:
                raise self._memory_error(
                    "child runtime snapshot exceeds the maximum shadow region size"
                )
            before = self._read_runtime_bytes(
                span.base, span.size, f"child runtime mapping at 0x{span.base:x}"
            )
            ranges.append(
                _RuntimeRangeSnapshot(
                    base=span.base,
                    size=span.size,
                    page_size=page_size,
                    before=before,
                    kind="child_mapping",
                    shadow_base=span.base,
                    tag=span.tag,
                )
            )

        materialized: tuple[Any, ...] = ()
        if any(not region.is_image and int(region.size) > 0 for region in space.regions):
            try:
                materialized = tuple(self._emulator.materialize_process_shadow(process))
            except ProcessMemoryError as exc:
                raise ChildExecutionRuntimeError(
                    f"cannot materialize child shadow: Win32 error {exc.win_error}: {exc}",
                    kind=ChildFailureKind.RUNTIME,
                    termination_reason=ChildTerminationReason.INVALID_MEMORY,
                ) from exc

        try:
            for region in materialized:
                base = int(region.base)
                size = int(region.size)
                if size <= 0 or size > MAX_SHADOW_REGION_SIZE:
                    raise self._memory_error(
                        f"materialized child shadow region at 0x{base:x} "
                        "has an invalid size"
                    )
                shadow_region = self._shadow_region_at(space, base, size)
                ranges.append(
                    _RuntimeRangeSnapshot(
                        base=base,
                        size=size,
                        page_size=page_size,
                        before=bytes(shadow_region.data),
                        kind="shadow_materialized",
                        shadow_base=base,
                        tag=str(region.tag),
                    )
                )
        except Exception:
            # A failure after physical backing was created must not leak it.
            self._release_materialized(materialized)
            raise

        return _RuntimeBackfill(
            address_space=space,
            process=process,
            image_base=image_base,
            image_size=image_size,
            page_size=page_size,
            ranges=tuple(ranges),
            materialized=materialized,
        )

    def _child_map_spans(
        self,
        process: Any,
        image_base: int,
        image_size: int,
        page_size: int,
    ) -> tuple[_ChildMapSpan, ...]:
        """Return page-aligned spans of child-attributed runtime mappings.

        Selection: ``MemMap.process is process``, not free, integer base/size,
        positive and bounded size, no overlap with the runtime image span, and
        not a materialized child-shadow mapping (those are tracked separately).
        Mappings whose page envelopes overlap (for example sub-page heap
        allocations in one emulator block) merge into one page-aligned span;
        merely adjacent mappings stay separate so an unchanged mapping is never
        adopted because its neighbour changed.

        Args:
            process: Child process owning the mappings.
            image_base: Runtime image base.
            image_size: Runtime PE ``SizeOfImage``.
            page_size: Emulator page size.

        Returns:
            Spans in ascending address order with one in-page sample address per
            page and a Win32 allocation protection.

        Raises:
            ChildExecutionRuntimeError: ``INVALID_MEMORY`` for a mapping larger
                than ``MAX_SHADOW_REGION_SIZE`` or a page not backed by a map.
        """

        image_start = image_base & ~(page_size - 1)
        image_end = (image_base + image_size + page_size - 1) & ~(page_size - 1)

        entries: list[tuple[int, int, Any]] = []
        for mm in self._emulator.get_mem_maps():
            if getattr(mm, "process", None) is not process:
                continue
            if bool(getattr(mm, "free", False)):
                continue
            base = getattr(mm, "base", None)
            size = getattr(mm, "size", None)
            if not isinstance(base, int) or not isinstance(size, int):
                continue
            if size <= 0:
                continue
            if str(getattr(mm, "tag", "")).startswith(SHADOW_MATERIALIZED_TAG_PREFIX):
                continue
            if size > MAX_SHADOW_REGION_SIZE:
                raise self._memory_error(
                    f"child runtime mapping at 0x{base:x} is too large to snapshot"
                )
            start = base & ~(page_size - 1)
            end = (base + size + page_size - 1) & ~(page_size - 1)
            if end <= start:
                continue
            if start < image_end and image_start < end:
                continue
            entries.append((start, end, mm))

        entries.sort(key=lambda entry: (entry[0], entry[1]))
        merged: list[list[Any]] = []
        for start, end, mm in entries:
            if merged and start < merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
                merged[-1][2].append(mm)
            else:
                merged.append([start, end, [mm]])

        spans: list[_ChildMapSpan] = []
        for start, end, mm_list in merged:
            size = end - start
            if size > MAX_SHADOW_REGION_SIZE:
                raise self._memory_error(
                    f"merged child runtime span at 0x{start:x} is too large to snapshot"
                )
            samples: dict[int, int] = {}
            for mm in mm_list:
                mstart = int(mm.base) & ~(page_size - 1)
                mend = (int(mm.base) + int(mm.size) + page_size - 1) & ~(page_size - 1)
                for page in range(mstart, mend, page_size):
                    samples.setdefault(page, max(page, int(mm.base)))
            sample_addresses: list[tuple[int, int]] = []
            for page in range(start, end, page_size):
                sample = samples.get(page)
                if sample is None:
                    raise self._memory_error(
                        f"child runtime page 0x{page:x} is not backed by a mapping"
                    )
                sample_addresses.append((page, sample))
            first = mm_list[0]
            allocation_protect = 0
            if is_virtual_alloc_view(first):
                allocation_protect = int(first.flags) & 0xFF
            if not allocation_protect:
                protect = emulator_page_win_protection(
                    self._emulator, sample_addresses[0][1]
                )
                if protect is None:
                    raise self._memory_error(
                        f"child runtime page 0x{sample_addresses[0][0]:x} has no protection"
                    )
                allocation_protect = int(protect)
            spans.append(
                _ChildMapSpan(
                    base=start,
                    size=size,
                    tag=str(getattr(first, "tag", "")),
                    sample_addresses=tuple(sample_addresses),
                    allocation_protect=allocation_protect,
                )
            )
        return tuple(spans)

    @staticmethod
    def _find_shadow_region(space: ProcessAddressSpace, base: int) -> Any | None:
        """Return the shadow region whose base equals ``base``, if any."""

        for region in space.regions:
            if int(region.base) == int(base):
                return region
        return None

    def _shadow_region_at(
        self, space: ProcessAddressSpace, base: int, size: int
    ) -> Any:
        """Return the exact-base shadow region or fail explicitly."""

        region = self._find_shadow_region(space, base)
        if region is None:
            raise self._memory_error(
                f"materialized child shadow region at 0x{base:x} is missing"
            )
        if int(region.size) != int(size):
            raise self._memory_error(
                f"materialized child shadow region size 0x{int(region.size):x} "
                f"does not match 0x{int(size):x}"
            )
        return region

    @staticmethod
    def _memory_error(message: str) -> ChildExecutionRuntimeError:
        """Build one explicit child ``INVALID_MEMORY`` failure."""

        return ChildExecutionRuntimeError(
            message,
            kind=ChildFailureKind.RUNTIME,
            termination_reason=ChildTerminationReason.INVALID_MEMORY,
        )

    def _release_materialized(self, materialized: tuple[Any, ...]) -> None:
        """Release materialized mappings after a preparation failure.

        Args:
            materialized: Tuple returned by ``materialize_process_shadow``.

        Raises:
            ChildExecutionRuntimeError: ``INVALID_MEMORY`` when the emulator
                refuses to release a mapping it created.
        """

        if not materialized:
            return
        try:
            self._emulator.release_materialized_process_shadow(materialized)
        except ProcessMemoryError as exc:
            raise self._memory_error(
                f"cannot release materialized child shadow during preparation: "
                f"Win32 error {exc.win_error}: {exc}"
            ) from exc

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

        return self._read_runtime_bytes(base, size, "runtime image")

    def _read_runtime_bytes(self, base: int, size: int, label: str) -> bytes:
        """Read exactly ``size`` runtime bytes from the shared emulator.

        Args:
            base: Runtime address.
            size: Number of bytes to read.
            label: Diagnostic label used in explicit failures.

        Returns:
            The current runtime bytes.

        Raises:
            ChildExecutionRuntimeError: ``INVALID_MEMORY`` when ``size`` is not
                positive, the engine read fails, or the read is short.
        """

        if size <= 0:
            raise self._memory_error(f"{label} has no size")
        try:
            data = bytes(self._emulator.mem_read(base, size))
        except Exception as exc:
            raise ChildExecutionRuntimeError(
                f"cannot read {label} at 0x{base:x}: {type(exc).__name__}: {exc}",
                kind=ChildFailureKind.RUNTIME,
                termination_reason=ChildTerminationReason.INVALID_MEMORY,
            ) from exc
        if len(data) != size:
            raise self._memory_error(
                f"short {label} read at 0x{base:x}: {len(data)} of {size} bytes"
            )
        return data

    def _backfill_runtime_memory(self, backfill: _RuntimeBackfill) -> int:
        """Project runtime bytes and protections into the child shadow view.

        The post-run state is reconciled per range:

        * image pages are diffed by offset against the shadow image base;
        * child-attributed mappings that still exist are diffed at their own
          addresses; maps that disappeared were freed by the child and release
          any exact-base shadow region;
        * materialized shadow regions are diffed while their mapping exists;
        * mappings created during the run are adopted with their complete
          post-run bytes and per-page protections.

        A pre-existing child mapping without a shadow region is adopted only
        when its bytes changed; an unchanged mapping is not re-adopted.  Pages
        whose protection changed without byte changes are synchronized through
        ``sync_runtime_protections``.  An unmapped runtime page or a refused
        shadow page is an explicit ``INVALID_MEMORY`` failure.

        Args:
            backfill: Prepared projection target, snapshots, and materialized
                mappings from :meth:`_prepare_runtime_backfill`.

        Returns:
            Number of pages projected or adopted.

        Raises:
            ChildExecutionRuntimeError: ``INVALID_MEMORY`` for an unreadable
                runtime range or a shadow view that refuses the projection.
        """

        current_spans = self._child_map_spans(
            backfill.process,
            backfill.image_base,
            backfill.image_size,
            backfill.page_size,
        )
        current_by_base = {span.base: span for span in current_spans}
        projected = 0

        for snap in backfill.ranges:
            if snap.kind == "image":
                after = self._read_runtime_bytes(snap.base, snap.size, "runtime image")
                projected += self._project_range(
                    backfill.address_space, snap, after, span=None
                )
                continue
            if snap.kind == "shadow_materialized":
                mm = self._emulator.get_address_map(snap.base)
                if mm is None or bool(getattr(mm, "free", False)):
                    # The child freed the materialized reservation.  MEM_RELEASE
                    # and MEM_DECOMMIT are indistinguishable after the fact;
                    # both leave the shadow reservation accessible only through
                    # a fresh MEM_COMMIT, so release the modeled region.
                    self._release_shadow_region(backfill.address_space, snap.base)
                    continue
                after = self._read_runtime_bytes(
                    snap.base, snap.size, f"child runtime mapping at 0x{snap.base:x}"
                )
                projected += self._project_range(
                    backfill.address_space, snap, after, span=None
                )
                continue

            span = current_by_base.get(snap.base)
            if span is None or span.size != snap.size:
                self._release_shadow_region(backfill.address_space, snap.base)
                continue
            after = self._read_runtime_bytes(
                snap.base, snap.size, f"child runtime mapping at 0x{snap.base:x}"
            )
            projected += self._project_range(
                backfill.address_space, snap, after, span=span
            )

        pre_existing = {
            (snap.base, snap.size)
            for snap in backfill.ranges
            if snap.kind == "child_mapping"
        }
        for span in current_spans:
            if (span.base, span.size) in pre_existing:
                continue
            payload = self._read_runtime_bytes(
                span.base, span.size, f"child runtime mapping at 0x{span.base:x}"
            )
            projected += self._adopt_span(
                backfill.address_space, span, payload, backfill.page_size
            )
        return projected

    def _project_range(
        self,
        space: ProcessAddressSpace,
        snap: _RuntimeRangeSnapshot,
        after: bytes,
        *,
        span: _ChildMapSpan | None,
    ) -> int:
        """Project one runtime range's changed bytes and protections.

        Args:
            space: Child shadow view.
            snap: Pre-run snapshot for the range.
            after: Post-run runtime bytes of the same length.
            span: Runtime span description for child mappings; ``None`` for the
                image and page-aligned materialized ranges.

        Returns:
            Number of pages with changed bytes that were projected.

        Raises:
            ChildExecutionRuntimeError: ``INVALID_MEMORY`` when the shadow
                region is missing/size-mismatched, a runtime page is unmapped,
                or the shadow refuses the projection.
        """

        before = snap.before
        if before is None or len(before) != len(after):
            raise self._memory_error(
                f"runtime range at 0x{snap.base:x} changed size during the run"
            )
        if span is not None:
            samples = dict(span.sample_addresses)
        else:
            samples = {
                snap.base + offset: snap.base + offset
                for offset in range(0, len(after), snap.page_size)
            }

        existing = self._find_shadow_region(space, snap.shadow_base)
        if existing is None:
            if snap.kind != "child_mapping":
                raise self._memory_error(
                    f"shadow region for {snap.kind} at 0x{snap.shadow_base:x} is missing"
                )
            if before == after:
                return 0
            if span is None:
                raise self._memory_error(
                    f"cannot adopt child runtime mapping at 0x{snap.base:x}"
                )
            return self._adopt_span(space, span, after, snap.page_size)
        if int(existing.size) != len(after):
            raise self._memory_error(
                f"shadow region at 0x{snap.shadow_base:x} has size "
                f"0x{int(existing.size):x}; runtime range is 0x{len(after):x}"
            )

        projected = 0
        for offset in range(0, len(after), snap.page_size):
            page_before = before[offset : offset + snap.page_size]
            page_after = after[offset : offset + snap.page_size]
            runtime_page = snap.base + offset
            sample = samples.get(runtime_page)
            if sample is None:
                raise self._memory_error(
                    f"runtime page 0x{runtime_page:x} is not backed by a mapping"
                )
            protect = emulator_page_win_protection(self._emulator, sample)
            if protect is None:
                raise self._memory_error(f"runtime page 0x{runtime_page:x} is not mapped")
            shadow_page = snap.shadow_base + offset
            snapshot = space.query(shadow_page)
            if snapshot is None:
                raise self._memory_error(
                    f"shadow page 0x{shadow_page:x} is not mapped in process {space.pid}"
                )
            try:
                if page_before != page_after:
                    space.sync_runtime_region(
                        shadow_page, page_after, page_protections=[int(protect)]
                    )
                    projected += 1
                elif int(snapshot["protect"]) != int(protect):
                    space.sync_runtime_protections(shadow_page, [int(protect)])
            except ProcessMemoryError as exc:
                raise ChildExecutionRuntimeError(
                    f"cannot backfill child runtime state at shadow address "
                    f"0x{shadow_page:x}: Win32 error {exc.win_error}: {exc}",
                    kind=ChildFailureKind.RUNTIME,
                    termination_reason=ChildTerminationReason.INVALID_MEMORY,
                ) from exc
        return projected

    def _adopt_span(
        self,
        space: ProcessAddressSpace,
        span: _ChildMapSpan,
        payload: bytes,
        page_size: int,
    ) -> int:
        """Adopt one child-attributed runtime span into the shadow view.

        Args:
            space: Child shadow view.
            span: Runtime span description with one sample address per page.
            payload: Complete post-run bytes of the span.
            page_size: Emulator page size.

        Returns:
            Number of pages adopted.

        Raises:
            ChildExecutionRuntimeError: ``INVALID_MEMORY`` when a page has no
                runtime protection or the shadow refuses the region.
        """

        protections: list[int] = []
        for page, sample in span.sample_addresses:
            protect = emulator_page_win_protection(self._emulator, sample)
            if protect is None:
                raise self._memory_error(
                    f"runtime page 0x{page:x} is not mapped for child adoption"
                )
            protections.append(int(protect))
        try:
            space.adopt_runtime_region(
                span.base,
                span.size,
                payload,
                page_protections=protections,
                allocation_protect=span.allocation_protect,
                tag=span.tag,
            )
        except ProcessMemoryError as exc:
            raise ChildExecutionRuntimeError(
                f"cannot adopt child runtime mapping at 0x{span.base:x}: "
                f"Win32 error {exc.win_error}: {exc}",
                kind=ChildFailureKind.RUNTIME,
                termination_reason=ChildTerminationReason.INVALID_MEMORY,
            ) from exc
        return span.size // page_size

    def _release_shadow_region(self, space: ProcessAddressSpace, base: int) -> None:
        """Release the exact-base shadow region for a runtime map the child freed.

        Args:
            space: Child shadow view.
            base: Runtime mapping base.

        Raises:
            ChildExecutionRuntimeError: ``INVALID_MEMORY`` when the shadow view
                refuses the release.
        """

        region = self._find_shadow_region(space, base)
        if region is None:
            return
        try:
            space.unmap(base, 0, MEM_RELEASE)
        except ProcessMemoryError as exc:
            raise ChildExecutionRuntimeError(
                f"cannot release child shadow region at 0x{base:x}: "
                f"Win32 error {exc.win_error}: {exc}",
                kind=ChildFailureKind.RUNTIME,
                termination_reason=ChildTerminationReason.INVALID_MEMORY,
            ) from exc

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
