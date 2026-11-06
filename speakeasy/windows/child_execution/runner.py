"""Execute one loaded child image and convert all outcomes to child results.

The runner is deliberately isolated from concrete emulator objects.  A child
runtime backend is injected through :class:`ChildExecutionBackend`; the runner
therefore controls lifecycle and accounting without patching the engine or
depending on its private state.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from .interfaces import (
    ChildBudgetFactory,
    ChildEntrypointObserver,
)
from .models import (
    BudgetUsage,
    ChildExecutionState,
    ChildFailure,
    ChildFailureKind,
    ChildLaunchRequest,
    ChildOutcome,
    ChildProcessContext,
    ChildRunResult,
    ChildTerminationReason,
    ExecutionBudget,
    LoadedChildImage,
    ResolvedChildTarget,
)


class ChildBudgetHooks(Protocol):
    """Budget callbacks supplied to a backend during one child execution.

    The backend must invoke ``observe_api`` exactly once for every emulated API
    call and ``observe_instructions`` for batches of emulated instructions.  It
    must stop execution immediately when either callback or ``should_continue``
    returns ``False``.
    """

    def observe_api(self) -> bool:
        """Record one API call and return whether execution may continue."""
        ...

    def observe_instructions(self, count: int = 1) -> bool:
        """Record instructions and return whether execution may continue."""
        ...

    def should_continue(self) -> bool:
        """Refresh elapsed time and return whether execution may continue."""
        ...


@dataclass(frozen=True)
class ChildExecutionBackendResult:
    """Facts reported by a backend after it stops executing child code.

    Args:
        run_indexes: Engine run indexes actually queued for the child.  An empty
            tuple proves that no child entry-point run was queued.
        returned_to_caller: Whether execution ended by returning to the return
            hook instead of an explicit normal-exit hook.
        reason: Optional machine-readable backend stop reason.
    """

    run_indexes: tuple[int, ...]
    returned_to_caller: bool = False
    reason: str | None = None


class ChildExecutionRuntimeError(Exception):
    """Expected backend failure that must become a child result.

    Args:
        message: Human-readable failure detail.
        kind: Failure boundary responsible for the error.
        termination_reason: Machine-readable child termination classification.
    """

    def __init__(
        self,
        message: str,
        *,
        kind: ChildFailureKind = ChildFailureKind.RUNTIME,
        termination_reason: ChildTerminationReason = ChildTerminationReason.INTERNAL_ERROR,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.termination_reason = termination_reason


class ChildExecutionBackend(Protocol):
    """Queue and execute one already-loaded child image.

    Implementations adapt the public emulator runtime.  They must not create
    process contexts, alter parent metadata, schedule grandchildren, or swallow
    budget callbacks.  Expected runtime errors should raise
    :class:`ChildExecutionRuntimeError`; unexpected exceptions are also caught
    and isolated by the runner.
    """

    def run(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
        image: LoadedChildImage,
        context: ChildProcessContext,
        budget_hooks: ChildBudgetHooks,
    ) -> ChildExecutionBackendResult:
        """Execute one child entry point within the supplied context.

        Args:
            request: Child launch and ownership identity.
            target: Resolved target evidence.
            image: Loaded non-primary child image.
            context: Active child process/thread/run context.
            budget_hooks: Live callbacks that enforce the child budget.

        Returns:
            Run indexes and normal-stop facts for the completed backend call.

        Side effects:
            Queues and executes emulated child code.  The backend may mutate
            engine execution state inside ``context`` but must not modify root
            metadata, parent outcome, or the supplied budget object.
        """
        ...


class ChildExecutionRunner:
    """Run and finalize exactly one child under an independent usage counter.

    Args:
        backend: Explicit runtime adapter that queues and executes child code.
        entrypoint_observer: One-shot observer armed immediately before the
            backend starts.
        budget_factory: Accounting interface used for API, instruction, and
            elapsed-time budget checks.
        clock: Monotonic clock returning seconds.  Tests inject a deterministic
            clock; production callers inject ``time.monotonic``.

    The runner owns result classification and the supplied usage object.  It
    does not own the child context, engine run queue, parent result, or report.
    """

    def __init__(
        self,
        backend: ChildExecutionBackend,
        entrypoint_observer: ChildEntrypointObserver,
        budget_factory: ChildBudgetFactory,
        clock: Callable[[], float],
    ) -> None:
        self._backend = backend
        self._entrypoint_observer = entrypoint_observer
        self._budget_factory = budget_factory
        self._clock = clock

    def run(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
        image: LoadedChildImage,
        context: ChildProcessContext,
        budget: ExecutionBudget,
        usage: BudgetUsage,
    ) -> ChildRunResult:
        """Queue, execute, and finalize one child run.

        Args:
            request: Child launch and ownership information.
            target: Trusted target evidence.
            image: Loaded child image; it must remain non-primary.
            context: Active child process/thread/run context.
            budget: Child limits that must equal the request's parent limits.
            usage: Fresh counter owned only by this child.

        Returns:
            A complete immutable child result.  Runtime failures and budget
            exhaustion are represented in the result instead of escaping as
            parent simulation errors.

        Side effects:
            Arms the one-shot entry observer, invokes the injected backend, and
            updates only the supplied ``usage`` counter.  This method never
            mutates parent metadata, parent outcome, or the budget object.
        """

        started_at = self._clock()
        last_observed_at = started_at
        run_indexes: tuple[int, ...] = ()
        backend_reason: str | None = None
        returned_to_caller = False
        failure: ChildFailure | None = None
        termination = ChildTerminationReason.NORMAL_EXIT

        def refresh_time() -> None:
            nonlocal last_observed_at, termination
            now = self._clock()
            elapsed = max(0.0, now - last_observed_at)
            last_observed_at = now
            if elapsed:
                self._budget_factory.observe_time(usage, elapsed)
            exceeded = self._budget_factory.exceeded(budget, usage)
            if exceeded is not None:
                termination = self._termination_for_limit(exceeded)

        def observe_api() -> bool:
            self._budget_factory.observe_api(usage)
            refresh_time()
            return self._budget_factory.exceeded(budget, usage) is None

        def observe_instructions(count: int = 1) -> bool:
            self._budget_factory.observe_instructions(usage, count)
            refresh_time()
            return self._budget_factory.exceeded(budget, usage) is None

        def should_continue() -> bool:
            refresh_time()
            return self._budget_factory.exceeded(budget, usage) is None

        hooks = _BudgetHooks(
            observe_api=observe_api,
            observe_instructions=observe_instructions,
            should_continue=should_continue,
        )

        try:
            self._validate_run_inputs(
                request,
                target,
                image,
                context,
                budget,
                usage,
            )
            self._entrypoint_observer.arm(context)
            backend_result = self._backend.run(
                request,
                target,
                image,
                context,
                hooks,
            )
            run_indexes = tuple(backend_result.run_indexes)
            backend_reason = backend_result.reason
            returned_to_caller = backend_result.returned_to_caller
        except ChildExecutionRuntimeError as exc:
            failure = ChildFailure(
                kind=exc.kind,
                message=str(exc),
            )
            termination = exc.termination_reason
        except Exception as exc:
            failure = ChildFailure(
                kind=ChildFailureKind.RUNTIME,
                message=f"{type(exc).__name__}: {exc}",
            )
            termination = ChildTerminationReason.INTERNAL_ERROR
        finally:
            try:
                self._entrypoint_observer.disarm(request.launch_id)
            except Exception as exc:
                if failure is None:
                    failure = ChildFailure(
                        kind=ChildFailureKind.CONTEXT,
                        message=(
                            "cannot disarm child entry observer: "
                            f"{type(exc).__name__}: {exc}"
                        ),
                    )
                    termination = ChildTerminationReason.INTERNAL_ERROR
            refresh_time()

        exceeded = self._budget_factory.exceeded(budget, usage)
        if exceeded is not None:
            termination = self._termination_for_limit(exceeded)
            failure = ChildFailure(
                kind=ChildFailureKind.BUDGET,
                message=f"child exceeded {exceeded}",
            )

        entrypoint_reached = self._entrypoint_observer.reached(request.launch_id)
        if termination in {
            ChildTerminationReason.NORMAL_EXIT,
            ChildTerminationReason.RETURNED_TO_CALLER,
        }:
            if returned_to_caller:
                termination = ChildTerminationReason.RETURNED_TO_CALLER
        if backend_reason and failure is None:
            failure = ChildFailure(
                kind=ChildFailureKind.RUNTIME,
                message=backend_reason,
            )
            if termination in {
                ChildTerminationReason.NORMAL_EXIT,
                ChildTerminationReason.RETURNED_TO_CALLER,
            }:
                termination = ChildTerminationReason.INTERNAL_ERROR
        if failure is None and not run_indexes:
            failure = ChildFailure(
                kind=ChildFailureKind.RUNTIME,
                message="child entry-point run was not queued",
            )
            termination = ChildTerminationReason.INVALID_FETCH
        elif failure is None and not entrypoint_reached:
            failure = ChildFailure(
                kind=ChildFailureKind.RUNTIME,
                message="child entry point was not reached",
            )
            termination = ChildTerminationReason.ENTRYPOINT_MISSING

        state, outcome = self._classify_result(
            run_indexes=run_indexes,
            entrypoint_reached=entrypoint_reached,
            termination=termination,
        )

        return ChildRunResult(
            launch_id=request.launch_id,
            ownership=context.ownership,
            state=state,
            outcome=outcome,
            termination_reason=termination,
            budget=budget,
            usage=usage,
            run_indexes=run_indexes,
            error=failure,
            entrypoint_reached=entrypoint_reached,
        )

    def _validate_run_inputs(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
        image: LoadedChildImage,
        context: ChildProcessContext,
        budget: ExecutionBudget,
        usage: BudgetUsage,
    ) -> None:
        """Reject identity or ownership mismatches before child execution.

        Args:
            request: Launch identity for the requested child.
            target: Trusted target resolution used for loading.
            image: Loaded image that will be executed.
            context: Active runtime context.
            budget: Limits applied to this child.
            usage: Mutable counters owned by this child.

        Returns:
            ``None`` when all inputs describe the same non-primary child.

        Side effects:
            None.

        Raises:
            ChildExecutionRuntimeError: If the image, context, or budget would
                violate launch ownership or parent-budget isolation.
        """

        if not target.resolved:
            raise ChildExecutionRuntimeError(
                "child target is unavailable",
                kind=ChildFailureKind.TARGET,
                termination_reason=ChildTerminationReason.TARGET_UNAVAILABLE,
            )
        if image.primary:
            raise ChildExecutionRuntimeError(
                "child execution requires a non-primary image",
                kind=ChildFailureKind.LOAD,
                termination_reason=ChildTerminationReason.LOAD_ERROR,
            )
        if image.request_launch_id != request.launch_id:
            raise ChildExecutionRuntimeError(
                "loaded image belongs to a different launch",
                kind=ChildFailureKind.LOAD,
                termination_reason=ChildTerminationReason.LOAD_ERROR,
            )
        expected_entrypoint = image.image_base + target.entrypoint_rva
        if image.entrypoint_address != expected_entrypoint:
            raise ChildExecutionRuntimeError(
                "loaded image entry point does not match target evidence",
                kind=ChildFailureKind.LOAD,
                termination_reason=ChildTerminationReason.ENTRYPOINT_OUT_OF_RANGE,
            )
        if context.ownership.launch_id != request.launch_id:
            raise ChildExecutionRuntimeError(
                "child context belongs to a different launch",
                kind=ChildFailureKind.CONTEXT,
                termination_reason=ChildTerminationReason.INTERNAL_ERROR,
            )
        if budget != request.parent_budget:
            raise ChildExecutionRuntimeError(
                "child budget differs from the captured parent limits",
                kind=ChildFailureKind.BUDGET,
                termination_reason=ChildTerminationReason.INTERNAL_ERROR,
            )
        if not isinstance(usage, BudgetUsage):
            raise ChildExecutionRuntimeError(
                "child usage must be a BudgetUsage instance",
                kind=ChildFailureKind.BUDGET,
                termination_reason=ChildTerminationReason.INTERNAL_ERROR,
            )
        if (
            usage.timeout_seconds_used != 0.0
            or usage.api_count_used != 0
            or usage.instructions_used != 0
        ):
            raise ChildExecutionRuntimeError(
                "child usage must start at zero and cannot be reused",
                kind=ChildFailureKind.BUDGET,
                termination_reason=ChildTerminationReason.INTERNAL_ERROR,
            )

    @staticmethod
    def _termination_for_limit(limit_name: str) -> ChildTerminationReason:
        """Map a budget limit name to its child termination reason.

        Args:
            limit_name: Name returned by the budget factory.

        Returns:
            The corresponding child termination reason.

        Side effects:
            None.
        """

        return {
            "timeout_seconds": ChildTerminationReason.TIMEOUT,
            "max_api_count": ChildTerminationReason.MAX_API_COUNT,
            "max_instructions": ChildTerminationReason.MAX_INSTRUCTIONS,
        }.get(limit_name, ChildTerminationReason.INTERNAL_ERROR)

    @staticmethod
    def _classify_result(
        *,
        run_indexes: tuple[int, ...],
        entrypoint_reached: bool,
        termination: ChildTerminationReason,
    ) -> tuple[ChildExecutionState, ChildOutcome]:
        """Classify a final backend outcome from independent evidence.

        Args:
            run_indexes: Run indexes actually queued by the backend.
            entrypoint_reached: Whether the one-shot entry observer fired.
            termination: Final termination classification.

        Returns:
            The final child state and high-level outcome.

        Side effects:
            None.  Queue existence is never used as proof that the entry point
            was reached.
        """

        if termination in {
            ChildTerminationReason.TIMEOUT,
            ChildTerminationReason.MAX_API_COUNT,
            ChildTerminationReason.MAX_INSTRUCTIONS,
        }:
            return ChildExecutionState.PARTIAL, ChildOutcome.PARTIAL
        if termination in {
            ChildTerminationReason.LOAD_ERROR,
            ChildTerminationReason.INVALID_FETCH,
            ChildTerminationReason.INTERNAL_ERROR,
        }:
            return ChildExecutionState.FAILED, ChildOutcome.ERROR
        if entrypoint_reached:
            return ChildExecutionState.COMPLETED, ChildOutcome.OK
        if run_indexes:
            return ChildExecutionState.PARTIAL, ChildOutcome.PARTIAL
        return ChildExecutionState.FAILED, ChildOutcome.ERROR


@dataclass(frozen=True)
class _BudgetHooks:
    """Concrete callable bundle implementing the backend's budget protocol."""

    observe_api: Callable[[], bool]
    observe_instructions: Callable[[int], bool]
    should_continue: Callable[[], bool]


__all__ = [
    "ChildBudgetHooks",
    "ChildExecutionBackend",
    "ChildExecutionBackendResult",
    "ChildExecutionRunner",
    "ChildExecutionRuntimeError",
]
