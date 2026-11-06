"""Frozen cross-module protocols for controlled child execution.

This module is the dependency boundary between request creation, target
resolution, admission, scheduling, execution, and reporting.  It contains
structural protocols only; concrete engine integration belongs in later
implementation steps.

Design constraints:

* Production modules communicate through these explicit interfaces.
* Callers must not patch concrete instances, inject undeclared attributes, or
  depend on another module's private fields.
* Every method docstring states what the caller supplies, what is returned,
  and which state, if any, the implementation is allowed to change.
"""

from __future__ import annotations

from collections.abc import Sequence
from contextlib import AbstractContextManager
from typing import Protocol, runtime_checkable

from speakeasy.report import ChildExecutionReport

from .models import (
    AdmissionDecision,
    BudgetUsage,
    ChildEventOwnership,
    ChildExecutionReportData,
    ChildLaunchRecord,
    ChildLaunchRequest,
    ChildProcessContext,
    ChildRunResult,
    EmulatedProcessProtocol,
    ExecutionBudget,
    LoadedChildImage,
    ParentExecutionSnapshot,
    ParentRunOutcome,
    ProcessCreationResult,
    ProcessLaunchOutcome,
    ProcessLaunchSpec,
    ResolvedChildTarget,
)


@runtime_checkable
class ChildRequestFactory(Protocol):
    """Build an immutable launch request without resolving or executing it."""

    def build(
        self,
        spec: ProcessLaunchSpec,
        *,
        root_sample_sha256: str,
        parent_pid: int,
        parent_tid: int | None,
        parent_launch_id: str | None,
        depth: int,
        parent_budget: ExecutionBudget,
        cwd: str,
    ) -> ChildLaunchRequest:
        """Create one stable child launch request.

        Args:
            spec: Decoded process-launch API parameters.
            root_sample_sha256: Identity of the root sample for the entire run.
            parent_pid: Emulated process that requested the launch.
            parent_tid: Requesting thread, or ``None`` when unavailable.
            parent_launch_id: Parent child launch, or ``None`` for direct root
                children.
            depth: One-based child depth proposed by the caller.
            parent_budget: Immutable parent limits to carry into the request.
            cwd: Emulated working directory used for command normalization.

        Returns:
            A fully populated immutable request with a generated ``launch_id``.

        Side effects:
            None.  This method must not read target bytes, create an emulated
            process, submit scheduler work, or execute code.
        """
        ...


@runtime_checkable
class ChildTargetResolverProtocol(Protocol):
    """Resolve target bytes from approved emulation-owned sources."""

    def resolve(self, request: ChildLaunchRequest) -> ResolvedChildTarget:
        """Resolve and describe the request target.

        Args:
            request: Immutable request whose target and working directory are
                used for resolution.

        Returns:
            Resolved target metadata, including source, digest, PE properties,
            and a rejection reason when resolution is incomplete.

        Side effects:
            May read emulation-owned root, dropped-file, or fixture bytes.
            Must not admit the request, create a process, or execute code.
        """
        ...

    def register_fixture(self, normalized_path: str, data: bytes) -> None:
        """Register exact bytes for an explicitly allowed fixture path.

        Args:
            normalized_path: Windows-style path key used by the resolver.
            data: Exact bytes to serve for this fixture.

        Returns:
            ``None``.

        Side effects:
            Replaces or adds this fixture in resolver-owned state.  It must not
            register a child, alter admission history, or change the run queue.
        """
        ...


@runtime_checkable
class ChildAdmissionPolicyProtocol(Protocol):
    """Evaluate policy without mutating scheduler or engine state."""

    def evaluate(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
        *,
        launch_history: Sequence[ChildLaunchRecord],
    ) -> AdmissionDecision:
        """Return an admission decision for one resolved request.

        Args:
            request: Request being considered for a process object and queue.
            target: Resolver evidence for the request's target bytes.
            launch_history: Read-only prior launch records for depth, count, and
                duplicate checks.

        Returns:
            An immutable decision containing eligibility, state, and an
            optional machine-readable reason.

        Side effects:
            None.  The policy must not mutate history, create a process, or
            enqueue work.
        """
        ...


@runtime_checkable
class ParentRuntimeConfig(Protocol):
    """Read-only parent runtime limits used to capture the execution budget."""

    timeout: float
    """Parent timeout limit in seconds; copied unchanged to every child."""

    max_api_count: int
    """Parent API-call limit; copied unchanged to every child."""

    max_instructions: int
    """Parent instruction limit; copied unchanged to every child."""


@runtime_checkable
class ChildBudgetFactory(Protocol):
    """Create equal parent/child limits while keeping usage independent."""

    def capture_parent(self, config: ParentRuntimeConfig) -> ExecutionBudget:
        """Snapshot the three parent limits at root-run start.

        Args:
            config: Parent runtime configuration.

        Returns:
            An immutable budget whose limits equal the parent configuration.

        Side effects:
            None.  The factory must not mutate ``config``.
        """
        ...

    def for_child(
        self,
        parent_budget: ExecutionBudget,
    ) -> tuple[ExecutionBudget, BudgetUsage]:
        """Create a child budget with equal limits and fresh usage.

        Args:
            parent_budget: Immutable limits captured from the parent.

        Returns:
            A pair ``(child_budget, child_usage)``.  All three child limits
            must equal the corresponding parent limits, while ``child_usage``
            must be a newly allocated object.

        Side effects:
            None.
        """
        ...

    def observe_time(
        self,
        usage: BudgetUsage,
        seconds: float,
    ) -> None:
        """Add elapsed wall-clock time to one child's usage.

        Args:
            usage: Usage counter owned by exactly one active child.
            seconds: Non-negative elapsed seconds to add.

        Returns:
            ``None``.

        Side effects:
            Adds only to the supplied usage object's wall-clock counter.
        """
        ...

    def observe_api(self, usage: BudgetUsage) -> None:
        """Increment one active child's API-call usage.

        Args:
            usage: Usage object owned by exactly one active child.

        Returns:
            ``None``.

        Side effects:
            Increments only the supplied usage object's API counter.
        """
        ...

    def observe_instructions(self, usage: BudgetUsage, count: int = 1) -> None:
        """Increment one active child's instruction usage.

        Args:
            usage: Usage object owned by exactly one active child.
            count: Number of instructions observed since the previous update.

        Returns:
            ``None``.

        Side effects:
            Adds only to the supplied usage object's instruction counter.
        """
        ...

    def exceeded(
        self,
        budget: ExecutionBudget,
        usage: BudgetUsage,
    ) -> str | None:
        """Report the first exceeded budget limit.

        Args:
            budget: Immutable child limits.
            usage: Mutable usage belonging to that same child.

        Returns:
            The exceeded limit name, or ``None`` when all limits remain within
            bounds.

        Side effects:
            None.
        """
        ...


@runtime_checkable
class ChildProcessFactory(Protocol):
    """Create emulated process and thread objects for an admitted request."""

    def create(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
    ) -> ProcessCreationResult:
        """Create one emulated process object.

        Args:
            request: Admitted immutable launch request.
            target: Resolved target bytes and metadata.

        Returns:
            The created process, assigned pid/tid, and an explicit success flag.

        Side effects:
            May create process/thread objects in engine-owned state.  This does
            not mean the child entry point has been queued or reached.
        """
        ...


@runtime_checkable
class ChildRuntimeLoader(Protocol):
    """Load child image bytes without replacing root-image metadata."""

    def load(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
    ) -> LoadedChildImage:
        """Load one child executable as a non-primary image.

        Args:
            request: Launch ownership and command information.
            target: Trusted target bytes and PE metadata.

        Returns:
            Loaded module, image base, entry-point address, and
            ``primary=False``.

        Side effects:
            May map child bytes into engine memory.  It must not modify root
            module metadata or execute the child.
        """
        ...


@runtime_checkable
class ChildContextManager(Protocol):
    """Create child runtime context and restore the parent on every exit path."""

    def enter(
        self,
        request: ChildLaunchRequest,
        image: LoadedChildImage,
        ownership: ChildEventOwnership,
    ) -> AbstractContextManager[ChildProcessContext]:
        """Enter one child execution context.

        Args:
            request: Launch being prepared for execution.
            image: Loaded non-primary child image.
            ownership: Stable parent/child correlation metadata.

        Returns:
            A context manager yielding the child process, thread, module, run,
            and ownership objects.

        Side effects:
            On entry, may switch process/thread/run context.  On every exit,
            including exceptions, it must restore the prior parent context.
        """
        ...


@runtime_checkable
class ChildSchedulerProtocol(Protocol):
    """Own queued child lifecycle and deterministic FIFO draining."""

    def submit(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
        decision: AdmissionDecision,
        process: EmulatedProcessProtocol,
    ) -> ChildLaunchRecord:
        """Record one admitted launch without executing it.

        Args:
            request: Admitted request.
            target: Resolved target evidence.
            decision: Admission result permitting queue insertion.
            process: Existing emulated process object for the request.

        Returns:
            The queued immutable launch record.

        Side effects:
            May append to the scheduler-owned queue.  It must not load or run
            child code.
        """
        ...

    def drain(
        self,
        parent_result: ParentRunOutcome,
    ) -> tuple[ChildRunResult, ...]:
        """Run queued children after parent execution has finished.

        Args:
            parent_result: Final parent outcome; a failed or stopped parent
                prevents further child starts.

        Returns:
            Child results in deterministic queue order.

        Side effects:
            May transition queued children through execution and completion,
            but only after the parent is closed for intake.
        """
        ...

    def stop(self, reason: str) -> None:
        """Stop pending and active child work.

        Args:
            reason: Machine-readable scheduler stop reason.

        Returns:
            ``None``.

        Side effects:
            Marks affected child work as stopped and prevents new starts.
        """
        ...

    def snapshot(self) -> ChildExecutionReportData:
        """Return an immutable report snapshot.

        Returns:
            Current request counts and completed child results without exposing
            mutable queue internals or engine objects.

        Side effects:
            None.
        """
        ...


@runtime_checkable
class ChildEntrypointObserver(Protocol):
    """Own the one-shot evidence that a child entry point was reached."""

    def arm(self, context: ChildProcessContext) -> None:
        """Arm entry-point observation for one child context.

        Args:
            context: Child context about to execute.

        Returns:
            ``None``.

        Side effects:
            Installs a one-shot observation mechanism owned by the observer.
        """
        ...

    def disarm(self, launch_id: str) -> None:
        """Remove any pending hook for one child without inventing evidence.

        Args:
            launch_id: Stable child launch identifier.

        Returns:
            ``None``.

        Side effects:
            Disables and forgets the pending observation hook for this launch.
            It is idempotent. Entry-point evidence already recorded by a real
            hook remains available to :meth:`reached`.
        """
        ...

    def reached(self, launch_id: str) -> bool:
        """Return whether the child entry point actually fired.

        Args:
            launch_id: Stable child launch identifier.

        Returns:
            ``True`` only when the one-shot entry hook fired for this launch.

        Side effects:
            None.  Queue state and process existence must not be used to infer
            this value.
        """
        ...


@runtime_checkable
class ChildRunnerProtocol(Protocol):
    """Execute exactly one loaded child under its independent usage counter."""

    def run(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
        image: LoadedChildImage,
        context: ChildProcessContext,
        budget: ExecutionBudget,
        usage: BudgetUsage,
    ) -> ChildRunResult:
        """Execute and finalize one child run.

        Args:
            request: Child launch and ownership information.
            target: Resolved target evidence.
            image: Loaded non-primary child image.
            context: Active child process/thread/run context.
            budget: Child limits equal to the parent limits.
            usage: Fresh mutable counter owned only by this child.

        Returns:
            Final child outcome, termination reason, budget evidence, and run
            indexes.

        Side effects:
            May execute emulated child code within the supplied context and
            update only the supplied usage object.  It must not modify parent
            outcome or root metadata.
        """
        ...


@runtime_checkable
class ChildResultSink(Protocol):
    """Attach one completed child result to the root report."""

    def publish(self, result: ChildRunResult) -> None:
        """Publish one child result.

        Args:
            result: Immutable completed child result.

        Returns:
            ``None``.

        Side effects:
            Updates reporting-owned attachments only; it must not mutate the
            scheduler or child execution state.
        """
        ...


@runtime_checkable
class ProcessExecutionTrackerProtocol(Protocol):
    """Minimal tracker surface used by the dynamic-stage adapter."""

    def update_child_execution(
        self,
        report: ChildExecutionReport,
    ) -> None:
        """Apply one immutable child report snapshot to tracker-owned state.

        Args:
            report: Serialized public child request and result summary.  The
                tracker must not require access to engine runtime objects.

        Returns:
            ``None``.

        Side effects:
            May update tracker-owned launch records.  It must not access
            engine objects, queues, or infer execution from pid activity.
        """
        ...


@runtime_checkable
class DynamicChildResultAdapter(Protocol):
    """Adapt authoritative report DTOs for the dynamic-stage tracker."""

    def apply(
        self,
        tracker: ProcessExecutionTrackerProtocol,
        report: ChildExecutionReport,
    ) -> None:
        """Apply authoritative child fields to a process tracker.

        Args:
            tracker: Dynamic-stage tracker receiving launch and result fields.
            report: Public immutable report DTO produced by the projector.

        Returns:
            ``None``.

        Side effects:
            May update tracker-owned process records.  It must not access
            engine objects, scheduler queues, or infer state from pid activity.
        """
        ...


@runtime_checkable
class ChildExecutionDispatcher(Protocol):
    """Provide the sole orchestration and state-transition entry point."""

    def submit(
        self,
        spec: ProcessLaunchSpec,
        *,
        parent_context: ParentExecutionSnapshot,
    ) -> ProcessLaunchOutcome:
        """Create, resolve, admit, and conditionally enqueue one request.

        Args:
            spec: Decoded process-launch API parameters.
            parent_context: Root identity, parent process/thread, cwd, and
                captured budget limits.

        Returns:
            The request, resolution, admission decision, and process-creation
            facts needed by the API handler.

        Side effects:
            Owns all request state transitions.  In model-only mode it records
            without queueing; in enabled mode it may enqueue only an admitted
            request.
        """
        ...

    def parent_finished(self, parent_result: ParentRunOutcome) -> None:
        """Close parent intake and begin bounded child draining.

        Args:
            parent_result: Final parent outcome and budget evidence.

        Returns:
            ``None``.

        Side effects:
            Prevents additional parent launches and may start deterministic
            child draining.  A failed parent stops pending children.
        """
        ...

    def stop(self, reason: str) -> None:
        """Propagate a lifecycle stop to all child layers.

        Args:
            reason: Machine-readable stop reason.

        Returns:
            ``None``.

        Side effects:
            Stops pending and active child work without rewriting the parent
            outcome.
        """
        ...

    def report(self) -> ChildExecutionReportData:
        """Return the current immutable child execution summary.

        Returns:
            A snapshot suitable for report serialization.

        Side effects:
            None.
        """
        ...


__all__ = [
    "ChildAdmissionPolicyProtocol",
    "ChildBudgetFactory",
    "ChildContextManager",
    "ChildEntrypointObserver",
    "ChildExecutionDispatcher",
    "ChildProcessFactory",
    "ChildRequestFactory",
    "ChildResultSink",
    "ChildRunnerProtocol",
    "ChildRuntimeLoader",
    "ChildSchedulerProtocol",
    "ChildTargetResolverProtocol",
    "DynamicChildResultAdapter",
    "ParentRuntimeConfig",
    "ProcessExecutionTrackerProtocol",
]
