"""Frozen data contracts for controlled child execution.

This package contains declarations only.  It does not resolve targets, create
processes, schedule work, load images, or execute child code.  Runtime modules
added in later steps must depend on these contracts through dependency
injection rather than patching concrete engine objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Protocol


class ChildExecutionState(str, Enum):
    """Lifecycle states for one child launch request."""

    REQUESTED = "requested"
    TARGET_RESOLVED = "target_resolved"
    ELIGIBLE = "eligible"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"
    REJECTED = "rejected"
    PROCESS_OBJECT_CREATED = "process_object_created"
    THREAD_QUEUED = "thread_queued"
    ENTRYPOINT_REACHED = "entrypoint_reached"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class ChildTargetSource(str, Enum):
    """Approved origins for child target bytes."""

    SELF = "self"
    DROPPED_FILE = "dropped_file"
    FIXTURE = "fixture"
    UNAVAILABLE = "unavailable"


class ChildOutcome(str, Enum):
    """High-level result of one child execution."""

    OK = "ok"
    PARTIAL = "partial"
    ERROR = "error"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"
    REJECTED = "rejected"


class ChildTerminationReason(str, Enum):
    """Machine-readable reasons why a child stopped or was not started."""

    NORMAL_EXIT = "normal_exit"
    RETURNED_TO_CALLER = "returned_to_caller"
    TIMEOUT = "timeout"
    MAX_API_COUNT = "max_api_count"
    MAX_INSTRUCTIONS = "max_instructions"
    PARENT_STOPPED = "parent_stopped"
    DEPTH_LIMIT = "depth_limit"
    CHILD_COUNT_LIMIT = "child_count_limit"
    DUPLICATE_LAUNCH = "duplicate_launch"
    TARGET_UNAVAILABLE = "target_unavailable"
    TARGET_NOT_PE = "target_not_pe"
    ARCH_MISMATCH = "arch_mismatch"
    ENTRYPOINT_MISSING = "entrypoint_missing"
    ENTRYPOINT_OUT_OF_RANGE = "entrypoint_out_of_range"
    LOAD_ERROR = "load_error"
    INVALID_FETCH = "invalid_fetch"
    INVALID_MEMORY = "invalid_memory"
    INTERNAL_ERROR = "internal_error"


class ChildFailureKind(str, Enum):
    """Module boundary at which a child failure occurred."""

    TARGET = "target"
    ADMISSION = "admission"
    LOAD = "load"
    CONTEXT = "context"
    SCHEDULER = "scheduler"
    BUDGET = "budget"
    RUNTIME = "runtime"
    INTERNAL = "internal"


@dataclass(frozen=True)
class ChildExecutionOptions:
    """Configuration that controls whether and how child work is admitted.

    The options do not contain execution limits.  Timeout, API, and instruction
    limits are captured from the parent as an :class:`ExecutionBudget`.

    Args:
        enabled: Whether admitted child work may eventually be executed.
        max_depth: Maximum launch depth; one means direct root children only.
        max_children_per_root: Maximum admitted child launches per root run.
        max_target_bytes: Maximum target bytes accepted for one child.
        allowed_sources: Target origins permitted by admission policy.
    """

    enabled: bool = False
    max_depth: int = 1
    max_children_per_root: int = 4
    max_target_bytes: int = 64 * 1024 * 1024
    allowed_sources: tuple[ChildTargetSource, ...] = (
        ChildTargetSource.SELF,
        ChildTargetSource.DROPPED_FILE,
        ChildTargetSource.FIXTURE,
    )

    def __post_init__(self) -> None:
        """Reject option values that would make scheduling ambiguous."""

        if self.max_depth < 1:
            raise ValueError("max_depth must be at least 1")
        if self.max_children_per_root < 0:
            raise ValueError("max_children_per_root cannot be negative")
        if self.max_target_bytes <= 0:
            raise ValueError("max_target_bytes must be positive")
        if ChildTargetSource.UNAVAILABLE in self.allowed_sources:
            raise ValueError("unavailable is not an executable target source")


@dataclass(frozen=True)
class ExecutionBudget:
    """Immutable limits shared by a parent and each of its children.

    The three limit values must match the parent's configured values.  A child
    receives an equal budget, not a copy of the parent's mutable usage.

    Args:
        timeout_seconds: Per-run wall-clock limit.
        max_api_count: Per-run emulated API-call limit.
        max_instructions: Per-run instruction limit; ``-1`` means unlimited.
        source: Identifies the authority from which limits were captured.
    """

    timeout_seconds: float
    max_api_count: int
    max_instructions: int
    source: Literal["parent_config"] = "parent_config"

    def __post_init__(self) -> None:
        """Reject invalid limits while preserving the supported unlimited value."""

        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_api_count < 1:
            raise ValueError("max_api_count must be positive")
        if self.max_instructions < -1:
            raise ValueError("max_instructions must be -1 or non-negative")


@dataclass
class BudgetUsage:
    """Mutable consumption counters owned by exactly one run.

    A new instance must be allocated for every child.  Sharing an instance
    between parent and child, or between sibling children, is forbidden.

    Args:
        timeout_seconds_used: Active execution time consumed by the run.
        api_count_used: Emulated API calls observed by the run.
        instructions_used: Emulated instructions observed by the run.
    """

    timeout_seconds_used: float = 0.0
    api_count_used: int = 0
    instructions_used: int = 0


@dataclass(frozen=True)
class ProcessLaunchSpec:
    """Decoded parameters from one process-launch API request.

    Args:
        source_api: Handler that produced the request.
        target: Explicit application path, if the API supplied one.
        command_line: Complete, unmodified command line.
        working_directory: Emulated working directory for this request.
        creation_flags: Windows process creation flags.
        requested_show_command: Shell show command, if supplied.
    """

    source_api: str
    target: str | None
    command_line: str
    working_directory: str | None
    creation_flags: int = 0
    requested_show_command: int | None = None


@dataclass(frozen=True)
class TargetPayloadRef:
    """Reference to bytes used to resolve a child target.

    ``data`` is intentionally excluded from representation and equality so it
    cannot leak accidentally through diagnostics or report serialization.

    Args:
        source: Origin of the referenced bytes.
        sha256: SHA-256 digest of the complete payload.
        size: Payload size in bytes.
        emu_path: Normalized emulated path associated with the payload.
        data: Optional in-memory payload for subsequent execution steps.
    """

    source: ChildTargetSource
    sha256: str
    size: int
    emu_path: str
    data: bytes | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class ResolvedChildTarget:
    """Resolution evidence for one target.

    Args:
        source: Origin of the target bytes.
        normalized_path: Canonical Windows path used for resolution.
        payload_ref: Reference to the exact bytes used for PE inspection.
        sha256: Target digest, if bytes were available.
        size: Target size in bytes.
        file_format: Detected format, such as ``pe`` or ``non_pe``.
        arch: Detected architecture.
        module_type: Detected module kind, such as ``exe``.
        entrypoint_rva: Relative virtual address of the PE entry point.
        resolved: Whether complete target bytes are available.
        reason: Machine-readable rejection or skip reason.
    """

    source: ChildTargetSource
    normalized_path: str
    payload_ref: TargetPayloadRef | None
    sha256: str | None
    size: int
    file_format: str
    arch: str
    module_type: str
    entrypoint_rva: int
    resolved: bool
    reason: str | None


@dataclass(frozen=True)
class AdmissionDecision:
    """Policy decision for one resolved request.

    Args:
        eligible: Whether the request may create a queued launch record.
        state: Resulting admission state.
        reason: Machine-readable rejection or skip reason.
    """

    eligible: bool
    state: ChildExecutionState
    reason: str | None


@dataclass(frozen=True)
class ChildLaunchRequest:
    """Immutable identity and command facts for one child launch.

    Args:
        launch_id: Stable, root-local, sortable launch identifier.
        root_sample_sha256: Root sample identity retained for ownership.
        parent_launch_id: Parent child launch, or ``None`` for a root child.
        source_api: Handler that requested the launch.
        parent_pid: Process that made the request.
        parent_tid: Requesting thread, if available.
        depth: One-based child depth.
        target: Original target argument or command-derived target.
        normalized_target: Canonical Windows target path.
        working_directory: Emulated working directory.
        command_line: Complete original command line.
        command_sha256: Digest of the canonical command line.
        parent_budget: Immutable parent limits carried into this request.
    """

    launch_id: str
    root_sample_sha256: str
    parent_launch_id: str | None
    source_api: str
    parent_pid: int
    parent_tid: int | None
    depth: int
    target: str
    normalized_target: str
    working_directory: str
    command_line: str
    command_sha256: str
    parent_budget: ExecutionBudget

    def __post_init__(self) -> None:
        """Reject requests without stable identity or valid launch depth."""

        if not self.launch_id:
            raise ValueError("launch_id cannot be empty")
        if not self.root_sample_sha256:
            raise ValueError("root_sample_sha256 cannot be empty")
        if self.depth < 1:
            raise ValueError("depth must be at least 1")


@dataclass(frozen=True)
class ChildLaunchRecord:
    """Immutable snapshot assembled by the dispatcher.

    Args:
        request: Stable launch request.
        target: Resolution evidence, once available.
        decision: Admission result, once evaluated.
        process: Emulated process object, once created.
        state: Latest lifecycle state.
        reason: Machine-readable explanation for the current state.
    """

    request: ChildLaunchRequest
    target: ResolvedChildTarget | None = None
    decision: AdmissionDecision | None = None
    process: EmulatedProcessProtocol | None = None
    state: ChildExecutionState = ChildExecutionState.REQUESTED
    reason: str | None = None


@dataclass(frozen=True)
class ProcessCreationResult:
    """Facts produced when the engine creates emulated process objects.

    Args:
        process: Created process object, if creation succeeded.
        created_pid: PID assigned to the created process.
        created_tid: TID assigned to the created thread.
        created: Whether process objects were actually created.
        reason: Machine-readable creation failure reason.
    """

    process: EmulatedProcessProtocol | None
    created_pid: int | None
    created_tid: int | None
    created: bool
    reason: str | None = None

    def __post_init__(self) -> None:
        """Keep the success flag consistent with the returned objects and pids."""

        if self.created and (self.process is None or self.created_pid is None):
            raise ValueError("created process results require process and pid")
        if not self.created and (
            self.process is not None
            or self.created_pid is not None
            or self.created_tid is not None
        ):
            raise ValueError("failed process results cannot carry created objects")


@dataclass(frozen=True)
class ProcessLaunchOutcome:
    """Complete model-only or admitted result returned to an API handler.

    Args:
        request: Request created for the API call.
        resolution: Target resolution evidence.
        decision: Admission result.
        creation: Process-object creation facts.
    """

    request: ChildLaunchRequest
    resolution: ResolvedChildTarget
    decision: AdmissionDecision
    creation: ProcessCreationResult


@dataclass(frozen=True)
class LoadedChildImage:
    """Non-primary image loaded for a child run.

    Args:
        request_launch_id: Launch identifier owning the image.
        module: Emulated module object.
        image_base: Runtime image base.
        entrypoint_address: Absolute entry-point address.
        primary: Must remain ``False`` for child images.
    """

    request_launch_id: str
    module: EmulatedModuleProtocol
    image_base: int
    entrypoint_address: int
    primary: Literal[False] = False


@dataclass(frozen=True)
class ChildEventOwnership:
    """Correlation fields attached to every child run and event."""

    root_sample_sha256: str
    launch_id: str
    parent_pid: int
    child_pid: int
    depth: int


@dataclass
class ChildProcessContext:
    """Runtime context active while one child executes.

    The context manager that yields this object owns context switching and is
    responsible for restoring the parent on every exit path.
    """

    process: EmulatedProcessProtocol
    thread: EmulatedThreadProtocol
    module: EmulatedModuleProtocol
    run: EmulatedRunProtocol
    ownership: ChildEventOwnership


@dataclass(frozen=True)
class ChildFailure:
    """Structured failure information for a child result."""

    kind: ChildFailureKind
    message: str
    pc: int | None = None
    fault_address: int | None = None
    access_type: str | None = None
    api_name: str | None = None


@dataclass(frozen=True)
class ChildRunResult:
    """Final result for one child execution.

    Args:
        launch_id: Stable launch identifier owning the result.
        ownership: Root, parent, child, and depth correlation fields.
        state: Terminal lifecycle state.
        outcome: High-level execution outcome.
        termination_reason: Machine-readable stop reason.
        budget: Immutable limits inherited from the parent.
        usage: Consumption counters owned by this child only.
        run_indexes: Root-report entry-point indexes owned by this child.
        error: Structured child-local failure, when present.
        entrypoint_reached: Whether the one-shot entrypoint hook fired.
    """

    launch_id: str
    ownership: ChildEventOwnership
    state: ChildExecutionState
    outcome: ChildOutcome
    termination_reason: ChildTerminationReason
    budget: ExecutionBudget
    usage: BudgetUsage
    run_indexes: tuple[int, ...]
    error: ChildFailure | None
    entrypoint_reached: bool = False


@dataclass(frozen=True)
class ParentExecutionSnapshot:
    """Root context captured before accepting child requests."""

    root_sample_sha256: str
    pid: int
    tid: int | None
    cwd: str
    budget: ExecutionBudget


@dataclass(frozen=True)
class ParentRunOutcome:
    """Final root outcome used to close child intake."""

    status: str
    termination_reason: str
    coverage_complete: bool
    budget: ExecutionBudget
    usage: BudgetUsage


@dataclass(frozen=True)
class ChildExecutionReportData:
    """Immutable child summary passed from the engine to reporting."""

    mode: str
    execution_enabled: bool
    request_count: int
    eligible_count: int
    target_resolved_count: int
    process_object_created_count: int
    thread_queued_count: int
    entrypoint_reached_count: int
    records: tuple[ChildLaunchRecord, ...]
    results: tuple[ChildRunResult, ...]


class EmulatedProcessProtocol(Protocol):
    """Minimal public process surface available to child modules."""

    id: int
    pid: int
    path: str
    cmdline: str
    threads: list[EmulatedThreadProtocol]


class EmulatedThreadProtocol(Protocol):
    """Minimal public thread surface available to child modules."""

    id: int
    tid: int


class EmulatedModuleProtocol(Protocol):
    """Minimal public module surface available to child modules."""

    base: int
    image_size: int
    emu_path: str


class EmulatedRunProtocol(Protocol):
    """Minimal public run surface available to child modules."""

    type: str | int | None
    start_addr: int | None
    process_context: EmulatedProcessProtocol | None
    thread: EmulatedThreadProtocol | None


__all__ = [
    "AdmissionDecision",
    "BudgetUsage",
    "ChildEventOwnership",
    "ChildExecutionOptions",
    "ChildExecutionReportData",
    "ChildExecutionState",
    "ChildFailure",
    "ChildFailureKind",
    "ChildLaunchRecord",
    "ChildLaunchRequest",
    "ChildOutcome",
    "ChildProcessContext",
    "ChildRunResult",
    "ChildTargetSource",
    "ChildTerminationReason",
    "EmulatedModuleProtocol",
    "EmulatedProcessProtocol",
    "EmulatedRunProtocol",
    "EmulatedThreadProtocol",
    "ExecutionBudget",
    "LoadedChildImage",
    "ParentExecutionSnapshot",
    "ParentRunOutcome",
    "ProcessCreationResult",
    "ProcessLaunchOutcome",
    "ProcessLaunchSpec",
    "ResolvedChildTarget",
    "TargetPayloadRef",
]
