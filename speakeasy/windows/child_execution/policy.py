"""Admission policy for model-only child execution."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .models import AdmissionDecision, ChildExecutionState, ChildTargetSource
from .request import ChildExecutionRequest


@dataclass(frozen=True)
class ChildExecutionPolicy:
    """Conservative admission limits for child launch requests.

    Args:
        mode: Public behavior mode; stage two remains ``model_only``.
        max_depth: Maximum launch depth; one means direct root children only.
        max_children_per_root: Maximum eligible launches per root run.
        max_target_bytes: Maximum accepted target size.
        per_child_timeout_sec: Deprecated stage-one placeholder.
        per_child_max_api_count: Deprecated stage-one placeholder.
        per_child_max_instructions: Deprecated stage-one placeholder.
        allowed_sources: Target origins that may be admitted.

    The ``per_child_*`` values are retained only for report-schema
    compatibility. They are not execution limits and must not be used to run
    child code. Later budget work replaces them with limits captured from the
    parent configuration.
    """

    mode: str = "model_only"
    max_depth: int = 1
    max_children_per_root: int = 4
    max_target_bytes: int = 64 * 1024 * 1024
    per_child_timeout_sec: float = 5.0
    per_child_max_api_count: int = 1000
    per_child_max_instructions: int = 1_000_000
    allowed_sources: tuple[str, ...] = (
        ChildTargetSource.SELF.value,
        ChildTargetSource.DROPPED_FILE.value,
        ChildTargetSource.FIXTURE.value,
    )

    def evaluate(
        self,
        request: ChildExecutionRequest,
        *,
        launch_history: Sequence[ChildExecutionRequest],
    ) -> AdmissionDecision:
        """Evaluate one request without mutating engine or request state.

        Args:
            request: Request containing resolution evidence to evaluate.
            launch_history: Earlier requests used for duplicate and count
                checks. This sequence is read only.

        Returns:
            An immutable state, eligibility flag, and optional reason.

        Side effects:
            None. The caller applies the returned decision to its own request.
        """

        if request.depth > self.max_depth:
            return _decision(ChildExecutionState.REJECTED, "depth_limit")
        if request.skip_reason == "non_pe_target":
            return _decision(ChildExecutionState.SKIPPED, None)
        if not request.target_resolved:
            return _decision(
                ChildExecutionState.UNAVAILABLE,
                request.rejection_reason or "target_unavailable",
            )
        if request.rejection_reason:
            return _decision(
                ChildExecutionState.REJECTED,
                request.rejection_reason,
            )
        if request.target_source not in self.allowed_sources:
            return _decision(
                ChildExecutionState.REJECTED,
                "target_source_not_allowed",
            )
        if request.target_size > self.max_target_bytes:
            return _decision(
                ChildExecutionState.REJECTED,
                "target_too_large",
            )
        if self._is_duplicate(request, launch_history):
            return _decision(
                ChildExecutionState.REJECTED,
                "duplicate_launch",
            )
        if self._eligible_count(launch_history) >= self.max_children_per_root:
            return _decision(
                ChildExecutionState.REJECTED,
                "child_count_limit",
            )
        return AdmissionDecision(
            eligible=True,
            state=ChildExecutionState.ELIGIBLE,
            reason=None,
        )

    @staticmethod
    def _is_duplicate(
        request: ChildExecutionRequest,
        launch_history: Sequence[ChildExecutionRequest],
    ) -> bool:
        """Return whether an eligible prior request has the same launch key.

        Args:
            request: Candidate request.
            launch_history: Prior requests considered for deduplication.

        Returns:
            ``True`` when target and canonical command digests both match an
            eligible prior request.

        Side effects:
            None.
        """

        if request.target_sha256 is None:
            return False
        return any(
            prior.eligible
            and prior.target_sha256 == request.target_sha256
            and prior.command_sha256 == request.command_sha256
            for prior in launch_history
        )

    @staticmethod
    def _eligible_count(
        launch_history: Sequence[ChildExecutionRequest],
    ) -> int:
        """Count eligible launches in the supplied history.

        Args:
            launch_history: Prior requests for the current root run.

        Returns:
            Number of eligible requests.

        Side effects:
            None.
        """

        return sum(request.eligible for request in launch_history)


def _decision(
    state: ChildExecutionState,
    reason: str | None,
) -> AdmissionDecision:
    """Build a non-eligible admission decision.

    Args:
        state: Resulting lifecycle state.
        reason: Machine-readable reason, if one applies.

    Returns:
        An immutable non-eligible decision.

    Side effects:
        None.
    """

    return AdmissionDecision(eligible=False, state=state, reason=reason)


__all__ = ["ChildExecutionPolicy"]
