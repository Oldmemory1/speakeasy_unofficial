"""Apply authoritative public child reports to a dynamic-stage tracker."""

from __future__ import annotations

from collections import Counter

from speakeasy.report import (
    ChildExecutionBudgetReport,
    ChildExecutionBudgetUsageReport,
    ChildExecutionReport,
    ChildExecutionRequestReport,
    ChildExecutionResultReport,
)

from .interfaces import ProcessExecutionTrackerProtocol

_TERMINAL_STATES = frozenset({"completed", "partial", "failed"})
_QUEUED_OR_LATER = frozenset(
    {"thread_queued", "entrypoint_reached", "completed", "partial"}
)
_ENTRYPOINT_OR_LATER = frozenset(
    {"entrypoint_reached", "completed", "partial"}
)


class ChildExecutionReportValidationError(ValueError):
    """Raised when a report cannot be applied without inventing child state."""


class DynamicChildExecutionAdapter:
    """Validate one public child report and apply it to a tracker.

    Args:
        None.  The target tracker is supplied to :meth:`apply`, allowing one
        stateless adapter instance to serve independent samples.

    The adapter owns no engine or tracker state.  It accesses tracker state
    only through the explicit ``update_child_execution`` protocol method.
    """

    def apply(
        self,
        tracker: ProcessExecutionTrackerProtocol,
        report: ChildExecutionReport,
    ) -> None:
        """Apply authoritative launch and result fields to a tracker.

        Args:
            tracker: Dynamic-stage tracker implementing
                ``update_child_execution(report)``.
            report: Public child report containing requests and terminal
                results.  Engine runtime objects must not be attached.

        Returns:
            ``None``.

        Side effects:
            Calls ``tracker.update_child_execution(report)`` exactly once,
            after validation succeeds.  Engine and scheduler state are not
            modified.

        Raises:
            ChildExecutionReportValidationError: If report counters, lineage,
                ownership, budgets, usage, or terminal states are inconsistent.
        """

        self._validate(report)
        tracker.update_child_execution(report)

    def _validate(self, report: ChildExecutionReport) -> None:
        """Validate all report facts required for conservative tracker updates.

        Args:
            report: Public child report to validate.

        Returns:
            ``None`` when launch and result lineage is internally consistent.

        Side effects:
            None.

        Raises:
            ChildExecutionReportValidationError: If a summary counter, state
                count, launch identity, or result relationship is invalid.
        """

        if report.request_count != len(report.requests):
            raise ChildExecutionReportValidationError(
                "request_count does not match launch requests"
            )

        requests_by_id: dict[str, ChildExecutionRequestReport] = {}
        roots: set[str] = set()
        for request in report.requests:
            if request.launch_id in requests_by_id:
                raise ChildExecutionReportValidationError(
                    f"duplicate child launch id: {request.launch_id}"
                )
            requests_by_id[request.launch_id] = request
            if request.root_sample_sha256:
                roots.add(request.root_sample_sha256)

        if len(roots) > 1:
            raise ChildExecutionReportValidationError(
                "child report contains multiple root sample identities"
            )

        expected_counts = {
            "eligible_count": sum(r.eligible for r in report.requests),
            "target_resolved_count": sum(
                r.target_resolved for r in report.requests
            ),
            "process_object_created_count": sum(
                r.process_object_created for r in report.requests
            ),
            "thread_queued_count": sum(
                r.thread_queued or r.state in _QUEUED_OR_LATER
                for r in report.requests
            ),
            "entrypoint_reached_count": sum(
                r.entrypoint_reached or r.state in _ENTRYPOINT_OR_LATER
                for r in report.requests
            ),
        }
        actual_counts = {
            "eligible_count": report.eligible_count,
            "target_resolved_count": report.target_resolved_count,
            "process_object_created_count": (
                report.process_object_created_count
            ),
            "thread_queued_count": report.thread_queued_count,
            "entrypoint_reached_count": report.entrypoint_reached_count,
        }
        for name, expected in expected_counts.items():
            if actual_counts[name] != expected:
                raise ChildExecutionReportValidationError(
                    f"{name} does not match launch requests"
                )

        expected_states = Counter(r.state for r in report.requests)
        if report.states != dict(expected_states):
            raise ChildExecutionReportValidationError(
                "states do not match launch requests"
            )

        result_ids: set[str] = set()
        for result in report.results:
            if result.launch_id in result_ids:
                raise ChildExecutionReportValidationError(
                    f"duplicate child result for launch id: {result.launch_id}"
                )
            result_ids.add(result.launch_id)
            request = requests_by_id.get(result.launch_id)
            if request is None:
                raise ChildExecutionReportValidationError(
                    f"child result has no launch record: {result.launch_id}"
                )
            self._validate_result(request, result)

    @staticmethod
    def _validate_result(
        request: ChildExecutionRequestReport,
        result: ChildExecutionResultReport,
    ) -> None:
        """Validate one terminal result against its launch request.

        Args:
            request: Public request carrying root, parent, and depth identity.
            result: Public result carrying ownership and execution facts.

        Returns:
            ``None`` when result lineage and terminal facts are valid.

        Side effects:
            None.

        Raises:
            ChildExecutionReportValidationError: If ownership, run indexes,
                terminal state, budget, or usage is invalid.
        """

        launch_id = result.launch_id
        ownership = result.ownership
        if ownership.launch_id != launch_id:
            raise ChildExecutionReportValidationError(
                f"result ownership launch id mismatch: {launch_id}"
            )
        if (
            request.root_sample_sha256 is not None
            and ownership.root_sample_sha256 != request.root_sample_sha256
        ):
            raise ChildExecutionReportValidationError(
                f"result root sample mismatch: {launch_id}"
            )
        if (
            request.parent_pid is not None
            and ownership.parent_pid != request.parent_pid
        ):
            raise ChildExecutionReportValidationError(
                f"result parent pid mismatch: {launch_id}"
            )
        if ownership.depth != request.depth:
            raise ChildExecutionReportValidationError(
                f"result depth mismatch: {launch_id}"
            )
        if ownership.child_pid is None or ownership.child_pid <= 0:
            raise ChildExecutionReportValidationError(
                f"result child pid is invalid: {launch_id}"
            )
        if result.state not in _TERMINAL_STATES:
            raise ChildExecutionReportValidationError(
                f"result state is not terminal: {launch_id}"
            )
        if len(set(result.run_indexes)) != len(result.run_indexes):
            raise ChildExecutionReportValidationError(
                f"result run indexes are duplicated: {launch_id}"
            )
        if any(index < 0 for index in result.run_indexes):
            raise ChildExecutionReportValidationError(
                f"result run index is negative: {launch_id}"
            )
        DynamicChildExecutionAdapter._validate_budget(result.budget)
        DynamicChildExecutionAdapter._validate_usage(result.usage)

    @staticmethod
    def _validate_budget(budget: ChildExecutionBudgetReport) -> None:
        """Validate limits without substituting child-specific defaults.

        Args:
            budget: Public child budget report.

        Returns:
            ``None`` when all limits satisfy the frozen contract.

        Side effects:
            None.

        Raises:
            ChildExecutionReportValidationError: If any limit is invalid.
        """

        if budget.timeout_seconds <= 0:
            raise ChildExecutionReportValidationError(
                "child timeout budget is invalid"
            )
        if budget.max_api_count < 1:
            raise ChildExecutionReportValidationError(
                "child API budget is invalid"
            )
        if budget.max_instructions < -1:
            raise ChildExecutionReportValidationError(
                "child instruction budget is invalid"
            )

    @staticmethod
    def _validate_usage(usage: ChildExecutionBudgetUsageReport) -> None:
        """Validate independent per-child consumption counters.

        Args:
            usage: Public child budget-usage report.

        Returns:
            ``None`` when every consumed counter is non-negative.

        Side effects:
            None.

        Raises:
            ChildExecutionReportValidationError: If usage is negative.
        """

        if (
            usage.timeout_seconds_used < 0
            or usage.api_count_used < 0
            or usage.instructions_used < 0
        ):
            raise ChildExecutionReportValidationError(
                "child budget usage cannot be negative"
            )


__all__ = [
    "ChildExecutionReportValidationError",
    "DynamicChildExecutionAdapter",
]
