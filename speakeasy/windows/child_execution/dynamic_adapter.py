"""Adapter from authoritative child report DTOs to dynamic-stage trackers.

The dynamic stage consumes engine facts only through
:class:`ChildExecutionReportData`.  This module deliberately has no dependency
on emulator processes, scheduler queues, API-handler results, or private
tracker dictionaries.
"""

from __future__ import annotations

from .interfaces import ProcessExecutionTrackerProtocol
from .models import (
    ChildExecutionReportData,
    ChildExecutionState,
    ChildLaunchRecord,
)


class ChildExecutionReportValidationError(ValueError):
    """Raised when a report cannot be applied without inventing ownership."""


class DynamicChildExecutionAdapter:
    """Validate and apply one immutable child report to a process tracker.

    Args:
        None.  The tracker is supplied per :meth:`apply` call so one adapter
        can serve multiple independent samples.

    The adapter owns no launch or tracker state.  It validates report
    referential integrity and delegates state changes to the tracker's
    explicit public interface.
    """

    def apply(
        self,
        tracker: ProcessExecutionTrackerProtocol,
        report: ChildExecutionReportData,
    ) -> None:
        """Apply authoritative child fields to a dynamic-stage tracker.

        Args:
            tracker: Tracker implementing the explicit
                ``update_child_execution`` protocol method.  Its storage and
                private fields are not accessed by this adapter.
            report: Immutable engine snapshot containing launch records and
                completed child results.

        Returns:
            ``None``.

        Side effects:
            Calls ``tracker.update_child_execution(report)`` exactly once after
            validation succeeds.  It does not mutate engine or scheduler state.

        Raises:
            ChildExecutionReportValidationError: If launch identities are
                duplicated, result ownership is orphaned, or result ownership
                disagrees with its request.
        """

        self._validate(report)
        tracker.update_child_execution(report)

    def _validate(self, report: ChildExecutionReportData) -> None:
        """Reject snapshots whose result lineage cannot be proven.

        Args:
            report: Immutable report snapshot to validate.

        Returns:
            ``None`` when every result can be tied to exactly one request.

        Side effects:
            None.

        Raises:
            ChildExecutionReportValidationError: If the report is internally
                inconsistent.
        """

        if report.request_count != len(report.records):
            raise ChildExecutionReportValidationError(
                "request_count does not match launch records"
            )

        records_by_launch_id = {}
        for record in report.records:
            launch_id = record.request.launch_id
            if launch_id in records_by_launch_id:
                raise ChildExecutionReportValidationError(
                    f"duplicate child launch id: {launch_id}"
                )
            records_by_launch_id[launch_id] = record

        result_launch_ids: set[str] = set()
        for result in report.results:
            launch_id = result.launch_id
            record = records_by_launch_id.get(launch_id)
            if record is None:
                raise ChildExecutionReportValidationError(
                    f"child result has no launch record: {launch_id}"
                )
            if launch_id in result_launch_ids:
                raise ChildExecutionReportValidationError(
                    f"duplicate child result for launch id: {launch_id}"
                )
            result_launch_ids.add(launch_id)

            ownership = result.ownership
            request = record.request
            if ownership.launch_id != launch_id:
                raise ChildExecutionReportValidationError(
                    f"result ownership launch id mismatch: {launch_id}"
                )
            if ownership.root_sample_sha256 != request.root_sample_sha256:
                raise ChildExecutionReportValidationError(
                    f"result root sample mismatch: {launch_id}"
                )
            if ownership.parent_pid != request.parent_pid:
                raise ChildExecutionReportValidationError(
                    f"result parent pid mismatch: {launch_id}"
                )
            if ownership.depth != request.depth:
                raise ChildExecutionReportValidationError(
                    f"result depth mismatch: {launch_id}"
                )
            if ownership.child_pid <= 0:
                raise ChildExecutionReportValidationError(
                    f"result child pid is invalid: {launch_id}"
                )

            if result.state not in (
                ChildExecutionState.COMPLETED,
                ChildExecutionState.PARTIAL,
                ChildExecutionState.FAILED,
            ):
                raise ChildExecutionReportValidationError(
                    f"result state is not terminal: {launch_id}"
                )

        self._validate_counts(report, records_by_launch_id)

    @staticmethod
    def _validate_counts(
        report: ChildExecutionReportData,
        records_by_launch_id: dict[str, ChildLaunchRecord],
    ) -> None:
        """Check summary counters against immutable launch records.

        Args:
            report: Snapshot whose summary counters are checked.
            records_by_launch_id: Validated records indexed by stable launch id.

        Returns:
            ``None`` when all summary counters agree with the records.

        Side effects:
            None.

        Raises:
            ChildExecutionReportValidationError: If a counter disagrees.
        """

        records = tuple(records_by_launch_id.values())
        expected_counts = {
            "eligible_count": sum(
                record.decision is not None and record.decision.eligible
                for record in records
            ),
            "target_resolved_count": sum(
                record.target is not None and record.target.resolved
                for record in records
            ),
            "process_object_created_count": sum(
                record.process is not None for record in records
            ),
            "thread_queued_count": sum(
                record.state
                in {
                    ChildExecutionState.THREAD_QUEUED,
                    ChildExecutionState.ENTRYPOINT_REACHED,
                    ChildExecutionState.COMPLETED,
                    ChildExecutionState.PARTIAL,
                }
                for record in records
            ),
            "entrypoint_reached_count": sum(
                record.state
                in {
                    ChildExecutionState.ENTRYPOINT_REACHED,
                    ChildExecutionState.COMPLETED,
                    ChildExecutionState.PARTIAL,
                }
                for record in records
            ),
        }
        actual_counts = {
            "eligible_count": report.eligible_count,
            "target_resolved_count": report.target_resolved_count,
            "process_object_created_count": report.process_object_created_count,
            "thread_queued_count": report.thread_queued_count,
            "entrypoint_reached_count": report.entrypoint_reached_count,
        }
        for name, expected in expected_counts.items():
            if actual_counts[name] != expected:
                raise ChildExecutionReportValidationError(
                    f"{name} does not match launch records"
                )


__all__ = [
    "ChildExecutionReportValidationError",
    "DynamicChildExecutionAdapter",
]
