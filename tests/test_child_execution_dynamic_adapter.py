"""Tests for the report-to-dynamic-stage adapter boundary."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from speakeasy.windows.child_execution.dynamic_adapter import (
    ChildExecutionReportValidationError,
    DynamicChildExecutionAdapter,
)
from speakeasy.windows.child_execution.interfaces import DynamicChildResultAdapter
from speakeasy.windows.child_execution.models import (
    BudgetUsage,
    ChildEventOwnership,
    ChildExecutionReportData,
    ChildExecutionState,
    ChildLaunchRecord,
    ChildLaunchRequest,
    ChildOutcome,
    ChildRunResult,
    ChildTerminationReason,
    ExecutionBudget,
)

ROOT_SHA256 = "a" * 64


@dataclass
class FakeTrackerView:
    """Recording tracker that implements only the declared public method."""

    reports: list[ChildExecutionReportData]

    def update_child_execution(
        self,
        report: ChildExecutionReportData,
    ) -> None:
        """Record one immutable report snapshot."""

        self.reports.append(report)


def _request(
    launch_id: str = "child-000001",
    *,
    root_sample_sha256: str = ROOT_SHA256,
) -> ChildLaunchRequest:
    return ChildLaunchRequest(
        launch_id=launch_id,
        root_sample_sha256=root_sample_sha256,
        parent_launch_id=None,
        source_api="CreateProcess",
        parent_pid=101,
        parent_tid=202,
        depth=1,
        target=r"C:\Windows\Temp\child.exe",
        normalized_target=r"C:\Windows\Temp\child.exe",
        working_directory=r"C:\Windows\Temp",
        command_line=r'"C:\Windows\Temp\child.exe" /quiet',
        command_sha256="b" * 64,
        parent_budget=ExecutionBudget(12.0, 200, 2_000),
    )


def _result(
    launch_id: str = "child-000001",
    *,
    root_sample_sha256: str = ROOT_SHA256,
    child_pid: int = 303,
    state: ChildExecutionState = ChildExecutionState.COMPLETED,
) -> ChildRunResult:
    budget = ExecutionBudget(12.0, 200, 2_000)
    return ChildRunResult(
        launch_id=launch_id,
        ownership=ChildEventOwnership(
            root_sample_sha256=root_sample_sha256,
            launch_id=launch_id,
            parent_pid=101,
            child_pid=child_pid,
            depth=1,
        ),
        state=state,
        outcome=ChildOutcome.OK,
        termination_reason=ChildTerminationReason.NORMAL_EXIT,
        budget=budget,
        usage=BudgetUsage(),
        run_indexes=(7,),
        error=None,
    )


def _report(
    *,
    records: tuple[ChildLaunchRecord, ...] | None = None,
    results: tuple[ChildRunResult, ...] | None = None,
) -> ChildExecutionReportData:
    actual_records = records or (
        ChildLaunchRecord(
            request=_request(),
            state=ChildExecutionState.COMPLETED,
        ),
    )
    actual_results = results or (_result(),)
    return ChildExecutionReportData(
        mode="scheduled",
        execution_enabled=True,
        request_count=len(actual_records),
        eligible_count=sum(
            record.decision is not None and record.decision.eligible
            for record in actual_records
        ),
        target_resolved_count=sum(
            record.target is not None and record.target.resolved
            for record in actual_records
        ),
        process_object_created_count=sum(
            record.process is not None for record in actual_records
        ),
        thread_queued_count=sum(
            record.state
            in {
                ChildExecutionState.THREAD_QUEUED,
                ChildExecutionState.ENTRYPOINT_REACHED,
                ChildExecutionState.COMPLETED,
                ChildExecutionState.PARTIAL,
            }
            for record in actual_records
        ),
        entrypoint_reached_count=sum(
            record.state
            in {
                ChildExecutionState.ENTRYPOINT_REACHED,
                ChildExecutionState.COMPLETED,
                ChildExecutionState.PARTIAL,
            }
            for record in actual_records
        ),
        records=actual_records,
        results=actual_results,
    )


def test_adapter_is_runtime_protocol_compatible() -> None:
    assert isinstance(DynamicChildExecutionAdapter(), DynamicChildResultAdapter)


def test_adapter_forwards_authoritative_report_once() -> None:
    tracker = FakeTrackerView([])
    report = _report()

    DynamicChildExecutionAdapter().apply(tracker, report)

    assert tracker.reports == [report]
    assert tracker.reports[0] is report


def test_adapter_rejects_duplicate_launch_ids_before_tracker_call() -> None:
    record = ChildLaunchRecord(
        request=_request(),
        state=ChildExecutionState.COMPLETED,
    )
    tracker = FakeTrackerView([])

    with pytest.raises(
        ChildExecutionReportValidationError,
        match="duplicate child launch id",
    ):
        DynamicChildExecutionAdapter().apply(
            tracker,
            _report(records=(record, record)),
        )

    assert tracker.reports == []


def test_adapter_rejects_result_without_launch_record() -> None:
    tracker = FakeTrackerView([])

    with pytest.raises(
        ChildExecutionReportValidationError,
        match="no launch record",
    ):
        DynamicChildExecutionAdapter().apply(
            tracker,
            _report(results=(_result("child-999999"),)),
        )

    assert tracker.reports == []


def test_adapter_rejects_root_ownership_mismatch() -> None:
    tracker = FakeTrackerView([])

    with pytest.raises(
        ChildExecutionReportValidationError,
        match="root sample mismatch",
    ):
        DynamicChildExecutionAdapter().apply(
            tracker,
            _report(results=(_result(root_sample_sha256="c" * 64),)),
        )

    assert tracker.reports == []


def test_adapter_rejects_invalid_child_pid() -> None:
    tracker = FakeTrackerView([])

    with pytest.raises(
        ChildExecutionReportValidationError,
        match="child pid is invalid",
    ):
        DynamicChildExecutionAdapter().apply(
            tracker,
            _report(results=(_result(child_pid=0),)),
        )

    assert tracker.reports == []
