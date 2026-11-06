"""Tests for the public-report-to-dynamic-tracker adapter boundary."""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from speakeasy.report import ChildExecutionReport
from speakeasy.windows.child_execution.dynamic_adapter import (
    ChildExecutionReportValidationError,
    DynamicChildExecutionAdapter,
)
from speakeasy.windows.child_execution.interfaces import DynamicChildResultAdapter
from speakeasy.windows.child_execution.models import (
    AdmissionDecision,
    BudgetUsage,
    ChildEventOwnership,
    ChildExecutionReportData,
    ChildExecutionState,
    ChildLaunchRecord,
    ChildLaunchRequest,
    ChildOutcome,
    ChildRunResult,
    ChildTargetSource,
    ChildTerminationReason,
    ExecutionBudget,
    ResolvedChildTarget,
)
from speakeasy.windows.child_execution.reporting import (
    ChildExecutionReportProjector,
)

ROOT_SHA256 = "a" * 64


@dataclass
class FakeTrackerView:
    """Recording tracker implementing only the declared public method."""

    reports: list[ChildExecutionReport]

    def update_child_execution(self, report: ChildExecutionReport) -> None:
        """Record one immutable public report."""

        self.reports.append(report)


def _report() -> ChildExecutionReport:
    """Build one projected terminal child report."""

    request = ChildLaunchRequest(
        launch_id="child-000001",
        root_sample_sha256=ROOT_SHA256,
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
    target = ResolvedChildTarget(
        source=ChildTargetSource.DROPPED_FILE,
        normalized_path=request.normalized_target,
        payload_ref=None,
        sha256="c" * 64,
        size=4096,
        file_format="pe",
        arch="x86",
        module_type="exe",
        entrypoint_rva=0x1000,
        resolved=True,
        reason=None,
    )
    record = ChildLaunchRecord(
        request=request,
        target=target,
        decision=AdmissionDecision(
            eligible=True,
            state=ChildExecutionState.ELIGIBLE,
            reason=None,
        ),
        process=SimpleNamespace(pid=303),
        state=ChildExecutionState.COMPLETED,
    )
    result = ChildRunResult(
        launch_id=request.launch_id,
        ownership=ChildEventOwnership(
            root_sample_sha256=ROOT_SHA256,
            launch_id=request.launch_id,
            parent_pid=101,
            child_pid=303,
            depth=1,
        ),
        state=ChildExecutionState.COMPLETED,
        outcome=ChildOutcome.OK,
        termination_reason=ChildTerminationReason.NORMAL_EXIT,
        budget=ExecutionBudget(12.0, 200, 2_000),
        usage=BudgetUsage(1.25, 17, 250),
        run_indexes=(7,),
        error=None,
        entrypoint_reached=True,
    )
    snapshot = ChildExecutionReportData(
        mode="scheduled",
        execution_enabled=True,
        request_count=1,
        eligible_count=1,
        target_resolved_count=1,
        process_object_created_count=1,
        thread_queued_count=1,
        entrypoint_reached_count=1,
        records=(record,),
        results=(result,),
    )
    return ChildExecutionReportProjector(
        policy={"max_depth": 1}
    ).project(snapshot)


def test_adapter_is_runtime_protocol_compatible() -> None:
    assert isinstance(DynamicChildExecutionAdapter(), DynamicChildResultAdapter)


def test_adapter_forwards_public_report_once() -> None:
    tracker = FakeTrackerView([])
    report = _report()

    DynamicChildExecutionAdapter().apply(tracker, report)

    assert tracker.reports == [report]
    assert tracker.reports[0] is report


def test_adapter_rejects_duplicate_launch_ids_before_tracker_call() -> None:
    report = _report()
    request = report.requests[0]
    tracker = FakeTrackerView([])

    with pytest.raises(
        ChildExecutionReportValidationError,
        match="duplicate child launch id",
    ):
        DynamicChildExecutionAdapter().apply(
            tracker,
            report.model_copy(
                update={
                    "request_count": 2,
                    "requests": [request, request],
                }
            ),
        )

    assert tracker.reports == []


def test_adapter_rejects_orphan_result_before_tracker_call() -> None:
    report = _report()
    orphan = report.results[0].model_copy(
        update={"launch_id": "child-999999"}
    )
    tracker = FakeTrackerView([])

    with pytest.raises(
        ChildExecutionReportValidationError,
        match="no launch record",
    ):
        DynamicChildExecutionAdapter().apply(
            tracker,
            report.model_copy(update={"results": [orphan]}),
        )

    assert tracker.reports == []


def test_adapter_rejects_ownership_mismatch_before_tracker_call() -> None:
    report = _report()
    result = report.results[0]
    ownership = result.ownership.model_copy(
        update={"root_sample_sha256": "c" * 64}
    )
    tracker = FakeTrackerView([])

    with pytest.raises(
        ChildExecutionReportValidationError,
        match="root sample mismatch",
    ):
        DynamicChildExecutionAdapter().apply(
            tracker,
            report.model_copy(
                update={
                    "results": [
                        result.model_copy(update={"ownership": ownership})
                    ]
                }
            ),
        )

    assert tracker.reports == []


def test_adapter_rejects_state_count_mismatch_before_tracker_call() -> None:
    tracker = FakeTrackerView([])

    with pytest.raises(
        ChildExecutionReportValidationError,
        match="states do not match",
    ):
        DynamicChildExecutionAdapter().apply(
            tracker,
            _report().model_copy(update={"states": {}}),
        )

    assert tracker.reports == []


def test_adapter_rejects_invalid_child_budget_before_tracker_call() -> None:
    report = _report()
    result = report.results[0]
    budget = result.budget.model_copy(update={"max_instructions": -2})
    tracker = FakeTrackerView([])

    with pytest.raises(
        ChildExecutionReportValidationError,
        match="instruction budget is invalid",
    ):
        DynamicChildExecutionAdapter().apply(
            tracker,
            report.model_copy(
                update={
                    "results": [
                        result.model_copy(update={"budget": budget})
                    ]
                }
            ),
        )

    assert tracker.reports == []
