from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from speakeasy.report import Report
from speakeasy.windows.child_execution.models import (
    AdmissionDecision,
    BudgetUsage,
    ChildEventOwnership,
    ChildExecutionReportData,
    ChildExecutionState,
    ChildFailure,
    ChildFailureKind,
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
    ChildExecutionReportAdapter,
)


def _report_data() -> ChildExecutionReportData:
    budget = ExecutionBudget(42.0, 900, 30_000)
    request = ChildLaunchRequest(
        launch_id="child-000001",
        root_sample_sha256="a" * 64,
        parent_launch_id=None,
        source_api="CreateProcess",
        parent_pid=100,
        parent_tid=101,
        depth=1,
        target=r"C:\Temp\child.exe",
        normalized_target=r"C:\Temp\child.exe",
        working_directory=r"C:\Temp",
        command_line=r'"C:\Temp\child.exe" /quiet',
        command_sha256="b" * 64,
        parent_budget=budget,
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
    process = SimpleNamespace(pid=200)
    ownership = ChildEventOwnership(
        root_sample_sha256="a" * 64,
        launch_id=request.launch_id,
        parent_pid=100,
        child_pid=200,
        depth=1,
    )
    record = ChildLaunchRecord(
        request=request,
        target=target,
        decision=AdmissionDecision(
            eligible=True,
            state=ChildExecutionState.ELIGIBLE,
            reason=None,
        ),
        process=process,
        state=ChildExecutionState.ENTRYPOINT_REACHED,
        reason=None,
    )
    result = ChildRunResult(
        launch_id=request.launch_id,
        ownership=ownership,
        state=ChildExecutionState.FAILED,
        outcome=ChildOutcome.ERROR,
        termination_reason=ChildTerminationReason.INVALID_FETCH,
        budget=budget,
        usage=BudgetUsage(
            timeout_seconds_used=1.5,
            api_count_used=20,
            instructions_used=300,
        ),
        run_indexes=(7,),
        error=ChildFailure(
            kind=ChildFailureKind.RUNTIME,
            message="invalid child fetch",
            pc=0x401000,
            api_name="kernel32.CreateProcess",
        ),
        entrypoint_reached=True,
    )
    return ChildExecutionReportData(
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


def test_report_adapter_serializes_results_and_ownership() -> None:
    child_report = ChildExecutionReportAdapter(
        policy={"max_depth": 1}
    ).from_report_data(_report_data())

    payload = child_report.model_dump(mode="json")
    request = payload["requests"][0]
    result = payload["results"][0]

    assert request["launch_id"] == "child-000001"
    assert request["target_sha256"] == "c" * 64
    assert "target_bytes" not in request
    assert result["ownership"]["child_pid"] == 200
    assert result["termination_reason"] == "invalid_fetch"
    assert result["budget"]["max_api_count"] == 900
    assert result["usage"]["api_count_used"] == 20
    assert result["failure"]["kind"] == "runtime"


def test_report_adapter_preserves_root_report_identity() -> None:
    child_report = ChildExecutionReportAdapter().from_report_data(
        _report_data()
    )
    report = Report(
        emulation_total_runtime=1.0,
        timestamp=1,
        sha256="f" * 64,
        child_execution=child_report,
    )

    payload = report.model_dump(mode="json")

    assert payload["sha256"] == "f" * 64
    assert payload["child_execution"]["request_count"] == 1
    assert payload["child_execution"]["results"][0]["launch_id"] == (
        "child-000001"
    )


def test_model_only_report_has_empty_results() -> None:
    data = _report_data()
    child_report = ChildExecutionReportAdapter().from_report_data(
        ChildExecutionReportData(
            mode="model_only",
            execution_enabled=False,
            request_count=data.request_count,
            eligible_count=data.eligible_count,
            target_resolved_count=data.target_resolved_count,
            process_object_created_count=data.process_object_created_count,
            thread_queued_count=0,
            entrypoint_reached_count=0,
            records=(
                replace(
                    data.records[0],
                    state=ChildExecutionState.TARGET_RESOLVED,
                ),
            ),
            results=(),
        )
    )

    assert child_report.execution_enabled is False
    assert child_report.results == []


def test_report_adapter_rejects_orphan_result() -> None:
    data = _report_data()
    orphan = ChildExecutionReportData(
        mode=data.mode,
        execution_enabled=data.execution_enabled,
        request_count=0,
        eligible_count=0,
        target_resolved_count=0,
        process_object_created_count=0,
        thread_queued_count=0,
        entrypoint_reached_count=0,
        records=(),
        results=data.results,
    )

    with pytest.raises(ValueError, match="no launch record"):
        ChildExecutionReportAdapter().from_report_data(orphan)
