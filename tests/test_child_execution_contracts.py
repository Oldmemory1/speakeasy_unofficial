from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from speakeasy.windows.child_execution import (
    BudgetUsage,
    ChildBudgetFactory,
    ChildExecutionOptions,
    ChildRequestFactory,
    ChildTargetSource,
    ExecutionBudget,
    TargetPayloadRef,
)


class FakeParentConfig:
    """Explicit parent limit input used to test the budget protocol."""

    timeout = 37.5
    max_api_count = 977
    max_instructions = 123_456


class FakeExecutionBudgetFactory:
    """Minimal budget factory proving the declared interface is injectable."""

    def capture_parent(self, config):
        """Copy the parent limits without retaining mutable parent state."""

        return ExecutionBudget(
            timeout_seconds=config.timeout,
            max_api_count=config.max_api_count,
            max_instructions=config.max_instructions,
        )

    def for_child(self, parent_budget):
        """Return equal child limits and a fresh usage counter."""

        return parent_budget, BudgetUsage()

    def observe_time(self, usage, seconds):
        """Increment the supplied child's elapsed-time usage."""

        usage.timeout_seconds_used += seconds

    def observe_api(self, usage):
        """Increment the supplied child's API usage."""

        usage.api_count_used += 1

    def observe_instructions(self, usage, count=1):
        """Increment the supplied child's instruction usage."""

        usage.instructions_used += count

    def exceeded(self, budget, usage):
        """Return the first exceeded limit for the supplied usage."""

        if usage.timeout_seconds_used > budget.timeout_seconds:
            return "timeout_seconds"
        if usage.api_count_used > budget.max_api_count:
            return "max_api_count"
        if (
            budget.max_instructions >= 0
            and usage.instructions_used > budget.max_instructions
        ):
            return "max_instructions"
        return None


def test_budget_protocol_accepts_explicit_dependency() -> None:
    factory = FakeExecutionBudgetFactory()

    assert isinstance(factory, ChildBudgetFactory)


def test_child_budget_limits_equal_parent_but_usage_is_fresh() -> None:
    factory = FakeExecutionBudgetFactory()
    parent_budget = factory.capture_parent(FakeParentConfig())
    child_budget, child_usage = factory.for_child(parent_budget)
    sibling_budget, sibling_usage = factory.for_child(parent_budget)

    assert child_budget.timeout_seconds == FakeParentConfig.timeout
    assert child_budget.max_api_count == FakeParentConfig.max_api_count
    assert child_budget.max_instructions == FakeParentConfig.max_instructions
    assert sibling_budget == child_budget
    assert child_usage is not sibling_usage

    factory.observe_api(child_usage)
    factory.observe_instructions(child_usage, 3)

    assert child_usage.api_count_used == 1
    assert child_usage.instructions_used == 3
    assert sibling_usage.api_count_used == 0
    assert sibling_usage.instructions_used == 0


def test_execution_budget_is_frozen() -> None:
    budget = ExecutionBudget(
        timeout_seconds=12.0,
        max_api_count=200,
        max_instructions=-1,
    )

    with pytest.raises(FrozenInstanceError):
        budget.timeout_seconds = 1.0

    assert budget.source == "parent_config"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_depth", 0),
        ("max_children_per_root", -1),
        ("max_target_bytes", 0),
    ],
)
def test_child_execution_options_reject_invalid_limits(
    field: str,
    value: int,
) -> None:
    with pytest.raises(ValueError):
        ChildExecutionOptions(**{field: value})


def test_options_reject_unavailable_as_an_executable_source() -> None:
    with pytest.raises(ValueError, match="unavailable"):
        ChildExecutionOptions(
            allowed_sources=(ChildTargetSource.UNAVAILABLE,),
        )


def test_target_payload_does_not_expose_bytes_in_repr() -> None:
    payload = TargetPayloadRef(
        source=ChildTargetSource.FIXTURE,
        sha256="a" * 64,
        size=4,
        emu_path=r"C:\fixtures\child.exe",
        data=b"\x7fELF",
    )

    assert "\\x7fELF" not in repr(payload)
    assert payload.data == b"\x7fELF"


def test_request_factory_protocol_is_runtime_checkable() -> None:
    class ExplicitFactory:
        """Stub implementing only the declared request-factory method."""

        def build(self, *args, **kwargs):
            """Return no request because this test checks structure only."""

            return None

    assert isinstance(ExplicitFactory(), ChildRequestFactory)
