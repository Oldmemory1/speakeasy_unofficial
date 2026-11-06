from __future__ import annotations

import pytest

from speakeasy.windows.child_execution.budget import ExecutionBudgetFactory
from speakeasy.windows.child_execution.interfaces import ChildBudgetFactory
from speakeasy.windows.child_execution.models import BudgetUsage, ExecutionBudget


class ParentConfig:
    """Explicit non-default parent limits used by budget tests."""

    timeout = 47.25
    max_api_count = 1_337
    max_instructions = 9_876_543


def test_child_budget_equals_parent_and_usage_is_fresh() -> None:
    factory = ExecutionBudgetFactory()
    parent_budget = factory.capture_parent(ParentConfig())

    child_budget, child_usage = factory.for_child(parent_budget)
    sibling_budget, sibling_usage = factory.for_child(parent_budget)

    assert child_budget.timeout_seconds == ParentConfig.timeout
    assert child_budget.max_api_count == ParentConfig.max_api_count
    assert child_budget.max_instructions == ParentConfig.max_instructions
    assert sibling_budget == child_budget
    assert child_usage is not sibling_usage
    assert child_usage == BudgetUsage()


def test_usage_observations_do_not_leak_between_children() -> None:
    factory = ExecutionBudgetFactory()
    _, first_usage = factory.for_child(
        factory.capture_parent(ParentConfig())
    )
    _, second_usage = factory.for_child(
        factory.capture_parent(ParentConfig())
    )

    factory.observe_api(first_usage)
    factory.observe_api(first_usage)
    factory.observe_time(first_usage, seconds=2.5)
    factory.observe_instructions(first_usage, count=7)

    assert first_usage.timeout_seconds_used == 2.5
    assert first_usage.api_count_used == 2
    assert first_usage.instructions_used == 7
    assert second_usage == BudgetUsage()


@pytest.mark.parametrize(
    ("usage", "expected"),
    [
        (BudgetUsage(timeout_seconds_used=47.5), "timeout_seconds"),
        (BudgetUsage(api_count_used=1_338), "max_api_count"),
        (BudgetUsage(instructions_used=9_876_544), "max_instructions"),
    ],
)
def test_exceeded_reports_first_exceeded_limit(
    usage: BudgetUsage,
    expected: str,
) -> None:
    factory = ExecutionBudgetFactory()
    budget = factory.capture_parent(ParentConfig())

    assert factory.exceeded(budget, usage) == expected


def test_reaching_an_exact_limit_is_not_exceeded() -> None:
    factory = ExecutionBudgetFactory()
    budget = factory.capture_parent(ParentConfig())
    usage = BudgetUsage(
        timeout_seconds_used=ParentConfig.timeout,
        api_count_used=ParentConfig.max_api_count,
        instructions_used=ParentConfig.max_instructions,
    )

    assert factory.exceeded(budget, usage) is None


def test_unlimited_instruction_budget_is_preserved() -> None:
    class UnlimitedConfig:
        """Parent configuration with an explicit unlimited instruction cap."""

        timeout = 3.5
        max_api_count = 19
        max_instructions = -1

    factory = ExecutionBudgetFactory()
    parent_budget = factory.capture_parent(UnlimitedConfig())
    child_budget, child_usage = factory.for_child(parent_budget)
    factory.observe_instructions(child_usage, count=10_000_000)

    assert child_budget.max_instructions == -1
    assert factory.exceeded(child_budget, child_usage) is None


def test_negative_instruction_observation_is_rejected() -> None:
    factory = ExecutionBudgetFactory()

    with pytest.raises(ValueError, match="negative"):
        factory.observe_instructions(BudgetUsage(), count=-1)


def test_negative_time_observation_is_rejected() -> None:
    factory = ExecutionBudgetFactory()

    with pytest.raises(ValueError, match="negative"):
        factory.observe_time(BudgetUsage(), seconds=-0.1)


def test_invalid_parent_limits_are_rejected() -> None:
    class InvalidConfig:
        """Parent configuration that violates the frozen budget contract."""

        timeout = 0.0
        max_api_count = 0
        max_instructions = -2

    with pytest.raises(ValueError, match="timeout_seconds"):
        ExecutionBudgetFactory().capture_parent(InvalidConfig())


def test_execution_budget_source_is_parent_config() -> None:
    budget = ExecutionBudget(
        timeout_seconds=1.0,
        max_api_count=2,
        max_instructions=3,
    )

    assert budget.source == "parent_config"


def test_concrete_budget_factory_implements_frozen_protocol() -> None:
    assert isinstance(ExecutionBudgetFactory(), ChildBudgetFactory)
