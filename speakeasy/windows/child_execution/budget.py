"""Execution-budget construction and accounting for child runs.

The factory in this module has no engine references and no global state.  It
copies the parent's three configured limits into an immutable
``ExecutionBudget`` and allocates fresh usage counters for every child.
"""

from __future__ import annotations

from .interfaces import ParentRuntimeConfig
from .models import BudgetUsage, ExecutionBudget


class ExecutionBudgetFactory:
    """Create equal parent/child limits with independent usage counters.

    The factory is safe to share between the parent and all children because
    it stores no per-run mutable state.  Callers own each ``BudgetUsage``
    object and pass it explicitly to the observation methods.
    """

    def capture_parent(self, config: ParentRuntimeConfig) -> ExecutionBudget:
        """Capture the parent's configured limits.

        Args:
            config: Runtime configuration exposing ``timeout``,
                ``max_api_count``, and ``max_instructions``.

        Returns:
            A frozen budget whose three limits equal the supplied parent
            configuration.

        Side effects:
            None.  The configuration object is not retained or mutated.

        Raises:
            ValueError: If any configured limit is invalid.
        """

        return ExecutionBudget(
            timeout_seconds=float(config.timeout),
            max_api_count=int(config.max_api_count),
            max_instructions=int(config.max_instructions),
            source="parent_config",
        )

    def for_child(
        self,
        parent_budget: ExecutionBudget,
    ) -> tuple[ExecutionBudget, BudgetUsage]:
        """Create an equal child budget and a fresh usage counter.

        Args:
            parent_budget: Immutable limits captured from the parent.

        Returns:
            ``(child_budget, child_usage)``.  The child budget has exactly the
            parent's three limits.  ``child_usage`` is a new zeroed object and
            is never shared with a parent or sibling.

        Side effects:
            Allocates one ``BudgetUsage`` object.  No engine state changes.
        """

        child_budget = ExecutionBudget(
            timeout_seconds=parent_budget.timeout_seconds,
            max_api_count=parent_budget.max_api_count,
            max_instructions=parent_budget.max_instructions,
            source="parent_config",
        )
        return child_budget, BudgetUsage()

    def observe_time(self, usage: BudgetUsage, seconds: float) -> None:
        """Record elapsed wall-clock time for one child.

        Args:
            usage: Usage counter owned by exactly one active child.
            seconds: Non-negative elapsed seconds to add.

        Returns:
            ``None``.

        Side effects:
            Adds ``seconds`` only to ``usage.timeout_seconds_used``.

        Raises:
            ValueError: If ``seconds`` is negative.
        """

        if seconds < 0:
            raise ValueError("elapsed time cannot be negative")
        usage.timeout_seconds_used += seconds

    def observe_api(self, usage: BudgetUsage) -> None:
        """Record one emulated API call for one child.

        Args:
            usage: Usage counter owned by exactly one active child.

        Returns:
            ``None``.

        Side effects:
            Increments only ``usage.api_count_used``.
        """

        usage.api_count_used += 1

    def observe_instructions(
        self,
        usage: BudgetUsage,
        count: int = 1,
    ) -> None:
        """Record emulated instructions for one child.

        Args:
            usage: Usage counter owned by exactly one active child.
            count: Non-negative number of instructions to add.

        Returns:
            ``None``.

        Side effects:
            Adds ``count`` only to ``usage.instructions_used``.

        Raises:
            ValueError: If ``count`` is negative.
        """

        if count < 0:
            raise ValueError("instruction count cannot be negative")
        usage.instructions_used += count

    def exceeded(
        self,
        budget: ExecutionBudget,
        usage: BudgetUsage,
    ) -> str | None:
        """Return the first limit exceeded by a child.

        Limits are checked in a stable order: wall-clock time, API count, then
        instruction count.  Reaching a limit itself is allowed; the next
        observation beyond it is reported as exceeded.  A parent instruction
        limit of ``-1`` remains unlimited.

        Args:
            budget: Immutable limits for the child that owns ``usage``.
            usage: Mutable counters for that same child.

        Returns:
            ``"timeout_seconds"``, ``"max_api_count"``,
            ``"max_instructions"``, or ``None`` when no limit is exceeded.

        Side effects:
            None.
        """

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


__all__ = ["ExecutionBudgetFactory"]
