"""Exhaustive lifecycle and state-machine tests."""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from typing import Any

import pytest
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, rule

from github_steward.domain.errors import InvalidTransitionError
from github_steward.domain.lifecycles import (
    Approval,
    ApprovalCandidate,
    ApprovalCandidateState,
    ApprovalState,
    BlockReason,
    ExecutableOperation,
    ExecutableOperationState,
    ExecutionAttempt,
    ExecutionAttemptState,
)

CASES: tuple[
    tuple[
        type[Any],
        Callable[[Any], Any],
        frozenset[tuple[Any, Any]],
    ],
    ...,
] = (
    (
        ApprovalCandidateState,
        ApprovalCandidate,
        ApprovalCandidate._TRANSITIONS,
    ),
    (ApprovalState, Approval, Approval._TRANSITIONS),
    (
        ExecutableOperationState,
        ExecutableOperation,
        ExecutableOperation._TRANSITIONS,
    ),
    (
        ExecutionAttemptState,
        ExecutionAttempt,
        ExecutionAttempt._TRANSITIONS,
    ),
)


@pytest.mark.parametrize(("enum_type", "factory", "accepted"), CASES)
def test_transition_matrices_are_exhaustive_and_fail_closed(
    enum_type: type[StrEnum],
    factory: Callable[[Any], Any],
    accepted: frozenset[tuple[StrEnum, StrEnum]],
) -> None:
    for source in enum_type:
        for target in enum_type:
            original = factory(source)
            if (source, target) in accepted:
                result = original.transition(target)
                assert result.state is target
                assert original.state is source
                assert result == original.transition(target)
            else:
                with pytest.raises(InvalidTransitionError):
                    original.transition(target)
                assert original.state is source


def test_block_reasons_are_complete_and_not_operation_states() -> None:
    expected = {
        "INTEGRITY_FAILURE",
        "INCOMPATIBLE_SCHEMA",
        "REPOSITORY_ROUTE_MISMATCH",
        "PERMISSION_CHANGED",
        "POLICY_CHANGED",
        "AUTHORIZATION_REVOKED",
    }
    assert {reason.value for reason in BlockReason} == expected
    assert expected.isdisjoint(state.value for state in ExecutableOperationState)


class ExecutableOperationStateMachine(RuleBasedStateMachine):
    """Hypothesis explores accepted and rejected operation transitions."""

    @initialize()
    def create(self) -> None:
        self.operation = ExecutableOperation()

    @rule(next_state=st.sampled_from(list(ExecutableOperationState)))
    def request_transition(self, next_state: ExecutableOperationState) -> None:
        original = self.operation
        edge = (original.state, next_state)
        if edge in ExecutableOperation._TRANSITIONS:
            self.operation = original.transition(next_state)
            assert self.operation.state is next_state
            assert original.state is edge[0]
        else:
            with pytest.raises(InvalidTransitionError):
                original.transition(next_state)
            assert self.operation is original


TestExecutableOperationStateMachine = ExecutableOperationStateMachine.TestCase
