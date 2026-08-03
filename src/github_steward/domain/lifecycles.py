"""Immutable fail-closed lifecycle state machines."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar, Self

from github_steward.domain.errors import InvalidTransitionError


class ApprovalCandidateState(StrEnum):
    """Approval-candidate lifecycle states."""

    PREVIEWED = "PREVIEWED"
    APPROVED = "APPROVED"
    EXPIRED = "EXPIRED"
    SUPERSEDED = "SUPERSEDED"
    CANCELED = "CANCELED"


class ApprovalState(StrEnum):
    """Approval lifecycle states."""

    APPROVED = "APPROVED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    INVALIDATED_BY_STATE_CHANGE = "INVALIDATED_BY_STATE_CHANGE"
    SUPERSEDED = "SUPERSEDED"


class ExecutableOperationState(StrEnum):
    """Executable-operation lifecycle states."""

    SEALED = "SEALED"
    QUEUED = "QUEUED"
    VALIDATING = "VALIDATING"
    EXECUTION_IN_PROGRESS = "EXECUTION_IN_PROGRESS"
    SUCCEEDED = "SUCCEEDED"
    INVALIDATED = "INVALIDATED"
    BLOCKED = "BLOCKED"
    CANCELED = "CANCELED"
    MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"


class ExecutionAttemptState(StrEnum):
    """Execution-attempt lifecycle states."""

    CREATED = "CREATED"
    STARTED = "STARTED"
    REQUEST_SENT_OR_POSSIBLE = "REQUEST_SENT_OR_POSSIBLE"
    RESPONSE_RECEIVED = "RESPONSE_RECEIVED"
    UNKNOWN_OUTCOME = "UNKNOWN_OUTCOME"
    RECONCILING = "RECONCILING"
    CONFIRMED_APPLIED = "CONFIRMED_APPLIED"
    CONFIRMED_NOT_APPLIED = "CONFIRMED_NOT_APPLIED"
    MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"


class BlockReason(StrEnum):
    """Reasons for a blocked operation; these are not lifecycle states."""

    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    INCOMPATIBLE_SCHEMA = "INCOMPATIBLE_SCHEMA"
    REPOSITORY_ROUTE_MISMATCH = "REPOSITORY_ROUTE_MISMATCH"
    PERMISSION_CHANGED = "PERMISSION_CHANGED"
    POLICY_CHANGED = "POLICY_CHANGED"
    AUTHORIZATION_REVOKED = "AUTHORIZATION_REVOKED"


def _transition[StateT: StrEnum](
    *,
    lifecycle: str,
    source: StateT,
    target: StateT,
    transitions: frozenset[tuple[StateT, StateT]],
) -> StateT:
    if (source, target) not in transitions:
        raise InvalidTransitionError(lifecycle, source.value, target.value)
    return target


@dataclass(frozen=True, slots=True)
class ApprovalCandidate:
    """An immutable approval-candidate state value."""

    state: ApprovalCandidateState = ApprovalCandidateState.PREVIEWED
    _TRANSITIONS: ClassVar[
        frozenset[tuple[ApprovalCandidateState, ApprovalCandidateState]]
    ] = frozenset(
        {
            (ApprovalCandidateState.PREVIEWED, ApprovalCandidateState.APPROVED),
            (ApprovalCandidateState.PREVIEWED, ApprovalCandidateState.EXPIRED),
            (ApprovalCandidateState.PREVIEWED, ApprovalCandidateState.SUPERSEDED),
            (ApprovalCandidateState.PREVIEWED, ApprovalCandidateState.CANCELED),
        }
    )

    def transition(self, target: ApprovalCandidateState) -> Self:
        return type(self)(
            _transition(
                lifecycle=type(self).__name__,
                source=self.state,
                target=target,
                transitions=self._TRANSITIONS,
            )
        )


@dataclass(frozen=True, slots=True)
class Approval:
    """An immutable approval state value."""

    state: ApprovalState = ApprovalState.APPROVED
    _TRANSITIONS: ClassVar[frozenset[tuple[ApprovalState, ApprovalState]]] = frozenset(
        {
            (ApprovalState.APPROVED, ApprovalState.EXPIRED),
            (ApprovalState.APPROVED, ApprovalState.REVOKED),
            (
                ApprovalState.APPROVED,
                ApprovalState.INVALIDATED_BY_STATE_CHANGE,
            ),
            (ApprovalState.APPROVED, ApprovalState.SUPERSEDED),
        }
    )

    def transition(self, target: ApprovalState) -> Self:
        return type(self)(
            _transition(
                lifecycle=type(self).__name__,
                source=self.state,
                target=target,
                transitions=self._TRANSITIONS,
            )
        )


@dataclass(frozen=True, slots=True)
class ExecutableOperation:
    """An immutable executable-operation state value."""

    state: ExecutableOperationState = ExecutableOperationState.SEALED
    _TRANSITIONS: ClassVar[
        frozenset[tuple[ExecutableOperationState, ExecutableOperationState]]
    ] = frozenset(
        {
            (ExecutableOperationState.SEALED, ExecutableOperationState.QUEUED),
            (
                ExecutableOperationState.QUEUED,
                ExecutableOperationState.VALIDATING,
            ),
            (
                ExecutableOperationState.VALIDATING,
                ExecutableOperationState.EXECUTION_IN_PROGRESS,
            ),
            (
                ExecutableOperationState.EXECUTION_IN_PROGRESS,
                ExecutableOperationState.SUCCEEDED,
            ),
            *{
                (source, target)
                for source in (
                    ExecutableOperationState.SEALED,
                    ExecutableOperationState.QUEUED,
                    ExecutableOperationState.VALIDATING,
                )
                for target in (
                    ExecutableOperationState.INVALIDATED,
                    ExecutableOperationState.BLOCKED,
                    ExecutableOperationState.CANCELED,
                )
            },
            (
                ExecutableOperationState.EXECUTION_IN_PROGRESS,
                ExecutableOperationState.MANUAL_REVIEW_REQUIRED,
            ),
        }
    )

    def transition(self, target: ExecutableOperationState) -> Self:
        return type(self)(
            _transition(
                lifecycle=type(self).__name__,
                source=self.state,
                target=target,
                transitions=self._TRANSITIONS,
            )
        )


@dataclass(frozen=True, slots=True)
class ExecutionAttempt:
    """An immutable execution-attempt state value."""

    state: ExecutionAttemptState = ExecutionAttemptState.CREATED
    _TRANSITIONS: ClassVar[
        frozenset[tuple[ExecutionAttemptState, ExecutionAttemptState]]
    ] = frozenset(
        {
            (ExecutionAttemptState.CREATED, ExecutionAttemptState.STARTED),
            (
                ExecutionAttemptState.STARTED,
                ExecutionAttemptState.REQUEST_SENT_OR_POSSIBLE,
            ),
            (
                ExecutionAttemptState.REQUEST_SENT_OR_POSSIBLE,
                ExecutionAttemptState.RESPONSE_RECEIVED,
            ),
            (
                ExecutionAttemptState.REQUEST_SENT_OR_POSSIBLE,
                ExecutionAttemptState.UNKNOWN_OUTCOME,
            ),
            (
                ExecutionAttemptState.RESPONSE_RECEIVED,
                ExecutionAttemptState.CONFIRMED_APPLIED,
            ),
            (
                ExecutionAttemptState.RESPONSE_RECEIVED,
                ExecutionAttemptState.CONFIRMED_NOT_APPLIED,
            ),
            (
                ExecutionAttemptState.RESPONSE_RECEIVED,
                ExecutionAttemptState.UNKNOWN_OUTCOME,
            ),
            (
                ExecutionAttemptState.UNKNOWN_OUTCOME,
                ExecutionAttemptState.RECONCILING,
            ),
            (
                ExecutionAttemptState.RECONCILING,
                ExecutionAttemptState.CONFIRMED_APPLIED,
            ),
            (
                ExecutionAttemptState.RECONCILING,
                ExecutionAttemptState.CONFIRMED_NOT_APPLIED,
            ),
            (
                ExecutionAttemptState.RECONCILING,
                ExecutionAttemptState.MANUAL_REVIEW_REQUIRED,
            ),
        }
    )

    def transition(self, target: ExecutionAttemptState) -> Self:
        return type(self)(
            _transition(
                lifecycle=type(self).__name__,
                source=self.state,
                target=target,
                transitions=self._TRANSITIONS,
            )
        )
