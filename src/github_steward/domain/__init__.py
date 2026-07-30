"""Framework-free domain contracts."""

from github_steward.domain.canonical import (
    DIGEST_FORMAT,
    CanonicalEnvelope,
    CanonicalValue,
    Digest,
    JsonCanonicalValue,
    freeze_canonical_value,
    to_json_compatible,
    validate_digest_timestamp,
)
from github_steward.domain.errors import (
    CanonicalizationError,
    DomainValidationError,
    InvalidTransitionError,
)
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

__all__ = [
    "DIGEST_FORMAT",
    "Approval",
    "ApprovalCandidate",
    "ApprovalCandidateState",
    "ApprovalState",
    "BlockReason",
    "CanonicalEnvelope",
    "CanonicalValue",
    "CanonicalizationError",
    "Digest",
    "DomainValidationError",
    "ExecutableOperation",
    "ExecutableOperationState",
    "ExecutionAttempt",
    "ExecutionAttemptState",
    "InvalidTransitionError",
    "JsonCanonicalValue",
    "freeze_canonical_value",
    "to_json_compatible",
    "validate_digest_timestamp",
]
