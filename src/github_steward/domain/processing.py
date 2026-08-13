"""Deterministic GS-I2 receipt, lease, retry, and recovery contracts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final, cast
from uuid import UUID, uuid5

from github_steward.domain.canonical import (
    MAX_SAFE_INTEGER,
    CanonicalValue,
    freeze_canonical_value,
    validate_digest_timestamp,
)
from github_steward.domain.errors import DomainValidationError

IDENTITY_NAMESPACE: Final = UUID("15200e7d-6747-5b89-bf26-870ce9894353")
PROVIDER: Final = "synthetic"
WORK_TYPE: Final = "PROCESS_SYNTHETIC_OBSERVATION"
DELIVERY_SCHEMA_ID: Final = "github-steward.synthetic-delivery"
OBSERVATION_SCHEMA_ID: Final = "github-steward.synthetic-observation"
ANALYSIS_VIEW_SCHEMA_ID: Final = "github-steward.synthetic-analysis-view"
AUDIT_SCHEMA_ID: Final = "github-steward.local-processing-audit"
SCHEMA_VERSION: Final = 1
LEASE_DURATION_SECONDS: Final = 300
RETRY_DELAY_SECONDS: Final = 60
MAXIMUM_ATTEMPTS: Final = 3
RECONCILIATION_BATCH_LIMIT: Final = 100

_SYNTHETIC_KEYS: Final = frozenset(
    {
        "entity_kind",
        "entity_id",
        "observed_at",
        "sequence",
        "expected_pointer_version",
        "observation",
    }
)


class WorkState(StrEnum):
    """Complete durable work-state inventory."""

    AVAILABLE = "AVAILABLE"
    PROCESSING = "PROCESSING"
    RETRY_WAIT = "RETRY_WAIT"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class AttemptState(StrEnum):
    """Complete durable attempt-state inventory."""

    STARTED = "STARTED"
    SUCCEEDED = "SUCCEEDED"
    RETRYABLE_FAILURE = "RETRYABLE_FAILURE"
    TERMINAL_FAILURE = "TERMINAL_FAILURE"
    ABANDONED = "ABANDONED"


class PointerOutcome(StrEnum):
    """Explicit current-pointer completion outcomes."""

    CREATED = "CREATED"
    UPDATED = "UPDATED"
    POINTER_CONFLICT = "POINTER_CONFLICT"


class ProcessingOutcome(StrEnum):
    """One local processing invocation outcome."""

    NO_WORK = "NO_WORK"
    SUCCEEDED = "SUCCEEDED"
    RETRY_SCHEDULED = "RETRY_SCHEDULED"
    FAILED = "FAILED"
    LEASE_LOST = "LEASE_LOST"


class FailureKind(StrEnum):
    """Project-owned failure classifications persisted by T5."""

    RETRYABLE_LOCAL_PROCESSING = "RETRYABLE_LOCAL_PROCESSING"
    PERMANENT_LOCAL_PROCESSING = "PERMANENT_LOCAL_PROCESSING"
    UNEXPECTED_LOCAL_FAILURE = "UNEXPECTED_LOCAL_FAILURE"


class FaultPoint(StrEnum):
    """Mandatory deterministic transaction fault-injection locations."""

    AFTER_INBOX_INSERT = "after_inbox_insert_before_work_insert"
    AFTER_CLAIM_UPDATE = "after_work_claim_update_before_attempt_insert"
    AFTER_ATTEMPT_INSERT = "after_attempt_insert_before_claim_commit"
    AFTER_OBSERVATION_INSERT = "after_canonical_observation_insert"
    AFTER_ANALYSIS_VIEW_INSERT = "after_analysis_view_insert"
    AFTER_ASSOCIATION_INSERT = "after_association_insert"
    AFTER_POINTER_WRITE = "after_pointer_create_or_compare_and_swap"
    AFTER_AUDIT_INSERT = "after_audit_insert"
    AFTER_ATTEMPT_COMPLETION = "after_attempt_completion_before_work_completion"
    AFTER_WORK_COMPLETION = "after_work_completion_before_commit"
    AFTER_COMPLETION_COMMIT = "after_completion_commit_before_acknowledgement"
    DURING_RECONCILIATION = "during_expired_work_reconciliation"


@dataclass(frozen=True, slots=True, init=False)
class SyntheticDelivery:
    """Validated, copied, and deeply frozen decoded synthetic mapping."""

    entity_kind: str
    entity_id: str
    observed_at: datetime
    observed_at_text: str
    sequence: int
    expected_pointer_version: int | None
    observation: CanonicalValue
    payload: Mapping[str, CanonicalValue]

    def __init__(self, value: Mapping[str, object]) -> None:
        if not isinstance(value, Mapping):
            raise DomainValidationError("synthetic delivery must be a decoded mapping")
        keys = frozenset(value)
        if keys != _SYNTHETIC_KEYS:
            missing = sorted(_SYNTHETIC_KEYS - keys)
            additional = sorted(keys - _SYNTHETIC_KEYS)
            raise DomainValidationError(
                f"synthetic delivery keys differ: missing={missing}, additional={additional}"
            )

        entity_kind = _nonempty_string(value["entity_kind"], "entity_kind")
        entity_id = _nonempty_string(value["entity_id"], "entity_id")
        observed_at_text = _timestamp_string(value["observed_at"])
        sequence = _bounded_integer(value["sequence"], "sequence", minimum=0)
        expected = value["expected_pointer_version"]
        if expected is not None:
            expected = _bounded_integer(
                expected,
                "expected_pointer_version",
                minimum=0,
            )
        observation = freeze_canonical_value(value["observation"])
        payload = freeze_canonical_value(
            {
                "entity_kind": entity_kind,
                "entity_id": entity_id,
                "observed_at": observed_at_text,
                "sequence": sequence,
                "expected_pointer_version": expected,
                "observation": observation,
            }
        )
        frozen_payload = cast(Mapping[str, CanonicalValue], payload)

        object.__setattr__(self, "entity_kind", entity_kind)
        object.__setattr__(self, "entity_id", entity_id)
        object.__setattr__(
            self,
            "observed_at",
            datetime.strptime(observed_at_text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                tzinfo=UTC
            ),
        )
        object.__setattr__(self, "observed_at_text", observed_at_text)
        object.__setattr__(self, "sequence", sequence)
        object.__setattr__(self, "expected_pointer_version", expected)
        object.__setattr__(self, "observation", observation)
        object.__setattr__(self, "payload", frozen_payload)


def _nonempty_string(value: object, field: str) -> str:
    if not isinstance(value, str) or value == "":
        raise DomainValidationError(f"{field} must be a non-empty string")
    return value


def _timestamp_string(value: object) -> str:
    if not isinstance(value, str):
        raise DomainValidationError("observed_at must be a UTC timestamp string")
    return validate_digest_timestamp(value)


def _bounded_integer(value: object, field: str, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise DomainValidationError(f"{field} must be an integer")
    if value < minimum or value > MAX_SAFE_INTEGER:
        raise DomainValidationError(
            f"{field} must be between {minimum} and {MAX_SAFE_INTEGER}"
        )
    return value


def require_utc_datetime(value: datetime, field: str = "timestamp") -> datetime:
    """Reject naive or non-UTC clock values while preserving microseconds."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise DomainValidationError(f"{field} must be timezone-aware UTC")
    if value.utcoffset() != UTC.utcoffset(value):
        raise DomainValidationError(f"{field} must use UTC")
    return value


def delivery_id(provider_delivery_id: str) -> str:
    """Derive the exact deterministic synthetic delivery identifier."""

    return str(uuid5(IDENTITY_NAMESPACE, f"delivery:synthetic:{provider_delivery_id}"))


def work_record_id(delivery_identifier: str) -> str:
    """Derive the exact deterministic work identifier."""

    return str(
        uuid5(
            IDENTITY_NAMESPACE,
            f"work:{delivery_identifier}:{WORK_TYPE}",
        )
    )


def work_attempt_id(work_identifier: str, attempt_number: int) -> str:
    """Derive the exact deterministic attempt identifier."""

    return str(
        uuid5(
            IDENTITY_NAMESPACE,
            f"attempt:{work_identifier}:{attempt_number}",
        )
    )


def observation_version_id(work_identifier: str, payload_digest: str) -> str:
    """Derive the exact deterministic immutable observation identifier."""

    return str(
        uuid5(
            IDENTITY_NAMESPACE,
            f"observation:{work_identifier}:{payload_digest}",
        )
    )


def analysis_view_id(work_identifier: str, payload_digest: str) -> str:
    """Derive the exact deterministic analysis-view identifier."""

    return str(
        uuid5(
            IDENTITY_NAMESPACE,
            f"analysis-view:{work_identifier}:{payload_digest}",
        )
    )


def audit_event_id(
    work_identifier: str,
    attempt_number: int,
    event_kind: str,
) -> str:
    """Derive an audit identifier including work, attempt, and event kind."""

    return str(
        uuid5(
            IDENTITY_NAMESPACE,
            f"audit:{work_identifier}:{attempt_number}:{event_kind}",
        )
    )


def retry_work_state(attempt_number: int) -> WorkState:
    """Return the exact retry decision at the three-attempt ceiling."""

    if not 1 <= attempt_number <= MAXIMUM_ATTEMPTS:
        raise DomainValidationError("attempt number is outside the permitted range")
    if attempt_number == MAXIMUM_ATTEMPTS:
        return WorkState.FAILED
    return WorkState.RETRY_WAIT


def lease_is_renewable(*, now: datetime, lease_expires_at: datetime) -> bool:
    """Apply the exact strict-before-expiry renewal boundary."""

    return require_utc_datetime(now, "now") < require_utc_datetime(
        lease_expires_at,
        "lease_expires_at",
    )


def pointer_ordering_key(sequence: int) -> Mapping[str, CanonicalValue]:
    """Construct and deeply freeze the exact canonical pointer ordering key."""

    checked = _bounded_integer(sequence, "sequence", minimum=0)
    return cast(
        Mapping[str, CanonicalValue],
        freeze_canonical_value({"sequence": str(checked)}),
    )
