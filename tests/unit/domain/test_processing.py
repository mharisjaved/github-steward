"""Deterministic GS-I2 domain processing contracts."""

from __future__ import annotations

import operator
from datetime import UTC, datetime, timedelta, timezone
from types import MappingProxyType
from typing import cast
from uuid import UUID, uuid5

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from github_steward.adapters.canonicalization.rfc8785 import envelope_payload
from github_steward.domain.canonical import MAX_SAFE_INTEGER
from github_steward.domain.errors import (
    CanonicalizationError,
    DomainValidationError,
)
from github_steward.domain.processing import (
    GITHUB_REFRESH_WORK_TYPE,
    IDENTITY_NAMESPACE,
    WORK_TYPE,
    AttemptState,
    PointerOutcome,
    SyntheticDelivery,
    WorkState,
    analysis_view_id,
    audit_event_id,
    delivery_id,
    github_work_record_id,
    github_work_subject,
    lease_is_renewable,
    observation_version_id,
    pointer_ordering_key,
    require_utc_datetime,
    retry_work_state,
    work_attempt_id,
    work_record_id,
)
from github_steward.infrastructure.clock import SystemClock

NOW = datetime(2026, 7, 31, 10, 11, 12, 123456, tzinfo=UTC)


def valid_mapping() -> dict[str, object]:
    return {
        "entity_kind": "pull_request",
        "entity_id": "17",
        "observed_at": "2026-07-31T10:11:12.123456Z",
        "sequence": 7,
        "expected_pointer_version": None,
        "observation": {"items": [{"id": 1}]},
    }


def test_valid_mapping_is_copied_parsed_and_deeply_frozen() -> None:
    source = valid_mapping()
    receipt = SyntheticDelivery(source)
    source["entity_id"] = "mutated"
    cast(dict[str, object], source["observation"])["items"] = []

    assert receipt.entity_id == "17"
    assert receipt.observed_at == NOW
    assert receipt.sequence == 7
    assert receipt.expected_pointer_version is None
    assert isinstance(receipt.payload, MappingProxyType)
    with pytest.raises(TypeError):
        operator.setitem(
            cast(dict[str, object], receipt.payload),
            "entity_id",
            "mutated",
        )
    observation = cast(MappingProxyType[str, object], receipt.observation)
    assert len(cast(tuple[object, ...], observation["items"])) == 1


@pytest.mark.parametrize("key", sorted(valid_mapping()))
def test_missing_keys_are_rejected(key: str) -> None:
    value = valid_mapping()
    del value[key]
    with pytest.raises(DomainValidationError, match="keys differ"):
        SyntheticDelivery(value)


def test_additional_keys_and_nonmapping_are_rejected() -> None:
    value = valid_mapping()
    value["extra"] = True
    with pytest.raises(DomainValidationError, match="keys differ"):
        SyntheticDelivery(value)
    with pytest.raises(DomainValidationError, match="decoded mapping"):
        SyntheticDelivery(cast(dict[str, object], object()))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("entity_kind", "", "non-empty string"),
        ("entity_kind", 1, "non-empty string"),
        ("entity_id", "", "non-empty string"),
        ("sequence", True, "must be an integer"),
        ("sequence", 1.0, "must be an integer"),
        ("sequence", -1, "must be between"),
        ("sequence", MAX_SAFE_INTEGER + 1, "must be between"),
        ("expected_pointer_version", False, "must be an integer"),
        ("expected_pointer_version", -1, "must be between"),
        ("expected_pointer_version", MAX_SAFE_INTEGER + 1, "must be between"),
        ("observed_at", NOW, "UTC timestamp string"),
        ("observed_at", "2026-07-31T10:11:12Z", "YYYY-MM-DD"),
        ("observed_at", "2026-02-30T10:11:12.000000Z", "valid UTC"),
    ],
)
def test_invalid_fields_are_rejected(field: str, value: object, message: str) -> None:
    mapping = valid_mapping()
    mapping[field] = value
    with pytest.raises(DomainValidationError, match=message):
        SyntheticDelivery(mapping)


def test_unsupported_observation_values_fail_before_authority() -> None:
    mapping = valid_mapping()
    mapping["observation"] = {"score": 1.5}
    with pytest.raises(CanonicalizationError, match="float"):
        SyntheticDelivery(mapping)


@pytest.mark.parametrize(
    "value",
    [
        datetime(2026, 7, 31, 10, 11, 12),
        datetime(2026, 7, 31, 10, 11, 12, tzinfo=timezone(timedelta(hours=1))),
    ],
)
def test_clock_values_must_be_aware_utc(value: datetime) -> None:
    with pytest.raises(DomainValidationError, match=r"must .*UTC"):
        require_utc_datetime(value)
    assert require_utc_datetime(NOW) is NOW


def test_exact_deterministic_uuid_derivations() -> None:
    delivery = delivery_id("provider-id")
    work = work_record_id(delivery)
    assert delivery == str(uuid5(IDENTITY_NAMESPACE, "delivery:synthetic:provider-id"))
    assert work == str(uuid5(IDENTITY_NAMESPACE, f"work:{delivery}:{WORK_TYPE}"))
    assert work_attempt_id(work, 2) == str(
        uuid5(IDENTITY_NAMESPACE, f"attempt:{work}:2")
    )
    assert observation_version_id(work, "a" * 64) == str(
        uuid5(IDENTITY_NAMESPACE, f"observation:{work}:{'a' * 64}")
    )
    assert analysis_view_id(work, "a" * 64) == str(
        uuid5(IDENTITY_NAMESPACE, f"analysis-view:{work}:{'a' * 64}")
    )
    event = audit_event_id(work, 2, "EVENT")
    assert event == str(uuid5(IDENTITY_NAMESPACE, f"audit:{work}:2:EVENT"))
    assert UUID(event).version == 5

    github_work = github_work_record_id(delivery)
    assert github_work == str(
        uuid5(
            IDENTITY_NAMESPACE,
            f"work:{delivery}:{GITHUB_REFRESH_WORK_TYPE}",
        )
    )
    assert github_work_subject(123, 7) == "123:7"


@pytest.mark.parametrize(("repository_id", "pull_number"), [(True, 1), (1, 0)])
def test_github_work_subject_rejects_nonpositive_or_boolean_identity(
    repository_id: int,
    pull_number: int,
) -> None:
    with pytest.raises(DomainValidationError):
        github_work_subject(repository_id, pull_number)


@settings(derandomize=True, max_examples=200, deadline=None)
@given(st.integers(min_value=0, max_value=MAX_SAFE_INTEGER))
def test_sequence_and_digest_are_deterministic(sequence: int) -> None:
    mapping = valid_mapping()
    mapping["sequence"] = sequence
    first = SyntheticDelivery(mapping)
    second = SyntheticDelivery(mapping)
    assert (
        envelope_payload(first.payload).digest
        == envelope_payload(second.payload).digest
    )
    assert pointer_ordering_key(sequence) == {"sequence": str(sequence)}


def test_exact_state_inventories_and_pointer_outcomes() -> None:
    assert {state.value for state in WorkState} == {
        "AVAILABLE",
        "PROCESSING",
        "RETRY_WAIT",
        "SUCCEEDED",
        "FAILED",
    }
    assert {state.value for state in AttemptState} == {
        "STARTED",
        "SUCCEEDED",
        "RETRYABLE_FAILURE",
        "TERMINAL_FAILURE",
        "ABANDONED",
    }
    assert {outcome.value for outcome in PointerOutcome} == {
        "CREATED",
        "UPDATED",
        "POINTER_CONFLICT",
    }


@pytest.mark.parametrize(
    ("attempt", "expected"),
    [(1, WorkState.RETRY_WAIT), (2, WorkState.RETRY_WAIT), (3, WorkState.FAILED)],
)
def test_retry_ceiling(attempt: int, expected: WorkState) -> None:
    assert retry_work_state(attempt) is expected


@pytest.mark.parametrize("attempt", [0, 4])
def test_retry_rejects_out_of_range_attempts(attempt: int) -> None:
    with pytest.raises(DomainValidationError, match="outside"):
        retry_work_state(attempt)


def test_exact_lease_boundary_before_at_and_after_expiry() -> None:
    expiry = NOW + timedelta(seconds=300)
    assert lease_is_renewable(
        now=expiry - timedelta(microseconds=1), lease_expires_at=expiry
    )
    assert not lease_is_renewable(now=expiry, lease_expires_at=expiry)
    assert not lease_is_renewable(
        now=expiry + timedelta(microseconds=1), lease_expires_at=expiry
    )


def test_pointer_ordering_key_rejects_invalid_sequence() -> None:
    with pytest.raises(DomainValidationError):
        pointer_ordering_key(-1)


def test_standard_clock_returns_aware_utc() -> None:
    value = SystemClock().now()
    assert value.tzinfo is UTC
    assert value.utcoffset() == timedelta(0)
