"""Concrete PostgreSQL repository transaction and lease behavior."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from github_steward.adapters.canonicalization.rfc8785 import envelope_payload
from github_steward.adapters.postgres.metadata import (
    delivery_inbox,
    work_attempt,
    work_record,
)
from github_steward.adapters.postgres.unit_of_work import PostgresUnitOfWork
from github_steward.application.local_processing import SyntheticReceiptService
from github_steward.domain.processing import (
    AttemptState,
    FailureKind,
    FaultPoint,
    WorkState,
)
from github_steward.ports.persistence import (
    ClaimOutcome,
    DeliveryIngressOutcome,
    LeaseOperationOutcome,
    LeaseToken,
    ObservationPointer,
    ObservationVersionId,
    WorkLease,
    WorkRecordId,
)

NOW = datetime(2026, 7, 31, 12, 0, 0, 123456, tzinfo=UTC)


class FixedClock:
    def __init__(self, now: datetime = NOW) -> None:
        self.value = now

    def now(self) -> datetime:
        return self.value


class InjectedFault(RuntimeError):
    """Test-only deterministic transaction fault."""


def mapping(*, entity_id: str = "17", sequence: int = 1) -> dict[str, object]:
    return {
        "entity_kind": "pull_request",
        "entity_id": entity_id,
        "observed_at": "2026-07-31T12:00:00.123456Z",
        "sequence": sequence,
        "expected_pointer_version": None,
        "observation": {"id": entity_id, "sequence": sequence},
    }


def factory(
    engine: Engine,
    fault: Callable[[FaultPoint], None] | None = None,
) -> Callable[[], PostgresUnitOfWork]:
    return lambda: PostgresUnitOfWork(engine, fault)


def receipt_service(
    engine: Engine,
    fault: Callable[[FaultPoint], None] | None = None,
) -> SyntheticReceiptService:
    return SyntheticReceiptService(
        unit_of_work_factory=factory(engine, fault),
        clock=FixedClock(),
        envelope_factory=envelope_payload,
    )


def retire_claimable(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(
            work_record.update()
            .where(
                work_record.c.state.in_(
                    [WorkState.AVAILABLE.value, WorkState.RETRY_WAIT.value]
                )
            )
            .values(state=WorkState.SUCCEEDED.value)
        )


def test_atomic_receipt_idempotency_and_durable_payload(
    postgres_engine: Engine,
) -> None:
    service = receipt_service(postgres_engine)
    created = service.receive(
        provider_delivery_id="repository-idempotency",
        mapping=mapping(),
    )
    same = service.receive(
        provider_delivery_id="repository-idempotency",
        mapping=mapping(),
    )
    conflicting = service.receive(
        provider_delivery_id="repository-idempotency",
        mapping=mapping(sequence=2),
    )

    assert created.outcome is DeliveryIngressOutcome.CREATED
    assert same.outcome is DeliveryIngressOutcome.DUPLICATE_SAME_DIGEST
    assert conflicting.outcome is (
        DeliveryIngressOutcome.INTEGRITY_FAILURE_DIFFERENT_DIGEST
    )
    assert same.delivery_id == created.delivery_id == conflicting.delivery_id
    assert same.work_record_id == created.work_record_id == conflicting.work_record_id
    with postgres_engine.connect() as connection:
        delivery = (
            connection.execute(
                sa.select(delivery_inbox).where(
                    delivery_inbox.c.delivery_id == created.delivery_id
                )
            )
            .mappings()
            .one()
        )
        assert delivery["provider"] == "synthetic"
        assert delivery["canonical_payload"] == mapping()
        assert delivery["payload_schema_id"] == "github-steward.synthetic-delivery"
        assert delivery["payload_schema_version"] == 1
        assert delivery["payload_digest_format"] == "jcs-sha256/v1"
        assert delivery["payload_digest"] == envelope_payload(mapping()).digest.value
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(work_record)
                .where(work_record.c.work_record_id == created.work_record_id)
            )
            == 1
        )


def test_receipt_fault_after_inbox_insert_rolls_back_both_rows(
    postgres_engine: Engine,
) -> None:
    def inject(point: FaultPoint) -> None:
        if point is FaultPoint.AFTER_INBOX_INSERT:
            raise InjectedFault(point.value)

    service = receipt_service(postgres_engine, inject)
    with pytest.raises(InjectedFault):
        service.receive(
            provider_delivery_id="repository-receipt-fault",
            mapping=mapping(entity_id="fault"),
        )
    with postgres_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(delivery_inbox)
                .where(
                    delivery_inbox.c.provider_delivery_id == "repository-receipt-fault"
                )
            )
            == 0
        )


@pytest.mark.parametrize(
    "fault_point",
    [FaultPoint.AFTER_CLAIM_UPDATE, FaultPoint.AFTER_ATTEMPT_INSERT],
)
def test_claim_faults_roll_back_work_and_attempt(
    postgres_engine: Engine,
    fault_point: FaultPoint,
) -> None:
    retire_claimable(postgres_engine)
    provider_id = f"claim-fault-{fault_point.value}"
    created = receipt_service(postgres_engine).receive(
        provider_delivery_id=provider_id,
        mapping=mapping(entity_id=provider_id),
    )

    def inject(point: FaultPoint) -> None:
        if point is fault_point:
            raise InjectedFault(point.value)

    with pytest.raises(InjectedFault), factory(postgres_engine, inject)() as unit:
        unit.work.claim_next(owner="worker", now=NOW)
        unit.commit()
    with postgres_engine.connect() as connection:
        row = connection.execute(
            sa.select(work_record.c.state, work_record.c.version).where(
                work_record.c.work_record_id == created.work_record_id
            )
        ).one()
        assert row == (WorkState.AVAILABLE.value, 0)
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(work_attempt)
                .where(work_attempt.c.work_record_id == created.work_record_id)
            )
            == 0
        )


def test_claim_renewal_boundaries_stale_guards_release_and_attempt_numbers(
    postgres_engine: Engine,
) -> None:
    retire_claimable(postgres_engine)
    created = receipt_service(postgres_engine).receive(
        provider_delivery_id="lease-boundaries",
        mapping=mapping(entity_id="lease"),
    )
    with factory(postgres_engine)() as unit:
        claim = unit.work.claim_next(owner="worker-1", now=NOW)
        unit.commit()
    assert claim.outcome is ClaimOutcome.CLAIMED
    first = claim.claimed_work
    assert first is not None
    assert first.attempt_number == 1
    assert first.lease.expires_at == NOW + timedelta(seconds=300)

    with factory(postgres_engine)() as unit:
        at_expiry = unit.work.renew(lease=first.lease, now=first.lease.expires_at)
        unit.commit()
    assert at_expiry.outcome is LeaseOperationOutcome.STALE

    with factory(postgres_engine)() as unit:
        before_expiry = unit.work.renew(
            lease=first.lease,
            now=first.lease.expires_at - timedelta(microseconds=1),
        )
        unit.commit()
    assert before_expiry.outcome is LeaseOperationOutcome.SUCCEEDED
    renewed = before_expiry.lease
    assert renewed is not None
    assert renewed.version == first.lease.version + 1
    assert renewed.expires_at == first.lease.expires_at + timedelta(
        seconds=300
    ) - timedelta(microseconds=1)

    stale_token = WorkLease(
        work_record_id=renewed.work_record_id,
        owner=renewed.owner,
        token=LeaseToken("00000000-0000-0000-0000-000000000001"),
        expires_at=renewed.expires_at,
        version=renewed.version,
    )
    with factory(postgres_engine)() as unit:
        assert (
            unit.work.renew(
                lease=stale_token,
                now=NOW + timedelta(seconds=1),
            ).outcome
            is LeaseOperationOutcome.STALE
        )
        concrete = unit.work
        assert concrete.release(lease=renewed, now=NOW + timedelta(seconds=1))
        unit.commit()

    with postgres_engine.connect() as connection:
        attempt = connection.execute(
            sa.select(work_attempt.c.state, work_attempt.c.completed_at).where(
                work_attempt.c.work_record_id == created.work_record_id
            )
        ).one()
        assert attempt.state == AttemptState.ABANDONED.value
        assert attempt.completed_at == NOW + timedelta(seconds=1)

    with factory(postgres_engine)() as unit:
        second_claim = unit.work.claim_next(
            owner="worker-2",
            now=NOW + timedelta(seconds=1),
        )
        unit.commit()
    assert second_claim.claimed_work is not None
    assert second_claim.claimed_work.attempt_number == 2


def test_retryable_and_terminal_completion_states(postgres_engine: Engine) -> None:
    retire_claimable(postgres_engine)
    first_receipt = receipt_service(postgres_engine).receive(
        provider_delivery_id="retryable-completion",
        mapping=mapping(entity_id="retryable"),
    )
    with factory(postgres_engine)() as unit:
        first_claim = unit.work.claim_next(owner="worker", now=NOW)
        unit.commit()
    claimed = first_claim.claimed_work
    assert claimed is not None
    with factory(postgres_engine)() as unit:
        result = unit.work.complete_failure(
            lease=claimed.lease,
            attempt_number=claimed.attempt_number,
            now=NOW,
            failure_kind=FailureKind.RETRYABLE_LOCAL_PROCESSING,
        )
        unit.commit()
    assert result.work_state is WorkState.RETRY_WAIT
    with postgres_engine.connect() as connection:
        retry = connection.execute(
            sa.select(work_record.c.state, work_record.c.available_at).where(
                work_record.c.work_record_id == first_receipt.work_record_id
            )
        ).one()
        assert retry == (WorkState.RETRY_WAIT.value, NOW + timedelta(seconds=60))

    receipt_service(postgres_engine).receive(
        provider_delivery_id="terminal-completion",
        mapping=mapping(entity_id="terminal"),
    )
    with factory(postgres_engine)() as unit:
        second_claim = unit.work.claim_next(owner="worker", now=NOW)
        unit.commit()
    terminal = second_claim.claimed_work
    assert terminal is not None
    with factory(postgres_engine)() as unit:
        result = unit.work.complete_failure(
            lease=terminal.lease,
            attempt_number=terminal.attempt_number,
            now=NOW,
            failure_kind=FailureKind.PERMANENT_LOCAL_PROCESSING,
        )
        unit.commit()
    assert result.work_state is WorkState.FAILED


def test_accepted_acquire_and_release_support_stale_guards_without_attempt(
    postgres_engine: Engine,
) -> None:
    retire_claimable(postgres_engine)
    created = receipt_service(postgres_engine).receive(
        provider_delivery_id="accepted-acquire-release",
        mapping=mapping(entity_id="accepted-acquire-release"),
    )
    token = LeaseToken("00000000-0000-0000-0000-000000000020")
    with factory(postgres_engine)() as unit:
        assert (
            unit.work.acquire(
                work_record_id=created.work_record_id,
                owner="worker",
                token=token,
                now=NOW,
                expires_at=NOW + timedelta(seconds=300),
                expected_version=1,
            )
            is None
        )
        lease = unit.work.acquire(
            work_record_id=created.work_record_id,
            owner="worker",
            token=token,
            now=NOW,
            expires_at=NOW + timedelta(seconds=300),
            expected_version=0,
        )
        unit.commit()
    assert lease is not None
    stale = WorkLease(
        work_record_id=lease.work_record_id,
        owner=lease.owner,
        token=LeaseToken("00000000-0000-0000-0000-000000000021"),
        expires_at=lease.expires_at,
        version=lease.version,
    )
    with factory(postgres_engine)() as unit:
        assert not unit.work.release(lease=stale, now=NOW)
        assert unit.work.release(lease=lease, now=NOW)
        unit.commit()
    with postgres_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(work_record.c.state).where(
                    work_record.c.work_record_id == created.work_record_id
                )
            )
            == WorkState.AVAILABLE.value
        )


def test_stale_and_wrong_attempt_completions_update_nothing(
    postgres_engine: Engine,
) -> None:
    retire_claimable(postgres_engine)
    receipt_service(postgres_engine).receive(
        provider_delivery_id="stale-completion-guards",
        mapping=mapping(entity_id="stale-completion-guards"),
    )
    with factory(postgres_engine)() as unit:
        claim = unit.work.claim_next(owner="worker", now=NOW)
        unit.commit()
    claimed = claim.claimed_work
    assert claimed is not None
    stale = WorkLease(
        work_record_id=claimed.lease.work_record_id,
        owner=claimed.lease.owner,
        token=LeaseToken("00000000-0000-0000-0000-000000000030"),
        expires_at=claimed.lease.expires_at,
        version=claimed.lease.version,
    )
    with factory(postgres_engine)() as unit:
        assert (
            unit.work.complete_success(
                lease=stale,
                attempt_number=1,
                now=NOW,
            ).outcome
            is LeaseOperationOutcome.STALE
        )
        assert (
            unit.work.complete_failure(
                lease=stale,
                attempt_number=1,
                now=NOW,
                failure_kind=FailureKind.PERMANENT_LOCAL_PROCESSING,
            ).outcome
            is LeaseOperationOutcome.STALE
        )
        assert (
            unit.work.complete_success(
                lease=claimed.lease,
                attempt_number=2,
                now=NOW,
            ).outcome
            is LeaseOperationOutcome.STALE
        )
        assert (
            unit.work.complete_failure(
                lease=claimed.lease,
                attempt_number=2,
                now=NOW,
                failure_kind=FailureKind.PERMANENT_LOCAL_PROCESSING,
            ).outcome
            is LeaseOperationOutcome.STALE
        )
        assert unit.work.release(lease=claimed.lease, now=NOW)
        unit.commit()


def test_pointer_replacement_must_increment_exactly_one(
    postgres_engine: Engine,
) -> None:
    pointer = ObservationPointer(
        entity_kind="pull_request",
        entity_id="invalid-pointer-version",
        observation_version_id=ObservationVersionId(
            "00000000-0000-0000-0000-000000000040"
        ),
        ordering_key={"sequence": "1"},
        pointer_version=3,
        updated_at=NOW,
    )
    with (
        factory(postgres_engine)() as unit,
        pytest.raises(ValueError, match="increment"),
    ):
        unit.pointers.compare_and_swap(
            expected_version=0,
            replacement=pointer,
        )


def test_unit_of_work_rejects_invalid_lifecycle_operations(
    postgres_engine: Engine,
) -> None:
    unit = PostgresUnitOfWork(postgres_engine)
    with pytest.raises(RuntimeError, match="active transaction"):
        unit.commit()
    with unit:
        with pytest.raises(RuntimeError, match="entered twice"):
            unit.__enter__()
        unit.rollback()
        with pytest.raises(RuntimeError, match="active transaction"):
            unit.commit()
    with pytest.raises(RuntimeError, match="active transaction"):
        unit.rollback()
    assert unit.__exit__(None, None, None) is None


def test_reconciliation_fails_closed_for_processing_work_without_attempt(
    postgres_engine: Engine,
) -> None:
    retire_claimable(postgres_engine)
    created = receipt_service(postgres_engine).receive(
        provider_delivery_id="reconcile-without-attempt",
        mapping=mapping(entity_id="reconcile-without-attempt"),
    )
    lease = WorkLease(
        work_record_id=WorkRecordId(created.work_record_id),
        owner="worker",
        token=LeaseToken("00000000-0000-0000-0000-000000000050"),
        expires_at=NOW,
        version=1,
    )
    with factory(postgres_engine)() as unit:
        acquired = unit.work.acquire(
            work_record_id=created.work_record_id,
            owner=lease.owner,
            token=lease.token,
            now=NOW,
            expires_at=NOW,
            expected_version=0,
        )
        assert acquired == lease
        unit.commit()
    with (
        pytest.raises(RuntimeError, match="no durable attempt"),
        factory(postgres_engine)() as unit,
    ):
        unit.work.reconcile_expired(now=NOW)
        unit.commit()
