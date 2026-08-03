"""Expired-lease reconciliation, bounded recovery, and rollback evidence."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from github_steward.adapters.canonicalization.rfc8785 import envelope_payload
from github_steward.adapters.postgres.metadata import work_attempt, work_record
from github_steward.adapters.postgres.unit_of_work import PostgresUnitOfWork
from github_steward.application.local_processing import (
    LocalReconciliationService,
    SyntheticReceiptService,
)
from github_steward.domain.processing import AttemptState, FaultPoint, WorkState
from github_steward.ports.persistence import ClaimedWork

NOW = datetime(2026, 7, 31, 16, 0, 0, 888999, tzinfo=UTC)


class FixedClock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


class InjectedFault(RuntimeError):
    """Test-only deterministic reconciliation fault."""


def mapping(identifier: str) -> dict[str, object]:
    return {
        "entity_kind": "pull_request",
        "entity_id": identifier,
        "observed_at": "2026-07-31T16:00:00.888999Z",
        "sequence": 1,
        "expected_pointer_version": None,
        "observation": {"id": identifier},
    }


def receive(engine: Engine, identifier: str) -> str:
    return (
        SyntheticReceiptService(
            unit_of_work_factory=lambda: PostgresUnitOfWork(engine),
            clock=FixedClock(),
            envelope_factory=envelope_payload,
        )
        .receive(
            provider_delivery_id=identifier,
            mapping=mapping(identifier),
        )
        .work_record_id
    )


def reconcile_service(
    engine: Engine,
    *,
    now: datetime,
    fault: Callable[[FaultPoint], None] | None = None,
) -> LocalReconciliationService:
    return LocalReconciliationService(
        unit_of_work_factory=lambda: PostgresUnitOfWork(engine, fault),
        clock=FixedClock(now),
    )


def sanitize_prior_work(engine: Engine) -> None:
    while True:
        result = reconcile_service(
            engine,
            now=NOW + timedelta(days=1),
        ).reconcile()
        if result.reconciled == 0:
            break
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


def claim(engine: Engine, now: datetime = NOW) -> ClaimedWork:
    with PostgresUnitOfWork(engine) as unit:
        result = unit.work.claim_next(owner="worker", now=now)
        unit.commit()
    assert result.claimed_work is not None
    return result.claimed_work


def test_expired_attempt_is_abandoned_retried_and_reconciliation_is_idempotent(
    postgres_engine: Engine,
) -> None:
    sanitize_prior_work(postgres_engine)
    work_id = receive(postgres_engine, "reconcile-retry")
    claimed = claim(postgres_engine)
    expiry = claimed.lease.expires_at

    before = reconcile_service(
        postgres_engine,
        now=expiry - timedelta(microseconds=1),
    ).reconcile()
    assert before.reconciled == 0
    at_expiry = reconcile_service(postgres_engine, now=expiry).reconcile()
    assert at_expiry.reconciled == 1
    assert at_expiry.retry_scheduled == 1
    assert at_expiry.terminally_failed == 0
    again = reconcile_service(postgres_engine, now=expiry).reconcile()
    assert again.reconciled == 0

    with postgres_engine.connect() as connection:
        work = connection.execute(
            sa.select(
                work_record.c.state,
                work_record.c.available_at,
                work_record.c.lease_owner,
                work_record.c.lease_token,
                work_record.c.lease_expires_at,
                work_record.c.version,
            ).where(work_record.c.work_record_id == work_id)
        ).one()
        assert work.state == WorkState.RETRY_WAIT.value
        assert work.available_at == expiry
        assert work.lease_owner is None
        assert work.lease_token is None
        assert work.lease_expires_at is None
        assert work.version == 2
        attempt = connection.execute(
            sa.select(work_attempt.c.state, work_attempt.c.completed_at).where(
                work_attempt.c.work_record_id == work_id
            )
        ).one()
        assert attempt == (AttemptState.ABANDONED.value, expiry)


def test_third_expired_attempt_is_terminal(postgres_engine: Engine) -> None:
    sanitize_prior_work(postgres_engine)
    work_id = receive(postgres_engine, "reconcile-terminal")
    first = claim(postgres_engine)
    with PostgresUnitOfWork(postgres_engine) as unit:
        assert unit.work.release(lease=first.lease, now=NOW)
        unit.commit()
    second = claim(postgres_engine)
    with PostgresUnitOfWork(postgres_engine) as unit:
        assert unit.work.release(lease=second.lease, now=NOW)
        unit.commit()
    third = claim(postgres_engine)

    result = reconcile_service(
        postgres_engine,
        now=third.lease.expires_at,
    ).reconcile()
    assert result.reconciled == 1
    assert result.retry_scheduled == 0
    assert result.terminally_failed == 1
    with postgres_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(work_record.c.state).where(
                    work_record.c.work_record_id == work_id
                )
            )
            == WorkState.FAILED.value
        )
        states = list(
            connection.execute(
                sa.select(work_attempt.c.state)
                .where(work_attempt.c.work_record_id == work_id)
                .order_by(work_attempt.c.attempt_number)
            ).scalars()
        )
        assert states == [
            AttemptState.ABANDONED.value,
            AttemptState.ABANDONED.value,
            AttemptState.ABANDONED.value,
        ]


def test_reconciliation_fault_rolls_back_whole_batch(postgres_engine: Engine) -> None:
    sanitize_prior_work(postgres_engine)
    work_id = receive(postgres_engine, "reconcile-fault")
    claimed = claim(postgres_engine)

    def inject(point: FaultPoint) -> None:
        if point is FaultPoint.DURING_RECONCILIATION:
            raise InjectedFault(point.value)

    with pytest.raises(InjectedFault):
        reconcile_service(
            postgres_engine,
            now=claimed.lease.expires_at,
            fault=inject,
        ).reconcile()
    with postgres_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(work_record.c.state).where(
                    work_record.c.work_record_id == work_id
                )
            )
            == WorkState.PROCESSING.value
        )
        assert (
            connection.scalar(
                sa.select(work_attempt.c.state).where(
                    work_attempt.c.work_record_id == work_id
                )
            )
            == AttemptState.STARTED.value
        )


def test_reconciliation_batch_is_bounded_to_one_hundred(
    postgres_engine: Engine,
) -> None:
    sanitize_prior_work(postgres_engine)
    for number in range(101):
        receive(postgres_engine, f"bounded-{number:03d}")
    for _ in range(101):
        claim(postgres_engine)

    expiry = NOW + timedelta(seconds=300)
    first = reconcile_service(postgres_engine, now=expiry).reconcile()
    second = reconcile_service(postgres_engine, now=expiry).reconcile()
    assert first.reconciled == 100
    assert first.retry_scheduled == 100
    assert first.terminally_failed == 0
    assert second.reconciled == 1
    assert second.retry_scheduled == 1
    assert second.terminally_failed == 0
