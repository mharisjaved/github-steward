"""PostgreSQL uniqueness and SKIP LOCKED concurrency authority."""

from __future__ import annotations

from datetime import UTC, datetime
from threading import Barrier, Thread

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
from github_steward.domain.processing import WorkState
from github_steward.ports.persistence import ClaimOutcome, DeliveryIngressOutcome

NOW = datetime(2026, 7, 31, 13, 0, 0, 654321, tzinfo=UTC)


class FixedClock:
    def now(self) -> datetime:
        return NOW


def mapping(sequence: int) -> dict[str, object]:
    return {
        "entity_kind": "pull_request",
        "entity_id": "concurrent",
        "observed_at": "2026-07-31T13:00:00.654321Z",
        "sequence": sequence,
        "expected_pointer_version": None,
        "observation": {"sequence": sequence},
    }


def service(engine: Engine) -> SyntheticReceiptService:
    return SyntheticReceiptService(
        unit_of_work_factory=lambda: PostgresUnitOfWork(engine),
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


def test_concurrent_same_digest_receipt_creates_exactly_one_work(
    postgres_engine: Engine,
) -> None:
    barrier = Barrier(4)
    outcomes: list[DeliveryIngressOutcome] = []

    def receive() -> None:
        barrier.wait()
        outcomes.append(
            service(postgres_engine)
            .receive(
                provider_delivery_id="concurrent-same",
                mapping=mapping(1),
            )
            .outcome
        )

    threads = [Thread(target=receive) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert outcomes.count(DeliveryIngressOutcome.CREATED) == 1
    assert outcomes.count(DeliveryIngressOutcome.DUPLICATE_SAME_DIGEST) == 3
    with postgres_engine.connect() as connection:
        delivery_id = connection.scalar(
            sa.select(delivery_inbox.c.delivery_id).where(
                delivery_inbox.c.provider_delivery_id == "concurrent-same"
            )
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(work_record)
                .where(work_record.c.delivery_id == delivery_id)
            )
            == 1
        )


def test_concurrent_different_digests_never_overwrite_durable_payload(
    postgres_engine: Engine,
) -> None:
    barrier = Barrier(2)
    outcomes: list[tuple[int, DeliveryIngressOutcome]] = []

    def receive(sequence: int) -> None:
        barrier.wait()
        outcome = service(postgres_engine).receive(
            provider_delivery_id="concurrent-conflict",
            mapping=mapping(sequence),
        )
        outcomes.append((sequence, outcome.outcome))

    threads = [Thread(target=receive, args=(sequence,)) for sequence in (2, 3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(outcome for _, outcome in outcomes) == sorted(
        [
            DeliveryIngressOutcome.CREATED,
            DeliveryIngressOutcome.INTEGRITY_FAILURE_DIFFERENT_DIGEST,
        ]
    )
    durable_sequence = next(
        sequence
        for sequence, outcome in outcomes
        if outcome is DeliveryIngressOutcome.CREATED
    )
    with postgres_engine.connect() as connection:
        row = (
            connection.execute(
                sa.select(
                    delivery_inbox.c.canonical_payload,
                    delivery_inbox.c.payload_digest,
                ).where(delivery_inbox.c.provider_delivery_id == "concurrent-conflict")
            )
            .mappings()
            .one()
        )
        assert row["canonical_payload"] == mapping(durable_sequence)
        assert (
            row["payload_digest"]
            == envelope_payload(mapping(durable_sequence)).digest.value
        )


def test_skip_locked_concurrent_claim_creates_one_unique_attempt(
    postgres_engine: Engine,
) -> None:
    retire_claimable(postgres_engine)
    created = service(postgres_engine).receive(
        provider_delivery_id="concurrent-claim",
        mapping=mapping(4),
    )
    barrier = Barrier(2)
    outcomes: list[ClaimOutcome] = []

    def claim(owner: str) -> None:
        with PostgresUnitOfWork(postgres_engine) as unit:
            barrier.wait()
            result = unit.work.claim_next(owner=owner, now=NOW)
            unit.commit()
        outcomes.append(result.outcome)

    threads = [Thread(target=claim, args=(f"worker-{number}",)) for number in (1, 2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(outcomes) == sorted([ClaimOutcome.CLAIMED, ClaimOutcome.NO_WORK])
    with postgres_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(work_attempt)
                .where(work_attempt.c.work_record_id == created.work_record_id)
            )
            == 1
        )
        row = connection.execute(
            sa.select(
                work_record.c.state,
                work_record.c.lease_owner,
                work_record.c.lease_token,
                work_record.c.lease_expires_at,
                work_record.c.version,
            ).where(work_record.c.work_record_id == created.work_record_id)
        ).one()
        assert row.state == WorkState.PROCESSING.value
        assert row.lease_owner in {"worker-1", "worker-2"}
        assert row.lease_token is not None
        assert row.lease_expires_at is not None
        assert row.version == 1
