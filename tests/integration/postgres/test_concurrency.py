"""Transactional inbox, pointer CAS, and deterministic lease contention."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from threading import Barrier, Thread
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import IntegrityError

from github_steward.adapters.postgres.metadata import (
    canonical_observation,
    current_observation_pointer,
    delivery_inbox,
    work_record,
)

NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def _delivery_values(
    *,
    delivery_id: object,
    provider_delivery_id: str,
    digest: str,
) -> dict[str, object]:
    return {
        "delivery_id": delivery_id,
        "provider": "github",
        "provider_delivery_id": provider_delivery_id,
        "payload_digest": digest,
        "received_at": NOW,
    }


def _work_values(*, work_id: object, delivery_id: object) -> dict[str, object]:
    return {
        "work_record_id": work_id,
        "delivery_id": delivery_id,
        "work_type": "INGEST_DELIVERY",
        "state": "AVAILABLE",
        "available_at": NOW,
    }


def test_delivery_and_work_commit_together_and_induced_failure_rolls_back(
    postgres_engine: Engine,
) -> None:
    delivery_id = uuid4()
    work_id = uuid4()
    with postgres_engine.begin() as connection:
        connection.execute(
            delivery_inbox.insert().values(
                **_delivery_values(
                    delivery_id=delivery_id,
                    provider_delivery_id="atomic-success",
                    digest=DIGEST_A,
                )
            )
        )
        connection.execute(
            work_record.insert().values(
                **_work_values(work_id=work_id, delivery_id=delivery_id)
            )
        )
    with postgres_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(work_record)
                .where(work_record.c.work_record_id == work_id)
            )
            == 1
        )

    failed_delivery = uuid4()
    with pytest.raises(IntegrityError), postgres_engine.begin() as connection:
        connection.execute(
            delivery_inbox.insert().values(
                **_delivery_values(
                    delivery_id=failed_delivery,
                    provider_delivery_id="atomic-failure",
                    digest=DIGEST_A,
                )
            )
        )
        connection.execute(
            work_record.insert().values(
                **_work_values(work_id=uuid4(), delivery_id=uuid4())
            )
        )
    with postgres_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(delivery_inbox)
                .where(delivery_inbox.c.delivery_id == failed_delivery)
            )
            == 0
        )


def test_duplicate_delivery_same_and_different_digest_are_distinguishable(
    postgres_engine: Engine,
) -> None:
    values = _delivery_values(
        delivery_id=uuid4(),
        provider_delivery_id="duplicate",
        digest=DIGEST_A,
    )
    with postgres_engine.begin() as connection:
        connection.execute(delivery_inbox.insert().values(**values))

    def classify(candidate_digest: str) -> str:
        candidate = _delivery_values(
            delivery_id=uuid4(),
            provider_delivery_id="duplicate",
            digest=candidate_digest,
        )
        with postgres_engine.begin() as connection:
            persisted = connection.execute(
                sa.select(delivery_inbox.c.payload_digest).where(
                    delivery_inbox.c.provider == "github",
                    delivery_inbox.c.provider_delivery_id == "duplicate",
                )
            ).scalar_one()
            nested = connection.begin_nested()
            with pytest.raises(IntegrityError):
                connection.execute(delivery_inbox.insert().values(**candidate))
            nested.rollback()
            if persisted == candidate_digest:
                return "DUPLICATE_SAME_DIGEST"
            return "INTEGRITY_FAILURE_DIFFERENT_DIGEST"

    assert classify(DIGEST_A) == "DUPLICATE_SAME_DIGEST"
    assert classify(DIGEST_B) == "INTEGRITY_FAILURE_DIFFERENT_DIGEST"

    with postgres_engine.connect() as connection:
        persisted = connection.execute(
            sa.select(delivery_inbox.c.payload_digest).where(
                delivery_inbox.c.provider == "github",
                delivery_inbox.c.provider_delivery_id == "duplicate",
            )
        ).scalar_one()
        assert persisted == DIGEST_A
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(delivery_inbox)
                .where(
                    delivery_inbox.c.provider == "github",
                    delivery_inbox.c.provider_delivery_id == "duplicate",
                )
            )
            == 1
        )


def _insert_observation(connection: Connection, entity_id: str) -> object:
    identifier = uuid4()
    connection.execute(
        canonical_observation.insert().values(
            observation_version_id=identifier,
            entity_kind="pull_request",
            entity_id=entity_id,
            schema_id="github.pull-request",
            schema_version=1,
            observed_at=NOW,
            canonical_payload={"id": entity_id},
            digest_format="jcs-sha256/v1",
            digest_value=DIGEST_A,
        )
    )
    return identifier


def test_pointer_compare_and_swap_succeeds_once_and_stale_updates_zero_rows(
    postgres_engine: Engine,
) -> None:
    with postgres_engine.begin() as connection:
        first = _insert_observation(connection, "cas")
        second = _insert_observation(connection, "cas")
        connection.execute(
            current_observation_pointer.insert().values(
                entity_kind="pull_request",
                entity_id="cas",
                observation_version_id=first,
                ordering_key={"updated_at": "1"},
                pointer_version=0,
            )
        )
        statement = (
            current_observation_pointer.update()
            .where(
                current_observation_pointer.c.entity_kind == "pull_request",
                current_observation_pointer.c.entity_id == "cas",
                current_observation_pointer.c.pointer_version == 0,
            )
            .values(
                observation_version_id=second,
                ordering_key={"updated_at": "2"},
                pointer_version=1,
                updated_at=NOW,
            )
        )
        assert connection.execute(statement).rowcount == 1
        assert connection.execute(statement).rowcount == 0


def test_two_connections_cannot_both_acquire_the_same_lease(
    postgres_engine: Engine,
) -> None:
    delivery_id = uuid4()
    work_id = uuid4()
    with postgres_engine.begin() as connection:
        connection.execute(
            delivery_inbox.insert().values(
                **_delivery_values(
                    delivery_id=delivery_id,
                    provider_delivery_id="lease",
                    digest=DIGEST_A,
                )
            )
        )
        connection.execute(
            work_record.insert().values(
                **_work_values(work_id=work_id, delivery_id=delivery_id)
            )
        )

    barrier = Barrier(2)
    outcomes: list[int] = []

    def contend(owner: str) -> None:
        with postgres_engine.begin() as connection:
            barrier.wait()
            result = connection.execute(
                work_record.update()
                .where(
                    work_record.c.work_record_id == work_id,
                    work_record.c.version == 0,
                    work_record.c.lease_token.is_(None),
                )
                .values(
                    lease_owner=owner,
                    lease_token=uuid4(),
                    lease_expires_at=NOW + timedelta(minutes=5),
                    version=1,
                    updated_at=NOW,
                )
            )
            outcomes.append(result.rowcount)

    contenders = [Thread(target=contend, args=(f"worker-{index}",)) for index in (1, 2)]
    for contender in contenders:
        contender.start()
    for contender in contenders:
        contender.join()
    assert sorted(outcomes) == [0, 1]
    with postgres_engine.connect() as connection:
        row = connection.execute(
            sa.select(
                work_record.c.lease_owner,
                work_record.c.lease_expires_at,
                work_record.c.version,
            ).where(work_record.c.work_record_id == work_id)
        ).one()
        assert row.lease_owner in {"worker-1", "worker-2"}
        assert row.lease_expires_at == NOW + timedelta(minutes=5)
        assert row.version == 1
