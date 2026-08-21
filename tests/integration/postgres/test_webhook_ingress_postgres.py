"""Durable webhook replay, concurrency, and atomicity invariants."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from threading import Barrier, Thread
from typing import cast
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from github_steward.adapters.canonicalization.rfc8785 import envelope_payload
from github_steward.adapters.postgres.metadata import (
    delivery_inbox,
    security_event,
    work_record,
)
from github_steward.adapters.postgres.unit_of_work import PostgresUnitOfWork
from github_steward.application.webhook_ingress import (
    GitHubWebhookIngressService,
    WebhookIngressOutcome,
)
from github_steward.domain.canonical import to_json_compatible
from github_steward.domain.processing import WORK_TYPE, WorkState
from github_steward.domain.webhook import (
    DeliveryClassification,
    SecurityEventKind,
    SecurityEventReason,
    SecurityEventV1,
    WebhookDeliveryV1,
    WebhookHeaders,
    WebhookReplayOutcome,
    WebhookReplayResult,
    WebhookSubject,
    WebhookWorkType,
    WebhookWorkV1,
    delivery_id,
    payload_digest,
    security_event_metadata,
    webhook_delivery_projection,
    work_record_id,
)
from github_steward.infrastructure.broker.credential_broker import (
    BrokerFailureCode,
    CredentialBrokerError,
    GitHubReadCredentialBroker,
)
from github_steward.ports.github_app import (
    GitHubControlPlaneResponse,
    InstallationTokenRequest,
    InstallationTokenResponse,
)
from github_steward.ports.github_authorization import (
    GitHubAuthorizationUnitOfWorkFactory,
)
from github_steward.ports.persistence import ClaimOutcome

NOW = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)


class _FixedClock:
    def now(self) -> datetime:
        return NOW


class _RejectingControlPlane:
    def __init__(self) -> None:
        self.token_requests = 0

    def get_installation(self, installation_id: int) -> GitHubControlPlaneResponse:
        raise AssertionError("broker must reject GS-I6 work before control-plane use")

    def get_repository_installation(
        self,
        *,
        owner: str,
        repository: str,
    ) -> GitHubControlPlaneResponse:
        raise AssertionError("broker must reject GS-I6 work before control-plane use")

    def create_installation_token(
        self,
        *,
        installation_id: int,
        request: InstallationTokenRequest,
    ) -> InstallationTokenResponse:
        self.token_requests += 1
        raise AssertionError("broker must reject GS-I6 work before token minting")


def _delivery_and_work(
    provider_delivery_id: str,
    raw_body: bytes,
    *,
    with_work: bool = True,
) -> tuple[WebhookDeliveryV1, WebhookWorkV1 | None]:
    identifier = delivery_id(provider_delivery_id)
    subject = (
        WebhookSubject(repository_id=7101, installation_id=8101, pull_number=17)
        if with_work
        else None
    )
    work_type = WebhookWorkType.REFRESH_GITHUB_PULL_REQUEST if with_work else None
    classification = (
        DeliveryClassification.SCHEDULE_PULL_REQUEST_REFRESH
        if with_work
        else DeliveryClassification.VALID_NO_WORK
    )
    event = "pull_request" if with_work else "ping"
    action = "synchronize" if with_work else None
    projection = webhook_delivery_projection(
        delivery_identifier=identifier,
        event=event,
        action=action,
        classification=classification,
        reported_subject=subject,
        proposed_work_type=work_type,
        proposed_work_subject=subject,
    )
    envelope = envelope_payload(projection)
    delivery = WebhookDeliveryV1(
        delivery_id=identifier,
        provider_delivery_id=provider_delivery_id,
        payload_digest=payload_digest(raw_body),
        event=event,
        action=action,
        classification=classification,
        reported_subject=subject,
        proposed_work_type=work_type,
        proposed_work_subject=subject,
        received_at=NOW,
        sanitized_payload=envelope.payload,
        sanitized_payload_digest=envelope.digest,
    )
    work = None
    if work_type is not None and subject is not None:
        work = WebhookWorkV1(
            work_record_id=work_record_id(identifier, work_type),
            delivery_id=identifier,
            work_type=work_type,
            subject=subject,
            available_at=NOW,
        )
    return delivery, work


def _repository_delivery_and_work(
    provider_delivery_id: str,
    raw_body: bytes,
    *,
    event: str,
    action: str | None,
) -> tuple[WebhookDeliveryV1, WebhookWorkV1]:
    identifier = delivery_id(provider_delivery_id)
    subject = WebhookSubject(repository_id=7101, installation_id=8101)
    work_type = WebhookWorkType.REFRESH_GITHUB_REPOSITORY
    projection = webhook_delivery_projection(
        delivery_identifier=identifier,
        event=event,
        action=action,
        classification=DeliveryClassification.SCHEDULE_REPOSITORY_REFRESH,
        reported_subject=subject,
        proposed_work_type=work_type,
        proposed_work_subject=subject,
    )
    envelope = envelope_payload(projection)
    delivery = WebhookDeliveryV1(
        delivery_id=identifier,
        provider_delivery_id=provider_delivery_id,
        payload_digest=payload_digest(raw_body),
        event=event,
        action=action,
        classification=DeliveryClassification.SCHEDULE_REPOSITORY_REFRESH,
        reported_subject=subject,
        proposed_work_type=work_type,
        proposed_work_subject=subject,
        received_at=NOW,
        sanitized_payload=envelope.payload,
        sanitized_payload_digest=envelope.digest,
    )
    return delivery, WebhookWorkV1(
        work_record_id=work_record_id(identifier, work_type),
        delivery_id=identifier,
        work_type=work_type,
        subject=subject,
        available_at=NOW,
    )


def _authorization_delivery_and_work(
    provider_delivery_id: str,
    raw_body: bytes,
) -> tuple[WebhookDeliveryV1, WebhookWorkV1]:
    identifier = delivery_id(provider_delivery_id)
    subject = WebhookSubject(installation_id=8101)
    work_type = WebhookWorkType.REFRESH_GITHUB_AUTHORIZATION
    projection = webhook_delivery_projection(
        delivery_identifier=identifier,
        event="installation",
        action="created",
        classification=DeliveryClassification.SCHEDULE_AUTHORIZATION_REFRESH,
        reported_subject=subject,
        proposed_work_type=work_type,
        proposed_work_subject=subject,
    )
    envelope = envelope_payload(projection)
    delivery = WebhookDeliveryV1(
        delivery_id=identifier,
        provider_delivery_id=provider_delivery_id,
        payload_digest=payload_digest(raw_body),
        event="installation",
        action="created",
        classification=DeliveryClassification.SCHEDULE_AUTHORIZATION_REFRESH,
        reported_subject=subject,
        proposed_work_type=work_type,
        proposed_work_subject=subject,
        received_at=NOW,
        sanitized_payload=envelope.payload,
        sanitized_payload_digest=envelope.digest,
    )
    return delivery, WebhookWorkV1(
        work_record_id=work_record_id(identifier, work_type),
        delivery_id=identifier,
        work_type=work_type,
        subject=subject,
        available_at=NOW,
    )


def _security_event(
    delivery: WebhookDeliveryV1,
    *,
    kind: SecurityEventKind = (SecurityEventKind.WEBHOOK_DELIVERY_INTEGRITY_CONFLICT),
    reason: SecurityEventReason = SecurityEventReason.DELIVERY_DIGEST_MISMATCH,
) -> SecurityEventV1:
    metadata = security_event_metadata(
        kind=kind,
        reason=reason,
        provider_delivery_id=delivery.provider_delivery_id,
        event=delivery.event,
        action=delivery.action,
        reported_subject=delivery.reported_subject,
    )
    envelope = envelope_payload(metadata)
    return SecurityEventV1(
        event_id=str(uuid4()),
        delivery_id=delivery.delivery_id,
        kind=kind,
        occurred_at=NOW,
        metadata=envelope.payload,
        metadata_digest=envelope.digest,
    )


def _persist(
    engine: Engine,
    delivery: WebhookDeliveryV1,
    work: WebhookWorkV1 | None,
) -> WebhookReplayResult:
    with PostgresUnitOfWork(engine) as unit:
        result = unit.webhook_deliveries.classify_or_insert(delivery)
        if result.outcome is WebhookReplayOutcome.CREATED and work is not None:
            unit.webhook_deliveries.append_work(work)
        elif result.outcome is WebhookReplayOutcome.INTEGRITY_CONFLICT:
            unit.security_events.append(_security_event(delivery))
        unit.commit()
    return result


def _durable_counts(engine: Engine, provider_delivery_id: str) -> tuple[int, int, int]:
    with engine.connect() as connection:
        delivery_identifier = connection.scalar(
            sa.select(delivery_inbox.c.delivery_id).where(
                delivery_inbox.c.provider == "github",
                delivery_inbox.c.provider_delivery_id == provider_delivery_id,
            )
        )
        if delivery_identifier is None:
            return (0, 0, 0)
        return (
            1,
            int(
                connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(work_record)
                    .where(work_record.c.delivery_id == delivery_identifier)
                )
                or 0
            ),
            int(
                connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(security_event)
                    .where(security_event.c.delivery_id == delivery_identifier)
                )
                or 0
            ),
        )


def test_new_delivery_persists_sanitized_projection_and_optional_work(
    postgres_engine: Engine,
) -> None:
    raw_body = b'{"distinctive-unpersisted-body":"sensitive"}'
    delivery, work = _delivery_and_work(str(uuid4()), raw_body)

    result = _persist(postgres_engine, delivery, work)

    assert result.outcome is WebhookReplayOutcome.CREATED
    assert _durable_counts(postgres_engine, delivery.provider_delivery_id) == (1, 1, 0)
    with postgres_engine.connect() as connection:
        row = (
            connection.execute(
                sa.select(delivery_inbox).where(
                    delivery_inbox.c.delivery_id == delivery.delivery_id
                )
            )
            .mappings()
            .one()
        )
    assert row["raw_payload_digest"] == delivery.payload_digest.value
    assert row["payload_digest"] == delivery.sanitized_payload_digest.value
    assert row["payload_digest_format"] == "jcs-sha256/v1"
    assert row["canonical_payload"] == to_json_compatible(delivery.sanitized_payload)
    assert "distinctive-unpersisted-body" not in str(row["canonical_payload"])

    no_work_delivery, _ = _delivery_and_work(
        str(uuid4()),
        b'{"zen":"bounded"}',
        with_work=False,
    )
    no_work = _persist(postgres_engine, no_work_delivery, None)
    assert no_work.outcome is WebhookReplayOutcome.CREATED
    assert _durable_counts(
        postgres_engine,
        no_work_delivery.provider_delivery_id,
    ) == (1, 0, 0)


def test_authenticated_malformed_json_is_durable_and_replay_safe(
    postgres_engine: Engine,
) -> None:
    provider_delivery_id = str(uuid4())
    service = GitHubWebhookIngressService(
        unit_of_work_factory=lambda: PostgresUnitOfWork(postgres_engine),
        clock=_FixedClock(),
        envelope_factory=envelope_payload,
    )

    first = service.receive(
        headers=WebhookHeaders(provider_delivery_id, "pull_request"),
        raw_body=b'{"malformed":',
    )
    replay = service.receive(
        headers=WebhookHeaders(provider_delivery_id, "pull_request"),
        raw_body=b'{"malformed":',
    )

    assert first.outcome is WebhookIngressOutcome.ACCEPTED_NEW
    assert replay.outcome is WebhookIngressOutcome.IDEMPOTENT_REPLAY
    assert _durable_counts(postgres_engine, provider_delivery_id) == (1, 0, 1)


def test_same_digest_replay_and_lost_ack_create_no_duplicate(
    postgres_engine: Engine,
) -> None:
    delivery, work = _delivery_and_work(str(uuid4()), b'{"same":true}')
    first = _persist(postgres_engine, delivery, work)

    def acknowledgement_was_lost() -> None:
        raise ConnectionError("simulated response loss after commit")

    with pytest.raises(ConnectionError, match="response loss"):
        acknowledgement_was_lost()
    replay = _persist(postgres_engine, delivery, work)

    assert first.outcome is WebhookReplayOutcome.CREATED
    assert replay.outcome is WebhookReplayOutcome.SAME_DIGEST
    assert replay.delivery_id == delivery.delivery_id
    assert work is not None
    assert replay.work_record_id == work.work_record_id
    assert _durable_counts(postgres_engine, delivery.provider_delivery_id) == (1, 1, 0)

    with (
        pytest.raises(RuntimeError, match="newly inserted"),
        PostgresUnitOfWork(postgres_engine) as unit,
    ):
        unit.webhook_deliveries.append_work(work)


def test_different_digest_preserves_original_and_appends_security_event(
    postgres_engine: Engine,
) -> None:
    provider_delivery_id = str(uuid4())
    original, work = _delivery_and_work(provider_delivery_id, b'{"version":1}')
    conflicting, conflicting_work = _delivery_and_work(
        provider_delivery_id,
        b'{"version":2}',
    )
    _persist(postgres_engine, original, work)

    result = _persist(postgres_engine, conflicting, conflicting_work)

    assert result.outcome is WebhookReplayOutcome.INTEGRITY_CONFLICT
    assert _durable_counts(postgres_engine, provider_delivery_id) == (1, 1, 1)
    with postgres_engine.connect() as connection:
        stored_digest = connection.scalar(
            sa.select(delivery_inbox.c.raw_payload_digest).where(
                delivery_inbox.c.delivery_id == original.delivery_id
            )
        )
        stored_kind = connection.scalar(
            sa.select(security_event.c.event_kind).where(
                security_event.c.delivery_id == original.delivery_id
            )
        )
    assert stored_digest == original.payload_digest.value
    assert stored_digest != conflicting.payload_digest.value
    assert stored_kind == "WEBHOOK_DELIVERY_INTEGRITY_CONFLICT"


def test_optional_work_must_match_the_new_delivery_projection(
    postgres_engine: Engine,
) -> None:
    provider_delivery_id = str(uuid4())
    no_work, _ = _delivery_and_work(
        provider_delivery_id,
        b'{"zen":"safe"}',
        with_work=False,
    )
    _, mismatched_work = _delivery_and_work(
        provider_delivery_id,
        b'{"zen":"safe"}',
    )
    assert mismatched_work is not None

    with (
        pytest.raises(RuntimeError, match="sanitized delivery projection"),
        PostgresUnitOfWork(postgres_engine) as unit,
    ):
        created = unit.webhook_deliveries.classify_or_insert(no_work)
        assert created.outcome is WebhookReplayOutcome.CREATED
        unit.webhook_deliveries.append_work(mismatched_work)

    assert _durable_counts(postgres_engine, provider_delivery_id) == (0, 0, 0)


def _run_threads(functions: list[Callable[[], None]]) -> None:
    threads = [Thread(target=function) for function in functions]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def test_concurrent_duplicates_have_exactly_one_durable_effect(
    postgres_engine: Engine,
) -> None:
    provider_delivery_id = str(uuid4())
    delivery, work = _delivery_and_work(provider_delivery_id, b'{"same":true}')
    barrier = Barrier(4)
    outcomes: list[WebhookReplayOutcome] = []

    def receive() -> None:
        barrier.wait()
        outcomes.append(_persist(postgres_engine, delivery, work).outcome)

    _run_threads([receive, receive, receive, receive])

    assert outcomes.count(WebhookReplayOutcome.CREATED) == 1
    assert outcomes.count(WebhookReplayOutcome.SAME_DIGEST) == 3
    assert _durable_counts(postgres_engine, provider_delivery_id) == (1, 1, 0)


def test_gs_i6_lim_001_distinct_ci_deliveries_create_one_repository_work_each(
    postgres_engine: Engine,
) -> None:
    routes = [
        ("check_run", "created"),
        ("check_run", "completed"),
        ("check_suite", "completed"),
        ("status", None),
    ]
    deliveries = [
        _repository_delivery_and_work(
            str(uuid4()),
            f'{{"ci-delivery":{index}}}'.encode(),
            event=event,
            action=action,
        )
        for index, (event, action) in enumerate(routes, start=1)
    ]

    outcomes = [
        _persist(postgres_engine, delivery, work).outcome
        for delivery, work in deliveries
    ]

    assert outcomes == [WebhookReplayOutcome.CREATED] * len(deliveries)
    provider_delivery_ids = [
        delivery.provider_delivery_id for delivery, _ in deliveries
    ]
    with postgres_engine.connect() as connection:
        delivery_ids = list(
            connection.scalars(
                sa.select(delivery_inbox.c.delivery_id).where(
                    delivery_inbox.c.provider == "github",
                    delivery_inbox.c.provider_delivery_id.in_(provider_delivery_ids),
                )
            )
        )
        work_counts = dict(
            list(
                connection.execute(
                    sa.select(work_record.c.delivery_id, sa.func.count())
                    .where(work_record.c.delivery_id.in_(delivery_ids))
                    .group_by(work_record.c.delivery_id)
                ).tuples()
            )
        )
        repository_work = int(
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(work_record)
                .where(
                    work_record.c.delivery_id.in_(delivery_ids),
                    work_record.c.work_type == "REFRESH_GITHUB_REPOSITORY",
                )
            )
            or 0
        )
        pull_request_fan_out = int(
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(work_record)
                .where(
                    work_record.c.delivery_id.in_(delivery_ids),
                    work_record.c.work_type == "REFRESH_GITHUB_PULL_REQUEST",
                )
            )
            or 0
        )

    assert len(delivery_ids) == len(deliveries)
    assert work_counts == {
        delivery_identifier: 1 for delivery_identifier in delivery_ids
    }
    assert repository_work == len(deliveries)
    assert pull_request_fan_out == 0


def test_concurrent_integrity_conflict_never_overwrites_winner(
    postgres_engine: Engine,
) -> None:
    provider_delivery_id = str(uuid4())
    first, first_work = _delivery_and_work(provider_delivery_id, b'{"winner":1}')
    second, second_work = _delivery_and_work(provider_delivery_id, b'{"winner":2}')
    barrier = Barrier(2)
    outcomes: list[WebhookReplayOutcome] = []

    def receive(delivery: WebhookDeliveryV1, work: WebhookWorkV1 | None) -> None:
        barrier.wait()
        outcomes.append(_persist(postgres_engine, delivery, work).outcome)

    _run_threads(
        [
            lambda: receive(first, first_work),
            lambda: receive(second, second_work),
        ]
    )

    assert sorted(outcomes) == sorted(
        [WebhookReplayOutcome.CREATED, WebhookReplayOutcome.INTEGRITY_CONFLICT]
    )
    assert _durable_counts(postgres_engine, provider_delivery_id) == (1, 1, 1)
    with postgres_engine.connect() as connection:
        stored_digest = connection.scalar(
            sa.select(delivery_inbox.c.raw_payload_digest).where(
                delivery_inbox.c.provider_delivery_id == provider_delivery_id
            )
        )
    assert stored_digest in {first.payload_digest.value, second.payload_digest.value}


def test_transaction_rollback_leaves_no_partial_webhook_effect(
    postgres_engine: Engine,
) -> None:
    delivery, work = _delivery_and_work(str(uuid4()), b'{"rollback":true}')
    event = _security_event(
        delivery,
        kind=SecurityEventKind.WEBHOOK_SIGNED_SCHEMA_INVALID,
        reason=SecurityEventReason.INVALID_JSON,
    )

    with (
        pytest.raises(RuntimeError, match="injected before commit"),
        PostgresUnitOfWork(postgres_engine) as unit,
    ):
        result = unit.webhook_deliveries.classify_or_insert(delivery)
        assert result.outcome is WebhookReplayOutcome.CREATED
        assert work is not None
        unit.webhook_deliveries.append_work(work)
        unit.security_events.append(event)
        raise RuntimeError("injected before commit")

    assert _durable_counts(postgres_engine, delivery.provider_delivery_id) == (0, 0, 0)


def test_legacy_synthetic_processor_cannot_claim_webhook_refresh_work(
    postgres_engine: Engine,
) -> None:
    with postgres_engine.begin() as connection:
        connection.execute(
            work_record.update()
            .where(work_record.c.work_type == WORK_TYPE)
            .values(
                state=WorkState.SUCCEEDED.value,
                lease_owner=None,
                lease_token=None,
                lease_expires_at=None,
            )
        )
    delivery, work = _delivery_and_work(str(uuid4()), b'{"scheduled":true}')
    created = _persist(postgres_engine, delivery, work)
    assert created.outcome is WebhookReplayOutcome.CREATED

    with PostgresUnitOfWork(postgres_engine) as unit:
        claim = unit.work.claim_next(owner="legacy-synthetic-worker", now=NOW)
        unit.rollback()

    assert claim.outcome is ClaimOutcome.NO_WORK
    assert _durable_counts(postgres_engine, delivery.provider_delivery_id) == (1, 1, 0)


@pytest.mark.parametrize(
    "new_work_type",
    [
        WebhookWorkType.REFRESH_GITHUB_REPOSITORY,
        WebhookWorkType.REFRESH_GITHUB_AUTHORIZATION,
    ],
)
def test_postgres_backed_gs_i6_work_remains_broker_ineligible(
    postgres_engine: Engine,
    new_work_type: WebhookWorkType,
) -> None:
    provider_delivery_id = str(uuid4())
    if new_work_type is WebhookWorkType.REFRESH_GITHUB_REPOSITORY:
        delivery, work = _repository_delivery_and_work(
            provider_delivery_id,
            b'{"event":"check_run"}',
            event="check_run",
            action="created",
        )
    else:
        delivery, work = _authorization_delivery_and_work(
            provider_delivery_id,
            b'{"event":"installation"}',
        )
    assert _persist(postgres_engine, delivery, work).outcome is (
        WebhookReplayOutcome.CREATED
    )

    with PostgresUnitOfWork(postgres_engine) as unit:
        identity = unit.github_authorization.get_work_identity(work.work_record_id)
    assert identity is not None
    assert identity.work_type == new_work_type.value
    assert identity.repository_id == 0
    assert identity.pull_number == 0

    control_plane = _RejectingControlPlane()
    broker = GitHubReadCredentialBroker(
        unit_of_work_factory=cast(
            GitHubAuthorizationUnitOfWorkFactory,
            lambda: PostgresUnitOfWork(postgres_engine),
        ),
        control_plane=control_plane,
        clock=_FixedClock(),
    )
    with pytest.raises(CredentialBrokerError) as raised:
        broker.MintReadToken(work.work_record_id)

    assert raised.value.code is BrokerFailureCode.WORK_NOT_AUTHORIZED
    assert control_plane.token_requests == 0
