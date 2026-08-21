"""PostgreSQL persistence for verified GitHub webhook ingress."""

from __future__ import annotations

from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import Connection

from github_steward.adapters.postgres.metadata import (
    delivery_inbox,
    security_event,
    work_record,
)
from github_steward.domain.canonical import to_json_compatible
from github_steward.domain.processing import WorkState
from github_steward.domain.webhook import (
    SCHEMA_VERSION,
    SECURITY_EVENT_SCHEMA_ID,
    WEBHOOK_DELIVERY_SCHEMA_ID,
    SecurityEventV1,
    WebhookDeliveryV1,
    WebhookReplayOutcome,
    WebhookReplayResult,
    WebhookWorkV1,
)


def _uuid(value: str) -> UUID:
    return UUID(value)


class PostgresWebhookDeliveryRepository:
    """Classify delivery replay and append at most one durable work record."""

    def __init__(self, connection: Connection) -> None:
        self._connection = connection
        self._created_deliveries: dict[str, WebhookDeliveryV1] = {}

    def classify_or_insert(
        self,
        delivery: WebhookDeliveryV1,
    ) -> WebhookReplayResult:
        """Serialize an exact provider identity and classify its raw digest."""

        self._connection.execute(
            sa.select(
                sa.func.pg_advisory_xact_lock(
                    sa.func.hashtext(delivery.provider),
                    sa.func.hashtext(delivery.provider_delivery_id),
                )
            )
        )
        inserted = self._connection.execute(
            pg_insert(delivery_inbox)
            .values(
                delivery_id=_uuid(delivery.delivery_id),
                provider=delivery.provider,
                provider_delivery_id=delivery.provider_delivery_id,
                payload_digest=delivery.sanitized_payload_digest.value,
                raw_payload_digest=delivery.payload_digest.value,
                received_at=delivery.received_at,
                payload_schema_id=WEBHOOK_DELIVERY_SCHEMA_ID,
                payload_schema_version=SCHEMA_VERSION,
                canonical_payload=to_json_compatible(delivery.sanitized_payload),
                payload_digest_format=delivery.sanitized_payload_digest.format,
            )
            .on_conflict_do_nothing(
                index_elements=[
                    delivery_inbox.c.provider,
                    delivery_inbox.c.provider_delivery_id,
                ]
            )
            .returning(delivery_inbox.c.delivery_id)
        ).scalar_one_or_none()
        if inserted is not None:
            self._created_deliveries[delivery.delivery_id] = delivery
            return WebhookReplayResult(
                outcome=WebhookReplayOutcome.CREATED,
                delivery_id=delivery.delivery_id,
                work_record_id=None,
            )

        original = (
            self._connection.execute(
                sa.select(
                    delivery_inbox.c.delivery_id,
                    delivery_inbox.c.raw_payload_digest,
                    work_record.c.work_record_id,
                )
                .select_from(
                    delivery_inbox.outerjoin(
                        work_record,
                        work_record.c.delivery_id == delivery_inbox.c.delivery_id,
                    )
                )
                .where(
                    delivery_inbox.c.provider == delivery.provider,
                    delivery_inbox.c.provider_delivery_id
                    == delivery.provider_delivery_id,
                )
            )
            .mappings()
            .one()
        )
        outcome = (
            WebhookReplayOutcome.SAME_DIGEST
            if original["raw_payload_digest"] == delivery.payload_digest.value
            else WebhookReplayOutcome.INTEGRITY_CONFLICT
        )
        persisted_work = original["work_record_id"]
        return WebhookReplayResult(
            outcome=outcome,
            delivery_id=str(original["delivery_id"]),
            work_record_id=(None if persisted_work is None else str(persisted_work)),
        )

    def append_work(self, work: WebhookWorkV1) -> None:
        """Append one work record; the delivery uniqueness constraint is authoritative."""

        created = self._created_deliveries.get(work.delivery_id)
        if created is None:
            raise RuntimeError("work requires a newly inserted webhook delivery")
        if (
            created.proposed_work_type is not work.work_type
            or created.proposed_work_subject != work.subject
        ):
            raise RuntimeError("work differs from the sanitized delivery projection")
        self._connection.execute(
            work_record.insert().values(
                work_record_id=_uuid(work.work_record_id),
                delivery_id=_uuid(work.delivery_id),
                work_type=work.work_type.value,
                state=WorkState.AVAILABLE.value,
                available_at=work.available_at,
            )
        )
        del self._created_deliveries[work.delivery_id]


class PostgresSecurityEventRepository:
    """Append SecurityEventV1 values without exposing mutation operations."""

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def append(self, event: SecurityEventV1) -> None:
        """Append one bounded, canonical, secret-safe security event."""

        self._connection.execute(
            security_event.insert().values(
                security_event_id=_uuid(event.event_id),
                delivery_id=_uuid(event.delivery_id),
                event_kind=event.kind.value,
                occurred_at=event.occurred_at,
                schema_id=SECURITY_EVENT_SCHEMA_ID,
                schema_version=SCHEMA_VERSION,
                canonical_metadata=to_json_compatible(event.metadata),
                digest_format=event.metadata_digest.format,
                digest_value=event.metadata_digest.value,
            )
        )
