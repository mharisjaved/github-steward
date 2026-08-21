"""Verified webhook routing into one atomic durable scheduling transaction."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import cast
from uuid import UUID, uuid4

from github_steward.domain.canonical import CanonicalEnvelope
from github_steward.domain.processing import require_utc_datetime
from github_steward.domain.webhook import (
    GITHUB_WEBHOOK_PROVIDER,
    WEBHOOK_AUDIT_SCHEMA_ID,
    DeliveryClassification,
    RoutingDisposition,
    SecurityEventKind,
    SecurityEventReason,
    SecurityEventV1,
    SignedPayloadError,
    WebhookDeliveryV1,
    WebhookHeaders,
    WebhookReplayOutcome,
    WebhookRouteDecision,
    WebhookSubject,
    WebhookWorkType,
    WebhookWorkV1,
    audit_payload,
    authorize_route,
    delivery_id,
    parse_payload,
    payload_digest,
    route_event,
    security_event_metadata,
    webhook_delivery_projection,
    work_record_id,
)
from github_steward.ports.clock import Clock
from github_steward.ports.persistence import AuditEventId, AuditEventRecord
from github_steward.ports.webhook import (
    WebhookIngressUnitOfWork,
    WebhookIngressUnitOfWorkFactory,
)

type EnvelopeFactory = Callable[[object], CanonicalEnvelope]
type EventIdFactory = Callable[[], UUID]


class WebhookIngressOutcome(StrEnum):
    """Stable successful transport-neutral webhook outcomes."""

    ACCEPTED_NEW = "ACCEPTED_NEW"
    IDEMPOTENT_REPLAY = "IDEMPOTENT_REPLAY"
    INTEGRITY_CONFLICT = "INTEGRITY_CONFLICT"


@dataclass(frozen=True, slots=True)
class WebhookIngressResult:
    """A committed result; a work identity is present only when one was made."""

    outcome: WebhookIngressOutcome
    delivery_id: str
    work_record_id: str | None = None


class WebhookDurabilityError(RuntimeError):
    """A secret-free failure to durably commit webhook state."""


class GitHubWebhookIngressService:
    """Persist a verified delivery and no more than one refresh work record."""

    def __init__(
        self,
        *,
        unit_of_work_factory: WebhookIngressUnitOfWorkFactory,
        clock: Clock,
        envelope_factory: EnvelopeFactory,
        event_id_factory: EventIdFactory = uuid4,
    ) -> None:
        self._unit_of_work_factory = unit_of_work_factory
        self._clock = clock
        self._envelope_factory = envelope_factory
        self._event_id_factory = event_id_factory

    def receive(
        self,
        *,
        headers: WebhookHeaders,
        raw_body: bytes,
    ) -> WebhookIngressResult:
        """Classify and commit one already-authenticated exact request body."""

        if not isinstance(headers, WebhookHeaders):
            raise TypeError("headers must be authenticated WebhookHeaders")
        raw_digest = payload_digest(raw_body)
        decision = self._parse_and_route(headers, raw_body)
        received_at = require_utc_datetime(self._clock.now(), "webhook_received_at")
        delivery_identifier = delivery_id(headers.provider_delivery_id)

        try:
            with self._unit_of_work_factory() as unit_of_work:
                final_decision = self._authorize(unit_of_work, decision)
                projection = webhook_delivery_projection(
                    delivery_identifier=delivery_identifier,
                    event=final_decision.event,
                    action=final_decision.action,
                    classification=final_decision.classification,
                    reported_subject=final_decision.reported_subject,
                    proposed_work_type=final_decision.work_type,
                    proposed_work_subject=final_decision.work_subject,
                )
                projection_envelope = self._envelope_factory(projection)
                delivery = WebhookDeliveryV1(
                    delivery_id=delivery_identifier,
                    provider_delivery_id=headers.provider_delivery_id,
                    payload_digest=raw_digest,
                    event=final_decision.event,
                    action=final_decision.action,
                    classification=final_decision.classification,
                    reported_subject=final_decision.reported_subject,
                    proposed_work_type=final_decision.work_type,
                    proposed_work_subject=final_decision.work_subject,
                    received_at=received_at,
                    sanitized_payload=projection_envelope.payload,
                    sanitized_payload_digest=projection_envelope.digest,
                )
                replay = unit_of_work.webhook_deliveries.classify_or_insert(delivery)
                if replay.outcome is WebhookReplayOutcome.CREATED:
                    if replay.delivery_id != delivery_identifier:
                        raise RuntimeError(
                            "persistence returned a mismatched delivery identity"
                        )
                    result = self._persist_new(
                        unit_of_work,
                        headers=headers,
                        decision=final_decision,
                        delivery_identifier=delivery_identifier,
                        occurred_at=received_at,
                    )
                elif replay.outcome is WebhookReplayOutcome.SAME_DIGEST:
                    result = WebhookIngressResult(
                        WebhookIngressOutcome.IDEMPOTENT_REPLAY,
                        replay.delivery_id,
                        replay.work_record_id,
                    )
                else:
                    self._append_security_event(
                        unit_of_work,
                        delivery_identifier=replay.delivery_id,
                        provider_delivery_id=headers.provider_delivery_id,
                        kind=(SecurityEventKind.WEBHOOK_DELIVERY_INTEGRITY_CONFLICT),
                        reason=SecurityEventReason.DELIVERY_DIGEST_MISMATCH,
                        occurred_at=received_at,
                    )
                    result = WebhookIngressResult(
                        WebhookIngressOutcome.INTEGRITY_CONFLICT,
                        replay.delivery_id,
                        replay.work_record_id,
                    )
                unit_of_work.commit()
        except Exception as exc:
            raise WebhookDurabilityError(
                "webhook durability transaction failed"
            ) from exc
        return result

    @staticmethod
    def _parse_and_route(
        headers: WebhookHeaders,
        raw_body: bytes,
    ) -> WebhookRouteDecision:
        try:
            payload = parse_payload(raw_body)
        except SignedPayloadError as exc:
            return WebhookRouteDecision(
                event=headers.event,
                action=None,
                disposition=RoutingDisposition.NO_WORK,
                classification=DeliveryClassification.SIGNED_SCHEMA_INVALID,
                security_kind=SecurityEventKind.WEBHOOK_SIGNED_SCHEMA_INVALID,
                security_reason=exc.reason,
            )
        return route_event(headers.event, payload)

    @staticmethod
    def _authorize(
        unit_of_work: WebhookIngressUnitOfWork,
        decision: WebhookRouteDecision,
    ) -> WebhookRouteDecision:
        if decision.work_type not in {
            WebhookWorkType.REFRESH_GITHUB_PULL_REQUEST,
            WebhookWorkType.REFRESH_GITHUB_REPOSITORY,
        }:
            return decision
        reported_subject = cast(WebhookSubject, decision.reported_subject)
        repository_id = cast(int, reported_subject.repository_id)
        authorization = unit_of_work.github_authorization.get_repository_authorization(
            repository_id
        )
        return authorize_route(decision, authorization)

    def _persist_new(
        self,
        unit_of_work: WebhookIngressUnitOfWork,
        *,
        headers: WebhookHeaders,
        decision: WebhookRouteDecision,
        delivery_identifier: str,
        occurred_at: datetime,
    ) -> WebhookIngressResult:
        checked_time = require_utc_datetime(occurred_at, "webhook_occurred_at")
        durable_work_id: str | None = None
        if decision.disposition is RoutingDisposition.SCHEDULE:
            work_type = cast(WebhookWorkType, decision.work_type)
            work_subject = cast(WebhookSubject, decision.work_subject)
            durable_work_id = work_record_id(delivery_identifier, work_type)
            unit_of_work.webhook_deliveries.append_work(
                WebhookWorkV1(
                    work_record_id=durable_work_id,
                    delivery_id=delivery_identifier,
                    work_type=work_type,
                    subject=work_subject,
                    available_at=checked_time,
                )
            )

        if decision.security_kind is not None:
            reason = cast(SecurityEventReason, decision.security_reason)
            self._append_security_event(
                unit_of_work,
                delivery_identifier=delivery_identifier,
                provider_delivery_id=headers.provider_delivery_id,
                kind=decision.security_kind,
                reason=reason,
                occurred_at=checked_time,
                event=decision.event,
                action=decision.action,
                reported_subject=decision.reported_subject,
            )

        if decision.audit_kind is not None:
            self._append_audit(
                unit_of_work,
                provider_delivery_id=headers.provider_delivery_id,
                decision=decision,
                occurred_at=checked_time,
            )
        return WebhookIngressResult(
            WebhookIngressOutcome.ACCEPTED_NEW,
            delivery_identifier,
            durable_work_id,
        )

    def _append_security_event(
        self,
        unit_of_work: WebhookIngressUnitOfWork,
        *,
        delivery_identifier: str,
        provider_delivery_id: str,
        kind: SecurityEventKind,
        reason: SecurityEventReason,
        occurred_at: datetime,
        event: str | None = None,
        action: str | None = None,
        reported_subject: WebhookSubject | None = None,
    ) -> None:
        metadata = security_event_metadata(
            kind=kind,
            reason=reason,
            provider_delivery_id=provider_delivery_id,
            event=event,
            action=action,
            reported_subject=reported_subject,
        )
        envelope = self._envelope_factory(metadata)
        unit_of_work.security_events.append(
            SecurityEventV1(
                event_id=str(self._event_id_factory()),
                delivery_id=delivery_identifier,
                kind=kind,
                occurred_at=require_utc_datetime(
                    occurred_at,
                    "security_event_occurred_at",
                ),
                metadata=envelope.payload,
                metadata_digest=envelope.digest,
            )
        )

    def _append_audit(
        self,
        unit_of_work: WebhookIngressUnitOfWork,
        *,
        provider_delivery_id: str,
        decision: WebhookRouteDecision,
        occurred_at: datetime,
    ) -> None:
        payload = audit_payload(
            provider_delivery_id=provider_delivery_id,
            event=decision.event,
            action=cast(str, decision.action),
        )
        envelope = self._envelope_factory(payload)
        unit_of_work.webhook_audits.append(
            AuditEventRecord(
                event_id=AuditEventId(str(self._event_id_factory())),
                event_kind=cast(str, decision.audit_kind),
                actor_or_authority_id=GITHUB_WEBHOOK_PROVIDER,
                occurred_at=require_utc_datetime(
                    occurred_at,
                    "webhook_audit_occurred_at",
                ),
                schema_id=WEBHOOK_AUDIT_SCHEMA_ID,
                schema_version=1,
                payload=envelope.payload,
                digest=envelope.digest,
            )
        )
