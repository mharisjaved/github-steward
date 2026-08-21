"""Secret-safe contracts for verified GitHub webhook scheduling.

This module deliberately treats a signed webhook as permission to schedule later
verification.  Parsed webhook content is used only for bounded routing; it is
never represented as trusted repository evidence.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Final, NoReturn, cast
from uuid import UUID, uuid5

from github_steward.domain.acquisition import GITHUB_REFRESH_WORK_TYPE
from github_steward.domain.canonical import (
    MAX_SAFE_INTEGER,
    CanonicalValue,
    Digest,
    freeze_canonical_value,
)
from github_steward.domain.errors import DomainValidationError
from github_steward.domain.github_authorization import (
    AuthorizationCapability,
    RepositoryAuthorizationV1,
)

GITHUB_WEBHOOK_PROVIDER: Final = "github"
DEFAULT_MAX_BODY_BYTES: Final = 8 * 1024 * 1024
HARD_MAX_BODY_BYTES: Final = 25 * 1024 * 1024
RAW_SHA256_FORMAT: Final = "raw-sha256/v1"
WEBHOOK_DELIVERY_SCHEMA_ID: Final = "github-steward.github-webhook-delivery/v1"
SECURITY_EVENT_SCHEMA_ID: Final = "github-steward.security-event/v1"
WEBHOOK_AUDIT_SCHEMA_ID: Final = "github-steward.webhook-audit/v1"
SCHEMA_VERSION: Final = 1
GITHUB_APP_AUTHORIZATION_REVOKED_AUDIT_KIND: Final = (
    "github.webhook.authorization_revoked"
)

_MAX_EVENT_LENGTH: Final = 64
_IDENTITY_NAMESPACE: Final = UUID("15200e7d-6747-5b89-bf26-870ce9894353")
_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")
_EVENT_NAME: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ACTION_NAME: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class WebhookEvent(StrEnum):
    """The exact GS-I6 recognized GitHub webhook event inventory."""

    PING = "ping"
    INSTALLATION = "installation"
    INSTALLATION_REPOSITORIES = "installation_repositories"
    GITHUB_APP_AUTHORIZATION = "github_app_authorization"
    PULL_REQUEST = "pull_request"
    PULL_REQUEST_REVIEW = "pull_request_review"
    CHECK_RUN = "check_run"
    CHECK_SUITE = "check_suite"
    STATUS = "status"


class WebhookWorkType(StrEnum):
    """Durable refresh work that a verified webhook may schedule."""

    REFRESH_GITHUB_PULL_REQUEST = GITHUB_REFRESH_WORK_TYPE
    REFRESH_GITHUB_REPOSITORY = "REFRESH_GITHUB_REPOSITORY"
    REFRESH_GITHUB_AUTHORIZATION = "REFRESH_GITHUB_AUTHORIZATION"


class SecurityEventKind(StrEnum):
    """Initial append-only GS-I6 security-event inventory."""

    WEBHOOK_DELIVERY_INTEGRITY_CONFLICT = "WEBHOOK_DELIVERY_INTEGRITY_CONFLICT"
    WEBHOOK_SIGNED_SCHEMA_INVALID = "WEBHOOK_SIGNED_SCHEMA_INVALID"
    WEBHOOK_SIGNED_IDENTITY_MISMATCH = "WEBHOOK_SIGNED_IDENTITY_MISMATCH"
    WEBHOOK_AUTHORIZATION_CONTEXT_MISMATCH = "WEBHOOK_AUTHORIZATION_CONTEXT_MISMATCH"
    WEBHOOK_PERMISSION_CEILING_MISMATCH = "WEBHOOK_PERMISSION_CEILING_MISMATCH"


class SecurityEventReason(StrEnum):
    """Bounded explanations that cannot carry parser or request-body text."""

    DELIVERY_DIGEST_MISMATCH = "DELIVERY_DIGEST_MISMATCH"
    INVALID_UTF8 = "INVALID_UTF8"
    INVALID_JSON = "INVALID_JSON"
    DUPLICATE_JSON_KEY = "DUPLICATE_JSON_KEY"
    NONFINITE_NUMBER = "NONFINITE_NUMBER"
    INVALID_UNICODE_SCALAR = "INVALID_UNICODE_SCALAR"
    JSON_ROOT_NOT_OBJECT = "JSON_ROOT_NOT_OBJECT"
    ACTION_MISSING_OR_INVALID = "ACTION_MISSING_OR_INVALID"
    REQUIRED_IDENTITY_MISSING_OR_INVALID = "REQUIRED_IDENTITY_MISSING_OR_INVALID"
    REPOSITORY_IDENTITY_MISMATCH = "REPOSITORY_IDENTITY_MISMATCH"
    PULL_REQUEST_IDENTITY_MISMATCH = "PULL_REQUEST_IDENTITY_MISMATCH"
    AUTHORIZATION_MISSING = "AUTHORIZATION_MISSING"
    AUTHORIZATION_REPOSITORY_MISMATCH = "AUTHORIZATION_REPOSITORY_MISMATCH"
    AUTHORIZATION_INSTALLATION_MISMATCH = "AUTHORIZATION_INSTALLATION_MISMATCH"
    AUTHORIZATION_CAPABILITY_DENIED = "AUTHORIZATION_CAPABILITY_DENIED"
    AUTHORIZATION_WRITE_ENABLED = "AUTHORIZATION_WRITE_ENABLED"
    CHECK_RUN_ACTION_EXCEEDS_PERMISSION_CEILING = (
        "CHECK_RUN_ACTION_EXCEEDS_PERMISSION_CEILING"
    )
    CHECK_SUITE_ACTION_EXCEEDS_PERMISSION_CEILING = (
        "CHECK_SUITE_ACTION_EXCEEDS_PERMISSION_CEILING"
    )


class DeliveryClassification(StrEnum):
    """Secret-safe semantic classification stored for a signed delivery."""

    VALID_NO_WORK = "VALID_NO_WORK"
    UNSUPPORTED_AUTHENTICATED_EVENT = "UNSUPPORTED_AUTHENTICATED_EVENT"
    SCHEDULE_PULL_REQUEST_REFRESH = "SCHEDULE_PULL_REQUEST_REFRESH"
    SCHEDULE_REPOSITORY_REFRESH = "SCHEDULE_REPOSITORY_REFRESH"
    SCHEDULE_AUTHORIZATION_REFRESH = "SCHEDULE_AUTHORIZATION_REFRESH"
    AUTHORIZATION_REVOKED = "AUTHORIZATION_REVOKED"
    SIGNED_SCHEMA_INVALID = "SIGNED_SCHEMA_INVALID"
    SIGNED_IDENTITY_MISMATCH = "SIGNED_IDENTITY_MISMATCH"
    PERMISSION_CEILING_MISMATCH = "PERMISSION_CEILING_MISMATCH"
    AUTHORIZATION_CONTEXT_MISMATCH = "AUTHORIZATION_CONTEXT_MISMATCH"


class RoutingDisposition(StrEnum):
    """Whether a route currently carries one proposed durable work item."""

    SCHEDULE = "SCHEDULE"
    NO_WORK = "NO_WORK"


class WebhookReplayOutcome(StrEnum):
    """Transaction-locked provider-delivery replay classifications."""

    CREATED = "CREATED"
    SAME_DIGEST = "SAME_DIGEST"
    INTEGRITY_CONFLICT = "INTEGRITY_CONFLICT"


class SignedPayloadError(ValueError):
    """A safe, stable signed-input parsing failure."""

    def __init__(self, reason: SecurityEventReason) -> None:
        self.reason = reason
        super().__init__("authenticated webhook payload was invalid")


@dataclass(frozen=True, slots=True)
class RawBodyDigest:
    """SHA-256 of the exact raw request bytes, distinct from a JCS digest."""

    value: str
    format: str = RAW_SHA256_FORMAT

    def __post_init__(self) -> None:
        if self.format != RAW_SHA256_FORMAT:
            raise DomainValidationError(
                f"raw body digest format must be {RAW_SHA256_FORMAT}"
            )
        if not isinstance(self.value, str) or _SHA256.fullmatch(self.value) is None:
            raise DomainValidationError("raw body digest must be lowercase SHA-256")


@dataclass(frozen=True, slots=True)
class WebhookHeaders:
    """Authenticated, non-secret headers passed inward by the web boundary."""

    provider_delivery_id: str
    event: str

    def __post_init__(self) -> None:
        _canonical_uuid(self.provider_delivery_id, "provider_delivery_id")
        if not isinstance(self.event, str) or _EVENT_NAME.fullmatch(self.event) is None:
            raise DomainValidationError("event header was malformed")


@dataclass(frozen=True, slots=True)
class WebhookSubject:
    """Validated numeric identities reported by or selected for one delivery."""

    repository_id: int | None = None
    installation_id: int | None = None
    pull_number: int | None = None

    def __post_init__(self) -> None:
        for name, value in (
            ("repository_id", self.repository_id),
            ("installation_id", self.installation_id),
            ("pull_number", self.pull_number),
        ):
            if value is not None:
                _positive_bigint(value, name)
        if (
            self.repository_id is None
            and self.installation_id is None
            and self.pull_number is None
        ):
            raise DomainValidationError("webhook subject must contain an identity")
        if self.pull_number is not None and self.repository_id is None:
            raise DomainValidationError(
                "pull_number requires a numeric repository identity"
            )


@dataclass(frozen=True, slots=True)
class WebhookRouteDecision:
    """A pure routing decision before or after the trusted authorization gate."""

    event: str
    action: str | None
    disposition: RoutingDisposition
    classification: DeliveryClassification
    reported_subject: WebhookSubject | None = None
    work_type: WebhookWorkType | None = None
    work_subject: WebhookSubject | None = None
    security_kind: SecurityEventKind | None = None
    security_reason: SecurityEventReason | None = None
    audit_kind: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.event, str) or _EVENT_NAME.fullmatch(self.event) is None:
            raise DomainValidationError("route event was malformed")
        if self.action is not None and (
            not isinstance(self.action, str)
            or _ACTION_NAME.fullmatch(self.action) is None
        ):
            raise DomainValidationError("route action was malformed")
        if not isinstance(self.disposition, RoutingDisposition):
            raise DomainValidationError("route disposition was invalid")
        if not isinstance(self.classification, DeliveryClassification):
            raise DomainValidationError("delivery classification was invalid")
        scheduled = self.disposition is RoutingDisposition.SCHEDULE
        if (self.work_type is None) != (self.work_subject is None):
            raise DomainValidationError(
                "work type and subject must be present together"
            )
        if scheduled != (self.work_type is not None):
            raise DomainValidationError(
                "scheduled routes require exactly one typed work subject"
            )
        if self.work_type is not None:
            _validate_work_subject(
                self.work_type, cast(WebhookSubject, self.work_subject)
            )
        if (
            self.work_type
            in {
                WebhookWorkType.REFRESH_GITHUB_PULL_REQUEST,
                WebhookWorkType.REFRESH_GITHUB_REPOSITORY,
            }
            and self.reported_subject is None
        ):
            raise DomainValidationError(
                "repository work requires a reported numeric subject"
            )
        if (self.security_kind is None) != (self.security_reason is None):
            raise DomainValidationError(
                "security kind and reason must be present together"
            )
        if self.audit_kind is not None:
            if self.audit_kind != GITHUB_APP_AUTHORIZATION_REVOKED_AUDIT_KIND:
                raise DomainValidationError("webhook audit kind was invalid")
            if (
                self.event != WebhookEvent.GITHUB_APP_AUTHORIZATION.value
                or self.action != "revoked"
            ):
                raise DomainValidationError("webhook audit route was incomplete")


@dataclass(frozen=True, slots=True)
class WebhookDeliveryV1:
    """Append-only delivery identity with only a sanitized JCS projection."""

    delivery_id: str
    provider_delivery_id: str
    payload_digest: RawBodyDigest
    event: str
    action: str | None
    classification: DeliveryClassification
    reported_subject: WebhookSubject | None
    proposed_work_type: WebhookWorkType | None
    proposed_work_subject: WebhookSubject | None
    received_at: datetime
    sanitized_payload: CanonicalValue
    sanitized_payload_digest: Digest
    provider: str = GITHUB_WEBHOOK_PROVIDER
    payload_schema_id: str = WEBHOOK_DELIVERY_SCHEMA_ID
    payload_schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _canonical_uuid(self.delivery_id, "delivery_id")
        _canonical_uuid(self.provider_delivery_id, "provider_delivery_id")
        if self.provider != GITHUB_WEBHOOK_PROVIDER:
            raise DomainValidationError("webhook provider must be github")
        if not isinstance(self.payload_digest, RawBodyDigest):
            raise DomainValidationError("payload_digest must be a RawBodyDigest")
        if not isinstance(self.event, str) or _EVENT_NAME.fullmatch(self.event) is None:
            raise DomainValidationError("delivery event was malformed")
        if self.action is not None and (
            not isinstance(self.action, str)
            or _ACTION_NAME.fullmatch(self.action) is None
        ):
            raise DomainValidationError("delivery action was malformed")
        if not isinstance(self.classification, DeliveryClassification):
            raise DomainValidationError("delivery classification was invalid")
        if (self.proposed_work_type is None) != (self.proposed_work_subject is None):
            raise DomainValidationError(
                "proposed work type and subject must be present together"
            )
        if self.proposed_work_type is not None:
            _validate_work_subject(
                self.proposed_work_type,
                cast(WebhookSubject, self.proposed_work_subject),
            )
        checked_time = _utc(self.received_at, "received_at")
        object.__setattr__(self, "received_at", checked_time)
        expected_payload = webhook_delivery_projection(
            delivery_identifier=self.delivery_id,
            event=self.event,
            action=self.action,
            classification=self.classification,
            reported_subject=self.reported_subject,
            proposed_work_type=self.proposed_work_type,
            proposed_work_subject=self.proposed_work_subject,
        )
        frozen = freeze_canonical_value(self.sanitized_payload)
        if frozen != expected_payload:
            raise DomainValidationError(
                "sanitized webhook payload did not match its typed projection"
            )
        object.__setattr__(self, "sanitized_payload", frozen)
        if not isinstance(self.sanitized_payload_digest, Digest):
            raise DomainValidationError(
                "sanitized_payload_digest must be a canonical Digest"
            )
        if self.payload_schema_id != WEBHOOK_DELIVERY_SCHEMA_ID:
            raise DomainValidationError("webhook delivery schema id was invalid")
        if self.payload_schema_version != SCHEMA_VERSION:
            raise DomainValidationError("webhook delivery schema version was invalid")


@dataclass(frozen=True, slots=True)
class WebhookWorkV1:
    """Exactly one durable refresh work record selected for a delivery."""

    work_record_id: str
    delivery_id: str
    work_type: WebhookWorkType
    subject: WebhookSubject
    available_at: datetime

    def __post_init__(self) -> None:
        _canonical_uuid(self.work_record_id, "work_record_id")
        _canonical_uuid(self.delivery_id, "delivery_id")
        if not isinstance(self.work_type, WebhookWorkType):
            raise DomainValidationError("work_type must be a WebhookWorkType")
        if not isinstance(self.subject, WebhookSubject):
            raise DomainValidationError("subject must be a WebhookSubject")
        _validate_work_subject(self.work_type, self.subject)
        object.__setattr__(
            self,
            "available_at",
            _utc(self.available_at, "available_at"),
        )


@dataclass(frozen=True, slots=True)
class SecurityEventV1:
    """Append-only, bounded, canonical and secret-safe security evidence."""

    event_id: str
    delivery_id: str
    kind: SecurityEventKind
    occurred_at: datetime
    metadata: CanonicalValue
    metadata_digest: Digest
    schema_id: str = SECURITY_EVENT_SCHEMA_ID
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _canonical_uuid(self.event_id, "event_id")
        _canonical_uuid(self.delivery_id, "delivery_id")
        if not isinstance(self.kind, SecurityEventKind):
            raise DomainValidationError("security event kind was invalid")
        object.__setattr__(
            self,
            "occurred_at",
            _utc(self.occurred_at, "occurred_at"),
        )
        frozen = _validate_security_metadata(self.kind, self.metadata)
        object.__setattr__(self, "metadata", frozen)
        if not isinstance(self.metadata_digest, Digest):
            raise DomainValidationError("metadata_digest must be a canonical Digest")
        if self.schema_id != SECURITY_EVENT_SCHEMA_ID:
            raise DomainValidationError("security event schema id was invalid")
        if self.schema_version != SCHEMA_VERSION:
            raise DomainValidationError("security event schema version was invalid")


@dataclass(frozen=True, slots=True)
class WebhookReplayResult:
    """Durable classification bound to the original delivery identity."""

    outcome: WebhookReplayOutcome
    delivery_id: str
    work_record_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, WebhookReplayOutcome):
            raise DomainValidationError("webhook replay outcome was invalid")
        _canonical_uuid(self.delivery_id, "delivery_id")
        if self.work_record_id is not None:
            _canonical_uuid(self.work_record_id, "work_record_id")


def payload_digest(raw_body: bytes) -> RawBodyDigest:
    """Hash the exact bytes received at the authenticated boundary."""

    if not isinstance(raw_body, bytes):
        raise TypeError("raw_body must be bytes")
    return RawBodyDigest(hashlib.sha256(raw_body).hexdigest())


def parse_payload(raw_body: bytes) -> Mapping[str, object]:
    """Strictly decode and parse a signed JSON object without body echo."""

    if not isinstance(raw_body, bytes):
        raise TypeError("raw_body must be bytes")
    try:
        text = raw_body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SignedPayloadError(SecurityEventReason.INVALID_UTF8) from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite_constant,
        )
    except _DuplicateJsonKeyError as exc:
        raise SignedPayloadError(SecurityEventReason.DUPLICATE_JSON_KEY) from exc
    except _NonfiniteJsonNumberError as exc:
        raise SignedPayloadError(SecurityEventReason.NONFINITE_NUMBER) from exc
    except (json.JSONDecodeError, RecursionError) as exc:
        raise SignedPayloadError(SecurityEventReason.INVALID_JSON) from exc
    except ValueError as exc:
        # CPython applies a process-wide bounded integer-string conversion
        # limit.  Treat that implementation guard like any other invalid JSON
        # shape and never expose its size/detail in a response or event.
        raise SignedPayloadError(SecurityEventReason.INVALID_JSON) from exc
    if not isinstance(parsed, Mapping):
        raise SignedPayloadError(SecurityEventReason.JSON_ROOT_NOT_OBJECT)
    try:
        _validate_json_value(parsed)
    except _NonfiniteJsonNumberError as exc:
        raise SignedPayloadError(SecurityEventReason.NONFINITE_NUMBER) from exc
    except _InvalidUnicodeScalarError as exc:
        raise SignedPayloadError(SecurityEventReason.INVALID_UNICODE_SCALAR) from exc
    except RecursionError as exc:
        raise SignedPayloadError(SecurityEventReason.INVALID_JSON) from exc
    return cast(Mapping[str, object], parsed)


def route_event(event: str, payload: Mapping[str, object]) -> WebhookRouteDecision:
    """Route only the exact recognized event/action matrix."""

    if not isinstance(event, str) or _EVENT_NAME.fullmatch(event) is None:
        raise DomainValidationError("event was malformed")
    if not isinstance(payload, Mapping):
        raise DomainValidationError("payload must be a mapping")
    try:
        recognized = WebhookEvent(event)
    except ValueError:
        return _no_work(
            event,
            None,
            DeliveryClassification.UNSUPPORTED_AUTHENTICATED_EVENT,
        )

    if recognized is WebhookEvent.PING:
        return _actionless_no_work(event, payload)
    if recognized is WebhookEvent.GITHUB_APP_AUTHORIZATION:
        return _route_github_app_authorization(event, payload)
    if recognized is WebhookEvent.INSTALLATION:
        return _route_installation(
            event,
            payload,
            frozenset(
                {
                    "created",
                    "deleted",
                    "new_permissions_accepted",
                    "suspend",
                    "unsuspend",
                }
            ),
        )
    if recognized is WebhookEvent.INSTALLATION_REPOSITORIES:
        return _route_installation(event, payload, frozenset({"added", "removed"}))
    if recognized is WebhookEvent.PULL_REQUEST:
        return _route_pull_request(
            event,
            payload,
            frozenset(
                {
                    "opened",
                    "reopened",
                    "closed",
                    "edited",
                    "synchronize",
                    "converted_to_draft",
                    "ready_for_review",
                    "review_requested",
                    "review_request_removed",
                }
            ),
        )
    if recognized is WebhookEvent.PULL_REQUEST_REVIEW:
        return _route_pull_request(
            event,
            payload,
            frozenset({"submitted", "edited", "dismissed"}),
        )
    if recognized is WebhookEvent.CHECK_RUN:
        return _route_check(
            event,
            payload,
            actionable=frozenset({"created", "completed"}),
            ceiling=frozenset({"rerequested", "requested_action"}),
            ceiling_reason=(
                SecurityEventReason.CHECK_RUN_ACTION_EXCEEDS_PERMISSION_CEILING
            ),
        )
    if recognized is WebhookEvent.CHECK_SUITE:
        return _route_check(
            event,
            payload,
            actionable=frozenset({"completed"}),
            ceiling=frozenset({"requested", "rerequested"}),
            ceiling_reason=(
                SecurityEventReason.CHECK_SUITE_ACTION_EXCEEDS_PERMISSION_CEILING
            ),
        )
    return _route_status(event, payload)


def authorize_route(
    decision: WebhookRouteDecision,
    authorization: RepositoryAuthorizationV1 | None,
) -> WebhookRouteDecision:
    """Gate repository-read work against exact current GS-I5 authorization."""

    if not isinstance(decision, WebhookRouteDecision):
        raise DomainValidationError("decision must be a WebhookRouteDecision")
    if decision.work_type not in {
        WebhookWorkType.REFRESH_GITHUB_PULL_REQUEST,
        WebhookWorkType.REFRESH_GITHUB_REPOSITORY,
    }:
        return decision
    reported = cast(WebhookSubject, decision.reported_subject)
    repository_id = cast(int, reported.repository_id)
    installation_id = cast(int, reported.installation_id)
    if authorization is None:
        return _authorization_mismatch(
            decision,
            SecurityEventReason.AUTHORIZATION_MISSING,
            fallback_installation_id=None,
        )
    if authorization.repository_id != repository_id:
        return _authorization_mismatch(
            decision,
            SecurityEventReason.AUTHORIZATION_REPOSITORY_MISMATCH,
            fallback_installation_id=None,
        )
    if authorization.write_enabled:
        return _authorization_mismatch(
            decision,
            SecurityEventReason.AUTHORIZATION_WRITE_ENABLED,
            fallback_installation_id=None,
        )
    if authorization.installation_id != installation_id:
        return _authorization_mismatch(
            decision,
            SecurityEventReason.AUTHORIZATION_INSTALLATION_MISMATCH,
            fallback_installation_id=authorization.installation_id,
        )
    if authorization.capability is not AuthorizationCapability.AUTHORIZED_READ:
        return _authorization_mismatch(
            decision,
            SecurityEventReason.AUTHORIZATION_CAPABILITY_DENIED,
            fallback_installation_id=authorization.installation_id,
        )
    return decision


def delivery_id(provider_delivery_id: str) -> str:
    """Derive the canonical internal identity for one GitHub delivery ID."""

    _canonical_uuid(provider_delivery_id, "provider_delivery_id")
    return str(
        uuid5(
            _IDENTITY_NAMESPACE,
            f"delivery:{GITHUB_WEBHOOK_PROVIDER}:{provider_delivery_id}",
        )
    )


def work_record_id(delivery_identifier: str, work_type: WebhookWorkType) -> str:
    """Derive a stable work identity without granting broker eligibility."""

    _canonical_uuid(delivery_identifier, "delivery_identifier")
    if not isinstance(work_type, WebhookWorkType):
        raise DomainValidationError("work_type must be a WebhookWorkType")
    return str(
        uuid5(
            _IDENTITY_NAMESPACE,
            f"work:{delivery_identifier}:{work_type.value}",
        )
    )


def webhook_delivery_projection(
    *,
    delivery_identifier: str,
    event: str,
    action: str | None,
    classification: DeliveryClassification,
    reported_subject: WebhookSubject | None,
    proposed_work_type: WebhookWorkType | None,
    proposed_work_subject: WebhookSubject | None,
) -> CanonicalValue:
    """Build the only payload projection permitted at the delivery boundary."""

    _canonical_uuid(delivery_identifier, "delivery_identifier")
    if not isinstance(event, str) or _EVENT_NAME.fullmatch(event) is None:
        raise DomainValidationError("projection event was malformed")
    if action is not None and (
        not isinstance(action, str) or _ACTION_NAME.fullmatch(action) is None
    ):
        raise DomainValidationError("projection action was malformed")
    if not isinstance(classification, DeliveryClassification):
        raise DomainValidationError("projection classification was invalid")
    if (proposed_work_type is None) != (proposed_work_subject is None):
        raise DomainValidationError("projection work identity was incomplete")
    if proposed_work_type is not None:
        _validate_work_subject(
            proposed_work_type,
            cast(WebhookSubject, proposed_work_subject),
        )
    entity_kind, entity_id = _entity_identity(
        delivery_identifier,
        proposed_work_type,
        proposed_work_subject,
    )
    projection: dict[str, object] = {
        "schema_id": WEBHOOK_DELIVERY_SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "provider": GITHUB_WEBHOOK_PROVIDER,
        "event": event,
        "action": action,
        "classification": classification.value,
        "entity_kind": entity_kind,
        "entity_id": entity_id,
        "scheduled_work_type": (
            None if proposed_work_type is None else proposed_work_type.value
        ),
        "reported_repository_id": (
            None if reported_subject is None else reported_subject.repository_id
        ),
        "reported_installation_id": (
            None if reported_subject is None else reported_subject.installation_id
        ),
        "reported_pull_number": (
            None if reported_subject is None else reported_subject.pull_number
        ),
    }
    return freeze_canonical_value(projection)


def security_event_metadata(
    *,
    kind: SecurityEventKind,
    reason: SecurityEventReason,
    provider_delivery_id: str,
    event: str | None = None,
    action: str | None = None,
    reported_subject: WebhookSubject | None = None,
) -> CanonicalValue:
    """Construct whitelisted security metadata with no free-form field."""

    if not isinstance(kind, SecurityEventKind):
        raise DomainValidationError("security event kind was invalid")
    if not isinstance(reason, SecurityEventReason):
        raise DomainValidationError("security event reason was invalid")
    _canonical_uuid(provider_delivery_id, "provider_delivery_id")
    if event is not None and (
        not isinstance(event, str) or _EVENT_NAME.fullmatch(event) is None
    ):
        raise DomainValidationError("security event name was malformed")
    if action is not None and (
        not isinstance(action, str) or _ACTION_NAME.fullmatch(action) is None
    ):
        raise DomainValidationError("security action was malformed")
    _validate_kind_reason(kind, reason)
    metadata: dict[str, object] = {
        "provider": GITHUB_WEBHOOK_PROVIDER,
        "provider_delivery_id": provider_delivery_id,
        "reason": reason.value,
    }
    if event is not None:
        metadata["event"] = event
    if action is not None:
        metadata["action"] = action
    if reported_subject is not None:
        if reported_subject.repository_id is not None:
            metadata["reported_repository_id"] = reported_subject.repository_id
        if reported_subject.installation_id is not None:
            metadata["reported_installation_id"] = reported_subject.installation_id
        if reported_subject.pull_number is not None:
            metadata["reported_pull_number"] = reported_subject.pull_number
    return _validate_security_metadata(kind, metadata)


def audit_payload(
    *,
    provider_delivery_id: str,
    event: str,
    action: str,
) -> CanonicalValue:
    """Build the bounded authorization-revocation audit projection."""

    _canonical_uuid(provider_delivery_id, "provider_delivery_id")
    if event != WebhookEvent.GITHUB_APP_AUTHORIZATION.value or action != "revoked":
        raise DomainValidationError("authorization revocation audit was invalid")
    return freeze_canonical_value(
        {
            "provider": GITHUB_WEBHOOK_PROVIDER,
            "provider_delivery_id": provider_delivery_id,
            "event": event,
            "action": action,
        }
    )


def _route_github_app_authorization(
    event: str,
    payload: Mapping[str, object],
) -> WebhookRouteDecision:
    action = _required_action(event, payload)
    if isinstance(action, WebhookRouteDecision):
        return action
    if action != "revoked":
        return _no_work(event, action, DeliveryClassification.VALID_NO_WORK)
    return WebhookRouteDecision(
        event=event,
        action=action,
        disposition=RoutingDisposition.NO_WORK,
        classification=DeliveryClassification.AUTHORIZATION_REVOKED,
        audit_kind=GITHUB_APP_AUTHORIZATION_REVOKED_AUDIT_KIND,
    )


def _route_installation(
    event: str,
    payload: Mapping[str, object],
    actionable: frozenset[str],
) -> WebhookRouteDecision:
    action = _required_action(event, payload)
    if isinstance(action, WebhookRouteDecision):
        return action
    if action not in actionable:
        return _no_work(event, action, DeliveryClassification.VALID_NO_WORK)
    try:
        installation_id = _nested_positive(payload, "installation", "id")
    except _SchemaIdentityError:
        return _schema_invalid(
            event,
            action,
            SecurityEventReason.REQUIRED_IDENTITY_MISSING_OR_INVALID,
        )
    subject = WebhookSubject(installation_id=installation_id)
    return _schedule(
        event,
        action,
        DeliveryClassification.SCHEDULE_AUTHORIZATION_REFRESH,
        WebhookWorkType.REFRESH_GITHUB_AUTHORIZATION,
        subject,
    )


def _route_pull_request(
    event: str,
    payload: Mapping[str, object],
    actionable: frozenset[str],
) -> WebhookRouteDecision:
    action = _required_action(event, payload)
    if isinstance(action, WebhookRouteDecision):
        return action
    if action not in actionable:
        return _no_work(event, action, DeliveryClassification.VALID_NO_WORK)
    subject_or_decision = _repository_subject(event, action, payload, pull=True)
    if isinstance(subject_or_decision, WebhookRouteDecision):
        return subject_or_decision
    return _schedule(
        event,
        action,
        DeliveryClassification.SCHEDULE_PULL_REQUEST_REFRESH,
        WebhookWorkType.REFRESH_GITHUB_PULL_REQUEST,
        subject_or_decision,
    )


def _route_check(
    event: str,
    payload: Mapping[str, object],
    *,
    actionable: frozenset[str],
    ceiling: frozenset[str],
    ceiling_reason: SecurityEventReason,
) -> WebhookRouteDecision:
    action = _required_action(event, payload)
    if isinstance(action, WebhookRouteDecision):
        return action
    if action in ceiling:
        return WebhookRouteDecision(
            event=event,
            action=action,
            disposition=RoutingDisposition.NO_WORK,
            classification=DeliveryClassification.PERMISSION_CEILING_MISMATCH,
            security_kind=SecurityEventKind.WEBHOOK_PERMISSION_CEILING_MISMATCH,
            security_reason=ceiling_reason,
        )
    if action not in actionable:
        return _no_work(event, action, DeliveryClassification.VALID_NO_WORK)
    subject_or_decision = _repository_subject(event, action, payload, pull=False)
    if isinstance(subject_or_decision, WebhookRouteDecision):
        return subject_or_decision
    return _schedule(
        event,
        action,
        DeliveryClassification.SCHEDULE_REPOSITORY_REFRESH,
        WebhookWorkType.REFRESH_GITHUB_REPOSITORY,
        subject_or_decision,
    )


def _route_status(
    event: str,
    payload: Mapping[str, object],
) -> WebhookRouteDecision:
    action = _optional_action(event, payload)
    if isinstance(action, WebhookRouteDecision):
        return action
    if action is not None:
        return _no_work(event, action, DeliveryClassification.VALID_NO_WORK)
    subject_or_decision = _repository_subject(event, None, payload, pull=False)
    if isinstance(subject_or_decision, WebhookRouteDecision):
        return subject_or_decision
    return _schedule(
        event,
        None,
        DeliveryClassification.SCHEDULE_REPOSITORY_REFRESH,
        WebhookWorkType.REFRESH_GITHUB_REPOSITORY,
        subject_or_decision,
    )


def _actionless_no_work(
    event: str,
    payload: Mapping[str, object],
) -> WebhookRouteDecision:
    action = _optional_action(event, payload)
    if isinstance(action, WebhookRouteDecision):
        return action
    return _no_work(event, action, DeliveryClassification.VALID_NO_WORK)


def _repository_subject(
    event: str,
    action: str | None,
    payload: Mapping[str, object],
    *,
    pull: bool,
) -> WebhookSubject | WebhookRouteDecision:
    try:
        repository_id = _nested_positive(payload, "repository", "id")
        installation_id = _nested_positive(payload, "installation", "id")
        pull_number: int | None = None
        if pull:
            pull_value = payload.get("pull_request")
            if not isinstance(pull_value, Mapping):
                raise _SchemaIdentityError
            nested_number = _positive_bigint(
                pull_value.get("number"),
                "pull_request.number",
            )
            top_number = payload.get("number")
            if event == WebhookEvent.PULL_REQUEST.value:
                pull_number = _positive_bigint(top_number, "number")
            elif top_number is None:
                pull_number = nested_number
            else:
                pull_number = _positive_bigint(top_number, "number")
            if nested_number != pull_number:
                return _identity_mismatch(
                    event,
                    action,
                    SecurityEventReason.PULL_REQUEST_IDENTITY_MISMATCH,
                )
            base_value = pull_value.get("base")
            if isinstance(base_value, Mapping) and "repo" in base_value:
                base_repository = _nested_positive(base_value, "repo", "id")
                if base_repository != repository_id:
                    return _identity_mismatch(
                        event,
                        action,
                        SecurityEventReason.REPOSITORY_IDENTITY_MISMATCH,
                    )
        event_value = payload.get(event)
        if isinstance(event_value, Mapping) and "repository" in event_value:
            nested_repository = _nested_positive(event_value, "repository", "id")
            if nested_repository != repository_id:
                return _identity_mismatch(
                    event,
                    action,
                    SecurityEventReason.REPOSITORY_IDENTITY_MISMATCH,
                )
    except (DomainValidationError, _SchemaIdentityError):
        return _schema_invalid(
            event,
            action,
            SecurityEventReason.REQUIRED_IDENTITY_MISSING_OR_INVALID,
        )
    return WebhookSubject(
        repository_id=repository_id,
        installation_id=installation_id,
        pull_number=pull_number,
    )


def _required_action(
    event: str,
    payload: Mapping[str, object],
) -> str | WebhookRouteDecision:
    action = payload.get("action")
    if not isinstance(action, str) or _ACTION_NAME.fullmatch(action) is None:
        return _schema_invalid(
            event,
            None,
            SecurityEventReason.ACTION_MISSING_OR_INVALID,
        )
    return action


def _optional_action(
    event: str,
    payload: Mapping[str, object],
) -> str | WebhookRouteDecision | None:
    if "action" not in payload or payload.get("action") is None:
        return None
    action = payload.get("action")
    if not isinstance(action, str) or _ACTION_NAME.fullmatch(action) is None:
        return _schema_invalid(
            event,
            None,
            SecurityEventReason.ACTION_MISSING_OR_INVALID,
        )
    return action


def _schedule(
    event: str,
    action: str | None,
    classification: DeliveryClassification,
    work_type: WebhookWorkType,
    subject: WebhookSubject,
) -> WebhookRouteDecision:
    return WebhookRouteDecision(
        event=event,
        action=action,
        disposition=RoutingDisposition.SCHEDULE,
        classification=classification,
        reported_subject=subject,
        work_type=work_type,
        work_subject=subject,
    )


def _no_work(
    event: str,
    action: str | None,
    classification: DeliveryClassification,
) -> WebhookRouteDecision:
    return WebhookRouteDecision(
        event=event,
        action=action,
        disposition=RoutingDisposition.NO_WORK,
        classification=classification,
    )


def _schema_invalid(
    event: str,
    action: str | None,
    reason: SecurityEventReason,
) -> WebhookRouteDecision:
    return WebhookRouteDecision(
        event=event,
        action=action,
        disposition=RoutingDisposition.NO_WORK,
        classification=DeliveryClassification.SIGNED_SCHEMA_INVALID,
        security_kind=SecurityEventKind.WEBHOOK_SIGNED_SCHEMA_INVALID,
        security_reason=reason,
    )


def _identity_mismatch(
    event: str,
    action: str | None,
    reason: SecurityEventReason,
) -> WebhookRouteDecision:
    return WebhookRouteDecision(
        event=event,
        action=action,
        disposition=RoutingDisposition.NO_WORK,
        classification=DeliveryClassification.SIGNED_IDENTITY_MISMATCH,
        security_kind=SecurityEventKind.WEBHOOK_SIGNED_IDENTITY_MISMATCH,
        security_reason=reason,
    )


def _authorization_mismatch(
    decision: WebhookRouteDecision,
    reason: SecurityEventReason,
    *,
    fallback_installation_id: int | None,
) -> WebhookRouteDecision:
    work_type: WebhookWorkType | None = None
    work_subject: WebhookSubject | None = None
    disposition = RoutingDisposition.NO_WORK
    if fallback_installation_id is not None:
        work_type = WebhookWorkType.REFRESH_GITHUB_AUTHORIZATION
        work_subject = WebhookSubject(installation_id=fallback_installation_id)
        disposition = RoutingDisposition.SCHEDULE
    return WebhookRouteDecision(
        event=decision.event,
        action=decision.action,
        disposition=disposition,
        classification=DeliveryClassification.AUTHORIZATION_CONTEXT_MISMATCH,
        reported_subject=decision.reported_subject,
        work_type=work_type,
        work_subject=work_subject,
        security_kind=SecurityEventKind.WEBHOOK_AUTHORIZATION_CONTEXT_MISMATCH,
        security_reason=reason,
    )


def _entity_identity(
    delivery_identifier: str,
    work_type: WebhookWorkType | None,
    work_subject: WebhookSubject | None,
) -> tuple[str, str]:
    if work_type is None or work_subject is None:
        return "github_webhook_delivery", delivery_identifier
    if work_type is WebhookWorkType.REFRESH_GITHUB_PULL_REQUEST:
        return (
            "github_pull_request",
            f"{work_subject.repository_id}:{work_subject.pull_number}",
        )
    if work_type is WebhookWorkType.REFRESH_GITHUB_REPOSITORY:
        return "github_repository", str(work_subject.repository_id)
    return "github_authorization", str(work_subject.installation_id)


def _validate_work_subject(
    work_type: WebhookWorkType,
    subject: WebhookSubject,
) -> None:
    if work_type is WebhookWorkType.REFRESH_GITHUB_PULL_REQUEST:
        valid = (
            subject.repository_id is not None
            and subject.installation_id is not None
            and subject.pull_number is not None
        )
    elif work_type is WebhookWorkType.REFRESH_GITHUB_REPOSITORY:
        valid = (
            subject.repository_id is not None
            and subject.installation_id is not None
            and subject.pull_number is None
        )
    else:
        valid = (
            subject.repository_id is None
            and subject.installation_id is not None
            and subject.pull_number is None
        )
    if not valid:
        raise DomainValidationError("work subject did not match its work type")


def _validate_kind_reason(
    kind: SecurityEventKind,
    reason: SecurityEventReason,
) -> None:
    allowed: dict[SecurityEventKind, frozenset[SecurityEventReason]] = {
        SecurityEventKind.WEBHOOK_DELIVERY_INTEGRITY_CONFLICT: frozenset(
            {SecurityEventReason.DELIVERY_DIGEST_MISMATCH}
        ),
        SecurityEventKind.WEBHOOK_SIGNED_SCHEMA_INVALID: frozenset(
            {
                SecurityEventReason.INVALID_UTF8,
                SecurityEventReason.INVALID_JSON,
                SecurityEventReason.DUPLICATE_JSON_KEY,
                SecurityEventReason.NONFINITE_NUMBER,
                SecurityEventReason.INVALID_UNICODE_SCALAR,
                SecurityEventReason.JSON_ROOT_NOT_OBJECT,
                SecurityEventReason.ACTION_MISSING_OR_INVALID,
                SecurityEventReason.REQUIRED_IDENTITY_MISSING_OR_INVALID,
            }
        ),
        SecurityEventKind.WEBHOOK_SIGNED_IDENTITY_MISMATCH: frozenset(
            {
                SecurityEventReason.REPOSITORY_IDENTITY_MISMATCH,
                SecurityEventReason.PULL_REQUEST_IDENTITY_MISMATCH,
            }
        ),
        SecurityEventKind.WEBHOOK_AUTHORIZATION_CONTEXT_MISMATCH: frozenset(
            {
                SecurityEventReason.AUTHORIZATION_MISSING,
                SecurityEventReason.AUTHORIZATION_REPOSITORY_MISMATCH,
                SecurityEventReason.AUTHORIZATION_INSTALLATION_MISMATCH,
                SecurityEventReason.AUTHORIZATION_CAPABILITY_DENIED,
                SecurityEventReason.AUTHORIZATION_WRITE_ENABLED,
            }
        ),
        SecurityEventKind.WEBHOOK_PERMISSION_CEILING_MISMATCH: frozenset(
            {
                SecurityEventReason.CHECK_RUN_ACTION_EXCEEDS_PERMISSION_CEILING,
                SecurityEventReason.CHECK_SUITE_ACTION_EXCEEDS_PERMISSION_CEILING,
            }
        ),
    }
    if reason not in allowed[kind]:
        raise DomainValidationError("security event kind and reason did not match")


def _validate_security_metadata(
    kind: SecurityEventKind,
    metadata: object,
) -> CanonicalValue:
    frozen = freeze_canonical_value(metadata)
    if not isinstance(frozen, Mapping):
        raise DomainValidationError("security metadata must be a mapping")
    allowed_keys = {
        "provider",
        "provider_delivery_id",
        "event",
        "action",
        "reason",
        "reported_repository_id",
        "reported_installation_id",
        "reported_pull_number",
    }
    if not set(frozen) <= allowed_keys or len(frozen) > len(allowed_keys):
        raise DomainValidationError("security metadata fields were not bounded")
    if frozen.get("provider") != GITHUB_WEBHOOK_PROVIDER:
        raise DomainValidationError("security metadata provider was invalid")
    delivery = frozen.get("provider_delivery_id")
    _canonical_uuid(delivery, "provider_delivery_id")
    reason_value = frozen.get("reason")
    if not isinstance(reason_value, str):
        raise DomainValidationError("security metadata reason was invalid")
    try:
        reason = SecurityEventReason(reason_value)
    except (TypeError, ValueError) as exc:
        raise DomainValidationError("security metadata reason was invalid") from exc
    _validate_kind_reason(kind, reason)
    event = frozen.get("event")
    if event is not None and (
        not isinstance(event, str) or _EVENT_NAME.fullmatch(event) is None
    ):
        raise DomainValidationError("security metadata event was invalid")
    action = frozen.get("action")
    if action is not None and (
        not isinstance(action, str) or _ACTION_NAME.fullmatch(action) is None
    ):
        raise DomainValidationError("security metadata action was invalid")
    for key in (
        "reported_repository_id",
        "reported_installation_id",
        "reported_pull_number",
    ):
        if key in frozen:
            _positive_bigint(frozen[key], key)
    return frozen


def _unique_object(pairs: list[tuple[str, object]]) -> Mapping[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKeyError
        result[key] = value
    return MappingProxyType(result)


def _reject_nonfinite_constant(_: str) -> NoReturn:
    raise _NonfiniteJsonNumberError


def _validate_json_value(value: object) -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise _InvalidUnicodeScalarError
        return
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _NonfiniteJsonNumberError
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            _validate_json_value(key)
            _validate_json_value(item)
        return
    # ``json.loads`` can produce only the cases above or a list.  Keeping the
    # final case branch-free makes that closed parser output inventory explicit.
    for item in cast(list[object], value):
        _validate_json_value(item)


def _nested_positive(
    value: Mapping[str, object],
    outer: str,
    inner: str,
) -> int:
    nested = value.get(outer)
    if not isinstance(nested, Mapping):
        raise _SchemaIdentityError
    try:
        return _positive_bigint(nested.get(inner), f"{outer}.{inner}")
    except DomainValidationError as exc:
        raise _SchemaIdentityError from exc


def _positive_bigint(value: object, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > MAX_SAFE_INTEGER
    ):
        raise DomainValidationError(f"{field} must be a positive JCS-safe integer")
    return value


def _canonical_uuid(value: object, field: str) -> UUID:
    if not isinstance(value, str):
        raise DomainValidationError(f"{field} must be a canonical UUID")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise DomainValidationError(f"{field} must be a canonical UUID") from exc
    if str(parsed) != value:
        raise DomainValidationError(f"{field} must be a canonical UUID")
    return parsed


def _utc(value: datetime, field: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise DomainValidationError(f"{field} must use UTC")
    return value.astimezone(UTC)


class _DuplicateJsonKeyError(ValueError):
    pass


class _NonfiniteJsonNumberError(ValueError):
    pass


class _InvalidUnicodeScalarError(ValueError):
    pass


class _SchemaIdentityError(ValueError):
    pass
