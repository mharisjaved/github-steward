"""Focused adversarial tests for the pure GS-I6 webhook contracts."""

from __future__ import annotations

import dataclasses
import json
import operator
from collections.abc import Mapping, MutableMapping
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

import pytest

from github_steward.adapters.canonicalization.rfc8785 import envelope_payload
from github_steward.domain.canonical import MAX_SAFE_INTEGER, CanonicalValue
from github_steward.domain.errors import DomainValidationError
from github_steward.domain.github_authorization import (
    GitHubPermissionLevel,
    InstallationAccount,
    InstallationAccountType,
    InstallationObservationV1,
    RepositoryAuthorizationV1,
    RepositoryPermissions,
    RepositoryRoute,
    RepositorySelection,
)
from github_steward.domain.webhook import (
    GITHUB_APP_AUTHORIZATION_REVOKED_AUDIT_KIND,
    RAW_SHA256_FORMAT,
    DeliveryClassification,
    RawBodyDigest,
    RoutingDisposition,
    SecurityEventKind,
    SecurityEventReason,
    SecurityEventV1,
    SignedPayloadError,
    WebhookDeliveryV1,
    WebhookHeaders,
    WebhookReplayOutcome,
    WebhookReplayResult,
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

NOW = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
DELIVERY = "11111111-1111-4111-8111-11111111111a"
EVENT_ID = "22222222-2222-4222-8222-222222222222"
REPOSITORY_ID = 123456
INSTALLATION_ID = 654321
PULL_NUMBER = 17


def _repository_payload(
    *,
    action: str | None = None,
    pull: bool = False,
    event: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "repository": {"id": REPOSITORY_ID},
        "installation": {"id": INSTALLATION_ID},
    }
    if action is not None:
        payload["action"] = action
    if pull:
        payload["number"] = PULL_NUMBER
        payload["pull_request"] = {"number": PULL_NUMBER}
    if event is not None:
        payload[event] = {}
    return payload


def _authorization(
    *,
    repository_id: int = REPOSITORY_ID,
    installation_id: int = INSTALLATION_ID,
    authorized: bool = True,
) -> RepositoryAuthorizationV1:
    level = GitHubPermissionLevel.READ if authorized else GitHubPermissionLevel.NONE
    permissions = RepositoryPermissions(level, level, level, level)
    observation = InstallationObservationV1(
        observation_id="33333333-3333-4333-8333-333333333333",
        installation_id=installation_id,
        app_id=99,
        account=InstallationAccount(44, InstallationAccountType.ORGANIZATION),
        repository_selection=RepositorySelection.SELECTED,
        permissions=permissions,
        suspended=False,
        suspended_at=None,
        observed_at=NOW,
        source_digest="a" * 64,
    )
    return RepositoryAuthorizationV1.derive(
        repository_id=repository_id,
        authorization_version=1,
        installation=observation,
        installation_id=installation_id,
        route=RepositoryRoute("owner", "repository"),
        installation_account_id=44,
        repository_selected=True,
        route_verified=True,
        granted_permissions=permissions,
        updated_at=NOW,
    )


def test_exact_raw_body_digest_is_distinct_from_jcs() -> None:
    body = b'{"value": 1}'
    digest = payload_digest(body)

    assert digest.value == (
        "e1d70a18cc129fcc812ebbe309bc5197df6ffa2228c77a4a7b98653ec5605354"
    )
    assert digest.format == RAW_SHA256_FORMAT
    assert payload_digest(b'{"value":1}') != digest
    with pytest.raises(TypeError, match="must be bytes"):
        payload_digest(cast(bytes, bytearray(body)))
    with pytest.raises(DomainValidationError, match="lowercase SHA-256"):
        RawBodyDigest("A" * 64)
    with pytest.raises(DomainValidationError, match="format"):
        RawBodyDigest("a" * 64, "jcs-sha256/v1")


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        (b"\xff", SecurityEventReason.INVALID_UTF8),
        (b'{"outer":{"id":1,"id":2}}', SecurityEventReason.DUPLICATE_JSON_KEY),
        (b'{"value":NaN}', SecurityEventReason.NONFINITE_NUMBER),
        (b'{"value":1e9999}', SecurityEventReason.NONFINITE_NUMBER),
        (b'{"value":"\\ud800"}', SecurityEventReason.INVALID_UNICODE_SCALAR),
        (b'{"broken":', SecurityEventReason.INVALID_JSON),
        (b"[]", SecurityEventReason.JSON_ROOT_NOT_OBJECT),
    ],
)
def test_strict_signed_json_rejects_unsafe_forms(
    body: bytes,
    reason: SecurityEventReason,
) -> None:
    with pytest.raises(SignedPayloadError) as captured:
        parse_payload(body)
    assert captured.value.reason is reason
    assert str(captured.value) == "authenticated webhook payload was invalid"


def test_strict_json_accepts_nested_unique_object_and_finite_number() -> None:
    parsed = parse_payload(b'{"outer":{"id":1},"ratio":1.5,"items":[true,null]}')

    assert parsed["outer"] == {"id": 1}
    assert parsed["ratio"] == 1.5
    with pytest.raises(TypeError):
        operator.setitem(cast(MutableMapping[str, object], parsed), "new", 2)


def test_deep_nesting_and_cpython_huge_integer_guard_are_safely_invalid() -> None:
    deeply_nested = b'{"value":' * 1_100 + b"0" + b"}" * 1_100
    huge_integer = b'{"value":' + b"9" * 5_000 + b"}"

    for body in (deeply_nested, huge_integer):
        with pytest.raises(SignedPayloadError) as captured:
            parse_payload(body)
        assert captured.value.reason is SecurityEventReason.INVALID_JSON


def test_post_decode_recursion_guard_is_safely_classified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parsed: object = 0
    for _ in range(1_100):
        parsed = {"value": parsed}

    def deeply_nested_decode(*args: object, **kwargs: object) -> object:
        del args, kwargs
        return parsed

    monkeypatch.setattr(json, "loads", deeply_nested_decode)
    with pytest.raises(SignedPayloadError) as captured:
        parse_payload(b"{}")
    assert captured.value.reason is SecurityEventReason.INVALID_JSON


def test_authenticated_headers_require_exact_bounded_identity() -> None:
    assert WebhookHeaders(DELIVERY, "pull_request").provider_delivery_id == DELIVERY
    with pytest.raises(DomainValidationError, match="canonical UUID"):
        WebhookHeaders(DELIVERY.upper(), "pull_request")
    with pytest.raises(DomainValidationError, match="event header"):
        WebhookHeaders(DELIVERY, "Pull Request")
    with pytest.raises(DomainValidationError, match="event header"):
        WebhookHeaders(DELIVERY, "a" * 65)


@pytest.mark.parametrize(
    "action",
    [
        "opened",
        "reopened",
        "closed",
        "edited",
        "synchronize",
        "converted_to_draft",
        "ready_for_review",
        "review_requested",
        "review_request_removed",
    ],
)
def test_pull_request_readiness_actions_route_one_pr_refresh(action: str) -> None:
    decision = route_event(
        "pull_request",
        _repository_payload(action=action, pull=True),
    )

    assert decision.disposition is RoutingDisposition.SCHEDULE
    assert decision.work_type is WebhookWorkType.REFRESH_GITHUB_PULL_REQUEST
    assert decision.work_subject == WebhookSubject(
        REPOSITORY_ID,
        INSTALLATION_ID,
        PULL_NUMBER,
    )


@pytest.mark.parametrize("action", ["submitted", "edited", "dismissed"])
def test_pull_request_review_uses_nested_number_without_top_level_number(
    action: str,
) -> None:
    payload = _repository_payload(action=action)
    payload["pull_request"] = {"number": PULL_NUMBER}

    decision = route_event("pull_request_review", payload)

    assert decision.work_type is WebhookWorkType.REFRESH_GITHUB_PULL_REQUEST
    assert decision.work_subject == WebhookSubject(
        REPOSITORY_ID,
        INSTALLATION_ID,
        PULL_NUMBER,
    )


@pytest.mark.parametrize(
    ("event", "action", "work", "security"),
    [
        ("check_run", "created", True, False),
        ("check_run", "completed", True, False),
        ("check_run", "rerequested", False, True),
        ("check_run", "requested_action", False, True),
        ("check_run", "future_action", False, False),
        ("check_suite", "completed", True, False),
        ("check_suite", "requested", False, True),
        ("check_suite", "rerequested", False, True),
        ("check_suite", "future_action", False, False),
    ],
)
def test_exact_checks_matrix(
    event: str,
    action: str,
    work: bool,
    security: bool,
) -> None:
    decision = route_event(event, _repository_payload(action=action))

    assert (decision.work_type is not None) is work
    if work:
        assert decision.work_type is WebhookWorkType.REFRESH_GITHUB_REPOSITORY
    assert (decision.security_kind is not None) is security
    if security:
        assert (
            decision.security_kind
            is SecurityEventKind.WEBHOOK_PERMISSION_CEILING_MISMATCH
        )
        assert decision.classification is (
            DeliveryClassification.PERMISSION_CEILING_MISMATCH
        )


def test_status_routes_one_repository_refresh_and_action_does_not_gain_authority() -> (
    None
):
    routed = route_event("status", _repository_payload())
    unknown_action = route_event(
        "status",
        _repository_payload(action="unexpected"),
    )

    assert routed.work_type is WebhookWorkType.REFRESH_GITHUB_REPOSITORY
    assert unknown_action.disposition is RoutingDisposition.NO_WORK


@pytest.mark.parametrize(
    ("event", "actions"),
    [
        (
            "installation",
            [
                "created",
                "deleted",
                "new_permissions_accepted",
                "suspend",
                "unsuspend",
            ],
        ),
        ("installation_repositories", ["added", "removed"]),
    ],
)
def test_installation_signals_schedule_only_authorization_refresh(
    event: str,
    actions: list[str],
) -> None:
    for action in actions:
        decision = route_event(
            event,
            {"action": action, "installation": {"id": INSTALLATION_ID}},
        )
        assert decision.work_type is (WebhookWorkType.REFRESH_GITHUB_AUTHORIZATION)
        assert decision.work_subject == WebhookSubject(installation_id=INSTALLATION_ID)
    assert (
        route_event(
            event,
            {"action": "future_action", "installation": {"id": INSTALLATION_ID}},
        ).disposition
        is RoutingDisposition.NO_WORK
    )


def test_control_and_unsupported_signals_create_no_repository_work() -> None:
    revoked = route_event(
        "github_app_authorization",
        {"action": "revoked"},
    )
    ping = route_event("ping", {})
    excluded = route_event("issue_comment", {"action": "created"})

    assert revoked.work_type is None
    assert revoked.audit_kind == GITHUB_APP_AUTHORIZATION_REVOKED_AUDIT_KIND
    assert revoked.classification is DeliveryClassification.AUTHORIZATION_REVOKED
    assert ping.classification is DeliveryClassification.VALID_NO_WORK
    assert excluded.classification is (
        DeliveryClassification.UNSUPPORTED_AUTHENTICATED_EVENT
    )


def test_missing_action_or_identity_is_signed_schema_invalid() -> None:
    missing_action = route_event("check_run", _repository_payload())
    missing_installation = route_event(
        "check_run",
        {"action": "created", "repository": {"id": REPOSITORY_ID}},
    )
    malformed_action = route_event(
        "pull_request",
        {**_repository_payload(pull=True), "action": 4},
    )

    for decision in (missing_action, missing_installation, malformed_action):
        assert decision.security_kind is (
            SecurityEventKind.WEBHOOK_SIGNED_SCHEMA_INVALID
        )
        assert decision.work_type is None


def test_conflicting_signed_numeric_identities_are_rejected() -> None:
    pull = _repository_payload(action="opened", pull=True)
    cast(dict[str, object], pull["pull_request"])["number"] = PULL_NUMBER + 1
    nested = _repository_payload(action="created")
    nested["check_run"] = {"repository": {"id": REPOSITORY_ID + 1}}
    base = _repository_payload(action="opened", pull=True)
    cast(dict[str, object], base["pull_request"])["base"] = {
        "repo": {"id": REPOSITORY_ID + 1}
    }

    for event, payload in (
        ("pull_request", pull),
        ("check_run", nested),
        ("pull_request", base),
    ):
        decision = route_event(event, payload)
        assert decision.security_kind is (
            SecurityEventKind.WEBHOOK_SIGNED_IDENTITY_MISMATCH
        )
        assert decision.work_type is None


def test_repository_gate_allows_only_exact_authorized_read_context() -> None:
    routed = route_event(
        "pull_request",
        _repository_payload(action="opened", pull=True),
    )

    assert authorize_route(routed, _authorization()) is routed

    missing = authorize_route(routed, None)
    assert missing.work_type is None
    assert missing.security_reason is SecurityEventReason.AUTHORIZATION_MISSING

    wrong_repo = authorize_route(
        routed,
        _authorization(repository_id=REPOSITORY_ID + 1),
    )
    assert wrong_repo.work_type is None
    assert wrong_repo.security_reason is (
        SecurityEventReason.AUTHORIZATION_REPOSITORY_MISMATCH
    )

    wrong_installation = authorize_route(
        routed,
        _authorization(installation_id=INSTALLATION_ID + 1),
    )
    assert wrong_installation.work_type is (
        WebhookWorkType.REFRESH_GITHUB_AUTHORIZATION
    )
    assert wrong_installation.work_subject == WebhookSubject(
        installation_id=INSTALLATION_ID + 1
    )
    assert wrong_installation.security_reason is (
        SecurityEventReason.AUTHORIZATION_INSTALLATION_MISMATCH
    )

    denied = authorize_route(routed, _authorization(authorized=False))
    assert denied.work_type is WebhookWorkType.REFRESH_GITHUB_AUTHORIZATION
    assert denied.security_reason is (
        SecurityEventReason.AUTHORIZATION_CAPABILITY_DENIED
    )


def test_authorization_gate_never_changes_non_repository_work() -> None:
    decision = route_event(
        "installation",
        {"action": "created", "installation": {"id": INSTALLATION_ID}},
    )
    assert authorize_route(decision, None) is decision


def test_security_metadata_is_typed_bounded_canonical_and_secret_safe() -> None:
    metadata = security_event_metadata(
        kind=SecurityEventKind.WEBHOOK_AUTHORIZATION_CONTEXT_MISMATCH,
        reason=SecurityEventReason.AUTHORIZATION_INSTALLATION_MISMATCH,
        provider_delivery_id=DELIVERY,
        event="pull_request",
        action="opened",
        reported_subject=WebhookSubject(
            REPOSITORY_ID,
            INSTALLATION_ID,
            PULL_NUMBER,
        ),
    )
    envelope = envelope_payload(metadata)
    event = SecurityEventV1(
        event_id=EVENT_ID,
        delivery_id=delivery_id(DELIVERY),
        kind=SecurityEventKind.WEBHOOK_AUTHORIZATION_CONTEXT_MISMATCH,
        occurred_at=NOW,
        metadata=envelope.payload,
        metadata_digest=envelope.digest,
    )

    assert event.metadata == metadata
    event_metadata = cast(Mapping[str, object], event.metadata)
    assert "signature" not in event_metadata
    assert "body" not in event_metadata
    with pytest.raises(TypeError):
        operator.setitem(
            cast(MutableMapping[str, object], event.metadata),
            "detail",
            "unsafe",
        )
    unsafe = dict(cast(Mapping[str, object], metadata))
    unsafe["detail"] = "free-form"
    unsafe_envelope = envelope_payload(unsafe)
    with pytest.raises(DomainValidationError, match="bounded"):
        SecurityEventV1(
            EVENT_ID,
            delivery_id(DELIVERY),
            SecurityEventKind.WEBHOOK_AUTHORIZATION_CONTEXT_MISMATCH,
            NOW,
            unsafe_envelope.payload,
            unsafe_envelope.digest,
        )


def test_security_kind_and_reason_must_match() -> None:
    with pytest.raises(DomainValidationError, match="did not match"):
        security_event_metadata(
            kind=SecurityEventKind.WEBHOOK_DELIVERY_INTEGRITY_CONFLICT,
            reason=SecurityEventReason.INVALID_JSON,
            provider_delivery_id=DELIVERY,
        )


def test_delivery_projection_contains_only_typed_scheduling_metadata() -> None:
    identifier = delivery_id(DELIVERY)
    subject = WebhookSubject(REPOSITORY_ID, INSTALLATION_ID, PULL_NUMBER)
    projection = webhook_delivery_projection(
        delivery_identifier=identifier,
        event="pull_request",
        action="opened",
        classification=DeliveryClassification.SCHEDULE_PULL_REQUEST_REFRESH,
        reported_subject=subject,
        proposed_work_type=WebhookWorkType.REFRESH_GITHUB_PULL_REQUEST,
        proposed_work_subject=subject,
    )
    envelope = envelope_payload(projection)
    record = WebhookDeliveryV1(
        delivery_id=identifier,
        provider_delivery_id=DELIVERY,
        payload_digest=payload_digest(b"not persisted"),
        event="pull_request",
        action="opened",
        classification=DeliveryClassification.SCHEDULE_PULL_REQUEST_REFRESH,
        reported_subject=subject,
        proposed_work_type=WebhookWorkType.REFRESH_GITHUB_PULL_REQUEST,
        proposed_work_subject=subject,
        received_at=NOW,
        sanitized_payload=envelope.payload,
        sanitized_payload_digest=envelope.digest,
    )

    sanitized = cast(Mapping[str, object], record.sanitized_payload)
    assert sanitized["entity_kind"] == "github_pull_request"
    assert sanitized["entity_id"] == (f"{REPOSITORY_ID}:{PULL_NUMBER}")
    assert "not persisted" not in repr(record.sanitized_payload)
    bad = dict(cast(Mapping[str, object], projection))
    bad["raw_body"] = "not allowed"
    with pytest.raises(DomainValidationError, match="typed projection"):
        dataclasses.replace(record, sanitized_payload=cast(CanonicalValue, bad))


def test_deterministic_delivery_and_work_identities_are_canonical() -> None:
    identifier = delivery_id(DELIVERY)
    work = work_record_id(
        identifier,
        WebhookWorkType.REFRESH_GITHUB_PULL_REQUEST,
    )

    assert delivery_id(DELIVERY) == identifier
    assert (
        work_record_id(
            identifier,
            WebhookWorkType.REFRESH_GITHUB_PULL_REQUEST,
        )
        == work
    )
    assert str(UUID(identifier)) == identifier
    assert str(UUID(work)) == work
    assert work != work_record_id(
        identifier,
        WebhookWorkType.REFRESH_GITHUB_REPOSITORY,
    )


def test_work_and_replay_records_enforce_typed_identities() -> None:
    identifier = delivery_id(DELIVERY)
    subject = WebhookSubject(REPOSITORY_ID, INSTALLATION_ID, PULL_NUMBER)
    work = WebhookWorkV1(
        work_record_id(
            identifier,
            WebhookWorkType.REFRESH_GITHUB_PULL_REQUEST,
        ),
        identifier,
        WebhookWorkType.REFRESH_GITHUB_PULL_REQUEST,
        subject,
        NOW,
    )
    replay = WebhookReplayResult(
        WebhookReplayOutcome.SAME_DIGEST,
        identifier,
        work.work_record_id,
    )

    assert replay.work_record_id == work.work_record_id
    with pytest.raises(DomainValidationError, match="did not match"):
        WebhookWorkV1(
            work.work_record_id,
            identifier,
            WebhookWorkType.REFRESH_GITHUB_REPOSITORY,
            subject,
            NOW,
        )


def test_revocation_audit_payload_is_exactly_bounded() -> None:
    payload = audit_payload(
        provider_delivery_id=DELIVERY,
        event="github_app_authorization",
        action="revoked",
    )
    assert payload == {
        "provider": "github",
        "provider_delivery_id": DELIVERY,
        "event": "github_app_authorization",
        "action": "revoked",
    }
    with pytest.raises(DomainValidationError, match="revocation"):
        audit_payload(
            provider_delivery_id=DELIVERY,
            event="github_app_authorization",
            action="created",
        )


def _valid_delivery_record() -> WebhookDeliveryV1:
    identifier = delivery_id(DELIVERY)
    subject = WebhookSubject(REPOSITORY_ID, INSTALLATION_ID, PULL_NUMBER)
    projection = webhook_delivery_projection(
        delivery_identifier=identifier,
        event="pull_request",
        action="opened",
        classification=DeliveryClassification.SCHEDULE_PULL_REQUEST_REFRESH,
        reported_subject=subject,
        proposed_work_type=WebhookWorkType.REFRESH_GITHUB_PULL_REQUEST,
        proposed_work_subject=subject,
    )
    envelope = envelope_payload(projection)
    return WebhookDeliveryV1(
        delivery_id=identifier,
        provider_delivery_id=DELIVERY,
        payload_digest=payload_digest(b"{}"),
        event="pull_request",
        action="opened",
        classification=DeliveryClassification.SCHEDULE_PULL_REQUEST_REFRESH,
        reported_subject=subject,
        proposed_work_type=WebhookWorkType.REFRESH_GITHUB_PULL_REQUEST,
        proposed_work_subject=subject,
        received_at=NOW,
        sanitized_payload=envelope.payload,
        sanitized_payload_digest=envelope.digest,
    )


def _valid_security_event() -> SecurityEventV1:
    metadata = security_event_metadata(
        kind=SecurityEventKind.WEBHOOK_SIGNED_SCHEMA_INVALID,
        reason=SecurityEventReason.INVALID_JSON,
        provider_delivery_id=DELIVERY,
        event="pull_request",
    )
    envelope = envelope_payload(metadata)
    return SecurityEventV1(
        event_id=EVENT_ID,
        delivery_id=delivery_id(DELIVERY),
        kind=SecurityEventKind.WEBHOOK_SIGNED_SCHEMA_INVALID,
        occurred_at=NOW,
        metadata=envelope.payload,
        metadata_digest=envelope.digest,
    )


def test_subject_validation_covers_empty_partial_and_canonical_bounds() -> None:
    with pytest.raises(DomainValidationError, match="contain an identity"):
        WebhookSubject()
    with pytest.raises(DomainValidationError, match="requires"):
        WebhookSubject(pull_number=1)
    assert WebhookSubject(repository_id=MAX_SAFE_INTEGER).repository_id == (
        MAX_SAFE_INTEGER
    )
    for invalid in (True, "1", 0, MAX_SAFE_INTEGER + 1, 1 << 63):
        with pytest.raises(DomainValidationError, match="positive JCS-safe integer"):
            WebhookSubject(repository_id=cast(int, invalid))


def test_route_rejects_identity_beyond_exact_jcs_range_as_signed_schema() -> None:
    payload = _repository_payload(action="created")
    payload["repository"] = {"id": MAX_SAFE_INTEGER + 1}

    decision = route_event("check_run", payload)

    assert decision.work_type is None
    assert decision.classification is DeliveryClassification.SIGNED_SCHEMA_INVALID
    assert decision.security_reason is (
        SecurityEventReason.REQUIRED_IDENTITY_MISSING_OR_INVALID
    )


def test_route_decision_rejects_incoherent_defensive_construction() -> None:
    valid = route_event("ping", {})
    invalid_changes: list[dict[str, object]] = [
        {"event": "Bad"},
        {"action": 1},
        {"disposition": "NO_WORK"},
        {"classification": "VALID_NO_WORK"},
        {"disposition": RoutingDisposition.SCHEDULE},
        {"work_type": WebhookWorkType.REFRESH_GITHUB_AUTHORIZATION},
        {
            "disposition": RoutingDisposition.SCHEDULE,
            "work_type": WebhookWorkType.REFRESH_GITHUB_REPOSITORY,
            "work_subject": WebhookSubject(REPOSITORY_ID, INSTALLATION_ID),
        },
        {"security_kind": SecurityEventKind.WEBHOOK_SIGNED_SCHEMA_INVALID},
        {"audit_kind": "unknown.audit"},
        {"audit_kind": GITHUB_APP_AUTHORIZATION_REVOKED_AUDIT_KIND},
    ]
    for changes in invalid_changes:
        with pytest.raises(DomainValidationError):
            dataclasses.replace(valid, **changes)  # type: ignore[arg-type]


def test_delivery_record_rejects_every_untyped_or_unbound_field() -> None:
    valid = _valid_delivery_record()
    invalid_changes: list[dict[str, object]] = [
        {"provider": "gitlab"},
        {"payload_digest": "a" * 64},
        {"event": "Bad"},
        {"action": 1},
        {"classification": "SCHEDULE_PULL_REQUEST_REFRESH"},
        {"proposed_work_subject": None},
        {"sanitized_payload_digest": "a" * 64},
        {"payload_schema_id": "wrong"},
        {"payload_schema_version": 2},
        {"received_at": NOW.replace(tzinfo=None)},
        {"delivery_id": "not-a-uuid"},
    ]
    for changes in invalid_changes:
        with pytest.raises(DomainValidationError):
            dataclasses.replace(valid, **changes)  # type: ignore[arg-type]


def test_work_and_replay_records_reject_untyped_fields_and_time() -> None:
    valid = _valid_delivery_record()
    subject = cast(WebhookSubject, valid.proposed_work_subject)
    work = WebhookWorkV1(
        work_record_id(
            valid.delivery_id,
            WebhookWorkType.REFRESH_GITHUB_PULL_REQUEST,
        ),
        valid.delivery_id,
        WebhookWorkType.REFRESH_GITHUB_PULL_REQUEST,
        subject,
        NOW,
    )
    for changes in (
        {"work_type": "REFRESH_GITHUB_PULL_REQUEST"},
        {"subject": "not-a-subject"},
        {"available_at": NOW.replace(tzinfo=None)},
        {"work_record_id": 4},
    ):
        with pytest.raises(DomainValidationError):
            dataclasses.replace(work, **changes)

    replay = WebhookReplayResult(WebhookReplayOutcome.CREATED, valid.delivery_id)
    with pytest.raises(DomainValidationError, match="outcome"):
        dataclasses.replace(
            replay,
            outcome=cast(WebhookReplayOutcome, "CREATED"),
        )
    with pytest.raises(DomainValidationError, match="canonical UUID"):
        dataclasses.replace(replay, work_record_id="not-a-uuid")


def test_public_helpers_reject_wrong_shapes_without_leaking_values() -> None:
    with pytest.raises(TypeError, match="must be bytes"):
        parse_payload(cast(bytes, "{}"))
    with pytest.raises(DomainValidationError, match="event was malformed"):
        route_event("Bad", {})
    with pytest.raises(DomainValidationError, match="payload must be a mapping"):
        route_event("ping", cast(Mapping[str, object], []))
    with pytest.raises(DomainValidationError, match="decision"):
        authorize_route(cast(object, "invalid"), None)  # type: ignore[arg-type]
    with pytest.raises(DomainValidationError, match="work_type"):
        work_record_id(
            delivery_id(DELIVERY),
            cast(WebhookWorkType, "REFRESH_GITHUB_REPOSITORY"),
        )
    with pytest.raises(DomainValidationError, match="canonical UUID"):
        delivery_id(cast(str, 4))


def test_authorization_write_flag_fails_closed_without_refresh_work() -> None:
    routed = route_event(
        "pull_request",
        _repository_payload(action="opened", pull=True),
    )
    corrupted = _authorization()
    object.__setattr__(corrupted, "write_enabled", True)

    denied = authorize_route(routed, corrupted)

    assert denied.work_type is None
    assert denied.security_reason is SecurityEventReason.AUTHORIZATION_WRITE_ENABLED


def test_projection_validation_and_all_entity_shapes() -> None:
    identifier = delivery_id(DELIVERY)
    repository_subject = WebhookSubject(REPOSITORY_ID, INSTALLATION_ID)
    repository = webhook_delivery_projection(
        delivery_identifier=identifier,
        event="status",
        action=None,
        classification=DeliveryClassification.SCHEDULE_REPOSITORY_REFRESH,
        reported_subject=repository_subject,
        proposed_work_type=WebhookWorkType.REFRESH_GITHUB_REPOSITORY,
        proposed_work_subject=repository_subject,
    )
    authorization_subject = WebhookSubject(installation_id=INSTALLATION_ID)
    authorization = webhook_delivery_projection(
        delivery_identifier=identifier,
        event="installation",
        action="created",
        classification=DeliveryClassification.SCHEDULE_AUTHORIZATION_REFRESH,
        reported_subject=authorization_subject,
        proposed_work_type=WebhookWorkType.REFRESH_GITHUB_AUTHORIZATION,
        proposed_work_subject=authorization_subject,
    )
    no_work = webhook_delivery_projection(
        delivery_identifier=identifier,
        event="ping",
        action=None,
        classification=DeliveryClassification.VALID_NO_WORK,
        reported_subject=None,
        proposed_work_type=None,
        proposed_work_subject=None,
    )

    assert cast(Mapping[str, object], repository)["entity_kind"] == (
        "github_repository"
    )
    assert cast(Mapping[str, object], authorization)["entity_kind"] == (
        "github_authorization"
    )
    assert cast(Mapping[str, object], no_work)["entity_kind"] == (
        "github_webhook_delivery"
    )

    valid_arguments: dict[str, object] = {
        "delivery_identifier": identifier,
        "event": "ping",
        "action": None,
        "classification": DeliveryClassification.VALID_NO_WORK,
        "reported_subject": None,
        "proposed_work_type": None,
        "proposed_work_subject": None,
    }
    for changes in (
        {"event": "Bad"},
        {"action": 1},
        {"classification": "VALID_NO_WORK"},
        {"proposed_work_type": WebhookWorkType.REFRESH_GITHUB_AUTHORIZATION},
    ):
        arguments = {**valid_arguments, **changes}
        with pytest.raises(DomainValidationError):
            webhook_delivery_projection(**arguments)  # type: ignore[arg-type]


def test_additional_action_and_identity_edges_fail_closed() -> None:
    missing_control_action = route_event("github_app_authorization", {})
    unknown_control_action = route_event(
        "github_app_authorization",
        {"action": "future_action"},
    )
    missing_installation = route_event(
        "installation",
        {"action": "created"},
    )
    missing_installation_action = route_event("installation", {})
    unknown_pull = route_event(
        "pull_request",
        _repository_payload(action="future_action", pull=True),
    )
    malformed_status_action = route_event(
        "status",
        {**_repository_payload(), "action": 4},
    )
    malformed_ping_action = route_event("ping", {"action": 4})
    missing_pull_object = route_event(
        "pull_request",
        {
            "action": "opened",
            "number": PULL_NUMBER,
            "repository": {"id": REPOSITORY_ID},
            "installation": {"id": INSTALLATION_ID},
        },
    )
    review_with_matching_top = _repository_payload(action="submitted")
    review_with_matching_top["number"] = PULL_NUMBER
    review_with_matching_top["pull_request"] = {
        "number": PULL_NUMBER,
        "base": {"repo": {"id": REPOSITORY_ID}},
    }
    matching_review = route_event("pull_request_review", review_with_matching_top)
    check_with_matching_nested_repo = _repository_payload(action="created")
    check_with_matching_nested_repo["check_run"] = {"repository": {"id": REPOSITORY_ID}}
    matching_check = route_event("check_run", check_with_matching_nested_repo)
    invalid_status_identity = route_event(
        "status",
        {"repository": {"id": 0}, "installation": {"id": INSTALLATION_ID}},
    )
    assert parse_payload(b'{"empty":[]}')["empty"] == []

    assert missing_control_action.security_kind is (
        SecurityEventKind.WEBHOOK_SIGNED_SCHEMA_INVALID
    )
    assert unknown_control_action.classification is (
        DeliveryClassification.VALID_NO_WORK
    )
    assert missing_installation.security_kind is (
        SecurityEventKind.WEBHOOK_SIGNED_SCHEMA_INVALID
    )
    assert missing_installation_action.security_kind is (
        SecurityEventKind.WEBHOOK_SIGNED_SCHEMA_INVALID
    )
    assert unknown_pull.work_type is None
    assert malformed_status_action.security_kind is (
        SecurityEventKind.WEBHOOK_SIGNED_SCHEMA_INVALID
    )
    assert malformed_ping_action.security_kind is (
        SecurityEventKind.WEBHOOK_SIGNED_SCHEMA_INVALID
    )
    assert missing_pull_object.security_kind is (
        SecurityEventKind.WEBHOOK_SIGNED_SCHEMA_INVALID
    )
    assert matching_review.work_type is (WebhookWorkType.REFRESH_GITHUB_PULL_REQUEST)
    assert matching_check.work_type is WebhookWorkType.REFRESH_GITHUB_REPOSITORY
    assert invalid_status_identity.security_kind is (
        SecurityEventKind.WEBHOOK_SIGNED_SCHEMA_INVALID
    )


def test_security_factory_and_record_reject_every_unbounded_shape() -> None:
    for arguments in (
        {
            "kind": "WEBHOOK_SIGNED_SCHEMA_INVALID",
            "reason": SecurityEventReason.INVALID_JSON,
        },
        {
            "kind": SecurityEventKind.WEBHOOK_SIGNED_SCHEMA_INVALID,
            "reason": "INVALID_JSON",
        },
        {
            "kind": SecurityEventKind.WEBHOOK_SIGNED_SCHEMA_INVALID,
            "reason": SecurityEventReason.INVALID_JSON,
            "event": "Bad",
        },
        {
            "kind": SecurityEventKind.WEBHOOK_SIGNED_SCHEMA_INVALID,
            "reason": SecurityEventReason.INVALID_JSON,
            "action": 4,
        },
    ):
        with pytest.raises(DomainValidationError):
            security_event_metadata(
                provider_delivery_id=DELIVERY,
                **arguments,
            )

    valid = _valid_security_event()
    for changes in (
        {"kind": "WEBHOOK_SIGNED_SCHEMA_INVALID"},
        {"metadata_digest": "a" * 64},
        {"schema_id": "wrong"},
        {"schema_version": 2},
        {"occurred_at": NOW.replace(tzinfo=None)},
    ):
        with pytest.raises(DomainValidationError):
            dataclasses.replace(valid, **changes)

    base = dict(cast(Mapping[str, object], valid.metadata))
    invalid_metadata = (
        "not-a-mapping",
        {**base, "provider": "gitlab"},
        {**base, "reason": 4},
        {**base, "reason": "NOT_A_REASON"},
        {**base, "event": "Bad"},
        {**base, "action": "Bad"},
        {**base, "reported_repository_id": 0},
    )
    for metadata in invalid_metadata:
        envelope = envelope_payload(metadata)
        with pytest.raises(DomainValidationError):
            dataclasses.replace(valid, metadata=envelope.payload)


def test_security_metadata_supports_each_bounded_subject_subset() -> None:
    repository_only = security_event_metadata(
        kind=SecurityEventKind.WEBHOOK_AUTHORIZATION_CONTEXT_MISMATCH,
        reason=SecurityEventReason.AUTHORIZATION_MISSING,
        provider_delivery_id=DELIVERY,
        event="status",
        reported_subject=WebhookSubject(repository_id=REPOSITORY_ID),
    )
    installation_only = security_event_metadata(
        kind=SecurityEventKind.WEBHOOK_AUTHORIZATION_CONTEXT_MISMATCH,
        reason=SecurityEventReason.AUTHORIZATION_INSTALLATION_MISMATCH,
        provider_delivery_id=DELIVERY,
        event="status",
        reported_subject=WebhookSubject(installation_id=INSTALLATION_ID),
    )
    assert "reported_repository_id" in cast(Mapping[str, object], repository_only)
    assert "reported_installation_id" in cast(Mapping[str, object], installation_only)
