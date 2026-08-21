"""Transactional application tests for verified GitHub webhook ingress."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from types import TracebackType
from typing import Self, cast
from uuid import UUID

import pytest

from github_steward.adapters.canonicalization.rfc8785 import envelope_payload
from github_steward.application.webhook_ingress import (
    GitHubWebhookIngressService,
    WebhookDurabilityError,
    WebhookIngressOutcome,
)
from github_steward.domain.canonical import MAX_SAFE_INTEGER
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
    DeliveryClassification,
    SecurityEventKind,
    SecurityEventV1,
    WebhookDeliveryV1,
    WebhookHeaders,
    WebhookReplayOutcome,
    WebhookReplayResult,
    WebhookWorkType,
    WebhookWorkV1,
)
from github_steward.ports.clock import Clock
from github_steward.ports.github_authorization import GitHubAuthorizationRepository
from github_steward.ports.persistence import AuditEventRecord
from github_steward.ports.webhook import (
    SecurityEventRepository,
    WebhookAuditRepository,
    WebhookDeliveryRepository,
    WebhookIngressUnitOfWorkFactory,
)

NOW = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
DELIVERY = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
REPOSITORY_ID = 123456
INSTALLATION_ID = 654321
PULL_NUMBER = 17


class _Clock:
    def now(self) -> datetime:
        return NOW


class _DeliveryRepository:
    def __init__(
        self,
        outcomes: list[WebhookReplayOutcome] | None = None,
        *,
        existing_work_record_id: str | None = None,
        returned_delivery_id: str | None = None,
        fail_classify: bool = False,
        fail_work: bool = False,
    ) -> None:
        self.outcomes = outcomes or [WebhookReplayOutcome.CREATED]
        self.existing_work_record_id = existing_work_record_id
        self.returned_delivery_id = returned_delivery_id
        self.fail_classify = fail_classify
        self.fail_work = fail_work
        self.deliveries: list[WebhookDeliveryV1] = []
        self.works: list[WebhookWorkV1] = []

    def classify_or_insert(
        self,
        delivery: WebhookDeliveryV1,
    ) -> WebhookReplayResult:
        if self.fail_classify:
            raise RuntimeError("database unavailable and detail must stay internal")
        self.deliveries.append(delivery)
        outcome = self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]
        return WebhookReplayResult(
            outcome,
            delivery.delivery_id
            if self.returned_delivery_id is None
            else self.returned_delivery_id,
            self.existing_work_record_id,
        )

    def append_work(self, work: WebhookWorkV1) -> None:
        if self.fail_work:
            raise RuntimeError("work insert failed")
        self.works.append(work)


class _SecurityRepository:
    def __init__(self) -> None:
        self.events: list[SecurityEventV1] = []

    def append(self, event: SecurityEventV1) -> None:
        self.events.append(event)


class _AuditRepository:
    def __init__(self) -> None:
        self.events: list[AuditEventRecord] = []

    def append(self, event: AuditEventRecord) -> None:
        self.events.append(event)


class _AuthorizationRepository:
    def __init__(self, authorization: RepositoryAuthorizationV1 | None) -> None:
        self.authorization = authorization
        self.requested: list[int] = []

    def get_repository_authorization(
        self,
        repository_id: int,
    ) -> RepositoryAuthorizationV1 | None:
        self.requested.append(repository_id)
        return self.authorization


class _UnitOfWork:
    def __init__(
        self,
        deliveries: _DeliveryRepository,
        authorization: _AuthorizationRepository,
        *,
        fail_commit: bool = False,
    ) -> None:
        self.webhook_deliveries = cast(WebhookDeliveryRepository, deliveries)
        self.security_events = cast(SecurityEventRepository, _SecurityRepository())
        self.webhook_audits = cast(WebhookAuditRepository, _AuditRepository())
        self.github_authorization = cast(
            GitHubAuthorizationRepository,
            authorization,
        )
        self.fail_commit = fail_commit
        self.commits = 0
        self.rollbacks = 0
        self.exit_exception: type[BaseException] | None = None

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_value, traceback
        self.exit_exception = exc_type
        if exc_type is not None:
            self.rollbacks += 1

    def commit(self) -> None:
        if self.fail_commit:
            raise RuntimeError("commit failed")
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


def _authorization(
    *,
    installation_id: int = INSTALLATION_ID,
    authorized: bool = True,
) -> RepositoryAuthorizationV1:
    level = GitHubPermissionLevel.READ if authorized else GitHubPermissionLevel.NONE
    permissions = RepositoryPermissions(level, level, level, level)
    observation = InstallationObservationV1(
        observation_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
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
        repository_id=REPOSITORY_ID,
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


def _service(
    unit: _UnitOfWork,
    *,
    event_ids: list[UUID] | None = None,
) -> GitHubWebhookIngressService:
    factory = cast(WebhookIngressUnitOfWorkFactory, lambda: unit)
    identifiers = iter(
        [UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")]
        if event_ids is None
        else event_ids
    )

    def identifier_factory() -> UUID:
        return next(identifiers)

    return GitHubWebhookIngressService(
        unit_of_work_factory=factory,
        clock=cast(Clock, _Clock()),
        envelope_factory=envelope_payload,
        event_id_factory=identifier_factory,
    )


def _pull_body(*, installation_id: int = INSTALLATION_ID) -> bytes:
    return (
        "{"
        '"action":"opened",'
        f'"number":{PULL_NUMBER},'
        f'"repository":{{"id":{REPOSITORY_ID}}},'
        f'"installation":{{"id":{installation_id}}},'
        f'"pull_request":{{"number":{PULL_NUMBER}}}'
        "}"
    ).encode()


def _security(unit: _UnitOfWork) -> _SecurityRepository:
    return cast(_SecurityRepository, unit.security_events)


def _audits(unit: _UnitOfWork) -> _AuditRepository:
    return cast(_AuditRepository, unit.webhook_audits)


def test_authorized_pr_delivery_commits_exactly_one_work() -> None:
    deliveries = _DeliveryRepository()
    authorization = _AuthorizationRepository(_authorization())
    unit = _UnitOfWork(deliveries, authorization)

    result = _service(unit).receive(
        headers=WebhookHeaders(DELIVERY, "pull_request"),
        raw_body=_pull_body(),
    )

    assert result.outcome is WebhookIngressOutcome.ACCEPTED_NEW
    assert result.work_record_id is not None
    assert unit.commits == 1
    assert authorization.requested == [REPOSITORY_ID]
    assert len(deliveries.works) == 1
    assert deliveries.works[0].work_type is (
        WebhookWorkType.REFRESH_GITHUB_PULL_REQUEST
    )
    persisted = deliveries.deliveries[0]
    assert persisted.classification is (
        DeliveryClassification.SCHEDULE_PULL_REQUEST_REFRESH
    )
    assert (
        cast(Mapping[str, object], persisted.sanitized_payload)["entity_kind"]
        == "github_pull_request"
    )
    assert _pull_body().decode() not in repr(persisted.sanitized_payload)
    assert _security(unit).events == []


def test_missing_authorization_projection_and_durable_effect_agree() -> None:
    deliveries = _DeliveryRepository()
    unit = _UnitOfWork(deliveries, _AuthorizationRepository(None))

    result = _service(unit).receive(
        headers=WebhookHeaders(DELIVERY, "pull_request"),
        raw_body=_pull_body(),
    )

    assert result.work_record_id is None
    assert deliveries.works == []
    persisted = deliveries.deliveries[0]
    assert persisted.classification is (
        DeliveryClassification.AUTHORIZATION_CONTEXT_MISMATCH
    )
    assert persisted.proposed_work_type is None
    assert (
        cast(Mapping[str, object], persisted.sanitized_payload)["scheduled_work_type"]
        is None
    )
    assert len(_security(unit).events) == 1
    assert _security(unit).events[0].kind is (
        SecurityEventKind.WEBHOOK_AUTHORIZATION_CONTEXT_MISMATCH
    )


def test_installation_mismatch_substitutes_only_trusted_authorization_refresh() -> None:
    trusted_installation = INSTALLATION_ID + 1
    deliveries = _DeliveryRepository()
    unit = _UnitOfWork(
        deliveries,
        _AuthorizationRepository(_authorization(installation_id=trusted_installation)),
    )

    result = _service(unit).receive(
        headers=WebhookHeaders(DELIVERY, "pull_request"),
        raw_body=_pull_body(),
    )

    assert result.work_record_id is not None
    assert deliveries.works[0].work_type is (
        WebhookWorkType.REFRESH_GITHUB_AUTHORIZATION
    )
    assert deliveries.works[0].subject.installation_id == trusted_installation
    persisted = deliveries.deliveries[0]
    assert persisted.classification is (
        DeliveryClassification.AUTHORIZATION_CONTEXT_MISMATCH
    )
    assert persisted.proposed_work_type is (
        WebhookWorkType.REFRESH_GITHUB_AUTHORIZATION
    )
    assert (
        cast(Mapping[str, object], persisted.sanitized_payload)["entity_kind"]
        == "github_authorization"
    )


@pytest.mark.parametrize(
    ("body", "expected_kind"),
    [
        (b'{"action":"opened","action":"closed"}', "DUPLICATE_JSON_KEY"),
        (b"\xff", "INVALID_UTF8"),
        (b'{"action":', "INVALID_JSON"),
        (b'{"value":' + b"9" * 5_000 + b"}", "INVALID_JSON"),
        (b'{"value":' * 1_100 + b"0" + b"}" * 1_100, "INVALID_JSON"),
        (
            (
                '{"action":"opened","number":17,'
                '"pull_request":{"number":17},"repository":{"id":'
                f"{MAX_SAFE_INTEGER + 1}"
                f'}},"installation":{{"id":{INSTALLATION_ID}}}}}'
            ).encode(),
            "REQUIRED_IDENTITY_MISSING_OR_INVALID",
        ),
    ],
)
def test_authenticated_malformed_payload_is_durably_safely_classified(
    body: bytes,
    expected_kind: str,
) -> None:
    deliveries = _DeliveryRepository()
    unit = _UnitOfWork(deliveries, _AuthorizationRepository(None))

    result = _service(unit).receive(
        headers=WebhookHeaders(DELIVERY, "pull_request"),
        raw_body=body,
    )

    assert result.work_record_id is None
    assert deliveries.works == []
    assert deliveries.deliveries[0].classification is (
        DeliveryClassification.SIGNED_SCHEMA_INVALID
    )
    event = _security(unit).events[0]
    assert event.kind is SecurityEventKind.WEBHOOK_SIGNED_SCHEMA_INVALID
    assert cast(Mapping[str, object], event.metadata)["reason"] == expected_kind
    assert body not in repr(event.metadata).encode()


def test_permission_ceiling_signal_commits_without_work() -> None:
    deliveries = _DeliveryRepository()
    unit = _UnitOfWork(deliveries, _AuthorizationRepository(None))
    body = (
        "{"
        '"action":"requested_action",'
        f'"repository":{{"id":{REPOSITORY_ID}}},'
        f'"installation":{{"id":{INSTALLATION_ID}}}'
        "}"
    ).encode()

    result = _service(unit).receive(
        headers=WebhookHeaders(DELIVERY, "check_run"),
        raw_body=body,
    )

    assert result.work_record_id is None
    assert deliveries.works == []
    assert _security(unit).events[0].kind is (
        SecurityEventKind.WEBHOOK_PERMISSION_CEILING_MISMATCH
    )
    assert cast(_AuthorizationRepository, unit.github_authorization).requested == []


def test_same_digest_replay_commits_without_new_effect() -> None:
    existing_work = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    deliveries = _DeliveryRepository(
        [WebhookReplayOutcome.SAME_DIGEST],
        existing_work_record_id=existing_work,
    )
    unit = _UnitOfWork(deliveries, _AuthorizationRepository(_authorization()))

    result = _service(unit).receive(
        headers=WebhookHeaders(DELIVERY, "pull_request"),
        raw_body=_pull_body(),
    )

    assert result.outcome is WebhookIngressOutcome.IDEMPOTENT_REPLAY
    assert result.work_record_id == existing_work
    assert deliveries.works == []
    assert _security(unit).events == []
    assert unit.commits == 1


def test_repeated_integrity_conflicts_append_distinct_security_events() -> None:
    deliveries = _DeliveryRepository(
        [
            WebhookReplayOutcome.INTEGRITY_CONFLICT,
            WebhookReplayOutcome.INTEGRITY_CONFLICT,
        ]
    )
    unit = _UnitOfWork(deliveries, _AuthorizationRepository(None))
    service = _service(
        unit,
        event_ids=[
            UUID("11111111-1111-4111-8111-111111111111"),
            UUID("22222222-2222-4222-8222-222222222222"),
        ],
    )

    first = service.receive(
        headers=WebhookHeaders(DELIVERY, "ping"),
        raw_body=b"{}",
    )
    second = service.receive(
        headers=WebhookHeaders(DELIVERY, "ping"),
        raw_body=b'{"changed":true}',
    )

    assert first.outcome is WebhookIngressOutcome.INTEGRITY_CONFLICT
    assert second.outcome is WebhookIngressOutcome.INTEGRITY_CONFLICT
    assert deliveries.works == []
    assert len(_security(unit).events) == 2
    assert len({event.event_id for event in _security(unit).events}) == 2
    assert all(
        event.kind is SecurityEventKind.WEBHOOK_DELIVERY_INTEGRITY_CONFLICT
        for event in _security(unit).events
    )


def test_commit_then_lost_ack_redelivery_creates_zero_duplicate_work() -> None:
    deliveries = _DeliveryRepository(
        [WebhookReplayOutcome.CREATED, WebhookReplayOutcome.SAME_DIGEST]
    )
    unit = _UnitOfWork(deliveries, _AuthorizationRepository(_authorization()))
    service = _service(unit)

    first = service.receive(
        headers=WebhookHeaders(DELIVERY, "pull_request"),
        raw_body=_pull_body(),
    )
    redelivery = service.receive(
        headers=WebhookHeaders(DELIVERY, "pull_request"),
        raw_body=_pull_body(),
    )

    assert first.outcome is WebhookIngressOutcome.ACCEPTED_NEW
    assert redelivery.outcome is WebhookIngressOutcome.IDEMPOTENT_REPLAY
    assert len(deliveries.works) == 1
    assert unit.commits == 2


def test_authorization_revocation_is_audited_without_work() -> None:
    deliveries = _DeliveryRepository()
    unit = _UnitOfWork(deliveries, _AuthorizationRepository(None))

    result = _service(unit).receive(
        headers=WebhookHeaders(DELIVERY, "github_app_authorization"),
        raw_body=b'{"action":"revoked"}',
    )

    assert result.work_record_id is None
    assert deliveries.works == []
    assert len(_audits(unit).events) == 1
    assert _audits(unit).events[0].event_kind == (
        "github.webhook.authorization_revoked"
    )


@pytest.mark.parametrize("failure", ["classify", "work", "commit"])
def test_durability_failures_are_secret_safe_and_roll_back(failure: str) -> None:
    deliveries = _DeliveryRepository(
        fail_classify=failure == "classify",
        fail_work=failure == "work",
    )
    unit = _UnitOfWork(
        deliveries,
        _AuthorizationRepository(_authorization()),
        fail_commit=failure == "commit",
    )

    with pytest.raises(WebhookDurabilityError) as captured:
        _service(unit).receive(
            headers=WebhookHeaders(DELIVERY, "pull_request"),
            raw_body=_pull_body(),
        )

    assert str(captured.value) == "webhook durability transaction failed"
    assert _pull_body().decode() not in str(captured.value)
    assert unit.commits == 0
    assert unit.rollbacks == 1
    assert unit.exit_exception is not None


def test_service_rejects_untrusted_header_object_before_persistence() -> None:
    deliveries = _DeliveryRepository()
    unit = _UnitOfWork(deliveries, _AuthorizationRepository(None))

    with pytest.raises(TypeError, match="authenticated WebhookHeaders"):
        _service(unit).receive(
            headers=cast(WebhookHeaders, {"event": "ping"}),
            raw_body=b"{}",
        )

    assert deliveries.deliveries == []


def test_mismatched_created_identity_is_a_durability_failure() -> None:
    deliveries = _DeliveryRepository(
        returned_delivery_id="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
    )
    unit = _UnitOfWork(deliveries, _AuthorizationRepository(None))

    with pytest.raises(WebhookDurabilityError):
        _service(unit).receive(
            headers=WebhookHeaders(DELIVERY, "ping"),
            raw_body=b"{}",
        )

    assert unit.commits == 0
    assert unit.rollbacks == 1
