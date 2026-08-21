"""Shape and immutability contracts for GS-I6 webhook persistence ports."""

from __future__ import annotations

import dataclasses
import inspect
import operator
from collections.abc import Mapping, MutableMapping
from datetime import UTC, datetime
from typing import cast

import pytest

from github_steward.adapters.canonicalization.rfc8785 import envelope_payload
from github_steward.domain.webhook import (
    SecurityEventKind,
    SecurityEventReason,
    SecurityEventV1,
    WebhookReplayOutcome,
    WebhookReplayResult,
    delivery_id,
    security_event_metadata,
)
from github_steward.ports.webhook import (
    SecurityEventRepository,
    WebhookAuditRepository,
    WebhookDeliveryRepository,
    WebhookIngressUnitOfWork,
)

NOW = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
PROVIDER_DELIVERY_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def _public_methods(protocol: type[object]) -> set[str]:
    return {
        name
        for name, value in inspect.getmembers(protocol, inspect.isfunction)
        if not name.startswith("_")
    }


def test_webhook_ports_expose_only_append_or_explicit_transaction_operations() -> None:
    assert _public_methods(WebhookDeliveryRepository) == {
        "append_work",
        "classify_or_insert",
    }
    assert _public_methods(SecurityEventRepository) == {"append"}
    assert _public_methods(WebhookAuditRepository) == {"append"}
    assert _public_methods(WebhookIngressUnitOfWork) == {"commit", "rollback"}
    for protocol in (
        WebhookDeliveryRepository,
        SecurityEventRepository,
        WebhookAuditRepository,
    ):
        methods = _public_methods(protocol)
        assert "update" not in methods
        assert "delete" not in methods
        assert "commit" not in methods
        assert "rollback" not in methods


def test_security_event_and_replay_result_are_frozen_typed_values() -> None:
    metadata = security_event_metadata(
        kind=SecurityEventKind.WEBHOOK_DELIVERY_INTEGRITY_CONFLICT,
        reason=SecurityEventReason.DELIVERY_DIGEST_MISMATCH,
        provider_delivery_id=PROVIDER_DELIVERY_ID,
    )
    envelope = envelope_payload(metadata)
    event = SecurityEventV1(
        event_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        delivery_id=delivery_id(PROVIDER_DELIVERY_ID),
        kind=SecurityEventKind.WEBHOOK_DELIVERY_INTEGRITY_CONFLICT,
        occurred_at=NOW,
        metadata=envelope.payload,
        metadata_digest=envelope.digest,
    )
    replay = WebhookReplayResult(
        WebhookReplayOutcome.INTEGRITY_CONFLICT,
        event.delivery_id,
    )

    assert dataclasses.is_dataclass(SecurityEventV1)
    assert vars(SecurityEventV1)["__dataclass_params__"].frozen
    assert dataclasses.is_dataclass(WebhookReplayResult)
    assert vars(WebhookReplayResult)["__dataclass_params__"].frozen
    assert replay.work_record_id is None
    with pytest.raises(dataclasses.FrozenInstanceError):
        event.kind = SecurityEventKind.WEBHOOK_SIGNED_SCHEMA_INVALID  # type: ignore[misc]


def test_security_event_copies_and_freezes_canonical_metadata() -> None:
    source = dict(
        cast(
            Mapping[str, object],
            security_event_metadata(
                kind=SecurityEventKind.WEBHOOK_SIGNED_SCHEMA_INVALID,
                reason=SecurityEventReason.INVALID_JSON,
                provider_delivery_id=PROVIDER_DELIVERY_ID,
                event="pull_request",
            ),
        )
    )
    envelope = envelope_payload(source)
    event = SecurityEventV1(
        event_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        delivery_id=delivery_id(PROVIDER_DELIVERY_ID),
        kind=SecurityEventKind.WEBHOOK_SIGNED_SCHEMA_INVALID,
        occurred_at=NOW,
        metadata=envelope.payload,
        metadata_digest=envelope.digest,
    )

    source["reason"] = "changed"
    assert cast(Mapping[str, object], event.metadata)["reason"] == "INVALID_JSON"
    with pytest.raises(TypeError):
        operator.setitem(
            cast(MutableMapping[str, object], event.metadata),
            "reason",
            "changed",
        )


def test_persistent_security_record_has_no_body_signature_or_secret_field() -> None:
    field_names = {
        field.name.casefold() for field in dataclasses.fields(SecurityEventV1)
    }
    prohibited = {
        "body",
        "raw_body",
        "secret",
        "signature",
        "expected_signature",
        "token",
        "private_key",
        "dsn",
    }
    assert not field_names & prohibited
