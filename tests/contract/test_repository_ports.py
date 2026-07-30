"""Repository interface shape and immutability contracts."""

from __future__ import annotations

import dataclasses
import inspect
import operator
from collections.abc import Callable, Mapping, MutableMapping
from datetime import UTC, datetime
from typing import cast

import pytest

from github_steward.domain.canonical import Digest
from github_steward.ports.persistence import (
    AnalysisViewId,
    AnalysisViewRecord,
    AnalysisViewRepository,
    AuditEventId,
    AuditEventRecord,
    AuditEventRepository,
    CanonicalObservationRecord,
    CanonicalObservationRepository,
    CurrentObservationPointerRepository,
    InboxWorkRepository,
    ObservationVersionId,
    UnitOfWork,
    WorkLeaseRepository,
)

NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
type ImmutableRecord = (
    CanonicalObservationRecord | AnalysisViewRecord | AuditEventRecord
)


def _public_methods(protocol: type[object]) -> set[str]:
    return {
        name
        for name, value in inspect.getmembers(protocol, inspect.isfunction)
        if not name.startswith("_")
    }


def test_append_only_ports_expose_no_update_or_delete() -> None:
    assert _public_methods(CanonicalObservationRepository) == {"append"}
    assert _public_methods(AnalysisViewRepository) == {"insert"}
    assert _public_methods(AuditEventRepository) == {"append"}


def test_mutable_ports_are_explicitly_cas_and_lease_oriented() -> None:
    assert _public_methods(CurrentObservationPointerRepository) == {"compare_and_swap"}
    assert _public_methods(WorkLeaseRepository) == {"acquire", "release"}
    assert _public_methods(InboxWorkRepository) == {"create_delivery_and_work"}
    assert _public_methods(UnitOfWork) == {"commit", "rollback"}


def test_immutable_port_records_are_frozen_values() -> None:
    for record in (
        CanonicalObservationRecord,
        AnalysisViewRecord,
        AuditEventRecord,
    ):
        assert dataclasses.is_dataclass(record)
        assert vars(record)["__dataclass_params__"].frozen


@pytest.mark.parametrize(
    "record",
    [
        CanonicalObservationRecord(
            version_id=ObservationVersionId("observation-1"),
            entity_kind="pull_request",
            entity_id="1",
            schema_id="github.pull-request",
            schema_version=1,
            observed_at=NOW,
            payload={"items": [{"value": 1}]},
            digest=Digest("a" * 64),
        ),
        AnalysisViewRecord(
            view_id=AnalysisViewId("view-1"),
            schema_id="github.analysis",
            schema_version=1,
            payload={"items": [{"value": 1}]},
            digest=Digest("b" * 64),
            observation_versions=(
                ("pull_request", ObservationVersionId("observation-1")),
            ),
        ),
        AuditEventRecord(
            event_id=AuditEventId("event-1"),
            event_kind="observation.recorded",
            actor_or_authority_id="github",
            occurred_at=NOW,
            schema_id="github.audit",
            schema_version=1,
            payload={"items": [{"value": 1}]},
            digest=Digest("c" * 64),
        ),
    ],
    ids=["canonical-observation", "analysis-view", "audit-event"],
)
def test_immutable_port_record_payloads_reject_nested_mutation(
    record: ImmutableRecord,
) -> None:
    payload = record.payload
    assert isinstance(payload, Mapping)
    with pytest.raises(TypeError):
        operator.setitem(cast(MutableMapping[str, object], payload), "items", ())
    items = payload["items"]
    assert isinstance(items, tuple)
    nested = items[0]
    assert isinstance(nested, Mapping)
    with pytest.raises(TypeError):
        operator.setitem(cast(MutableMapping[str, object], nested), "value", 2)


@pytest.mark.parametrize(
    "record_factory",
    [
        lambda payload: CanonicalObservationRecord(
            version_id=ObservationVersionId("observation-2"),
            entity_kind="pull_request",
            entity_id="2",
            schema_id="github.pull-request",
            schema_version=1,
            observed_at=NOW,
            payload=payload,
            digest=Digest("d" * 64),
        ),
        lambda payload: AnalysisViewRecord(
            view_id=AnalysisViewId("view-2"),
            schema_id="github.analysis",
            schema_version=1,
            payload=payload,
            digest=Digest("e" * 64),
            observation_versions=(),
        ),
        lambda payload: AuditEventRecord(
            event_id=AuditEventId("event-2"),
            event_kind="observation.recorded",
            actor_or_authority_id="github",
            occurred_at=NOW,
            schema_id="github.audit",
            schema_version=1,
            payload=payload,
            digest=Digest("f" * 64),
        ),
    ],
    ids=["canonical-observation", "analysis-view", "audit-event"],
)
def test_immutable_port_records_copy_caller_owned_payload(
    record_factory: Callable[[object], ImmutableRecord],
) -> None:
    source = {"items": [{"value": 1}]}
    record = record_factory(source)

    source["items"][0]["value"] = 2
    source["items"].append({"value": 3})

    payload = record.payload
    assert isinstance(payload, Mapping)
    items = payload["items"]
    assert isinstance(items, tuple)
    nested = items[0]
    assert isinstance(nested, Mapping)
    assert nested["value"] == 1
    assert len(items) == 1
