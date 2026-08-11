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
    Delivery,
    DeliveryId,
    DeliveryIngressOutcome,
    DeliveryIngressResult,
    InboxWorkRepository,
    ObservationVersionId,
    PreparednessAssessmentId,
    PreparednessAssessmentRecord,
    PreparednessAssessmentRepository,
    PreparednessProfileId,
    PreparednessProfileRecord,
    PreparednessProfileRepository,
    UnitOfWork,
    WorkLeaseRepository,
    WorkProcessingRepository,
    WorkRecordId,
)

NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
type ImmutableRecord = (
    Delivery
    | CanonicalObservationRecord
    | AnalysisViewRecord
    | PreparednessProfileRecord
    | PreparednessAssessmentRecord
    | AuditEventRecord
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
    assert _public_methods(PreparednessProfileRepository) == {
        "get",
        "get_successor",
        "insert",
    }
    assert _public_methods(PreparednessAssessmentRepository) == {"insert"}
    assert _public_methods(AuditEventRepository) == {"append"}


def test_mutable_ports_are_explicitly_cas_and_lease_oriented() -> None:
    assert _public_methods(CurrentObservationPointerRepository) == {
        "compare_and_swap",
        "create_if_absent",
        "get",
    }
    assert _public_methods(WorkLeaseRepository) == {"acquire", "release"}
    assert _public_methods(WorkProcessingRepository) == {
        "claim_next",
        "renew",
        "complete_success",
        "complete_failure",
        "reconcile_expired",
    }
    assert _public_methods(InboxWorkRepository) == {"create_delivery_and_work"}
    assert _public_methods(UnitOfWork) == {"commit", "rollback"}


def test_immutable_port_records_are_frozen_values() -> None:
    for record in (
        CanonicalObservationRecord,
        AnalysisViewRecord,
        PreparednessProfileRecord,
        PreparednessAssessmentRecord,
        AuditEventRecord,
        Delivery,
    ):
        assert dataclasses.is_dataclass(record)
        assert vars(record)["__dataclass_params__"].frozen


@pytest.mark.parametrize(
    "record",
    [
        Delivery(
            delivery_id=DeliveryId("delivery-1"),
            provider="synthetic",
            provider_delivery_id="provider-1",
            payload_schema_id="synthetic",
            payload_schema_version=1,
            payload={"items": [{"value": 1}]},
            payload_digest=Digest("9" * 64),
            received_at=NOW,
        ),
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
        PreparednessProfileRecord(
            profile_id=PreparednessProfileId("profile-1"),
            version=1,
            repository_id=1,
            effective_from=NOW,
            predecessor_profile_id=None,
            predecessor_profile_version=None,
            payload={"items": [{"value": 1}]},
            digest=Digest("1" * 64),
        ),
        PreparednessAssessmentRecord(
            assessment_id=PreparednessAssessmentId("assessment-1"),
            repository_id=1,
            pull_number=17,
            head_sha="a" * 40,
            profile_id=PreparednessProfileId("profile-1"),
            profile_version=1,
            analysis_view_id=AnalysisViewId("view-1"),
            evidence_sealed_at=NOW,
            evaluated_at=NOW,
            verdict="READY_FOR_HUMAN_REVIEW",
            payload={"items": [{"value": 1}]},
            digest=Digest("2" * 64),
            evidence_observations=(
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
    ids=[
        "delivery",
        "canonical-observation",
        "analysis-view",
        "preparedness-profile",
        "preparedness-assessment",
        "audit-event",
    ],
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
        lambda payload: Delivery(
            delivery_id=DeliveryId("delivery-2"),
            provider="synthetic",
            provider_delivery_id="provider-2",
            payload_schema_id="synthetic",
            payload_schema_version=1,
            payload=payload,
            payload_digest=Digest("9" * 64),
            received_at=NOW,
        ),
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
        lambda payload: PreparednessProfileRecord(
            profile_id=PreparednessProfileId("profile-2"),
            version=1,
            repository_id=2,
            effective_from=NOW,
            predecessor_profile_id=None,
            predecessor_profile_version=None,
            payload=payload,
            digest=Digest("1" * 64),
        ),
        lambda payload: PreparednessAssessmentRecord(
            assessment_id=PreparednessAssessmentId("assessment-2"),
            repository_id=2,
            pull_number=18,
            head_sha="b" * 40,
            profile_id=PreparednessProfileId("profile-2"),
            profile_version=1,
            analysis_view_id=AnalysisViewId("view-2"),
            evidence_sealed_at=NOW,
            evaluated_at=NOW,
            verdict="INDETERMINATE",
            payload=payload,
            digest=Digest("2" * 64),
            evidence_observations=(),
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
    ids=[
        "delivery",
        "canonical-observation",
        "analysis-view",
        "preparedness-profile",
        "preparedness-assessment",
        "audit-event",
    ],
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


def test_inbox_result_is_typed_and_carries_durable_identities() -> None:
    result = DeliveryIngressResult(
        DeliveryIngressOutcome.DUPLICATE_SAME_DIGEST,
        DeliveryId("delivery"),
        WorkRecordId("work"),
    )
    assert result.outcome is DeliveryIngressOutcome.DUPLICATE_SAME_DIGEST
    assert result.delivery_id == "delivery"
    assert result.work_record_id == "work"


def test_repositories_never_expose_transaction_control() -> None:
    repositories = (
        CanonicalObservationRepository,
        CurrentObservationPointerRepository,
        InboxWorkRepository,
        WorkLeaseRepository,
        WorkProcessingRepository,
        AnalysisViewRepository,
        PreparednessProfileRepository,
        PreparednessAssessmentRepository,
        AuditEventRepository,
    )
    for repository in repositories:
        methods = _public_methods(repository)
        assert "commit" not in methods
        assert "rollback" not in methods
