"""Concrete PostgreSQL repository transaction and lease behavior."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from psycopg.errors import UniqueViolation
from sqlalchemy.engine import Engine

from github_steward.adapters.canonicalization.rfc8785 import envelope_payload
from github_steward.adapters.postgres.metadata import (
    analysis_view,
    analysis_view_observation,
    canonical_observation,
    delivery_inbox,
    preparedness_assessment,
    preparedness_assessment_evidence,
    preparedness_profile,
    work_attempt,
    work_record,
)
from github_steward.adapters.postgres.unit_of_work import PostgresUnitOfWork
from github_steward.application.local_processing import SyntheticReceiptService
from github_steward.domain.canonical import Digest
from github_steward.domain.processing import (
    DELIVERY_SCHEMA_ID,
    PROVIDER,
    SCHEMA_VERSION,
    WORK_TYPE,
    AttemptState,
    FailureKind,
    FaultPoint,
    WorkState,
)
from github_steward.ports.persistence import (
    AnalysisViewId,
    AnalysisViewRecord,
    CanonicalObservationRecord,
    ClaimOutcome,
    Delivery,
    DeliveryIngressOutcome,
    LeaseOperationOutcome,
    LeaseToken,
    ObservationPointer,
    ObservationVersionId,
    PointerCreateOutcome,
    PreparednessAssessmentId,
    PreparednessAssessmentRecord,
    PreparednessProfileId,
    PreparednessProfileRecord,
    WorkLease,
    WorkRecord,
    WorkRecordId,
)

NOW = datetime(2026, 7, 31, 12, 0, 0, 123456, tzinfo=UTC)


class FixedClock:
    def __init__(self, now: datetime = NOW) -> None:
        self.value = now

    def now(self) -> datetime:
        return self.value


class InjectedFault(RuntimeError):
    """Test-only deterministic transaction fault."""


def mapping(*, entity_id: str = "17", sequence: int = 1) -> dict[str, object]:
    return {
        "entity_kind": "pull_request",
        "entity_id": entity_id,
        "observed_at": "2026-07-31T12:00:00.123456Z",
        "sequence": sequence,
        "expected_pointer_version": None,
        "observation": {"id": entity_id, "sequence": sequence},
    }


def factory(
    engine: Engine,
    fault: Callable[[FaultPoint], None] | None = None,
) -> Callable[[], PostgresUnitOfWork]:
    return lambda: PostgresUnitOfWork(engine, fault)


def receipt_service(
    engine: Engine,
    fault: Callable[[FaultPoint], None] | None = None,
) -> SyntheticReceiptService:
    return SyntheticReceiptService(
        unit_of_work_factory=factory(engine, fault),
        clock=FixedClock(),
        envelope_factory=envelope_payload,
    )


def retire_claimable(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(
            work_record.update()
            .where(
                work_record.c.state.in_(
                    [WorkState.AVAILABLE.value, WorkState.RETRY_WAIT.value]
                )
            )
            .values(state=WorkState.SUCCEEDED.value)
        )


def test_atomic_receipt_idempotency_and_durable_payload(
    postgres_engine: Engine,
) -> None:
    service = receipt_service(postgres_engine)
    created = service.receive(
        provider_delivery_id="repository-idempotency",
        mapping=mapping(),
    )
    same = service.receive(
        provider_delivery_id="repository-idempotency",
        mapping=mapping(),
    )
    conflicting = service.receive(
        provider_delivery_id="repository-idempotency",
        mapping=mapping(sequence=2),
    )

    assert created.outcome is DeliveryIngressOutcome.CREATED
    assert same.outcome is DeliveryIngressOutcome.DUPLICATE_SAME_DIGEST
    assert conflicting.outcome is (
        DeliveryIngressOutcome.INTEGRITY_FAILURE_DIFFERENT_DIGEST
    )
    assert same.delivery_id == created.delivery_id == conflicting.delivery_id
    assert same.work_record_id == created.work_record_id == conflicting.work_record_id
    with postgres_engine.connect() as connection:
        delivery = (
            connection.execute(
                sa.select(delivery_inbox).where(
                    delivery_inbox.c.delivery_id == created.delivery_id
                )
            )
            .mappings()
            .one()
        )
        assert delivery["provider"] == "synthetic"
        assert delivery["canonical_payload"] == mapping()
        assert delivery["payload_schema_id"] == "github-steward.synthetic-delivery"
        assert delivery["payload_schema_version"] == 1
        assert delivery["payload_digest_format"] == "jcs-sha256/v1"
        assert delivery["payload_digest"] == envelope_payload(mapping()).digest.value
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(work_record)
                .where(work_record.c.work_record_id == created.work_record_id)
            )
            == 1
        )


def test_unrelated_delivery_unique_conflict_is_not_swallowed(
    postgres_engine: Engine,
) -> None:
    created = receipt_service(postgres_engine).receive(
        provider_delivery_id="unrelated-conflict-original",
        mapping=mapping(entity_id="unrelated-conflict-original"),
    )
    with postgres_engine.connect() as connection:
        original_delivery = dict(
            connection.execute(
                sa.select(delivery_inbox).where(
                    delivery_inbox.c.delivery_id == created.delivery_id
                )
            )
            .mappings()
            .one()
        )
        original_work = dict(
            connection.execute(
                sa.select(work_record).where(
                    work_record.c.work_record_id == created.work_record_id
                )
            )
            .mappings()
            .one()
        )

    conflicting_provider_delivery_id = "unrelated-conflict-new-identity"
    conflicting_work_id = WorkRecordId("00000000-0000-0000-0000-000000000090")
    conflicting_envelope = envelope_payload(
        mapping(entity_id="unrelated-conflict-new-identity")
    )
    conflicting_delivery = Delivery(
        delivery_id=created.delivery_id,
        provider=PROVIDER,
        provider_delivery_id=conflicting_provider_delivery_id,
        payload_schema_id=DELIVERY_SCHEMA_ID,
        payload_schema_version=SCHEMA_VERSION,
        payload=conflicting_envelope.payload,
        payload_digest=conflicting_envelope.digest,
        received_at=NOW,
    )
    conflicting_work = WorkRecord(
        work_record_id=conflicting_work_id,
        delivery_id=created.delivery_id,
        work_type=WORK_TYPE,
        available_at=NOW,
    )

    with factory(postgres_engine)() as unit:
        with pytest.raises(sa.exc.IntegrityError) as raised:
            unit.inbox.create_delivery_and_work(
                delivery=conflicting_delivery,
                work=conflicting_work,
            )
        original_error = raised.value.orig
        assert isinstance(original_error, UniqueViolation)
        assert original_error.sqlstate == "23505"
        assert original_error.diag.constraint_name == "pk_delivery_inbox"
        unit.rollback()

    with postgres_engine.connect() as connection:
        preserved_delivery = dict(
            connection.execute(
                sa.select(delivery_inbox).where(
                    delivery_inbox.c.delivery_id == created.delivery_id
                )
            )
            .mappings()
            .one()
        )
        preserved_work = dict(
            connection.execute(
                sa.select(work_record).where(
                    work_record.c.work_record_id == created.work_record_id
                )
            )
            .mappings()
            .one()
        )
        assert preserved_delivery == original_delivery
        assert preserved_work == original_work
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(delivery_inbox)
                .where(
                    delivery_inbox.c.provider == PROVIDER,
                    delivery_inbox.c.provider_delivery_id
                    == conflicting_provider_delivery_id,
                )
            )
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(work_record)
                .where(work_record.c.work_record_id == conflicting_work_id)
            )
            == 0
        )


def test_receipt_fault_after_inbox_insert_rolls_back_both_rows(
    postgres_engine: Engine,
) -> None:
    def inject(point: FaultPoint) -> None:
        if point is FaultPoint.AFTER_INBOX_INSERT:
            raise InjectedFault(point.value)

    service = receipt_service(postgres_engine, inject)
    with pytest.raises(InjectedFault):
        service.receive(
            provider_delivery_id="repository-receipt-fault",
            mapping=mapping(entity_id="fault"),
        )
    with postgres_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(delivery_inbox)
                .where(
                    delivery_inbox.c.provider_delivery_id == "repository-receipt-fault"
                )
            )
            == 0
        )


@pytest.mark.parametrize(
    "fault_point",
    [FaultPoint.AFTER_CLAIM_UPDATE, FaultPoint.AFTER_ATTEMPT_INSERT],
)
def test_claim_faults_roll_back_work_and_attempt(
    postgres_engine: Engine,
    fault_point: FaultPoint,
) -> None:
    retire_claimable(postgres_engine)
    provider_id = f"claim-fault-{fault_point.value}"
    created = receipt_service(postgres_engine).receive(
        provider_delivery_id=provider_id,
        mapping=mapping(entity_id=provider_id),
    )

    def inject(point: FaultPoint) -> None:
        if point is fault_point:
            raise InjectedFault(point.value)

    with pytest.raises(InjectedFault), factory(postgres_engine, inject)() as unit:
        unit.work.claim_next(owner="worker", now=NOW)
        unit.commit()
    with postgres_engine.connect() as connection:
        row = connection.execute(
            sa.select(work_record.c.state, work_record.c.version).where(
                work_record.c.work_record_id == created.work_record_id
            )
        ).one()
        assert row == (WorkState.AVAILABLE.value, 0)
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(work_attempt)
                .where(work_attempt.c.work_record_id == created.work_record_id)
            )
            == 0
        )


def test_claim_renewal_boundaries_stale_guards_release_and_attempt_numbers(
    postgres_engine: Engine,
) -> None:
    retire_claimable(postgres_engine)
    created = receipt_service(postgres_engine).receive(
        provider_delivery_id="lease-boundaries",
        mapping=mapping(entity_id="lease"),
    )
    with factory(postgres_engine)() as unit:
        claim = unit.work.claim_next(owner="worker-1", now=NOW)
        unit.commit()
    assert claim.outcome is ClaimOutcome.CLAIMED
    first = claim.claimed_work
    assert first is not None
    assert first.attempt_number == 1
    assert first.lease.expires_at == NOW + timedelta(seconds=300)

    with factory(postgres_engine)() as unit:
        at_expiry = unit.work.renew(lease=first.lease, now=first.lease.expires_at)
        unit.commit()
    assert at_expiry.outcome is LeaseOperationOutcome.STALE

    with factory(postgres_engine)() as unit:
        before_expiry = unit.work.renew(
            lease=first.lease,
            now=first.lease.expires_at - timedelta(microseconds=1),
        )
        unit.commit()
    assert before_expiry.outcome is LeaseOperationOutcome.SUCCEEDED
    renewed = before_expiry.lease
    assert renewed is not None
    assert renewed.version == first.lease.version + 1
    assert renewed.expires_at == first.lease.expires_at + timedelta(
        seconds=300
    ) - timedelta(microseconds=1)

    stale_token = WorkLease(
        work_record_id=renewed.work_record_id,
        owner=renewed.owner,
        token=LeaseToken("00000000-0000-0000-0000-000000000001"),
        expires_at=renewed.expires_at,
        version=renewed.version,
    )
    with factory(postgres_engine)() as unit:
        assert (
            unit.work.renew(
                lease=stale_token,
                now=NOW + timedelta(seconds=1),
            ).outcome
            is LeaseOperationOutcome.STALE
        )
        concrete = unit.work
        assert concrete.release(lease=renewed, now=NOW + timedelta(seconds=1))
        unit.commit()

    with postgres_engine.connect() as connection:
        attempt = connection.execute(
            sa.select(work_attempt.c.state, work_attempt.c.completed_at).where(
                work_attempt.c.work_record_id == created.work_record_id
            )
        ).one()
        assert attempt.state == AttemptState.ABANDONED.value
        assert attempt.completed_at == NOW + timedelta(seconds=1)

    with factory(postgres_engine)() as unit:
        second_claim = unit.work.claim_next(
            owner="worker-2",
            now=NOW + timedelta(seconds=1),
        )
        unit.commit()
    assert second_claim.claimed_work is not None
    assert second_claim.claimed_work.attempt_number == 2


def test_retryable_and_terminal_completion_states(postgres_engine: Engine) -> None:
    retire_claimable(postgres_engine)
    first_receipt = receipt_service(postgres_engine).receive(
        provider_delivery_id="retryable-completion",
        mapping=mapping(entity_id="retryable"),
    )
    with factory(postgres_engine)() as unit:
        first_claim = unit.work.claim_next(owner="worker", now=NOW)
        unit.commit()
    claimed = first_claim.claimed_work
    assert claimed is not None
    with factory(postgres_engine)() as unit:
        result = unit.work.complete_failure(
            lease=claimed.lease,
            attempt_number=claimed.attempt_number,
            now=NOW,
            failure_kind=FailureKind.RETRYABLE_LOCAL_PROCESSING,
        )
        unit.commit()
    assert result.work_state is WorkState.RETRY_WAIT
    with postgres_engine.connect() as connection:
        retry = connection.execute(
            sa.select(work_record.c.state, work_record.c.available_at).where(
                work_record.c.work_record_id == first_receipt.work_record_id
            )
        ).one()
        assert retry == (WorkState.RETRY_WAIT.value, NOW + timedelta(seconds=60))

    receipt_service(postgres_engine).receive(
        provider_delivery_id="terminal-completion",
        mapping=mapping(entity_id="terminal"),
    )
    with factory(postgres_engine)() as unit:
        second_claim = unit.work.claim_next(owner="worker", now=NOW)
        unit.commit()
    terminal = second_claim.claimed_work
    assert terminal is not None
    with factory(postgres_engine)() as unit:
        result = unit.work.complete_failure(
            lease=terminal.lease,
            attempt_number=terminal.attempt_number,
            now=NOW,
            failure_kind=FailureKind.PERMANENT_LOCAL_PROCESSING,
        )
        unit.commit()
    assert result.work_state is WorkState.FAILED


def test_accepted_acquire_and_release_support_stale_guards_without_attempt(
    postgres_engine: Engine,
) -> None:
    retire_claimable(postgres_engine)
    created = receipt_service(postgres_engine).receive(
        provider_delivery_id="accepted-acquire-release",
        mapping=mapping(entity_id="accepted-acquire-release"),
    )
    token = LeaseToken("00000000-0000-0000-0000-000000000020")
    with factory(postgres_engine)() as unit:
        assert (
            unit.work.acquire(
                work_record_id=created.work_record_id,
                owner="worker",
                token=token,
                now=NOW,
                expires_at=NOW + timedelta(seconds=300),
                expected_version=1,
            )
            is None
        )
        lease = unit.work.acquire(
            work_record_id=created.work_record_id,
            owner="worker",
            token=token,
            now=NOW,
            expires_at=NOW + timedelta(seconds=300),
            expected_version=0,
        )
        unit.commit()
    assert lease is not None
    stale = WorkLease(
        work_record_id=lease.work_record_id,
        owner=lease.owner,
        token=LeaseToken("00000000-0000-0000-0000-000000000021"),
        expires_at=lease.expires_at,
        version=lease.version,
    )
    with factory(postgres_engine)() as unit:
        assert not unit.work.release(lease=stale, now=NOW)
        assert unit.work.release(lease=lease, now=NOW)
        unit.commit()
    with postgres_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(work_record.c.state).where(
                    work_record.c.work_record_id == created.work_record_id
                )
            )
            == WorkState.AVAILABLE.value
        )


def test_stale_and_wrong_attempt_completions_update_nothing(
    postgres_engine: Engine,
) -> None:
    retire_claimable(postgres_engine)
    receipt_service(postgres_engine).receive(
        provider_delivery_id="stale-completion-guards",
        mapping=mapping(entity_id="stale-completion-guards"),
    )
    with factory(postgres_engine)() as unit:
        claim = unit.work.claim_next(owner="worker", now=NOW)
        unit.commit()
    claimed = claim.claimed_work
    assert claimed is not None
    stale = WorkLease(
        work_record_id=claimed.lease.work_record_id,
        owner=claimed.lease.owner,
        token=LeaseToken("00000000-0000-0000-0000-000000000030"),
        expires_at=claimed.lease.expires_at,
        version=claimed.lease.version,
    )
    with factory(postgres_engine)() as unit:
        assert (
            unit.work.complete_success(
                lease=stale,
                attempt_number=1,
                now=NOW,
            ).outcome
            is LeaseOperationOutcome.STALE
        )
        assert (
            unit.work.complete_failure(
                lease=stale,
                attempt_number=1,
                now=NOW,
                failure_kind=FailureKind.PERMANENT_LOCAL_PROCESSING,
            ).outcome
            is LeaseOperationOutcome.STALE
        )
        assert (
            unit.work.complete_success(
                lease=claimed.lease,
                attempt_number=2,
                now=NOW,
            ).outcome
            is LeaseOperationOutcome.STALE
        )
        assert (
            unit.work.complete_failure(
                lease=claimed.lease,
                attempt_number=2,
                now=NOW,
                failure_kind=FailureKind.PERMANENT_LOCAL_PROCESSING,
            ).outcome
            is LeaseOperationOutcome.STALE
        )
        assert unit.work.release(lease=claimed.lease, now=NOW)
        unit.commit()


def test_pointer_replacement_must_increment_exactly_one(
    postgres_engine: Engine,
) -> None:
    pointer = ObservationPointer(
        entity_kind="pull_request",
        entity_id="invalid-pointer-version",
        observation_version_id=ObservationVersionId(
            "00000000-0000-0000-0000-000000000040"
        ),
        ordering_key={"sequence": "1"},
        pointer_version=3,
        updated_at=NOW,
    )
    with (
        factory(postgres_engine)() as unit,
        pytest.raises(ValueError, match="increment"),
    ):
        unit.pointers.compare_and_swap(
            expected_version=0,
            replacement=pointer,
        )


def test_unit_of_work_rejects_invalid_lifecycle_operations(
    postgres_engine: Engine,
) -> None:
    unit = PostgresUnitOfWork(postgres_engine)
    with pytest.raises(RuntimeError, match="active transaction"):
        unit.commit()
    with unit:
        with pytest.raises(RuntimeError, match="entered twice"):
            unit.__enter__()
        unit.rollback()
        with pytest.raises(RuntimeError, match="active transaction"):
            unit.commit()
    with pytest.raises(RuntimeError, match="active transaction"):
        unit.rollback()
    assert unit.__exit__(None, None, None) is None


def test_reconciliation_fails_closed_for_processing_work_without_attempt(
    postgres_engine: Engine,
) -> None:
    retire_claimable(postgres_engine)
    created = receipt_service(postgres_engine).receive(
        provider_delivery_id="reconcile-without-attempt",
        mapping=mapping(entity_id="reconcile-without-attempt"),
    )
    lease = WorkLease(
        work_record_id=WorkRecordId(created.work_record_id),
        owner="worker",
        token=LeaseToken("00000000-0000-0000-0000-000000000050"),
        expires_at=NOW,
        version=1,
    )
    with factory(postgres_engine)() as unit:
        acquired = unit.work.acquire(
            work_record_id=created.work_record_id,
            owner=lease.owner,
            token=lease.token,
            now=NOW,
            expires_at=NOW,
            expected_version=0,
        )
        assert acquired == lease
        unit.commit()
    with (
        pytest.raises(RuntimeError, match="no durable attempt"),
        factory(postgres_engine)() as unit,
    ):
        unit.work.reconcile_expired(now=NOW)
        unit.commit()


def test_pointer_can_be_loaded_for_exact_comparison(
    postgres_engine: Engine,
) -> None:
    observation_id = ObservationVersionId("00000000-0000-0000-0000-000000000060")
    pointer = ObservationPointer(
        entity_kind="github_pull_request",
        entity_id="1:17",
        observation_version_id=observation_id,
        ordering_key={"head_sha": "a" * 40},
        pointer_version=0,
        updated_at=NOW,
    )
    with factory(postgres_engine)() as unit:
        assert (
            unit.pointers.get(
                entity_kind=pointer.entity_kind,
                entity_id=pointer.entity_id,
            )
            is None
        )
        unit.observations.append(
            CanonicalObservationRecord(
                version_id=observation_id,
                entity_kind=pointer.entity_kind,
                entity_id=pointer.entity_id,
                schema_id="github-steward/coherent-analysis-view/v1",
                schema_version=1,
                observed_at=NOW,
                payload={"head_sha": "a" * 40},
                digest=Digest("6" * 64),
            )
        )
        assert unit.pointers.create_if_absent(pointer) is PointerCreateOutcome.CREATED
        assert (
            unit.pointers.get(
                entity_kind=pointer.entity_kind,
                entity_id=pointer.entity_id,
            )
            == pointer
        )
        unit.commit()


def test_profile_and_assessment_are_immutable_and_explicitly_linked(
    postgres_engine: Engine,
) -> None:
    profile_id = PreparednessProfileId("00000000-0000-0000-0000-000000000070")
    observation_id = ObservationVersionId("00000000-0000-0000-0000-000000000071")
    view_id = AnalysisViewId("00000000-0000-0000-0000-000000000072")
    assessment_id = PreparednessAssessmentId("00000000-0000-0000-0000-000000000073")
    root = PreparednessProfileRecord(
        profile_id=profile_id,
        version=1,
        repository_id=5174,
        effective_from=NOW,
        predecessor_profile_id=None,
        predecessor_profile_version=None,
        predecessor_digest=None,
        payload={"profile_id": profile_id, "version": 1},
        digest=Digest("7" * 64),
    )
    successor = PreparednessProfileRecord(
        profile_id=profile_id,
        version=2,
        repository_id=5174,
        effective_from=NOW + timedelta(seconds=1),
        predecessor_profile_id=profile_id,
        predecessor_profile_version=1,
        predecessor_digest=Digest("7" * 64),
        payload={"profile_id": profile_id, "version": 2},
        digest=Digest("8" * 64),
    )
    assessment = PreparednessAssessmentRecord(
        assessment_id=assessment_id,
        repository_id=5174,
        pull_number=17,
        head_sha="a" * 40,
        profile_id=profile_id,
        profile_version=1,
        profile_digest=Digest("7" * 64),
        analysis_view_id=view_id,
        analysis_view_digest=Digest("b" * 64),
        evidence_sealed_at=NOW,
        evaluated_at=NOW,
        verdict="READY_FOR_HUMAN_REVIEW",
        payload={"assessment_id": assessment_id, "verdict": "READY"},
        digest=Digest("9" * 64),
        evidence_observations=(("pull_request", observation_id),),
    )
    observation = CanonicalObservationRecord(
        version_id=observation_id,
        entity_kind="github_pull_request",
        entity_id="5174:17",
        schema_id="github-steward/github-evidence/v1",
        schema_version=1,
        observed_at=NOW,
        payload={"head_sha": "a" * 40},
        digest=Digest("a" * 64),
    )
    view = AnalysisViewRecord(
        view_id=view_id,
        schema_id="github-steward/coherent-analysis-view/v1",
        schema_version=1,
        payload={"evidence_sealed_at": "2026-07-31T12:00:00.123456Z"},
        digest=Digest("b" * 64),
        observation_versions=(("pull_request", observation_id),),
    )

    with factory(postgres_engine)() as unit:
        assert unit.profiles.get(profile_id=profile_id, version=1) is None
        assert unit.profiles.get_successor(profile_id=profile_id, version=1) is None
        unit.profiles.insert(root)
        assert unit.profiles.get(profile_id=profile_id, version=1) == root
        unit.profiles.insert(successor)
        assert (
            unit.profiles.get_successor(profile_id=profile_id, version=1) == successor
        )
        unit.observations.append(observation)
        unit.views.insert(view)
        unit.assessments.insert(assessment)
        unit.commit()

    with factory(postgres_engine)() as unit:
        unit.observations.append(observation)
        unit.views.insert(view)
        unit.assessments.insert(assessment)
        unit.commit()

    with (
        pytest.raises(ValueError, match="different immutable content"),
        factory(postgres_engine)() as unit,
    ):
        unit.observations.append(replace(observation, digest=Digest("c" * 64)))

    with (
        pytest.raises(ValueError, match="profile digest did not match"),
        factory(postgres_engine)() as unit,
    ):
        unit.assessments.insert(replace(assessment, profile_digest=Digest("c" * 64)))

    with (
        pytest.raises(ValueError, match="analysis-view digest did not match"),
        factory(postgres_engine)() as unit,
    ):
        unit.assessments.insert(
            replace(assessment, analysis_view_digest=Digest("c" * 64))
        )

    with (
        pytest.raises(ValueError, match="different immutable content"),
        factory(postgres_engine)() as unit,
    ):
        unit.assessments.insert(
            replace(
                assessment,
                payload={"assessment_id": assessment_id, "verdict": "CHANGED"},
                digest=Digest("c" * 64),
            )
        )

    with postgres_engine.connect() as connection:
        profile_count = connection.scalar(
            sa.select(sa.func.count()).select_from(preparedness_profile)
        )
        assert profile_count is not None
        assert profile_count >= 2
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(canonical_observation)
                .where(canonical_observation.c.observation_version_id == observation_id)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(analysis_view)
                .where(analysis_view.c.analysis_view_id == view_id)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(analysis_view_observation)
                .where(analysis_view_observation.c.analysis_view_id == view_id)
            )
            == 1
        )
        exact_binding = connection.execute(
            sa.select(
                preparedness_assessment.c.profile_id,
                preparedness_assessment.c.profile_version,
                preparedness_assessment.c.profile_digest_format,
                preparedness_assessment.c.profile_digest_value,
                preparedness_assessment.c.analysis_view_id,
                preparedness_assessment.c.analysis_view_digest_format,
                preparedness_assessment.c.analysis_view_digest_value,
            ).where(preparedness_assessment.c.assessment_id == assessment_id)
        ).one()
        assert (
            str(exact_binding.profile_id),
            exact_binding.profile_version,
            exact_binding.profile_digest_format,
            exact_binding.profile_digest_value,
            str(exact_binding.analysis_view_id),
            exact_binding.analysis_view_digest_format,
            exact_binding.analysis_view_digest_value,
        ) == (
            str(profile_id),
            1,
            "jcs-sha256/v1",
            "7" * 64,
            str(view_id),
            "jcs-sha256/v1",
            "b" * 64,
        )
        assert (
            connection.scalar(
                sa.select(preparedness_assessment_evidence.c.facet_role_id).where(
                    preparedness_assessment_evidence.c.assessment_id == assessment_id
                )
            )
            == "pull_request"
        )


def test_profile_successor_validation_fails_closed(
    postgres_engine: Engine,
) -> None:
    profile_id = PreparednessProfileId("00000000-0000-0000-0000-000000000080")
    root = PreparednessProfileRecord(
        profile_id=profile_id,
        version=1,
        repository_id=5180,
        effective_from=NOW,
        predecessor_profile_id=None,
        predecessor_profile_version=None,
        predecessor_digest=None,
        payload={"version": 1},
        digest=Digest("c" * 64),
    )
    with factory(postgres_engine)() as unit:
        unit.profiles.insert(root)
        with pytest.raises(ValueError, match="all-or-none"):
            unit.profiles.insert(
                PreparednessProfileRecord(
                    profile_id=profile_id,
                    version=2,
                    repository_id=5180,
                    effective_from=NOW + timedelta(seconds=1),
                    predecessor_profile_id=profile_id,
                    predecessor_profile_version=None,
                    predecessor_digest=Digest("c" * 64),
                    payload={"version": 2},
                    digest=Digest("d" * 64),
                )
            )
        with pytest.raises(ValueError, match="does not exist"):
            unit.profiles.insert(
                PreparednessProfileRecord(
                    profile_id=profile_id,
                    version=3,
                    repository_id=5180,
                    effective_from=NOW + timedelta(seconds=2),
                    predecessor_profile_id=profile_id,
                    predecessor_profile_version=2,
                    predecessor_digest=Digest("e" * 64),
                    payload={"version": 3},
                    digest=Digest("e" * 64),
                )
            )
        with pytest.raises(ValueError, match="repository differs"):
            unit.profiles.insert(
                PreparednessProfileRecord(
                    profile_id=profile_id,
                    version=2,
                    repository_id=5181,
                    effective_from=NOW + timedelta(seconds=1),
                    predecessor_profile_id=profile_id,
                    predecessor_profile_version=1,
                    predecessor_digest=Digest("c" * 64),
                    payload={"version": 2},
                    digest=Digest("f" * 64),
                )
            )
        with pytest.raises(ValueError, match="effective later"):
            unit.profiles.insert(
                PreparednessProfileRecord(
                    profile_id=profile_id,
                    version=2,
                    repository_id=5180,
                    effective_from=NOW,
                    predecessor_profile_id=profile_id,
                    predecessor_profile_version=1,
                    predecessor_digest=Digest("c" * 64),
                    payload={"version": 2},
                    digest=Digest("0" * 64),
                )
            )
        with pytest.raises(ValueError, match="predecessor digest differs"):
            unit.profiles.insert(
                PreparednessProfileRecord(
                    profile_id=profile_id,
                    version=2,
                    repository_id=5180,
                    effective_from=NOW + timedelta(seconds=1),
                    predecessor_profile_id=profile_id,
                    predecessor_profile_version=1,
                    predecessor_digest=Digest("1" * 64),
                    payload={"version": 2},
                    digest=Digest("2" * 64),
                )
            )
        unit.rollback()
