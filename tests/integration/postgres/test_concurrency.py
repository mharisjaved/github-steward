"""PostgreSQL uniqueness and SKIP LOCKED concurrency authority."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from threading import Barrier, Event, Thread

import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

from github_steward.adapters.canonicalization.rfc8785 import envelope_payload
from github_steward.adapters.postgres.metadata import (
    delivery_inbox,
    preparedness_assessment,
    preparedness_profile,
    work_attempt,
    work_record,
)
from github_steward.adapters.postgres.unit_of_work import PostgresUnitOfWork
from github_steward.application.local_processing import SyntheticReceiptService
from github_steward.domain.canonical import Digest
from github_steward.domain.processing import WorkState
from github_steward.ports.persistence import (
    AnalysisViewId,
    AnalysisViewRecord,
    ClaimOutcome,
    DeliveryIngressOutcome,
    PreparednessAssessmentId,
    PreparednessAssessmentRecord,
    PreparednessProfileId,
    PreparednessProfileRecord,
)

NOW = datetime(2026, 7, 31, 13, 0, 0, 654321, tzinfo=UTC)


class FixedClock:
    def now(self) -> datetime:
        return NOW


def mapping(sequence: int) -> dict[str, object]:
    return {
        "entity_kind": "pull_request",
        "entity_id": "concurrent",
        "observed_at": "2026-07-31T13:00:00.654321Z",
        "sequence": sequence,
        "expected_pointer_version": None,
        "observation": {"sequence": sequence},
    }


def service(engine: Engine) -> SyntheticReceiptService:
    return SyntheticReceiptService(
        unit_of_work_factory=lambda: PostgresUnitOfWork(engine),
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


def test_concurrent_same_digest_receipt_creates_exactly_one_work(
    postgres_engine: Engine,
) -> None:
    barrier = Barrier(4)
    outcomes: list[DeliveryIngressOutcome] = []

    def receive() -> None:
        barrier.wait()
        outcomes.append(
            service(postgres_engine)
            .receive(
                provider_delivery_id="concurrent-same",
                mapping=mapping(1),
            )
            .outcome
        )

    threads = [Thread(target=receive) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert outcomes.count(DeliveryIngressOutcome.CREATED) == 1
    assert outcomes.count(DeliveryIngressOutcome.DUPLICATE_SAME_DIGEST) == 3
    with postgres_engine.connect() as connection:
        delivery_id = connection.scalar(
            sa.select(delivery_inbox.c.delivery_id).where(
                delivery_inbox.c.provider_delivery_id == "concurrent-same"
            )
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(work_record)
                .where(work_record.c.delivery_id == delivery_id)
            )
            == 1
        )


def test_concurrent_different_digests_never_overwrite_durable_payload(
    postgres_engine: Engine,
) -> None:
    barrier = Barrier(2)
    outcomes: list[tuple[int, DeliveryIngressOutcome]] = []

    def receive(sequence: int) -> None:
        barrier.wait()
        outcome = service(postgres_engine).receive(
            provider_delivery_id="concurrent-conflict",
            mapping=mapping(sequence),
        )
        outcomes.append((sequence, outcome.outcome))

    threads = [Thread(target=receive, args=(sequence,)) for sequence in (2, 3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(outcome for _, outcome in outcomes) == sorted(
        [
            DeliveryIngressOutcome.CREATED,
            DeliveryIngressOutcome.INTEGRITY_FAILURE_DIFFERENT_DIGEST,
        ]
    )
    durable_sequence = next(
        sequence
        for sequence, outcome in outcomes
        if outcome is DeliveryIngressOutcome.CREATED
    )
    with postgres_engine.connect() as connection:
        row = (
            connection.execute(
                sa.select(
                    delivery_inbox.c.canonical_payload,
                    delivery_inbox.c.payload_digest,
                ).where(delivery_inbox.c.provider_delivery_id == "concurrent-conflict")
            )
            .mappings()
            .one()
        )
        assert row["canonical_payload"] == mapping(durable_sequence)
        assert (
            row["payload_digest"]
            == envelope_payload(mapping(durable_sequence)).digest.value
        )


def test_skip_locked_concurrent_claim_creates_one_unique_attempt(
    postgres_engine: Engine,
) -> None:
    retire_claimable(postgres_engine)
    created = service(postgres_engine).receive(
        provider_delivery_id="concurrent-claim",
        mapping=mapping(4),
    )
    barrier = Barrier(2)
    outcomes: list[ClaimOutcome] = []

    def claim(owner: str) -> None:
        with PostgresUnitOfWork(postgres_engine) as unit:
            barrier.wait()
            result = unit.work.claim_next(owner=owner, now=NOW)
            unit.commit()
        outcomes.append(result.outcome)

    threads = [Thread(target=claim, args=(f"worker-{number}",)) for number in (1, 2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(outcomes) == sorted([ClaimOutcome.CLAIMED, ClaimOutcome.NO_WORK])
    with postgres_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(work_attempt)
                .where(work_attempt.c.work_record_id == created.work_record_id)
            )
            == 1
        )
        row = connection.execute(
            sa.select(
                work_record.c.state,
                work_record.c.lease_owner,
                work_record.c.lease_token,
                work_record.c.lease_expires_at,
                work_record.c.version,
            ).where(work_record.c.work_record_id == created.work_record_id)
        ).one()
        assert row.state == WorkState.PROCESSING.value
        assert row.lease_owner in {"worker-1", "worker-2"}
        assert row.lease_token is not None
        assert row.lease_expires_at is not None
        assert row.version == 1


def test_competing_profile_successors_allow_exactly_one_commit(
    postgres_engine: Engine,
) -> None:
    profile_id = PreparednessProfileId("00000000-0000-0000-0000-000000000090")
    root = PreparednessProfileRecord(
        profile_id=profile_id,
        version=1,
        repository_id=5190,
        effective_from=NOW,
        predecessor_profile_id=None,
        predecessor_profile_version=None,
        payload={"version": 1},
        digest=Digest("1" * 64),
    )
    with PostgresUnitOfWork(postgres_engine) as unit:
        unit.profiles.insert(root)
        unit.commit()

    barrier = Barrier(2)
    outcomes: list[str] = []

    def create_successor(digest_character: str) -> None:
        successor = PreparednessProfileRecord(
            profile_id=profile_id,
            version=2,
            repository_id=5190,
            effective_from=NOW.replace(microsecond=654322),
            predecessor_profile_id=profile_id,
            predecessor_profile_version=1,
            payload={"version": 2, "candidate": digest_character},
            digest=Digest(digest_character * 64),
        )
        try:
            with PostgresUnitOfWork(postgres_engine) as unit:
                barrier.wait()
                unit.profiles.insert(successor)
                unit.commit()
            outcomes.append("committed")
        except IntegrityError:
            outcomes.append("rejected")

    threads = [
        Thread(target=create_successor, args=(character,)) for character in ("2", "3")
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(outcomes) == ["committed", "rejected"]
    with postgres_engine.connect() as connection:
        successors = list(
            connection.execute(
                sa.select(
                    preparedness_profile.c.predecessor_profile_id,
                    preparedness_profile.c.predecessor_profile_version,
                ).where(
                    preparedness_profile.c.profile_id == profile_id,
                    preparedness_profile.c.profile_version == 2,
                )
            ).tuples()
        )
    assert len(successors) == 1
    assert str(successors[0][0]) == profile_id
    assert successors[0][1] == 1


def test_assessment_lock_rejects_a_competing_backdated_successor(
    postgres_engine: Engine,
) -> None:
    profile_id = PreparednessProfileId("00000000-0000-0000-0000-000000000091")
    view_id = AnalysisViewId("00000000-0000-0000-0000-000000000092")
    assessment_id = PreparednessAssessmentId("00000000-0000-0000-0000-000000000093")
    repository_id = 5191
    evidence_sealed_at = NOW + timedelta(seconds=2)
    root = PreparednessProfileRecord(
        profile_id=profile_id,
        version=1,
        repository_id=repository_id,
        effective_from=NOW,
        predecessor_profile_id=None,
        predecessor_profile_version=None,
        payload={"version": 1},
        digest=Digest("4" * 64),
    )
    assessment = PreparednessAssessmentRecord(
        assessment_id=assessment_id,
        repository_id=repository_id,
        pull_number=91,
        head_sha="a" * 40,
        profile_id=profile_id,
        profile_version=1,
        analysis_view_id=view_id,
        evidence_sealed_at=evidence_sealed_at,
        evaluated_at=evidence_sealed_at,
        verdict="READY_FOR_HUMAN_REVIEW",
        payload={"assessment_id": assessment_id},
        digest=Digest("5" * 64),
        evidence_observations=(),
    )
    successor = PreparednessProfileRecord(
        profile_id=profile_id,
        version=2,
        repository_id=repository_id,
        effective_from=evidence_sealed_at,
        predecessor_profile_id=profile_id,
        predecessor_profile_version=1,
        payload={"version": 2},
        digest=Digest("6" * 64),
    )
    with PostgresUnitOfWork(postgres_engine) as unit:
        unit.profiles.insert(root)
        unit.views.insert(
            AnalysisViewRecord(
                view_id=view_id,
                schema_id="github-steward/coherent-analysis-view/v1",
                schema_version=1,
                payload={"evidence_sealed_at": evidence_sealed_at.isoformat()},
                digest=Digest("7" * 64),
                observation_versions=(),
            )
        )
        unit.commit()

    assessment_inserted = Event()
    release_assessment = Event()
    successor_attempting = Event()
    successor_finished = Event()
    outcomes: list[str] = []
    unexpected_errors: list[BaseException] = []
    rejection_messages: list[str] = []

    def create_assessment() -> None:
        try:
            with PostgresUnitOfWork(postgres_engine) as unit:
                locked = unit.profiles.get(profile_id=profile_id, version=1)
                if locked is None:
                    raise AssertionError("root profile disappeared")
                unit.assessments.insert(assessment)
                assessment_inserted.set()
                if not release_assessment.wait(timeout=10):
                    raise AssertionError("assessment commit was not released")
                unit.commit()
            outcomes.append("assessment_committed")
        except BaseException as exc:
            unexpected_errors.append(exc)

    def create_successor() -> None:
        try:
            if not assessment_inserted.wait(timeout=10):
                raise AssertionError(
                    "assessment was not inserted under the profile lock"
                )
            with PostgresUnitOfWork(postgres_engine) as unit:
                successor_attempting.set()
                unit.profiles.insert(successor)
                unit.commit()
            outcomes.append("successor_committed")
        except ValueError as exc:
            rejection_messages.append(str(exc))
            outcomes.append("successor_rejected")
        except BaseException as exc:
            unexpected_errors.append(exc)
        finally:
            successor_finished.set()

    threads = [Thread(target=create_assessment), Thread(target=create_successor)]
    for thread in threads:
        thread.start()
    assessment_was_inserted = assessment_inserted.wait(timeout=10)
    successor_did_attempt = successor_attempting.wait(timeout=10)
    successor_was_blocked = not successor_finished.wait(timeout=0.2)
    release_assessment.set()
    for thread in threads:
        thread.join(timeout=15)

    assert assessment_was_inserted
    assert successor_did_attempt
    assert successor_was_blocked
    assert not any(thread.is_alive() for thread in threads)
    assert unexpected_errors == []
    assert sorted(outcomes) == ["assessment_committed", "successor_rejected"]
    assert rejection_messages == [
        "profile successor cannot retroactively invalidate an assessment"
    ]
    with postgres_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(preparedness_assessment)
                .where(preparedness_assessment.c.assessment_id == assessment_id)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(preparedness_profile)
                .where(
                    preparedness_profile.c.profile_id == profile_id,
                    preparedness_profile.c.profile_version == 2,
                )
            )
            == 0
        )
