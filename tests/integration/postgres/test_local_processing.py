"""End-to-end durable local processing and T4/T5 fault boundaries."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from github_steward.adapters.canonicalization.rfc8785 import envelope_payload
from github_steward.adapters.postgres.metadata import (
    analysis_view,
    analysis_view_observation,
    audit_event,
    canonical_observation,
    current_observation_pointer,
    work_attempt,
    work_record,
)
from github_steward.adapters.postgres.unit_of_work import PostgresUnitOfWork
from github_steward.application.local_processing import (
    LocalProcessingService,
    ProcessedWork,
    SyntheticReceiptService,
)
from github_steward.domain.errors import (
    PermanentLocalProcessingError,
    RetryableLocalProcessingError,
)
from github_steward.domain.processing import (
    AttemptState,
    FaultPoint,
    PointerOutcome,
    ProcessingOutcome,
    WorkState,
)
from github_steward.ports.persistence import ClaimedWork, LeaseOperationOutcome

NOW = datetime(2026, 7, 31, 14, 0, 0, 222333, tzinfo=UTC)


class FixedClock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


class InjectedFault(RuntimeError):
    """Test-only deterministic fault."""


def mapping(
    *,
    entity_id: str,
    sequence: int,
    expected_pointer_version: int | None,
) -> dict[str, object]:
    return {
        "entity_kind": "pull_request",
        "entity_id": entity_id,
        "observed_at": "2026-07-31T14:00:00.222333Z",
        "sequence": sequence,
        "expected_pointer_version": expected_pointer_version,
        "observation": {"entity_id": entity_id, "sequence": sequence},
    }


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


def receive(
    engine: Engine,
    *,
    provider_id: str,
    entity_id: str,
    sequence: int = 1,
    expected_pointer_version: int | None = None,
) -> str:
    result = SyntheticReceiptService(
        unit_of_work_factory=lambda: PostgresUnitOfWork(engine),
        clock=FixedClock(),
        envelope_factory=envelope_payload,
    ).receive(
        provider_delivery_id=provider_id,
        mapping=mapping(
            entity_id=entity_id,
            sequence=sequence,
            expected_pointer_version=expected_pointer_version,
        ),
    )
    return result.work_record_id


def processor(
    engine: Engine,
    *,
    repository_fault: Callable[[FaultPoint], None] | None = None,
    service_fault: Callable[[FaultPoint], None] | None = None,
    deterministic_processor: Callable[[ClaimedWork], ProcessedWork] | None = None,
    clock: FixedClock | None = None,
) -> LocalProcessingService:
    return LocalProcessingService(
        unit_of_work_factory=lambda: PostgresUnitOfWork(engine, repository_fault),
        clock=clock or FixedClock(),
        envelope_factory=envelope_payload,
        processor=deterministic_processor,
        fault_injector=service_fault,
    )


def test_end_to_end_pointer_create_and_cas_conflict_are_successful(
    postgres_engine: Engine,
) -> None:
    retire_claimable(postgres_engine)
    first_work = receive(
        postgres_engine,
        provider_id="processing-create",
        entity_id="pointer-flow",
    )
    created = processor(postgres_engine).process_next(owner="worker")
    assert created.outcome is ProcessingOutcome.SUCCEEDED
    assert created.pointer_outcome is PointerOutcome.CREATED
    assert created.work_record_id == first_work

    second_work = receive(
        postgres_engine,
        provider_id="processing-update",
        entity_id="pointer-flow",
        sequence=2,
        expected_pointer_version=0,
    )
    updated = processor(postgres_engine).process_next(owner="worker")
    assert updated.pointer_outcome is PointerOutcome.UPDATED
    assert updated.work_record_id == second_work

    third_work = receive(
        postgres_engine,
        provider_id="processing-conflict",
        entity_id="pointer-flow",
        sequence=3,
        expected_pointer_version=0,
    )
    conflict = processor(postgres_engine).process_next(owner="worker")
    assert conflict.outcome is ProcessingOutcome.SUCCEEDED
    assert conflict.pointer_outcome is PointerOutcome.POINTER_CONFLICT
    assert conflict.work_record_id == third_work

    with postgres_engine.connect() as connection:
        pointer = connection.execute(
            sa.select(
                current_observation_pointer.c.pointer_version,
                current_observation_pointer.c.ordering_key,
            ).where(
                current_observation_pointer.c.entity_kind == "pull_request",
                current_observation_pointer.c.entity_id == "pointer-flow",
            )
        ).one()
        assert pointer == (1, {"sequence": "2"})
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(canonical_observation)
                .where(canonical_observation.c.entity_id == "pointer-flow")
            )
            == 3
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(analysis_view_observation)
                .join(
                    canonical_observation,
                    canonical_observation.c.observation_version_id
                    == analysis_view_observation.c.observation_version_id,
                )
                .where(canonical_observation.c.entity_id == "pointer-flow")
            )
            == 3
        )
        audit_payloads = list(
            connection.execute(
                sa.select(audit_event.c.canonical_payload).where(
                    audit_event.c.event_kind == "LOCAL_PROCESSING_SUCCEEDED",
                    audit_event.c.canonical_payload["work_record_id"].as_string()
                    == third_work,
                )
            ).scalars()
        )
        assert audit_payloads[0]["pointer_outcome"] == "POINTER_CONFLICT"


@pytest.mark.parametrize(
    "fault_point",
    [
        FaultPoint.AFTER_OBSERVATION_INSERT,
        FaultPoint.AFTER_ANALYSIS_VIEW_INSERT,
        FaultPoint.AFTER_ASSOCIATION_INSERT,
        FaultPoint.AFTER_POINTER_WRITE,
        FaultPoint.AFTER_AUDIT_INSERT,
        FaultPoint.AFTER_ATTEMPT_COMPLETION,
        FaultPoint.AFTER_WORK_COMPLETION,
    ],
)
def test_every_completion_fault_rolls_back_t4_and_preserves_claim(
    postgres_engine: Engine,
    fault_point: FaultPoint,
) -> None:
    retire_claimable(postgres_engine)
    entity = f"fault-{fault_point.value}"
    work_id = receive(
        postgres_engine,
        provider_id=entity,
        entity_id=entity,
    )

    def inject(point: FaultPoint) -> None:
        if point is fault_point:
            raise InjectedFault(point.value)

    with pytest.raises(InjectedFault):
        processor(postgres_engine, repository_fault=inject).process_next(owner="worker")
    with postgres_engine.connect() as connection:
        work = connection.execute(
            sa.select(work_record.c.state, work_record.c.lease_token).where(
                work_record.c.work_record_id == work_id
            )
        ).one()
        assert work.state == WorkState.PROCESSING.value
        assert work.lease_token is not None
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(work_attempt)
                .where(
                    work_attempt.c.work_record_id == work_id,
                    work_attempt.c.state == AttemptState.STARTED.value,
                )
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(canonical_observation)
                .where(canonical_observation.c.entity_id == entity)
            )
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(audit_event)
                .where(
                    audit_event.c.canonical_payload["work_record_id"].as_string()
                    == work_id
                )
            )
            == 0
        )


def test_completion_commit_before_acknowledgement_is_durable_and_not_replayed(
    postgres_engine: Engine,
) -> None:
    retire_claimable(postgres_engine)
    work_id = receive(
        postgres_engine,
        provider_id="commit-before-ack",
        entity_id="commit-before-ack",
    )

    def inject(point: FaultPoint) -> None:
        if point is FaultPoint.AFTER_COMPLETION_COMMIT:
            raise InjectedFault(point.value)

    with pytest.raises(InjectedFault):
        processor(postgres_engine, service_fault=inject).process_next(owner="worker")
    replay = processor(postgres_engine).process_next(owner="worker")
    assert replay.outcome is ProcessingOutcome.NO_WORK
    with postgres_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(work_record.c.state).where(
                    work_record.c.work_record_id == work_id
                )
            )
            == WorkState.SUCCEEDED.value
        )
        for table in (canonical_observation, analysis_view, audit_event):
            assert (
                int(
                    connection.scalar(sa.select(sa.func.count()).select_from(table))
                    or 0
                )
                >= 1
            )
        assert (
            int(
                connection.scalar(
                    sa.select(sa.func.count()).select_from(analysis_view_observation)
                )
                or 0
            )
            >= 1
        )


@pytest.mark.parametrize(
    ("failure", "expected_outcome", "expected_attempt", "expected_work"),
    [
        (
            RetryableLocalProcessingError("retry"),
            ProcessingOutcome.RETRY_SCHEDULED,
            AttemptState.RETRYABLE_FAILURE,
            WorkState.RETRY_WAIT,
        ),
        (
            PermanentLocalProcessingError("permanent"),
            ProcessingOutcome.FAILED,
            AttemptState.TERMINAL_FAILURE,
            WorkState.FAILED,
        ),
        (
            RuntimeError("unexpected"),
            ProcessingOutcome.FAILED,
            AttemptState.TERMINAL_FAILURE,
            WorkState.FAILED,
        ),
    ],
)
def test_processor_errors_receive_exact_classification(
    postgres_engine: Engine,
    failure: Exception,
    expected_outcome: ProcessingOutcome,
    expected_attempt: AttemptState,
    expected_work: WorkState,
) -> None:
    retire_claimable(postgres_engine)
    identity = f"classification-{type(failure).__name__}"
    work_id = receive(
        postgres_engine,
        provider_id=identity,
        entity_id=identity,
    )

    def fail(_: ClaimedWork) -> ProcessedWork:
        raise failure

    result = processor(
        postgres_engine,
        deterministic_processor=fail,
    ).process_next(owner="worker")
    assert result.outcome is expected_outcome
    with postgres_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(work_record.c.state).where(
                    work_record.c.work_record_id == work_id
                )
            )
            == expected_work.value
        )
        assert (
            connection.scalar(
                sa.select(work_attempt.c.state).where(
                    work_attempt.c.work_record_id == work_id
                )
            )
            == expected_attempt.value
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(canonical_observation)
                .where(canonical_observation.c.entity_id == identity)
            )
            == 0
        )


def test_retry_delay_retains_microseconds(postgres_engine: Engine) -> None:
    retire_claimable(postgres_engine)
    clock = FixedClock(NOW)
    work_id = receive(
        postgres_engine,
        provider_id="retry-microseconds",
        entity_id="retry-microseconds",
    )

    def fail(_: ClaimedWork) -> ProcessedWork:
        raise RetryableLocalProcessingError

    result = processor(
        postgres_engine,
        deterministic_processor=fail,
        clock=clock,
    ).process_next(owner="worker")
    assert result.outcome is ProcessingOutcome.RETRY_SCHEDULED
    with postgres_engine.connect() as connection:
        assert connection.scalar(
            sa.select(work_record.c.available_at).where(
                work_record.c.work_record_id == work_id
            )
        ) == NOW + timedelta(seconds=60)


def test_invalid_public_service_identity_inputs_fail_before_transaction(
    postgres_engine: Engine,
) -> None:
    receipt = SyntheticReceiptService(
        unit_of_work_factory=lambda: PostgresUnitOfWork(postgres_engine),
        clock=FixedClock(),
        envelope_factory=envelope_payload,
    )
    with pytest.raises(ValueError, match="provider_delivery_id"):
        receipt.receive(
            provider_delivery_id="",
            mapping=mapping(
                entity_id="invalid",
                sequence=1,
                expected_pointer_version=None,
            ),
        )
    with pytest.raises(ValueError, match="owner"):
        processor(postgres_engine).process_next(owner="")


def test_existing_pointer_conflicts_when_expected_version_is_null(
    postgres_engine: Engine,
) -> None:
    retire_claimable(postgres_engine)
    receive(
        postgres_engine,
        provider_id="create-conflict-first",
        entity_id="create-conflict",
    )
    assert (
        processor(postgres_engine).process_next(owner="worker").pointer_outcome
        is PointerOutcome.CREATED
    )
    receive(
        postgres_engine,
        provider_id="create-conflict-second",
        entity_id="create-conflict",
    )
    assert (
        processor(postgres_engine).process_next(owner="worker").pointer_outcome
        is PointerOutcome.POINTER_CONFLICT
    )


def test_stale_completion_rolls_back_outputs_and_returns_lease_lost(
    postgres_engine: Engine,
) -> None:
    retire_claimable(postgres_engine)
    work_id = receive(
        postgres_engine,
        provider_id="stale-completion",
        entity_id="stale-completion",
    )
    default = processor(postgres_engine)

    def renew_during_processing(claimed: ClaimedWork) -> ProcessedWork:
        renewal = processor(postgres_engine).renew(lease=claimed.lease)
        assert renewal.outcome is LeaseOperationOutcome.SUCCEEDED
        return default._deterministic_processor(claimed)

    result = processor(
        postgres_engine,
        deterministic_processor=renew_during_processing,
    ).process_next(owner="worker")
    assert result.outcome is ProcessingOutcome.LEASE_LOST
    with postgres_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(work_record.c.state).where(
                    work_record.c.work_record_id == work_id
                )
            )
            == WorkState.PROCESSING.value
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(canonical_observation)
                .where(canonical_observation.c.entity_id == "stale-completion")
            )
            == 0
        )


def test_stale_failure_rolls_back_audit_and_returns_lease_lost(
    postgres_engine: Engine,
) -> None:
    retire_claimable(postgres_engine)
    work_id = receive(
        postgres_engine,
        provider_id="stale-failure",
        entity_id="stale-failure",
    )

    def renew_then_fail(claimed: ClaimedWork) -> ProcessedWork:
        renewal = processor(postgres_engine).renew(lease=claimed.lease)
        assert renewal.outcome is LeaseOperationOutcome.SUCCEEDED
        raise RetryableLocalProcessingError

    result = processor(
        postgres_engine,
        deterministic_processor=renew_then_fail,
    ).process_next(owner="worker")
    assert result.outcome is ProcessingOutcome.LEASE_LOST
    with postgres_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(work_record.c.state).where(
                    work_record.c.work_record_id == work_id
                )
            )
            == WorkState.PROCESSING.value
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(audit_event)
                .where(
                    audit_event.c.canonical_payload["work_record_id"].as_string()
                    == work_id
                )
            )
            == 0
        )


def test_classified_failure_fault_rolls_back_t5(postgres_engine: Engine) -> None:
    retire_claimable(postgres_engine)
    work_id = receive(
        postgres_engine,
        provider_id="t5-fault",
        entity_id="t5-fault",
    )

    def fail(_: ClaimedWork) -> ProcessedWork:
        raise RetryableLocalProcessingError

    def inject(point: FaultPoint) -> None:
        if point is FaultPoint.AFTER_AUDIT_INSERT:
            raise InjectedFault(point.value)

    with pytest.raises(InjectedFault):
        processor(
            postgres_engine,
            repository_fault=inject,
            deterministic_processor=fail,
        ).process_next(owner="worker")
    with postgres_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(work_record.c.state).where(
                    work_record.c.work_record_id == work_id
                )
            )
            == WorkState.PROCESSING.value
        )
        assert (
            connection.scalar(
                sa.select(work_attempt.c.state).where(
                    work_attempt.c.work_record_id == work_id
                )
            )
            == AttemptState.STARTED.value
        )


def test_third_retryable_failure_reaches_attempt_ceiling(
    postgres_engine: Engine,
) -> None:
    retire_claimable(postgres_engine)
    work_id = receive(
        postgres_engine,
        provider_id="retry-ceiling",
        entity_id="retry-ceiling",
    )

    def fail(_: ClaimedWork) -> ProcessedWork:
        raise RetryableLocalProcessingError

    for attempt in range(1, 4):
        result = processor(
            postgres_engine,
            deterministic_processor=fail,
            clock=FixedClock(NOW + timedelta(seconds=60 * (attempt - 1))),
        ).process_next(owner="worker")
    assert result.outcome is ProcessingOutcome.FAILED
    with postgres_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(work_record.c.state).where(
                    work_record.c.work_record_id == work_id
                )
            )
            == WorkState.FAILED.value
        )
        assert (
            list(
                connection.execute(
                    sa.select(work_attempt.c.state)
                    .where(work_attempt.c.work_record_id == work_id)
                    .order_by(work_attempt.c.attempt_number)
                ).scalars()
            )
            == [AttemptState.RETRYABLE_FAILURE.value] * 3
        )
