"""Synchronous SQLAlchemy Core PostgreSQL repository adapters."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import Connection

from github_steward.adapters.postgres.metadata import (
    analysis_view,
    analysis_view_observation,
    audit_event,
    canonical_observation,
    current_observation_pointer,
    delivery_inbox,
    preparedness_assessment,
    preparedness_assessment_evidence,
    preparedness_profile,
    work_attempt,
    work_record,
)
from github_steward.domain.canonical import Digest, to_json_compatible
from github_steward.domain.processing import (
    LEASE_DURATION_SECONDS,
    RECONCILIATION_BATCH_LIMIT,
    RETRY_DELAY_SECONDS,
    AttemptState,
    FailureKind,
    FaultPoint,
    WorkState,
    retry_work_state,
    work_attempt_id,
)
from github_steward.ports.persistence import (
    AnalysisViewRecord,
    AuditEventRecord,
    CanonicalObservationRecord,
    ClaimedWork,
    ClaimOutcome,
    ClaimResult,
    Delivery,
    DeliveryId,
    DeliveryIngressOutcome,
    DeliveryIngressResult,
    LeaseOperationOutcome,
    LeaseOperationResult,
    LeaseToken,
    ObservationPointer,
    ObservationVersionId,
    PointerCreateOutcome,
    PreparednessAssessmentRecord,
    PreparednessProfileId,
    PreparednessProfileRecord,
    ReconciliationResult,
    WorkAttemptId,
    WorkLease,
    WorkRecord,
    WorkRecordId,
)

type FaultInjector = Callable[[FaultPoint], None]


def _no_fault(_: FaultPoint) -> None:
    return None


def _uuid(value: str) -> UUID:
    return UUID(value)


def _require_exact_replay(
    existing: Mapping[str, object],
    expected: Mapping[str, object],
    label: str,
) -> None:
    if any(existing[key] != value for key, value in expected.items()):
        raise ValueError(f"{label} identity collided with different immutable content")


class PostgresInboxWorkRepository:
    """Atomic idempotent delivery and one-work-record persistence."""

    def __init__(
        self,
        connection: Connection,
        fault_injector: FaultInjector | None = None,
    ) -> None:
        self._connection = connection
        self._fault = fault_injector or _no_fault

    def create_delivery_and_work(
        self,
        *,
        delivery: Delivery,
        work: WorkRecord,
    ) -> DeliveryIngressResult:
        self._connection.execute(
            sa.select(
                sa.func.pg_advisory_xact_lock(
                    sa.func.hashtext(delivery.provider),
                    sa.func.hashtext(delivery.provider_delivery_id),
                )
            )
        )
        statement = (
            pg_insert(delivery_inbox)
            .values(
                delivery_id=_uuid(delivery.delivery_id),
                provider=delivery.provider,
                provider_delivery_id=delivery.provider_delivery_id,
                payload_digest=delivery.payload_digest.value,
                received_at=delivery.received_at,
                payload_schema_id=delivery.payload_schema_id,
                payload_schema_version=delivery.payload_schema_version,
                canonical_payload=to_json_compatible(delivery.payload),
                payload_digest_format=delivery.payload_digest.format,
            )
            .on_conflict_do_nothing(
                index_elements=[
                    delivery_inbox.c.provider,
                    delivery_inbox.c.provider_delivery_id,
                ]
            )
            .returning(delivery_inbox.c.delivery_id)
        )
        inserted = self._connection.execute(statement).scalar_one_or_none()
        if inserted is not None:
            self._fault(FaultPoint.AFTER_INBOX_INSERT)
            self._connection.execute(
                work_record.insert().values(
                    work_record_id=_uuid(work.work_record_id),
                    delivery_id=_uuid(work.delivery_id),
                    work_type=work.work_type,
                    state=WorkState.AVAILABLE.value,
                    available_at=work.available_at,
                )
            )
            return DeliveryIngressResult(
                outcome=DeliveryIngressOutcome.CREATED,
                delivery_id=delivery.delivery_id,
                work_record_id=work.work_record_id,
            )

        original = (
            self._connection.execute(
                sa.select(
                    delivery_inbox.c.delivery_id,
                    delivery_inbox.c.payload_digest,
                    work_record.c.work_record_id,
                )
                .join(
                    work_record,
                    work_record.c.delivery_id == delivery_inbox.c.delivery_id,
                )
                .where(
                    delivery_inbox.c.provider == delivery.provider,
                    delivery_inbox.c.provider_delivery_id
                    == delivery.provider_delivery_id,
                )
            )
            .mappings()
            .one()
        )
        outcome = (
            DeliveryIngressOutcome.DUPLICATE_SAME_DIGEST
            if original["payload_digest"] == delivery.payload_digest.value
            else DeliveryIngressOutcome.INTEGRITY_FAILURE_DIFFERENT_DIGEST
        )
        return DeliveryIngressResult(
            outcome=outcome,
            delivery_id=DeliveryId(str(original["delivery_id"])),
            work_record_id=WorkRecordId(str(original["work_record_id"])),
        )


class PostgresWorkRepository:
    """Guarded lease and bounded durable processing operations."""

    def __init__(
        self,
        connection: Connection,
        fault_injector: FaultInjector | None = None,
    ) -> None:
        self._connection = connection
        self._fault = fault_injector or _no_fault

    def acquire(
        self,
        *,
        work_record_id: WorkRecordId,
        owner: str,
        token: LeaseToken,
        now: datetime,
        expires_at: datetime,
        expected_version: int,
    ) -> WorkLease | None:
        result = self._connection.execute(
            work_record.update()
            .where(
                work_record.c.work_record_id == _uuid(work_record_id),
                work_record.c.state.in_(
                    [WorkState.AVAILABLE.value, WorkState.RETRY_WAIT.value]
                ),
                work_record.c.available_at <= now,
                work_record.c.lease_token.is_(None),
                work_record.c.version == expected_version,
            )
            .values(
                state=WorkState.PROCESSING.value,
                lease_owner=owner,
                lease_token=_uuid(token),
                lease_expires_at=expires_at,
                version=work_record.c.version + 1,
                updated_at=now,
            )
            .returning(work_record.c.version)
        ).scalar_one_or_none()
        if result is None:
            return None
        return WorkLease(
            work_record_id=work_record_id,
            owner=owner,
            token=token,
            expires_at=expires_at,
            version=int(result),
        )

    def release(self, *, lease: WorkLease, now: datetime) -> bool:
        if not self._lock_owned(lease):
            return False
        active_attempt = self._connection.scalar(
            sa.select(sa.func.max(work_attempt.c.attempt_number)).where(
                work_attempt.c.work_record_id == _uuid(lease.work_record_id),
                work_attempt.c.state == AttemptState.STARTED.value,
                work_attempt.c.completed_at.is_(None),
            )
        )
        state = WorkState.AVAILABLE
        if active_attempt is not None:
            self._connection.execute(
                work_attempt.update()
                .where(
                    work_attempt.c.work_record_id == _uuid(lease.work_record_id),
                    work_attempt.c.attempt_number == active_attempt,
                    work_attempt.c.state == AttemptState.STARTED.value,
                )
                .values(state=AttemptState.ABANDONED.value, completed_at=now)
            )
            state = retry_work_state(int(active_attempt))
        result = self._connection.execute(
            work_record.update()
            .where(*self._ownership_predicates(lease))
            .values(
                state=state.value,
                available_at=now,
                lease_owner=None,
                lease_token=None,
                lease_expires_at=None,
                version=work_record.c.version + 1,
                updated_at=now,
            )
        )
        return result.rowcount == 1

    def claim_next(self, *, owner: str, now: datetime) -> ClaimResult:
        row = (
            self._connection.execute(
                sa.select(
                    work_record.c.work_record_id,
                    work_record.c.delivery_id,
                    work_record.c.version,
                    delivery_inbox.c.canonical_payload,
                    delivery_inbox.c.payload_digest,
                    delivery_inbox.c.payload_digest_format,
                )
                .join(
                    delivery_inbox,
                    delivery_inbox.c.delivery_id == work_record.c.delivery_id,
                )
                .where(
                    work_record.c.state.in_(
                        [WorkState.AVAILABLE.value, WorkState.RETRY_WAIT.value]
                    ),
                    work_record.c.available_at <= now,
                    work_record.c.lease_token.is_(None),
                )
                .order_by(work_record.c.available_at, work_record.c.work_record_id)
                .with_for_update(skip_locked=True, of=work_record)
                .limit(1)
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return ClaimResult(ClaimOutcome.NO_WORK, None)

        work_id = WorkRecordId(str(row["work_record_id"]))
        attempt_number = (
            int(
                self._connection.scalar(
                    sa.select(
                        sa.func.coalesce(sa.func.max(work_attempt.c.attempt_number), 0)
                    ).where(work_attempt.c.work_record_id == row["work_record_id"])
                )
                or 0
            )
            + 1
        )
        token = LeaseToken(str(uuid4()))
        expiry = now + timedelta(seconds=LEASE_DURATION_SECONDS)
        new_version = int(row["version"]) + 1
        self._connection.execute(
            work_record.update()
            .where(
                work_record.c.work_record_id == row["work_record_id"],
                work_record.c.version == row["version"],
            )
            .values(
                state=WorkState.PROCESSING.value,
                lease_owner=owner,
                lease_token=_uuid(token),
                lease_expires_at=expiry,
                version=new_version,
                updated_at=now,
            )
        )
        self._fault(FaultPoint.AFTER_CLAIM_UPDATE)

        attempt_identifier = WorkAttemptId(work_attempt_id(work_id, attempt_number))
        self._connection.execute(
            work_attempt.insert().values(
                work_attempt_id=_uuid(attempt_identifier),
                work_record_id=row["work_record_id"],
                attempt_number=attempt_number,
                state=AttemptState.STARTED.value,
                started_at=now,
            )
        )
        self._fault(FaultPoint.AFTER_ATTEMPT_INSERT)
        lease = WorkLease(
            work_record_id=work_id,
            owner=owner,
            token=token,
            expires_at=expiry,
            version=new_version,
        )
        return ClaimResult(
            ClaimOutcome.CLAIMED,
            ClaimedWork(
                lease=lease,
                attempt_id=attempt_identifier,
                attempt_number=attempt_number,
                delivery_id=DeliveryId(str(row["delivery_id"])),
                payload=row["canonical_payload"],
                payload_digest=Digest(
                    value=str(row["payload_digest"]),
                    format=str(row["payload_digest_format"]),
                ),
            ),
        )

    def renew(self, *, lease: WorkLease, now: datetime) -> LeaseOperationResult:
        new_expiry = now + timedelta(seconds=LEASE_DURATION_SECONDS)
        row = self._connection.execute(
            work_record.update()
            .where(
                *self._ownership_predicates(lease),
                now < work_record.c.lease_expires_at,
            )
            .values(
                lease_expires_at=new_expiry,
                version=work_record.c.version + 1,
                updated_at=now,
            )
            .returning(work_record.c.version)
        ).scalar_one_or_none()
        if row is None:
            return LeaseOperationResult(LeaseOperationOutcome.STALE)
        renewed = WorkLease(
            work_record_id=lease.work_record_id,
            owner=lease.owner,
            token=lease.token,
            expires_at=new_expiry,
            version=int(row),
        )
        return LeaseOperationResult(LeaseOperationOutcome.SUCCEEDED, lease=renewed)

    def complete_success(
        self,
        *,
        lease: WorkLease,
        attempt_number: int,
        now: datetime,
    ) -> LeaseOperationResult:
        if not self._lock_owned(lease):
            return LeaseOperationResult(LeaseOperationOutcome.STALE)
        completed = self._complete_attempt(
            lease=lease,
            attempt_number=attempt_number,
            state=AttemptState.SUCCEEDED,
            now=now,
        )
        if not completed:
            return LeaseOperationResult(LeaseOperationOutcome.STALE)
        self._fault(FaultPoint.AFTER_ATTEMPT_COMPLETION)
        self._finish_work(lease=lease, state=WorkState.SUCCEEDED, now=now)
        self._fault(FaultPoint.AFTER_WORK_COMPLETION)
        return LeaseOperationResult(
            LeaseOperationOutcome.SUCCEEDED,
            work_state=WorkState.SUCCEEDED,
        )

    def complete_failure(
        self,
        *,
        lease: WorkLease,
        attempt_number: int,
        now: datetime,
        failure_kind: FailureKind,
    ) -> LeaseOperationResult:
        if not self._lock_owned(lease):
            return LeaseOperationResult(LeaseOperationOutcome.STALE)
        retryable = failure_kind is FailureKind.RETRYABLE_LOCAL_PROCESSING
        attempt_state = (
            AttemptState.RETRYABLE_FAILURE
            if retryable
            else AttemptState.TERMINAL_FAILURE
        )
        completed = self._complete_attempt(
            lease=lease,
            attempt_number=attempt_number,
            state=attempt_state,
            now=now,
        )
        if not completed:
            return LeaseOperationResult(LeaseOperationOutcome.STALE)
        self._fault(FaultPoint.AFTER_ATTEMPT_COMPLETION)
        state = retry_work_state(attempt_number) if retryable else WorkState.FAILED
        available_at = (
            now + timedelta(seconds=RETRY_DELAY_SECONDS)
            if state is WorkState.RETRY_WAIT
            else None
        )
        self._finish_work(
            lease=lease,
            state=state,
            now=now,
            available_at=available_at,
        )
        self._fault(FaultPoint.AFTER_WORK_COMPLETION)
        return LeaseOperationResult(
            LeaseOperationOutcome.SUCCEEDED,
            work_state=state,
        )

    def reconcile_expired(self, *, now: datetime) -> ReconciliationResult:
        rows = list(
            self._connection.execute(
                sa.select(work_record.c.work_record_id, work_record.c.version)
                .where(
                    work_record.c.state == WorkState.PROCESSING.value,
                    work_record.c.lease_expires_at <= now,
                )
                .order_by(
                    work_record.c.lease_expires_at,
                    work_record.c.work_record_id,
                )
                .with_for_update(skip_locked=True)
                .limit(RECONCILIATION_BATCH_LIMIT)
            ).mappings()
        )
        retry_scheduled = 0
        terminally_failed = 0
        for row in rows:
            attempt_number = self._connection.scalar(
                sa.select(sa.func.max(work_attempt.c.attempt_number)).where(
                    work_attempt.c.work_record_id == row["work_record_id"]
                )
            )
            if attempt_number is None:
                raise RuntimeError("processing work has no durable attempt")
            self._connection.execute(
                work_attempt.update()
                .where(
                    work_attempt.c.work_record_id == row["work_record_id"],
                    work_attempt.c.attempt_number == attempt_number,
                    work_attempt.c.state == AttemptState.STARTED.value,
                    work_attempt.c.completed_at.is_(None),
                )
                .values(state=AttemptState.ABANDONED.value, completed_at=now)
            )
            state = retry_work_state(int(attempt_number))
            if state is WorkState.RETRY_WAIT:
                retry_scheduled += 1
            else:
                terminally_failed += 1
            values: dict[str, object] = {
                "state": state.value,
                "lease_owner": None,
                "lease_token": None,
                "lease_expires_at": None,
                "version": int(row["version"]) + 1,
                "updated_at": now,
            }
            if state is WorkState.RETRY_WAIT:
                values["available_at"] = now
            self._connection.execute(
                work_record.update()
                .where(
                    work_record.c.work_record_id == row["work_record_id"],
                    work_record.c.version == row["version"],
                )
                .values(**values)
            )
            self._fault(FaultPoint.DURING_RECONCILIATION)
        return ReconciliationResult(
            reconciled=len(rows),
            retry_scheduled=retry_scheduled,
            terminally_failed=terminally_failed,
        )

    @staticmethod
    def _ownership_predicates(lease: WorkLease) -> tuple[sa.ColumnElement[bool], ...]:
        return (
            work_record.c.work_record_id == _uuid(lease.work_record_id),
            work_record.c.state == WorkState.PROCESSING.value,
            work_record.c.lease_token == _uuid(lease.token),
            work_record.c.version == lease.version,
        )

    def _lock_owned(self, lease: WorkLease) -> bool:
        return (
            self._connection.scalar(
                sa.select(work_record.c.work_record_id)
                .where(*self._ownership_predicates(lease))
                .with_for_update()
            )
            is not None
        )

    def _complete_attempt(
        self,
        *,
        lease: WorkLease,
        attempt_number: int,
        state: AttemptState,
        now: datetime,
    ) -> bool:
        result = self._connection.execute(
            work_attempt.update()
            .where(
                work_attempt.c.work_record_id == _uuid(lease.work_record_id),
                work_attempt.c.attempt_number == attempt_number,
                work_attempt.c.state == AttemptState.STARTED.value,
                work_attempt.c.completed_at.is_(None),
            )
            .values(state=state.value, completed_at=now)
        )
        return result.rowcount == 1

    def _finish_work(
        self,
        *,
        lease: WorkLease,
        state: WorkState,
        now: datetime,
        available_at: datetime | None = None,
    ) -> None:
        values: dict[str, object] = {
            "state": state.value,
            "lease_owner": None,
            "lease_token": None,
            "lease_expires_at": None,
            "version": work_record.c.version + 1,
            "updated_at": now,
        }
        if available_at is not None:
            values["available_at"] = available_at
        self._connection.execute(
            work_record.update()
            .where(*self._ownership_predicates(lease))
            .values(**values)
        )


class PostgresCanonicalObservationRepository:
    """Append-only canonical-observation adapter."""

    def __init__(
        self,
        connection: Connection,
        fault_injector: FaultInjector | None = None,
    ) -> None:
        self._connection = connection
        self._fault = fault_injector or _no_fault

    def append(self, observation: CanonicalObservationRecord) -> None:
        values: dict[str, object] = {
            "observation_version_id": _uuid(observation.version_id),
            "entity_kind": observation.entity_kind,
            "entity_id": observation.entity_id,
            "schema_id": observation.schema_id,
            "schema_version": observation.schema_version,
            "observed_at": observation.observed_at,
            "canonical_payload": to_json_compatible(observation.payload),
            "digest_format": observation.digest.format,
            "digest_value": observation.digest.value,
        }
        inserted = self._connection.execute(
            pg_insert(canonical_observation)
            .values(**values)
            .on_conflict_do_nothing(
                index_elements=[canonical_observation.c.observation_version_id]
            )
            .returning(canonical_observation.c.observation_version_id)
        ).scalar_one_or_none()
        if inserted is None:
            existing = (
                self._connection.execute(
                    sa.select(canonical_observation).where(
                        canonical_observation.c.observation_version_id
                        == values["observation_version_id"]
                    )
                )
                .mappings()
                .one()
            )
            _require_exact_replay(
                cast(Mapping[str, object], existing),
                values,
                "canonical observation",
            )
            return
        self._fault(FaultPoint.AFTER_OBSERVATION_INSERT)


class PostgresCurrentObservationPointerRepository:
    """Entity-coupled pointer create and compare-and-swap adapter."""

    def __init__(
        self,
        connection: Connection,
        fault_injector: FaultInjector | None = None,
    ) -> None:
        self._connection = connection
        self._fault = fault_injector or _no_fault

    def create_if_absent(
        self,
        pointer: ObservationPointer,
    ) -> PointerCreateOutcome:
        inserted = self._connection.execute(
            pg_insert(current_observation_pointer)
            .values(**self._values(pointer))
            .on_conflict_do_nothing(
                index_elements=[
                    current_observation_pointer.c.entity_kind,
                    current_observation_pointer.c.entity_id,
                ]
            )
            .returning(current_observation_pointer.c.pointer_version)
        ).scalar_one_or_none()
        self._fault(FaultPoint.AFTER_POINTER_WRITE)
        if inserted is None:
            return PointerCreateOutcome.CONFLICT
        return PointerCreateOutcome.CREATED

    def get(self, *, entity_kind: str, entity_id: str) -> ObservationPointer | None:
        row = (
            self._connection.execute(
                sa.select(current_observation_pointer).where(
                    current_observation_pointer.c.entity_kind == entity_kind,
                    current_observation_pointer.c.entity_id == entity_id,
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None
        return ObservationPointer(
            entity_kind=str(row["entity_kind"]),
            entity_id=str(row["entity_id"]),
            observation_version_id=ObservationVersionId(
                str(row["observation_version_id"])
            ),
            ordering_key=row["ordering_key"],
            pointer_version=int(row["pointer_version"]),
            updated_at=row["updated_at"],
        )

    def compare_and_swap(
        self,
        *,
        expected_version: int,
        replacement: ObservationPointer,
    ) -> bool:
        if replacement.pointer_version != expected_version + 1:
            raise ValueError("replacement pointer version must increment by one")
        result = self._connection.execute(
            current_observation_pointer.update()
            .where(
                current_observation_pointer.c.entity_kind == replacement.entity_kind,
                current_observation_pointer.c.entity_id == replacement.entity_id,
                current_observation_pointer.c.pointer_version == expected_version,
            )
            .values(**self._values(replacement))
        )
        self._fault(FaultPoint.AFTER_POINTER_WRITE)
        return result.rowcount == 1

    @staticmethod
    def _values(pointer: ObservationPointer) -> dict[str, object]:
        return {
            "entity_kind": pointer.entity_kind,
            "entity_id": pointer.entity_id,
            "observation_version_id": _uuid(pointer.observation_version_id),
            "ordering_key": to_json_compatible(pointer.ordering_key),
            "pointer_version": pointer.pointer_version,
            "updated_at": pointer.updated_at,
        }


class PostgresAnalysisViewRepository:
    """Append-only analysis view and association adapter."""

    def __init__(
        self,
        connection: Connection,
        fault_injector: FaultInjector | None = None,
    ) -> None:
        self._connection = connection
        self._fault = fault_injector or _no_fault

    def insert(self, view: AnalysisViewRecord) -> None:
        values: dict[str, object] = {
            "analysis_view_id": _uuid(view.view_id),
            "schema_id": view.schema_id,
            "schema_version": view.schema_version,
            "canonical_payload": to_json_compatible(view.payload),
            "digest_format": view.digest.format,
            "digest_value": view.digest.value,
        }
        inserted = self._connection.execute(
            pg_insert(analysis_view)
            .values(**values)
            .on_conflict_do_nothing(index_elements=[analysis_view.c.analysis_view_id])
            .returning(analysis_view.c.analysis_view_id)
        ).scalar_one_or_none()
        if inserted is None:
            existing = (
                self._connection.execute(
                    sa.select(analysis_view).where(
                        analysis_view.c.analysis_view_id == values["analysis_view_id"]
                    )
                )
                .mappings()
                .one()
            )
            _require_exact_replay(
                cast(Mapping[str, object], existing), values, "analysis view"
            )
            existing_associations = set(
                self._connection.execute(
                    sa.select(
                        analysis_view_observation.c.facet_role_id,
                        analysis_view_observation.c.observation_version_id,
                    ).where(
                        analysis_view_observation.c.analysis_view_id
                        == values["analysis_view_id"]
                    )
                ).tuples()
            )
            expected_associations = {
                (facet_role_id, _uuid(observation_id))
                for facet_role_id, observation_id in view.observation_versions
            }
            if existing_associations != expected_associations:
                raise ValueError(
                    "analysis view identity collided with different evidence links"
                )
            return
        self._fault(FaultPoint.AFTER_ANALYSIS_VIEW_INSERT)
        for facet_role_id, observation_id in view.observation_versions:
            self._connection.execute(
                analysis_view_observation.insert().values(
                    analysis_view_id=_uuid(view.view_id),
                    observation_version_id=_uuid(observation_id),
                    facet_role_id=facet_role_id,
                )
            )
            self._fault(FaultPoint.AFTER_ASSOCIATION_INSERT)


class PostgresPreparednessProfileRepository:
    """Immutable exact-profile storage with linear-successor validation."""

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def get(
        self,
        *,
        profile_id: PreparednessProfileId,
        version: int,
    ) -> PreparednessProfileRecord | None:
        row = (
            self._connection.execute(
                sa.select(preparedness_profile)
                .where(
                    preparedness_profile.c.profile_id == _uuid(profile_id),
                    preparedness_profile.c.profile_version == version,
                )
                .with_for_update()
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None
        predecessor = row["predecessor_profile_id"]
        return PreparednessProfileRecord(
            profile_id=PreparednessProfileId(str(row["profile_id"])),
            version=int(row["profile_version"]),
            repository_id=int(row["repository_id"]),
            effective_from=row["effective_from"].astimezone(UTC),
            predecessor_profile_id=(
                PreparednessProfileId(str(predecessor))
                if predecessor is not None
                else None
            ),
            predecessor_profile_version=(
                int(row["predecessor_profile_version"])
                if row["predecessor_profile_version"] is not None
                else None
            ),
            predecessor_digest=(
                Digest(
                    format=str(row["predecessor_digest_format"]),
                    value=str(row["predecessor_digest_value"]),
                )
                if row["predecessor_digest_format"] is not None
                and row["predecessor_digest_value"] is not None
                else None
            ),
            payload=row["canonical_payload"],
            digest=Digest(
                value=str(row["digest_value"]),
                format=str(row["digest_format"]),
            ),
        )

    def get_successor(
        self,
        *,
        profile_id: PreparednessProfileId,
        version: int,
    ) -> PreparednessProfileRecord | None:
        successor_identity = (
            self._connection.execute(
                sa.select(
                    preparedness_profile.c.profile_id,
                    preparedness_profile.c.profile_version,
                ).where(
                    preparedness_profile.c.predecessor_profile_id == _uuid(profile_id),
                    preparedness_profile.c.predecessor_profile_version == version,
                )
            )
            .tuples()
            .one_or_none()
        )
        if successor_identity is None:
            return None
        successor_id, successor_version = successor_identity
        return self.get(
            profile_id=PreparednessProfileId(str(successor_id)),
            version=int(successor_version),
        )

    def insert(self, profile: PreparednessProfileRecord) -> None:
        predecessor_id = profile.predecessor_profile_id
        predecessor_version = profile.predecessor_profile_version
        predecessor_digest = profile.predecessor_digest
        if (
            len(
                {
                    predecessor_id is None,
                    predecessor_version is None,
                    predecessor_digest is None,
                }
            )
            != 1
        ):
            raise ValueError("profile predecessor identity must be all-or-none")
        if (
            predecessor_id is not None
            and predecessor_version is not None
            and predecessor_digest is not None
        ):
            predecessor = (
                self._connection.execute(
                    sa.select(
                        preparedness_profile.c.repository_id,
                        preparedness_profile.c.effective_from,
                        preparedness_profile.c.digest_format,
                        preparedness_profile.c.digest_value,
                    )
                    .where(
                        preparedness_profile.c.profile_id == _uuid(predecessor_id),
                        preparedness_profile.c.profile_version == predecessor_version,
                    )
                    .with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if predecessor is None:
                raise ValueError("exact predecessor profile does not exist")
            if int(predecessor["repository_id"]) != profile.repository_id:
                raise ValueError("profile successor repository differs")
            if (
                Digest(
                    format=str(predecessor["digest_format"]),
                    value=str(predecessor["digest_value"]),
                )
                != predecessor_digest
            ):
                raise ValueError("profile successor predecessor digest differs")
            if profile.effective_from <= predecessor["effective_from"]:
                raise ValueError("profile successor must become effective later")
            latest_assessment_seal = self._connection.scalar(
                sa.select(
                    sa.func.max(preparedness_assessment.c.evidence_sealed_at)
                ).where(
                    preparedness_assessment.c.profile_id == _uuid(predecessor_id),
                    preparedness_assessment.c.profile_version == predecessor_version,
                )
            )
            if (
                latest_assessment_seal is not None
                and profile.effective_from <= latest_assessment_seal
            ):
                raise ValueError(
                    "profile successor cannot retroactively invalidate an assessment"
                )

        self._connection.execute(
            preparedness_profile.insert().values(
                profile_id=_uuid(profile.profile_id),
                profile_version=profile.version,
                repository_id=profile.repository_id,
                effective_from=profile.effective_from,
                predecessor_profile_id=(
                    _uuid(predecessor_id) if predecessor_id is not None else None
                ),
                predecessor_profile_version=predecessor_version,
                predecessor_digest_format=(
                    predecessor_digest.format
                    if predecessor_digest is not None
                    else None
                ),
                predecessor_digest_value=(
                    predecessor_digest.value if predecessor_digest is not None else None
                ),
                schema_id="github-steward/preparedness-profile/v1",
                canonical_payload=to_json_compatible(profile.payload),
                digest_format=profile.digest.format,
                digest_value=profile.digest.value,
            )
        )


class PostgresPreparednessAssessmentRepository:
    """Immutable assessment storage bound to explicit analysis-view evidence."""

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def insert(self, assessment: PreparednessAssessmentRecord) -> None:
        locked_profile = (
            self._connection.execute(
                sa.select(
                    preparedness_profile.c.effective_from,
                    preparedness_profile.c.digest_format,
                    preparedness_profile.c.digest_value,
                )
                .where(
                    preparedness_profile.c.profile_id == _uuid(assessment.profile_id),
                    preparedness_profile.c.profile_version
                    == assessment.profile_version,
                )
                .with_for_update()
            )
            .mappings()
            .one_or_none()
        )
        if locked_profile is None:
            raise ValueError("exact assessment profile does not exist")
        if (
            Digest(
                format=str(locked_profile["digest_format"]),
                value=str(locked_profile["digest_value"]),
            )
            != assessment.profile_digest
        ):
            raise ValueError("exact assessment profile digest did not match")
        view_digest = (
            self._connection.execute(
                sa.select(
                    analysis_view.c.digest_format,
                    analysis_view.c.digest_value,
                ).where(
                    analysis_view.c.analysis_view_id
                    == _uuid(assessment.analysis_view_id)
                )
            )
            .mappings()
            .one_or_none()
        )
        if (
            view_digest is None
            or Digest(
                format=str(view_digest["digest_format"]),
                value=str(view_digest["digest_value"]),
            )
            != assessment.analysis_view_digest
        ):
            raise ValueError("exact assessment analysis-view digest did not match")
        values: dict[str, object] = {
            "assessment_id": _uuid(assessment.assessment_id),
            "repository_id": assessment.repository_id,
            "pull_number": assessment.pull_number,
            "head_sha": assessment.head_sha,
            "profile_id": _uuid(assessment.profile_id),
            "profile_version": assessment.profile_version,
            "profile_digest_format": assessment.profile_digest.format,
            "profile_digest_value": assessment.profile_digest.value,
            "analysis_view_id": _uuid(assessment.analysis_view_id),
            "analysis_view_digest_format": assessment.analysis_view_digest.format,
            "analysis_view_digest_value": assessment.analysis_view_digest.value,
            "evidence_sealed_at": assessment.evidence_sealed_at,
            "evaluated_at": assessment.evaluated_at,
            "verdict": assessment.verdict,
            "schema_id": "github-steward/preparedness-assessment/v1",
            "canonical_payload": to_json_compatible(assessment.payload),
            "digest_format": assessment.digest.format,
            "digest_value": assessment.digest.value,
        }
        inserted = self._connection.execute(
            pg_insert(preparedness_assessment)
            .values(**values)
            .on_conflict_do_nothing(
                index_elements=[preparedness_assessment.c.assessment_id]
            )
            .returning(preparedness_assessment.c.assessment_id)
        ).scalar_one_or_none()
        if inserted is None:
            existing = (
                self._connection.execute(
                    sa.select(preparedness_assessment).where(
                        preparedness_assessment.c.assessment_id
                        == values["assessment_id"]
                    )
                )
                .mappings()
                .one()
            )
            _require_exact_replay(
                cast(Mapping[str, object], existing),
                values,
                "preparedness assessment",
            )
            existing_evidence = set(
                self._connection.execute(
                    sa.select(
                        preparedness_assessment_evidence.c.facet_role_id,
                        preparedness_assessment_evidence.c.observation_version_id,
                    ).where(
                        preparedness_assessment_evidence.c.assessment_id
                        == values["assessment_id"]
                    )
                ).tuples()
            )
            expected_evidence = {
                (facet_role_id, _uuid(observation_id))
                for facet_role_id, observation_id in assessment.evidence_observations
            }
            if existing_evidence != expected_evidence:
                raise ValueError(
                    "preparedness assessment identity collided with different evidence"
                )
            return
        for facet_role_id, observation_id in assessment.evidence_observations:
            self._connection.execute(
                preparedness_assessment_evidence.insert().values(
                    assessment_id=_uuid(assessment.assessment_id),
                    analysis_view_id=_uuid(assessment.analysis_view_id),
                    observation_version_id=_uuid(observation_id),
                    facet_role_id=facet_role_id,
                )
            )


class PostgresAuditEventRepository:
    """Append-only audit-event adapter."""

    def __init__(
        self,
        connection: Connection,
        fault_injector: FaultInjector | None = None,
    ) -> None:
        self._connection = connection
        self._fault = fault_injector or _no_fault

    def append(self, event: AuditEventRecord) -> None:
        self._connection.execute(
            audit_event.insert().values(
                audit_event_id=_uuid(event.event_id),
                event_kind=event.event_kind,
                actor_or_authority_id=event.actor_or_authority_id,
                occurred_at=event.occurred_at,
                schema_id=event.schema_id,
                schema_version=event.schema_version,
                canonical_payload=to_json_compatible(event.payload),
                digest_format=event.digest.format,
                digest_value=event.digest.value,
            )
        )
        self._fault(FaultPoint.AFTER_AUDIT_INSERT)
