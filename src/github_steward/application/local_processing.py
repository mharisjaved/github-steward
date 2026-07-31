"""Bounded durable synthetic receipt, processing, and reconciliation services."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import cast

from github_steward.domain.canonical import CanonicalEnvelope
from github_steward.domain.errors import (
    DomainValidationError,
    PermanentLocalProcessingError,
    RetryableLocalProcessingError,
)
from github_steward.domain.processing import (
    ANALYSIS_VIEW_SCHEMA_ID,
    AUDIT_SCHEMA_ID,
    DELIVERY_SCHEMA_ID,
    OBSERVATION_SCHEMA_ID,
    PROVIDER,
    SCHEMA_VERSION,
    WORK_TYPE,
    FailureKind,
    FaultPoint,
    PointerOutcome,
    ProcessingOutcome,
    SyntheticDelivery,
    WorkState,
    analysis_view_id,
    audit_event_id,
    delivery_id,
    observation_version_id,
    pointer_ordering_key,
    require_utc_datetime,
    work_record_id,
)
from github_steward.ports.clock import Clock
from github_steward.ports.persistence import (
    AnalysisViewId,
    AnalysisViewRecord,
    AuditEventId,
    AuditEventRecord,
    CanonicalObservationRecord,
    ClaimedWork,
    ClaimOutcome,
    Delivery,
    DeliveryId,
    DeliveryIngressResult,
    LeaseOperationOutcome,
    LeaseOperationResult,
    ObservationPointer,
    ObservationVersionId,
    PointerCreateOutcome,
    ProcessingUnitOfWork,
    ReconciliationResult,
    WorkLease,
    WorkRecord,
    WorkRecordId,
)

type EnvelopeFactory = Callable[[object], CanonicalEnvelope]
type FaultInjector = Callable[[FaultPoint], None]
type Processor = Callable[[ClaimedWork], ProcessedWork]


def _no_fault(_: FaultPoint) -> None:
    return None


@dataclass(frozen=True, slots=True)
class LocalProcessingResult:
    """Deterministic result of one local-processing invocation."""

    outcome: ProcessingOutcome
    work_record_id: WorkRecordId | None = None
    attempt_number: int | None = None
    pointer_outcome: PointerOutcome | None = None


@dataclass(frozen=True, slots=True)
class ProcessedWork:
    """All CPU-only deterministic output prepared before T4 starts."""

    observation: CanonicalObservationRecord
    view: AnalysisViewRecord
    pointer_expected_version: int | None
    pointer: ObservationPointer
    audits: Mapping[PointerOutcome, AuditEventRecord]


class SyntheticReceiptService:
    """Validate and atomically durably classify one decoded synthetic delivery."""

    def __init__(
        self,
        *,
        unit_of_work_factory: Callable[[], ProcessingUnitOfWork],
        clock: Clock,
        envelope_factory: EnvelopeFactory,
    ) -> None:
        self._unit_of_work_factory = unit_of_work_factory
        self._clock = clock
        self._envelope_factory = envelope_factory

    def receive(
        self,
        *,
        provider_delivery_id: str,
        mapping: Mapping[str, object],
    ) -> DeliveryIngressResult:
        if not isinstance(provider_delivery_id, str) or provider_delivery_id == "":
            raise DomainValidationError(
                "provider_delivery_id must be a non-empty string"
            )
        synthetic = SyntheticDelivery(mapping)
        envelope = self._envelope_factory(synthetic.payload)
        received_at = require_utc_datetime(self._clock.now(), "received_at")
        delivery_identifier = DeliveryId(delivery_id(provider_delivery_id))
        work_identifier = WorkRecordId(work_record_id(delivery_identifier))
        delivery = Delivery(
            delivery_id=delivery_identifier,
            provider=PROVIDER,
            provider_delivery_id=provider_delivery_id,
            payload_schema_id=DELIVERY_SCHEMA_ID,
            payload_schema_version=SCHEMA_VERSION,
            payload=envelope.payload,
            payload_digest=envelope.digest,
            received_at=received_at,
        )
        work = WorkRecord(
            work_record_id=work_identifier,
            delivery_id=delivery_identifier,
            work_type=WORK_TYPE,
            available_at=received_at,
        )
        with self._unit_of_work_factory() as unit_of_work:
            result = unit_of_work.inbox.create_delivery_and_work(
                delivery=delivery,
                work=work,
            )
            unit_of_work.commit()
        return result


class LocalProcessingService:
    """Claim, process without a transaction, then atomically complete local work."""

    def __init__(
        self,
        *,
        unit_of_work_factory: Callable[[], ProcessingUnitOfWork],
        clock: Clock,
        envelope_factory: EnvelopeFactory,
        processor: Processor | None = None,
        fault_injector: FaultInjector | None = None,
    ) -> None:
        self._unit_of_work_factory = unit_of_work_factory
        self._clock = clock
        self._envelope_factory = envelope_factory
        self._processor = processor or self._deterministic_processor
        self._fault = fault_injector or _no_fault

    def process_next(self, *, owner: str) -> LocalProcessingResult:
        if not isinstance(owner, str) or owner == "":
            raise DomainValidationError("owner must be a non-empty string")
        claim_time = require_utc_datetime(self._clock.now(), "claim_time")
        with self._unit_of_work_factory() as unit_of_work:
            claim = unit_of_work.work.claim_next(owner=owner, now=claim_time)
            unit_of_work.commit()
        if claim.outcome is ClaimOutcome.NO_WORK:
            return LocalProcessingResult(ProcessingOutcome.NO_WORK)
        claimed = cast(ClaimedWork, claim.claimed_work)

        try:
            processed = self._processor(claimed)
        except RetryableLocalProcessingError:
            return self._record_failure(
                claimed=claimed,
                failure_kind=FailureKind.RETRYABLE_LOCAL_PROCESSING,
            )
        except PermanentLocalProcessingError:
            return self._record_failure(
                claimed=claimed,
                failure_kind=FailureKind.PERMANENT_LOCAL_PROCESSING,
            )
        except Exception:
            return self._record_failure(
                claimed=claimed,
                failure_kind=FailureKind.UNEXPECTED_LOCAL_FAILURE,
            )

        completion_time = require_utc_datetime(
            self._clock.now(),
            "completion_time",
        )
        with self._unit_of_work_factory() as unit_of_work:
            unit_of_work.observations.append(processed.observation)
            unit_of_work.views.insert(processed.view)
            pointer_outcome = self._write_pointer(unit_of_work, processed)
            unit_of_work.audits.append(processed.audits[pointer_outcome])
            completion = unit_of_work.work.complete_success(
                lease=claimed.lease,
                attempt_number=claimed.attempt_number,
                now=completion_time,
            )
            if completion.outcome is LeaseOperationOutcome.STALE:
                unit_of_work.rollback()
                return LocalProcessingResult(
                    ProcessingOutcome.LEASE_LOST,
                    claimed.lease.work_record_id,
                    claimed.attempt_number,
                )
            unit_of_work.commit()
            self._fault(FaultPoint.AFTER_COMPLETION_COMMIT)
        return LocalProcessingResult(
            ProcessingOutcome.SUCCEEDED,
            claimed.lease.work_record_id,
            claimed.attempt_number,
            pointer_outcome,
        )

    def renew(self, *, lease: WorkLease) -> LeaseOperationResult:
        """Renew current ownership using the explicit clock."""

        now = require_utc_datetime(self._clock.now(), "renewal_time")
        with self._unit_of_work_factory() as unit_of_work:
            result = unit_of_work.work.renew(lease=lease, now=now)
            unit_of_work.commit()
        return result

    def _write_pointer(
        self,
        unit_of_work: ProcessingUnitOfWork,
        processed: ProcessedWork,
    ) -> PointerOutcome:
        pointers = unit_of_work.pointers
        expected = processed.pointer_expected_version
        if expected is None:
            created = pointers.create_if_absent(processed.pointer)
            if created is PointerCreateOutcome.CREATED:
                return PointerOutcome.CREATED
            return PointerOutcome.POINTER_CONFLICT
        if pointers.compare_and_swap(
            expected_version=expected,
            replacement=processed.pointer,
        ):
            return PointerOutcome.UPDATED
        return PointerOutcome.POINTER_CONFLICT

    def _record_failure(
        self,
        *,
        claimed: ClaimedWork,
        failure_kind: FailureKind,
    ) -> LocalProcessingResult:
        completed_at = require_utc_datetime(self._clock.now(), "failure_time")
        audit = self._failure_audit(claimed, failure_kind, completed_at)
        with self._unit_of_work_factory() as unit_of_work:
            unit_of_work.audits.append(audit)
            result = unit_of_work.work.complete_failure(
                lease=claimed.lease,
                attempt_number=claimed.attempt_number,
                now=completed_at,
                failure_kind=failure_kind,
            )
            if result.outcome is LeaseOperationOutcome.STALE:
                unit_of_work.rollback()
                return LocalProcessingResult(
                    ProcessingOutcome.LEASE_LOST,
                    claimed.lease.work_record_id,
                    claimed.attempt_number,
                )
            unit_of_work.commit()
        outcome = (
            ProcessingOutcome.RETRY_SCHEDULED
            if result.work_state is WorkState.RETRY_WAIT
            else ProcessingOutcome.FAILED
        )
        return LocalProcessingResult(
            outcome,
            claimed.lease.work_record_id,
            claimed.attempt_number,
        )

    def _deterministic_processor(self, claimed: ClaimedWork) -> ProcessedWork:
        synthetic = SyntheticDelivery(cast(Mapping[str, object], claimed.payload))
        observation_envelope = self._envelope_factory(synthetic.observation)
        observation_identifier = ObservationVersionId(
            observation_version_id(
                claimed.lease.work_record_id,
                claimed.payload_digest.value,
            )
        )
        observation = CanonicalObservationRecord(
            version_id=observation_identifier,
            entity_kind=synthetic.entity_kind,
            entity_id=synthetic.entity_id,
            schema_id=OBSERVATION_SCHEMA_ID,
            schema_version=SCHEMA_VERSION,
            observed_at=synthetic.observed_at,
            payload=observation_envelope.payload,
            digest=observation_envelope.digest,
        )
        view_payload = {
            "entity_kind": synthetic.entity_kind,
            "entity_id": synthetic.entity_id,
            "observation_digest": observation_envelope.digest.value,
            "sequence": synthetic.sequence,
        }
        view_envelope = self._envelope_factory(view_payload)
        view_identifier = AnalysisViewId(
            analysis_view_id(
                claimed.lease.work_record_id,
                claimed.payload_digest.value,
            )
        )
        view = AnalysisViewRecord(
            view_id=view_identifier,
            schema_id=ANALYSIS_VIEW_SCHEMA_ID,
            schema_version=SCHEMA_VERSION,
            payload=view_envelope.payload,
            digest=view_envelope.digest,
            observation_versions=(("synthetic", observation_identifier),),
        )
        pointer_version = (
            0
            if synthetic.expected_pointer_version is None
            else synthetic.expected_pointer_version + 1
        )
        pointer = ObservationPointer(
            entity_kind=synthetic.entity_kind,
            entity_id=synthetic.entity_id,
            observation_version_id=observation_identifier,
            ordering_key=pointer_ordering_key(synthetic.sequence),
            pointer_version=pointer_version,
            updated_at=synthetic.observed_at,
        )
        audits = {
            outcome: self._success_audit(
                claimed,
                outcome,
                synthetic.observed_at,
                observation_identifier,
                view_identifier,
            )
            for outcome in PointerOutcome
        }
        return ProcessedWork(
            observation=observation,
            view=view,
            pointer_expected_version=synthetic.expected_pointer_version,
            pointer=pointer,
            audits=audits,
        )

    def _success_audit(
        self,
        claimed: ClaimedWork,
        pointer_outcome: PointerOutcome,
        occurred_at: datetime,
        observation_identifier: ObservationVersionId,
        view_identifier: AnalysisViewId,
    ) -> AuditEventRecord:
        event_kind = "LOCAL_PROCESSING_SUCCEEDED"
        payload = {
            "work_record_id": claimed.lease.work_record_id,
            "attempt_number": claimed.attempt_number,
            "pointer_outcome": pointer_outcome.value,
            "observation_version_id": observation_identifier,
            "analysis_view_id": view_identifier,
        }
        envelope = self._envelope_factory(payload)
        return AuditEventRecord(
            event_id=AuditEventId(
                audit_event_id(
                    claimed.lease.work_record_id,
                    claimed.attempt_number,
                    event_kind,
                )
            ),
            event_kind=event_kind,
            actor_or_authority_id="local-deterministic-processor",
            occurred_at=occurred_at,
            schema_id=AUDIT_SCHEMA_ID,
            schema_version=SCHEMA_VERSION,
            payload=envelope.payload,
            digest=envelope.digest,
        )

    def _failure_audit(
        self,
        claimed: ClaimedWork,
        failure_kind: FailureKind,
        occurred_at: datetime,
    ) -> AuditEventRecord:
        event_kind = failure_kind.value
        payload = {
            "work_record_id": claimed.lease.work_record_id,
            "attempt_number": claimed.attempt_number,
            "failure_kind": failure_kind.value,
        }
        envelope = self._envelope_factory(payload)
        return AuditEventRecord(
            event_id=AuditEventId(
                audit_event_id(
                    claimed.lease.work_record_id,
                    claimed.attempt_number,
                    event_kind,
                )
            ),
            event_kind=event_kind,
            actor_or_authority_id="local-deterministic-processor",
            occurred_at=occurred_at,
            schema_id=AUDIT_SCHEMA_ID,
            schema_version=SCHEMA_VERSION,
            payload=envelope.payload,
            digest=envelope.digest,
        )


class LocalReconciliationService:
    """Run one bounded, deterministic expired-work reconciliation transaction."""

    def __init__(
        self,
        *,
        unit_of_work_factory: Callable[[], ProcessingUnitOfWork],
        clock: Clock,
    ) -> None:
        self._unit_of_work_factory = unit_of_work_factory
        self._clock = clock

    def reconcile(self) -> ReconciliationResult:
        """Reconcile at most one hundred expired processing records."""

        now = require_utc_datetime(self._clock.now(), "reconciliation_time")
        with self._unit_of_work_factory() as unit_of_work:
            result = unit_of_work.work.reconcile_expired(now=now)
            unit_of_work.commit()
        return result
