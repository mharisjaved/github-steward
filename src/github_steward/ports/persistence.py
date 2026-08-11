"""Typed persistence boundaries without concrete repository implementations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import TracebackType
from typing import NewType, Protocol, Self

from github_steward.domain.canonical import (
    CanonicalValue,
    Digest,
    freeze_canonical_value,
)
from github_steward.domain.processing import FailureKind, WorkState

DeliveryId = NewType("DeliveryId", str)
WorkRecordId = NewType("WorkRecordId", str)
WorkAttemptId = NewType("WorkAttemptId", str)
ObservationVersionId = NewType("ObservationVersionId", str)
AnalysisViewId = NewType("AnalysisViewId", str)
AuditEventId = NewType("AuditEventId", str)
PreparednessProfileId = NewType("PreparednessProfileId", str)
PreparednessAssessmentId = NewType("PreparednessAssessmentId", str)
LeaseToken = NewType("LeaseToken", str)


@dataclass(frozen=True, slots=True, init=False)
class Delivery:
    """A canonical delivery accepted at the persistence boundary."""

    delivery_id: DeliveryId
    provider: str
    provider_delivery_id: str
    payload_schema_id: str
    payload_schema_version: int
    payload: CanonicalValue
    payload_digest: Digest
    received_at: datetime

    def __init__(
        self,
        *,
        delivery_id: DeliveryId,
        provider: str,
        provider_delivery_id: str,
        payload_schema_id: str,
        payload_schema_version: int,
        payload: object,
        payload_digest: Digest,
        received_at: datetime,
    ) -> None:
        object.__setattr__(self, "delivery_id", delivery_id)
        object.__setattr__(self, "provider", provider)
        object.__setattr__(self, "provider_delivery_id", provider_delivery_id)
        object.__setattr__(self, "payload_schema_id", payload_schema_id)
        object.__setattr__(self, "payload_schema_version", payload_schema_version)
        object.__setattr__(self, "payload", freeze_canonical_value(payload))
        object.__setattr__(self, "payload_digest", payload_digest)
        object.__setattr__(self, "received_at", received_at)


@dataclass(frozen=True, slots=True)
class WorkRecord:
    """A durable unit of local work created with a delivery."""

    work_record_id: WorkRecordId
    delivery_id: DeliveryId
    work_type: str
    available_at: datetime


@dataclass(frozen=True, slots=True, init=False)
class CanonicalObservationRecord:
    """An immutable canonical observation."""

    version_id: ObservationVersionId
    entity_kind: str
    entity_id: str
    schema_id: str
    schema_version: int
    observed_at: datetime
    payload: CanonicalValue
    digest: Digest

    def __init__(
        self,
        version_id: ObservationVersionId,
        entity_kind: str,
        entity_id: str,
        schema_id: str,
        schema_version: int,
        observed_at: datetime,
        payload: object,
        digest: Digest,
    ) -> None:
        object.__setattr__(self, "version_id", version_id)
        object.__setattr__(self, "entity_kind", entity_kind)
        object.__setattr__(self, "entity_id", entity_id)
        object.__setattr__(self, "schema_id", schema_id)
        object.__setattr__(self, "schema_version", schema_version)
        object.__setattr__(self, "observed_at", observed_at)
        object.__setattr__(self, "payload", freeze_canonical_value(payload))
        object.__setattr__(self, "digest", digest)


@dataclass(frozen=True, slots=True, init=False)
class ObservationPointer:
    """A current pointer represented as an immutable versioned value."""

    entity_kind: str
    entity_id: str
    observation_version_id: ObservationVersionId
    ordering_key: CanonicalValue
    pointer_version: int
    updated_at: datetime

    def __init__(
        self,
        *,
        entity_kind: str,
        entity_id: str,
        observation_version_id: ObservationVersionId,
        ordering_key: object,
        pointer_version: int,
        updated_at: datetime,
    ) -> None:
        object.__setattr__(self, "entity_kind", entity_kind)
        object.__setattr__(self, "entity_id", entity_id)
        object.__setattr__(self, "observation_version_id", observation_version_id)
        object.__setattr__(self, "ordering_key", freeze_canonical_value(ordering_key))
        object.__setattr__(self, "pointer_version", pointer_version)
        object.__setattr__(self, "updated_at", updated_at)


@dataclass(frozen=True, slots=True)
class WorkLease:
    """An opaque, guarded work lease."""

    work_record_id: WorkRecordId
    owner: str
    token: LeaseToken
    expires_at: datetime
    version: int


@dataclass(frozen=True, slots=True, init=False)
class AnalysisViewRecord:
    """An immutable analysis view and its observation-version references."""

    view_id: AnalysisViewId
    schema_id: str
    schema_version: int
    payload: CanonicalValue
    digest: Digest
    observation_versions: tuple[tuple[str, ObservationVersionId], ...]

    def __init__(
        self,
        view_id: AnalysisViewId,
        schema_id: str,
        schema_version: int,
        payload: object,
        digest: Digest,
        observation_versions: tuple[tuple[str, ObservationVersionId], ...],
    ) -> None:
        object.__setattr__(self, "view_id", view_id)
        object.__setattr__(self, "schema_id", schema_id)
        object.__setattr__(self, "schema_version", schema_version)
        object.__setattr__(self, "payload", freeze_canonical_value(payload))
        object.__setattr__(self, "digest", digest)
        object.__setattr__(self, "observation_versions", observation_versions)


@dataclass(frozen=True, slots=True, init=False)
class PreparednessProfileRecord:
    """An immutable, explicitly versioned preparedness profile."""

    profile_id: PreparednessProfileId
    version: int
    repository_id: int
    effective_from: datetime
    predecessor_profile_id: PreparednessProfileId | None
    predecessor_profile_version: int | None
    payload: CanonicalValue
    digest: Digest

    def __init__(
        self,
        *,
        profile_id: PreparednessProfileId,
        version: int,
        repository_id: int,
        effective_from: datetime,
        predecessor_profile_id: PreparednessProfileId | None,
        predecessor_profile_version: int | None,
        payload: object,
        digest: Digest,
    ) -> None:
        object.__setattr__(self, "profile_id", profile_id)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "repository_id", repository_id)
        object.__setattr__(self, "effective_from", effective_from)
        object.__setattr__(
            self,
            "predecessor_profile_id",
            predecessor_profile_id,
        )
        object.__setattr__(
            self,
            "predecessor_profile_version",
            predecessor_profile_version,
        )
        object.__setattr__(self, "payload", freeze_canonical_value(payload))
        object.__setattr__(self, "digest", digest)


@dataclass(frozen=True, slots=True, init=False)
class PreparednessAssessmentRecord:
    """An immutable assessment bound to exact profile and evidence versions."""

    assessment_id: PreparednessAssessmentId
    repository_id: int
    pull_number: int
    head_sha: str
    profile_id: PreparednessProfileId
    profile_version: int
    analysis_view_id: AnalysisViewId
    evidence_sealed_at: datetime
    evaluated_at: datetime
    verdict: str
    payload: CanonicalValue
    digest: Digest
    evidence_observations: tuple[tuple[str, ObservationVersionId], ...]

    def __init__(
        self,
        *,
        assessment_id: PreparednessAssessmentId,
        repository_id: int,
        pull_number: int,
        head_sha: str,
        profile_id: PreparednessProfileId,
        profile_version: int,
        analysis_view_id: AnalysisViewId,
        evidence_sealed_at: datetime,
        evaluated_at: datetime,
        verdict: str,
        payload: object,
        digest: Digest,
        evidence_observations: tuple[tuple[str, ObservationVersionId], ...],
    ) -> None:
        object.__setattr__(self, "assessment_id", assessment_id)
        object.__setattr__(self, "repository_id", repository_id)
        object.__setattr__(self, "pull_number", pull_number)
        object.__setattr__(self, "head_sha", head_sha)
        object.__setattr__(self, "profile_id", profile_id)
        object.__setattr__(self, "profile_version", profile_version)
        object.__setattr__(self, "analysis_view_id", analysis_view_id)
        object.__setattr__(self, "evidence_sealed_at", evidence_sealed_at)
        object.__setattr__(self, "evaluated_at", evaluated_at)
        object.__setattr__(self, "verdict", verdict)
        object.__setattr__(self, "payload", freeze_canonical_value(payload))
        object.__setattr__(self, "digest", digest)
        object.__setattr__(
            self,
            "evidence_observations",
            evidence_observations,
        )


@dataclass(frozen=True, slots=True, init=False)
class AuditEventRecord:
    """An append-only audit event without a cryptographic-chain claim."""

    event_id: AuditEventId
    event_kind: str
    actor_or_authority_id: str
    occurred_at: datetime
    schema_id: str
    schema_version: int
    payload: CanonicalValue
    digest: Digest

    def __init__(
        self,
        event_id: AuditEventId,
        event_kind: str,
        actor_or_authority_id: str,
        occurred_at: datetime,
        schema_id: str,
        schema_version: int,
        payload: object,
        digest: Digest,
    ) -> None:
        object.__setattr__(self, "event_id", event_id)
        object.__setattr__(self, "event_kind", event_kind)
        object.__setattr__(
            self,
            "actor_or_authority_id",
            actor_or_authority_id,
        )
        object.__setattr__(self, "occurred_at", occurred_at)
        object.__setattr__(self, "schema_id", schema_id)
        object.__setattr__(self, "schema_version", schema_version)
        object.__setattr__(self, "payload", freeze_canonical_value(payload))
        object.__setattr__(self, "digest", digest)


class DeliveryIngressOutcome(StrEnum):
    """Deterministic delivery-ingress outcomes."""

    CREATED = "CREATED"
    DUPLICATE_SAME_DIGEST = "DUPLICATE_SAME_DIGEST"
    INTEGRITY_FAILURE_DIFFERENT_DIGEST = "INTEGRITY_FAILURE_DIFFERENT_DIGEST"


@dataclass(frozen=True, slots=True)
class DeliveryIngressResult:
    """A receipt classification bound to the durable original identities."""

    outcome: DeliveryIngressOutcome
    delivery_id: DeliveryId
    work_record_id: WorkRecordId


class ClaimOutcome(StrEnum):
    """Bounded claim outcomes."""

    CLAIMED = "CLAIMED"
    NO_WORK = "NO_WORK"


@dataclass(frozen=True, slots=True, init=False)
class ClaimedWork:
    """Immutable processing input returned by the committed T2 claim."""

    lease: WorkLease
    attempt_id: WorkAttemptId
    attempt_number: int
    delivery_id: DeliveryId
    payload: CanonicalValue
    payload_digest: Digest

    def __init__(
        self,
        *,
        lease: WorkLease,
        attempt_id: WorkAttemptId,
        attempt_number: int,
        delivery_id: DeliveryId,
        payload: object,
        payload_digest: Digest,
    ) -> None:
        object.__setattr__(self, "lease", lease)
        object.__setattr__(self, "attempt_id", attempt_id)
        object.__setattr__(self, "attempt_number", attempt_number)
        object.__setattr__(self, "delivery_id", delivery_id)
        object.__setattr__(self, "payload", freeze_canonical_value(payload))
        object.__setattr__(self, "payload_digest", payload_digest)


@dataclass(frozen=True, slots=True)
class ClaimResult:
    """A deterministic claim or no-work result."""

    outcome: ClaimOutcome
    claimed_work: ClaimedWork | None


class LeaseOperationOutcome(StrEnum):
    """Explicit guarded lease-operation outcomes."""

    SUCCEEDED = "SUCCEEDED"
    STALE = "STALE"


@dataclass(frozen=True, slots=True)
class LeaseOperationResult:
    """Result of renewal, release, success, or failure completion."""

    outcome: LeaseOperationOutcome
    lease: WorkLease | None = None
    work_state: WorkState | None = None


class PointerCreateOutcome(StrEnum):
    """Create-if-absent outcomes."""

    CREATED = "CREATED"
    CONFLICT = "CONFLICT"


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    """Deterministic counts from one bounded expired-work pass."""

    reconciled: int
    retry_scheduled: int
    terminally_failed: int


class CanonicalObservationRepository(Protocol):
    """Append-only immutable observation storage."""

    def append(self, observation: CanonicalObservationRecord) -> None:
        """Append an observation; no update or delete operation is exposed."""


class CurrentObservationPointerRepository(Protocol):
    """Current-pointer create and compare-and-swap storage."""

    def create_if_absent(
        self,
        pointer: ObservationPointer,
    ) -> PointerCreateOutcome:
        """Create version zero only when no entity pointer exists."""

    def get(self, *, entity_kind: str, entity_id: str) -> ObservationPointer | None:
        """Load the exact current pointer for source-order comparison."""

    def compare_and_swap(
        self,
        *,
        expected_version: int,
        replacement: ObservationPointer,
    ) -> bool:
        """Replace only when the persisted version equals the expected version."""


class InboxWorkRepository(Protocol):
    """Transactional delivery-inbox and work creation."""

    def create_delivery_and_work(
        self,
        *,
        delivery: Delivery,
        work: WorkRecord,
    ) -> DeliveryIngressResult:
        """Create both records atomically and classify delivery-ID conflicts."""


class WorkLeaseRepository(Protocol):
    """Guarded work-lease acquisition and release."""

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
        """Acquire by guarded CAS without granting external retry authority."""

    def release(self, *, lease: WorkLease, now: datetime) -> bool:
        """Release only the matching opaque lease token and version."""


class WorkProcessingRepository(Protocol):
    """Bounded durable local-work operations."""

    def claim_next(self, *, owner: str, now: datetime) -> ClaimResult:
        """Claim one eligible item and create its STARTED attempt atomically."""

    def renew(self, *, lease: WorkLease, now: datetime) -> LeaseOperationResult:
        """Renew only current, unexpired ownership."""

    def complete_success(
        self,
        *,
        lease: WorkLease,
        attempt_number: int,
        now: datetime,
    ) -> LeaseOperationResult:
        """Complete attempt and work atomically for current ownership."""

    def complete_failure(
        self,
        *,
        lease: WorkLease,
        attempt_number: int,
        now: datetime,
        failure_kind: FailureKind,
    ) -> LeaseOperationResult:
        """Persist a classified attempt/work failure for current ownership."""

    def reconcile_expired(self, *, now: datetime) -> ReconciliationResult:
        """Reconcile one bounded ordered batch of expired work."""


class AnalysisViewRepository(Protocol):
    """Immutable analysis-view storage."""

    def insert(self, view: AnalysisViewRecord) -> None:
        """Insert a view and immutable associations without update/delete."""


class PreparednessProfileRepository(Protocol):
    """Immutable profile storage with exact-identity lookup only."""

    def get(
        self,
        *,
        profile_id: PreparednessProfileId,
        version: int,
    ) -> PreparednessProfileRecord | None:
        """Load one explicit profile identity; never infer a current profile."""

    def get_successor(
        self,
        *,
        profile_id: PreparednessProfileId,
        version: int,
    ) -> PreparednessProfileRecord | None:
        """Load the unique successor of one explicit predecessor identity."""

    def insert(self, profile: PreparednessProfileRecord) -> None:
        """Insert a root or exact linear successor profile."""


class PreparednessAssessmentRepository(Protocol):
    """Immutable assessment and explicit evidence-association storage."""

    def insert(self, assessment: PreparednessAssessmentRecord) -> None:
        """Insert one assessment and its exact analysis-view evidence links."""


class AuditEventRepository(Protocol):
    """Append-only audit-event storage."""

    def append(self, event: AuditEventRecord) -> None:
        """Append an event; no update or delete operation is exposed."""


class UnitOfWork(Protocol):
    """Explicit transaction boundary for repository operations."""

    def __enter__(self) -> Self:
        """Enter one local transaction."""

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """Exit the transaction, rolling back on failure."""

    def commit(self) -> None:
        """Commit the transaction."""

    def rollback(self) -> None:
        """Roll back the transaction."""


class ProcessingUnitOfWork(UnitOfWork, Protocol):
    """Minimal repository set used by bounded GS-I2 services."""

    @property
    def inbox(self) -> InboxWorkRepository:
        """Return the transaction-bound inbox repository."""

    @property
    def work(self) -> WorkProcessingRepository:
        """Return the transaction-bound processing repository."""

    @property
    def observations(self) -> CanonicalObservationRepository:
        """Return the transaction-bound observation repository."""

    @property
    def pointers(self) -> CurrentObservationPointerRepository:
        """Return the transaction-bound pointer repository."""

    @property
    def views(self) -> AnalysisViewRepository:
        """Return the transaction-bound analysis-view repository."""

    @property
    def audits(self) -> AuditEventRepository:
        """Return the transaction-bound audit repository."""

    @property
    def profiles(self) -> PreparednessProfileRepository:
        """Return exact-identity immutable profile storage."""

    @property
    def assessments(self) -> PreparednessAssessmentRepository:
        """Return immutable assessment and evidence storage."""


class ProcessingUnitOfWorkFactory(Protocol):
    """Create a fresh explicit PostgreSQL transaction boundary."""

    def __call__(self) -> ProcessingUnitOfWork:
        """Return an unentered unit of work."""
