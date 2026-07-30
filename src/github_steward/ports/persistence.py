"""Typed persistence boundaries without concrete repository implementations."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import TracebackType
from typing import NewType, Protocol, Self

from github_steward.domain.canonical import CanonicalValue, Digest

DeliveryId = NewType("DeliveryId", str)
WorkRecordId = NewType("WorkRecordId", str)
ObservationVersionId = NewType("ObservationVersionId", str)
AnalysisViewId = NewType("AnalysisViewId", str)
AuditEventId = NewType("AuditEventId", str)
LeaseToken = NewType("LeaseToken", str)


@dataclass(frozen=True, slots=True)
class Delivery:
    """A canonical delivery accepted at the persistence boundary."""

    delivery_id: DeliveryId
    provider: str
    provider_delivery_id: str
    payload_digest: Digest
    received_at: datetime


@dataclass(frozen=True, slots=True)
class WorkRecord:
    """A durable unit of local work created with a delivery."""

    work_record_id: WorkRecordId
    delivery_id: DeliveryId
    work_type: str
    available_at: datetime


@dataclass(frozen=True, slots=True)
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


@dataclass(frozen=True, slots=True)
class ObservationPointer:
    """A mutable current pointer represented as a versioned value."""

    entity_kind: str
    entity_id: str
    observation_version_id: ObservationVersionId
    ordering_key: Mapping[str, CanonicalValue]
    pointer_version: int
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class WorkLease:
    """An opaque lease; expiry does not authorize an external retry."""

    work_record_id: WorkRecordId
    owner: str
    token: LeaseToken
    expires_at: datetime
    version: int


@dataclass(frozen=True, slots=True)
class AnalysisViewRecord:
    """An immutable analysis view and its observation-version references."""

    view_id: AnalysisViewId
    schema_id: str
    schema_version: int
    payload: CanonicalValue
    digest: Digest
    observation_versions: tuple[tuple[str, ObservationVersionId], ...]


@dataclass(frozen=True, slots=True)
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


class DeliveryIngressResult(StrEnum):
    """Deterministic delivery-ingress outcomes."""

    CREATED = "CREATED"
    DUPLICATE_SAME_DIGEST = "DUPLICATE_SAME_DIGEST"
    INTEGRITY_FAILURE_DIFFERENT_DIGEST = "INTEGRITY_FAILURE_DIFFERENT_DIGEST"


class CanonicalObservationRepository(Protocol):
    """Append-only immutable observation storage."""

    def append(self, observation: CanonicalObservationRecord) -> None:
        """Append an observation; no update or delete operation is exposed."""


class CurrentObservationPointerRepository(Protocol):
    """Current-pointer compare-and-swap storage."""

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


class AnalysisViewRepository(Protocol):
    """Immutable analysis-view storage."""

    def insert(self, view: AnalysisViewRecord) -> None:
        """Insert a view; no update or delete operation is exposed."""


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
