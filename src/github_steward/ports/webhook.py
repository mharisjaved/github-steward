"""Transactional persistence ports for verified GitHub webhook ingress."""

from __future__ import annotations

from typing import Protocol

from github_steward.domain.webhook import (
    SecurityEventV1,
    WebhookDeliveryV1,
    WebhookReplayResult,
    WebhookWorkV1,
)
from github_steward.ports.github_authorization import GitHubAuthorizationRepository
from github_steward.ports.persistence import (
    AuditEventRecord,
    AuditEventRepository,
    UnitOfWork,
)


class WebhookDeliveryRepository(Protocol):
    """Transaction-locked delivery replay classification and optional work."""

    def classify_or_insert(
        self,
        delivery: WebhookDeliveryV1,
    ) -> WebhookReplayResult:
        """Insert once or classify the exact provider identity under a lock."""

    def append_work(self, work: WebhookWorkV1) -> None:
        """Append at most one work record for a newly inserted delivery."""


class SecurityEventRepository(Protocol):
    """Append-only GS-I6 security-event storage."""

    def append(self, event: SecurityEventV1) -> None:
        """Append one bounded event; no mutation operation is exposed."""


class WebhookAuditRepository(AuditEventRepository, Protocol):
    """Append-only audit storage used for webhook control signals."""

    def append(self, event: AuditEventRecord) -> None:
        """Append a secret-safe control-signal audit record."""


class WebhookIngressUnitOfWork(UnitOfWork, Protocol):
    """One cohesive delivery/work/security/audit transaction."""

    @property
    def webhook_deliveries(self) -> WebhookDeliveryRepository:
        """Return delivery replay and optional-work operations."""

    @property
    def security_events(self) -> SecurityEventRepository:
        """Return append-only security-event storage."""

    @property
    def webhook_audits(self) -> WebhookAuditRepository:
        """Return append-only webhook control-signal audit storage."""

    @property
    def github_authorization(self) -> GitHubAuthorizationRepository:
        """Return the trusted GS-I5 repository-authorization context."""


class WebhookIngressUnitOfWorkFactory(Protocol):
    """Create a fresh explicit webhook-ingress transaction."""

    def __call__(self) -> WebhookIngressUnitOfWork:
        """Return an unentered webhook ingress unit of work."""
