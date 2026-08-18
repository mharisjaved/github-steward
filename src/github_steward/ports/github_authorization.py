"""Secret-free persistence ports for GitHub App repository authorization."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from github_steward.domain.github_authorization import (
    InstallationObservationV1,
    RepositoryAuthorizationV1,
)
from github_steward.ports.persistence import UnitOfWork


@dataclass(frozen=True, slots=True)
class BrokerWorkIdentity:
    """Trusted numeric GitHub work subject loaded from durable intake."""

    work_record_id: str
    provider: str
    work_type: str
    repository_id: int
    pull_number: int


class GitHubAuthorizationRepository(Protocol):
    """Exact reads and guarded writes used by the credential broker."""

    def get_work_identity(self, work_record_id: str) -> BrokerWorkIdentity | None:
        """Load one work record and derive its stored numeric semantic subject."""

    def get_repository_authorization(
        self,
        repository_id: int,
    ) -> RepositoryAuthorizationV1 | None:
        """Load the current authorization for exactly one numeric repository."""

    def get_installation_observation(
        self,
        observation_id: str,
    ) -> InstallationObservationV1 | None:
        """Load one exact immutable installation observation."""

    def append_installation_observation(
        self,
        observation: InstallationObservationV1,
    ) -> None:
        """Append a validated observation without exposing mutation operations."""

    def compare_and_swap_repository_authorization(
        self,
        *,
        expected_authorization_version: int,
        replacement: RepositoryAuthorizationV1,
    ) -> bool:
        """Create at expected zero or replace only the exact expected version."""


class GitHubAuthorizationUnitOfWork(UnitOfWork, Protocol):
    """Transaction boundary containing the cohesive authorization repository."""

    @property
    def github_authorization(self) -> GitHubAuthorizationRepository:
        """Return exact broker work and authorization persistence operations."""


class GitHubAuthorizationUnitOfWorkFactory(Protocol):
    """Create a fresh authorization transaction boundary."""

    def __call__(self) -> GitHubAuthorizationUnitOfWork:
        """Return an unentered authorization unit of work."""
