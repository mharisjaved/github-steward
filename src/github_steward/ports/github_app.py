"""Narrow ports for GitHub App control-plane operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from github_steward.ports.secrets import OpaqueBearerToken

READ_PERMISSIONS = (
    ("checks", "read"),
    ("metadata", "read"),
    ("pull_requests", "read"),
    ("statuses", "read"),
)


@dataclass(frozen=True, slots=True)
class InstallationTokenRequest:
    """The only installation-token scope GS-I5 may request."""

    repository_id: int

    def __post_init__(self) -> None:
        if (
            isinstance(self.repository_id, bool)
            or not isinstance(self.repository_id, int)
            or self.repository_id < 1
        ):
            raise ValueError("repository_id must be a positive integer")

    def as_mapping(self) -> dict[str, object]:
        return {
            "repository_ids": [self.repository_id],
            "permissions": dict(READ_PERMISSIONS),
        }


@dataclass(frozen=True, slots=True)
class InstallationTokenResponse:
    """Strictly decoded token response; its bearer value remains opaque."""

    token: OpaqueBearerToken
    expires_at: str
    permissions: tuple[tuple[str, str], ...]
    repository_ids: tuple[int, ...] | None
    repository_selection: str | None


@dataclass(frozen=True, slots=True)
class GitHubControlPlaneResponse:
    """Strictly decoded control-plane JSON and non-secret raw provenance."""

    value: object
    raw_sha256: str
    status_code: int = 200


class GitHubAppControlPlanePort(Protocol):
    """Exact project-owned GitHub App operations; no arbitrary URL surface."""

    def get_installation(self, installation_id: int) -> GitHubControlPlaneResponse:
        """Read one installation by numeric identity."""

    def get_repository_installation(
        self,
        *,
        owner: str,
        repository: str,
    ) -> GitHubControlPlaneResponse:
        """Read GitHub's repository-to-installation relationship."""

    def create_installation_token(
        self,
        *,
        installation_id: int,
        request: InstallationTokenRequest,
    ) -> InstallationTokenResponse:
        """Mint one explicitly narrowed, one-repository read token."""
