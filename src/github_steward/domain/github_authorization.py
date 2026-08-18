"""Strict, secret-free GitHub App installation authorization state."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final, Self
from uuid import UUID

from github_steward.domain.errors import DomainValidationError

_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")
_ROUTE_COMPONENT: Final = re.compile(r"^[A-Za-z0-9_.-]+$")
_MAX_BIGINT: Final = (1 << 63) - 1


class GitHubPermissionLevel(StrEnum):
    """Only permission levels accepted by the Stage-1 read boundary."""

    NONE = "none"
    READ = "read"


class RepositorySelection(StrEnum):
    """GitHub App installation repository-selection modes."""

    ALL = "all"
    SELECTED = "selected"


class InstallationAccountType(StrEnum):
    """Supported GitHub installation target account kinds."""

    USER = "User"
    ORGANIZATION = "Organization"


class AuthorizationCapability(StrEnum):
    """Derived read capability for one numeric repository identity."""

    AUTHORIZED_READ = "AUTHORIZED_READ"
    INSTALLATION_SUSPENDED = "INSTALLATION_SUSPENDED"
    REPOSITORY_NOT_SELECTED = "REPOSITORY_NOT_SELECTED"
    INSUFFICIENT_PERMISSIONS = "INSUFFICIENT_PERMISSIONS"
    ROUTE_UNVERIFIED = "ROUTE_UNVERIFIED"
    INSTALLATION_MISMATCH = "INSTALLATION_MISMATCH"


@dataclass(frozen=True, slots=True)
class RepositoryPermissions:
    """The exact four repository permissions visible to GS-I5."""

    metadata: GitHubPermissionLevel
    pull_requests: GitHubPermissionLevel
    checks: GitHubPermissionLevel
    statuses: GitHubPermissionLevel

    def __post_init__(self) -> None:
        for field, value in (
            ("metadata", self.metadata),
            ("pull_requests", self.pull_requests),
            ("checks", self.checks),
            ("statuses", self.statuses),
        ):
            if not isinstance(value, GitHubPermissionLevel):
                raise DomainValidationError(
                    f"permissions.{field} must be a GitHubPermissionLevel"
                )

    @property
    def permits_exact_read(self) -> bool:
        """Return whether all four required permissions are exactly read."""

        return all(
            value is GitHubPermissionLevel.READ
            for value in (
                self.metadata,
                self.pull_requests,
                self.checks,
                self.statuses,
            )
        )


@dataclass(frozen=True, slots=True)
class InstallationAccount:
    """Numeric installation-account authority without login-based identity."""

    account_id: int
    account_type: InstallationAccountType

    def __post_init__(self) -> None:
        _positive_bigint(self.account_id, "account.account_id")
        if not isinstance(self.account_type, InstallationAccountType):
            raise DomainValidationError(
                "account.account_type must be an InstallationAccountType"
            )


@dataclass(frozen=True, slots=True)
class RepositoryRoute:
    """Validated routing metadata; never repository authorization authority."""

    owner: str
    repository: str

    def __post_init__(self) -> None:
        _route_component(self.owner, "route.owner")
        _route_component(self.repository, "route.repository")

    @property
    def full_name(self) -> str:
        """Return the GitHub API route fragment for display and routing."""

        return f"{self.owner}/{self.repository}"


@dataclass(frozen=True, slots=True)
class InstallationObservationV1:
    """Immutable observation of one validated GitHub installation response."""

    observation_id: str
    installation_id: int
    app_id: int
    account: InstallationAccount
    repository_selection: RepositorySelection
    permissions: RepositoryPermissions
    suspended: bool
    suspended_at: datetime | None
    observed_at: datetime
    source_digest: str

    def __post_init__(self) -> None:
        _canonical_uuid(self.observation_id, "observation_id")
        _positive_bigint(self.installation_id, "installation_id")
        _positive_bigint(self.app_id, "app_id")
        if not isinstance(self.account, InstallationAccount):
            raise DomainValidationError("account must be an InstallationAccount")
        if not isinstance(self.repository_selection, RepositorySelection):
            raise DomainValidationError(
                "repository_selection must be a RepositorySelection"
            )
        if not isinstance(self.permissions, RepositoryPermissions):
            raise DomainValidationError("permissions must be RepositoryPermissions")
        _strict_bool(self.suspended, "suspended")
        observed_at = _utc(self.observed_at, "observed_at")
        if self.suspended_at is None:
            if self.suspended:
                raise DomainValidationError(
                    "suspended installation must have suspended_at"
                )
        else:
            suspended_at = _utc(self.suspended_at, "suspended_at")
            if not self.suspended:
                raise DomainValidationError(
                    "unsuspended installation cannot have suspended_at"
                )
            if suspended_at > observed_at:
                raise DomainValidationError("suspended_at cannot follow observed_at")
        if (
            not isinstance(self.source_digest, str)
            or _SHA256.fullmatch(self.source_digest) is None
        ):
            raise DomainValidationError(
                "source_digest must be a lowercase SHA-256 digest"
            )


@dataclass(frozen=True, slots=True, init=False)
class RepositoryAuthorizationV1:
    """Current authorization state whose capability is always fact-derived."""

    repository_id: int
    authorization_version: int
    installation_id: int
    installation_observation_id: str
    route: RepositoryRoute
    installation_account_id: int
    repository_selected: bool
    route_verified: bool
    granted_permissions: RepositoryPermissions
    capability: AuthorizationCapability
    write_enabled: bool
    updated_at: datetime

    @classmethod
    def derive(
        cls,
        *,
        repository_id: int,
        authorization_version: int,
        installation: InstallationObservationV1,
        installation_id: int,
        route: RepositoryRoute,
        installation_account_id: int,
        repository_selected: bool,
        route_verified: bool,
        granted_permissions: RepositoryPermissions,
        updated_at: datetime,
    ) -> Self:
        """Create state from validated facts without accepting a capability."""

        _positive_bigint(repository_id, "repository_id")
        _positive_integer(authorization_version, "authorization_version")
        if not isinstance(installation, InstallationObservationV1):
            raise DomainValidationError(
                "installation must be an InstallationObservationV1"
            )
        _positive_bigint(installation_id, "installation_id")
        if not isinstance(route, RepositoryRoute):
            raise DomainValidationError("route must be a RepositoryRoute")
        _positive_bigint(installation_account_id, "installation_account_id")
        _strict_bool(repository_selected, "repository_selected")
        _strict_bool(route_verified, "route_verified")
        if not isinstance(granted_permissions, RepositoryPermissions):
            raise DomainValidationError(
                "granted_permissions must be RepositoryPermissions"
            )
        checked_updated_at = _utc(updated_at, "updated_at")
        if checked_updated_at < installation.observed_at:
            raise DomainValidationError(
                "updated_at cannot precede the installation observation"
            )
        capability = derive_authorization_capability(
            installation=installation,
            installation_id=installation_id,
            installation_account_id=installation_account_id,
            repository_selected=repository_selected,
            route_verified=route_verified,
            granted_permissions=granted_permissions,
        )
        instance = object.__new__(cls)
        object.__setattr__(instance, "repository_id", repository_id)
        object.__setattr__(
            instance,
            "authorization_version",
            authorization_version,
        )
        object.__setattr__(instance, "installation_id", installation_id)
        object.__setattr__(
            instance,
            "installation_observation_id",
            installation.observation_id,
        )
        object.__setattr__(instance, "route", route)
        object.__setattr__(
            instance,
            "installation_account_id",
            installation_account_id,
        )
        object.__setattr__(instance, "repository_selected", repository_selected)
        object.__setattr__(instance, "route_verified", route_verified)
        object.__setattr__(instance, "granted_permissions", granted_permissions)
        object.__setattr__(instance, "capability", capability)
        object.__setattr__(instance, "write_enabled", False)
        object.__setattr__(instance, "updated_at", checked_updated_at)
        return instance


def derive_authorization_capability(
    *,
    installation: InstallationObservationV1,
    installation_id: int,
    installation_account_id: int,
    repository_selected: bool,
    route_verified: bool,
    granted_permissions: RepositoryPermissions,
) -> AuthorizationCapability:
    """Derive one fail-closed capability using a stable security precedence."""

    if not isinstance(installation, InstallationObservationV1):
        raise DomainValidationError("installation must be an InstallationObservationV1")
    _positive_bigint(installation_id, "installation_id")
    _positive_bigint(installation_account_id, "installation_account_id")
    _strict_bool(repository_selected, "repository_selected")
    _strict_bool(route_verified, "route_verified")
    if not isinstance(granted_permissions, RepositoryPermissions):
        raise DomainValidationError("granted_permissions must be RepositoryPermissions")
    if (
        installation_id != installation.installation_id
        or installation_account_id != installation.account.account_id
    ):
        return AuthorizationCapability.INSTALLATION_MISMATCH
    if installation.suspended:
        return AuthorizationCapability.INSTALLATION_SUSPENDED
    if not repository_selected:
        return AuthorizationCapability.REPOSITORY_NOT_SELECTED
    if not route_verified:
        return AuthorizationCapability.ROUTE_UNVERIFIED
    if (
        not installation.permissions.permits_exact_read
        or not granted_permissions.permits_exact_read
    ):
        return AuthorizationCapability.INSUFFICIENT_PERMISSIONS
    return AuthorizationCapability.AUTHORIZED_READ


def _canonical_uuid(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise DomainValidationError(f"{field} must be a canonical UUID string")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise DomainValidationError(f"{field} must be a canonical UUID string") from exc
    if str(parsed) != value:
        raise DomainValidationError(f"{field} must be a canonical UUID string")
    return value


def _positive_bigint(value: object, field: str) -> int:
    checked = _positive_integer(value, field)
    if checked > _MAX_BIGINT:
        raise DomainValidationError(f"{field} exceeds PostgreSQL bigint")
    return checked


def _positive_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise DomainValidationError(f"{field} must be a positive integer")
    return value


def _strict_bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise DomainValidationError(f"{field} must be a boolean")
    return value


def _route_component(value: object, field: str) -> str:
    if not isinstance(value, str) or _ROUTE_COMPONENT.fullmatch(value) is None:
        raise DomainValidationError(f"{field} must be a valid GitHub route component")
    return value


def _utc(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise DomainValidationError(f"{field} must be timezone-aware UTC")
    if value.utcoffset() != UTC.utcoffset(value):
        raise DomainValidationError(f"{field} must use UTC")
    return value
