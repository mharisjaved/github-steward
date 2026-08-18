"""Strict secret-free GitHub authorization domain contracts."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
from datetime import UTC, datetime, timedelta, timezone

import pytest

from github_steward.domain.errors import DomainValidationError
from github_steward.domain.github_authorization import (
    AuthorizationCapability,
    GitHubPermissionLevel,
    InstallationAccount,
    InstallationAccountType,
    InstallationObservationV1,
    RepositoryAuthorizationV1,
    RepositoryPermissions,
    RepositoryRoute,
    RepositorySelection,
    derive_authorization_capability,
)

NOW = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
OBSERVATION_ID = "00000000-0000-0000-0000-000000000501"
READ = RepositoryPermissions(
    metadata=GitHubPermissionLevel.READ,
    pull_requests=GitHubPermissionLevel.READ,
    checks=GitHubPermissionLevel.READ,
    statuses=GitHubPermissionLevel.READ,
)


def observation(
    *,
    installation_id: int = 701,
    account_id: int = 801,
    suspended: bool = False,
    suspended_at: datetime | None = None,
    permissions: RepositoryPermissions = READ,
) -> InstallationObservationV1:
    return InstallationObservationV1(
        observation_id=OBSERVATION_ID,
        installation_id=installation_id,
        app_id=601,
        account=InstallationAccount(
            account_id=account_id,
            account_type=InstallationAccountType.ORGANIZATION,
        ),
        repository_selection=RepositorySelection.SELECTED,
        permissions=permissions,
        suspended=suspended,
        suspended_at=suspended_at,
        observed_at=NOW,
        source_digest="a" * 64,
    )


def authorization(
    installation: InstallationObservationV1 | None = None,
    **changes: object,
) -> RepositoryAuthorizationV1:
    values: dict[str, object] = {
        "repository_id": 901,
        "authorization_version": 1,
        "installation": installation or observation(),
        "installation_id": 701,
        "route": RepositoryRoute("octo", "repo"),
        "installation_account_id": 801,
        "repository_selected": True,
        "route_verified": True,
        "granted_permissions": READ,
        "updated_at": NOW,
    }
    values.update(changes)
    return RepositoryAuthorizationV1.derive(**values)  # type: ignore[arg-type]


def test_valid_models_are_immutable_nested_and_secret_free() -> None:
    installed = observation()
    current = authorization(installed)
    assert current.capability is AuthorizationCapability.AUTHORIZED_READ
    assert current.installation_observation_id == installed.observation_id
    assert current.route.full_name == "octo/repo"
    assert current.write_enabled is False
    with pytest.raises(FrozenInstanceError):
        current.authorization_version = 2  # type: ignore[misc]
    names = {
        field.name
        for model in (
            InstallationObservationV1,
            RepositoryAuthorizationV1,
        )
        for field in fields(model)
    }
    assert not names & {
        "private_key",
        "private_key_pem",
        "jwt",
        "token",
        "installation_token",
        "authorization_header",
    }


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"installation_id": 999}, AuthorizationCapability.INSTALLATION_MISMATCH),
        (
            {"installation_account_id": 999},
            AuthorizationCapability.INSTALLATION_MISMATCH,
        ),
        (
            {"repository_selected": False},
            AuthorizationCapability.REPOSITORY_NOT_SELECTED,
        ),
        ({"route_verified": False}, AuthorizationCapability.ROUTE_UNVERIFIED),
        (
            {
                "granted_permissions": RepositoryPermissions(
                    GitHubPermissionLevel.READ,
                    GitHubPermissionLevel.READ,
                    GitHubPermissionLevel.NONE,
                    GitHubPermissionLevel.READ,
                )
            },
            AuthorizationCapability.INSUFFICIENT_PERMISSIONS,
        ),
        (
            {
                "installation": observation(
                    permissions=RepositoryPermissions(
                        GitHubPermissionLevel.NONE,
                        GitHubPermissionLevel.READ,
                        GitHubPermissionLevel.READ,
                        GitHubPermissionLevel.READ,
                    )
                )
            },
            AuthorizationCapability.INSUFFICIENT_PERMISSIONS,
        ),
    ],
)
def test_capability_is_deterministically_derived(
    changes: dict[str, object],
    expected: AuthorizationCapability,
) -> None:
    assert authorization(**changes).capability is expected  # type: ignore[arg-type]


def test_suspension_and_security_precedence_are_deterministic() -> None:
    suspended = observation(suspended=True, suspended_at=NOW - timedelta(seconds=1))
    assert (
        authorization(suspended).capability
        is AuthorizationCapability.INSTALLATION_SUSPENDED
    )
    assert (
        authorization(suspended, installation_id=999).capability
        is AuthorizationCapability.INSTALLATION_MISMATCH
    )


@pytest.mark.parametrize("field", ["metadata", "pull_requests", "checks", "statuses"])
def test_permissions_require_enum_instances(field: str) -> None:
    values: dict[str, object] = {
        "metadata": GitHubPermissionLevel.READ,
        "pull_requests": GitHubPermissionLevel.READ,
        "checks": GitHubPermissionLevel.READ,
        "statuses": GitHubPermissionLevel.READ,
    }
    values[field] = "read"
    with pytest.raises(DomainValidationError, match=field):
        RepositoryPermissions(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("constructor", "message"),
    [
        (lambda: InstallationAccount(True, InstallationAccountType.USER), "positive"),
        (
            lambda: InstallationAccount(1, "User"),  # type: ignore[arg-type]
            "account_type",
        ),
        (lambda: RepositoryRoute("bad/owner", "repo"), "route.owner"),
        (lambda: RepositoryRoute("owner", ""), "route.repository"),
    ],
)
def test_nested_values_are_strict(constructor: object, message: str) -> None:
    with pytest.raises(DomainValidationError, match=message):
        constructor()  # type: ignore[operator]


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"observation_id": "not-a-uuid"}, "observation_id"),
        (
            {"observation_id": "AAAAAAAA-0000-0000-0000-000000000501"},
            "observation_id",
        ),
        ({"installation_id": 0}, "installation_id"),
        ({"app_id": True}, "app_id"),
        ({"account": object()}, "account"),
        ({"repository_selection": "selected"}, "repository_selection"),
        ({"permissions": object()}, "permissions"),
        ({"suspended": 1}, "suspended"),
        ({"suspended": True}, "suspended_at"),
        ({"suspended_at": NOW}, "unsuspended"),
        ({"observed_at": NOW.replace(tzinfo=None)}, "observed_at"),
        ({"source_digest": "A" * 64}, "source_digest"),
    ],
)
def test_installation_observation_rejects_untrusted_values(
    changes: dict[str, object],
    message: str,
) -> None:
    values: dict[str, object] = {
        "observation_id": OBSERVATION_ID,
        "installation_id": 701,
        "app_id": 601,
        "account": InstallationAccount(801, InstallationAccountType.USER),
        "repository_selection": RepositorySelection.SELECTED,
        "permissions": READ,
        "suspended": False,
        "suspended_at": None,
        "observed_at": NOW,
        "source_digest": "a" * 64,
    }
    values.update(changes)
    with pytest.raises(DomainValidationError, match=message):
        InstallationObservationV1(**values)  # type: ignore[arg-type]


def test_installation_observation_rejects_future_suspension() -> None:
    with pytest.raises(DomainValidationError, match="follow"):
        observation(suspended=True, suspended_at=NOW + timedelta(seconds=1))


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"repository_id": False}, "repository_id"),
        ({"repository_id": 1 << 63}, "bigint"),
        ({"authorization_version": 0}, "authorization_version"),
        ({"installation": object()}, "installation"),
        ({"installation_id": 0}, "installation_id"),
        ({"route": object()}, "route"),
        ({"installation_account_id": 0}, "installation_account_id"),
        ({"repository_selected": 1}, "repository_selected"),
        ({"route_verified": 1}, "route_verified"),
        ({"granted_permissions": object()}, "granted_permissions"),
        ({"updated_at": NOW - timedelta(seconds=1)}, "precede"),
        ({"updated_at": datetime.now(timezone(timedelta(hours=1)))}, "UTC"),
    ],
)
def test_repository_authorization_rejects_invalid_facts(
    changes: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(DomainValidationError, match=message):
        authorization(**changes)  # type: ignore[arg-type]


def test_derivation_function_rejects_non_observation() -> None:
    with pytest.raises(DomainValidationError, match="installation"):
        derive_authorization_capability(
            installation=object(),  # type: ignore[arg-type]
            installation_id=1,
            installation_account_id=1,
            repository_selected=True,
            route_verified=True,
            granted_permissions=READ,
        )


def test_derivation_function_rejects_non_permissions() -> None:
    installed = observation()
    with pytest.raises(DomainValidationError, match="granted_permissions"):
        derive_authorization_capability(
            installation=installed,
            installation_id=installed.installation_id,
            installation_account_id=installed.account.account_id,
            repository_selected=True,
            route_verified=True,
            granted_permissions=object(),  # type: ignore[arg-type]
        )


def test_observation_identifier_must_be_a_string() -> None:
    with pytest.raises(DomainValidationError, match="observation_id"):
        InstallationObservationV1(
            observation_id=1,  # type: ignore[arg-type]
            installation_id=1,
            app_id=1,
            account=InstallationAccount(1, InstallationAccountType.USER),
            repository_selection=RepositorySelection.ALL,
            permissions=READ,
            suspended=False,
            suspended_at=None,
            observed_at=NOW,
            source_digest="a" * 64,
        )
