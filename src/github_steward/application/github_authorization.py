"""Validate GitHub control-plane facts and persist authorization by CAS."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from github_steward.domain.acquisition import (
    GITHUB_PROVIDER,
    GITHUB_REFRESH_WORK_TYPE,
)
from github_steward.domain.github_authorization import (
    GitHubPermissionLevel,
    InstallationAccount,
    InstallationAccountType,
    InstallationObservationV1,
    RepositoryAuthorizationV1,
    RepositoryPermissions,
    RepositoryRoute,
    RepositorySelection,
)
from github_steward.domain.processing import require_utc_datetime
from github_steward.ports.clock import Clock
from github_steward.ports.github_app import (
    GitHubAppControlPlanePort,
    GitHubControlPlaneResponse,
)
from github_steward.ports.github_authorization import (
    BrokerWorkIdentity,
    GitHubAuthorizationUnitOfWorkFactory,
)

_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class AuthorizationObservationError(RuntimeError):
    """A safe fail-closed response-validation or persistence error."""


class AuthorizationCasConflict(AuthorizationObservationError):
    """The current authorization epoch did not match the expected version."""


@dataclass(frozen=True, slots=True)
class _InstallationFacts:
    installation_id: int
    app_id: int
    account: InstallationAccount
    repository_selection: RepositorySelection
    permissions: RepositoryPermissions
    suspended_at: datetime | None


class GitHubAuthorizationObservationService:
    """Establish installation truth only from validated control-plane reads."""

    def __init__(
        self,
        *,
        control_plane: GitHubAppControlPlanePort,
        unit_of_work_factory: GitHubAuthorizationUnitOfWorkFactory,
        clock: Clock,
        expected_app_id: int,
        observation_id_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        if (
            isinstance(expected_app_id, bool)
            or not isinstance(expected_app_id, int)
            or expected_app_id < 1
        ):
            raise ValueError("expected_app_id must be a positive integer")
        self._control_plane = control_plane
        self._unit_of_work_factory = unit_of_work_factory
        self._clock = clock
        self._expected_app_id = expected_app_id
        self._observation_id_factory = observation_id_factory

    def observe_for_work(
        self,
        *,
        work_record_id: str,
        installation_id: int,
        owner: str,
        repository: str,
        expected_authorization_version: int,
    ) -> RepositoryAuthorizationV1:
        """Observe facts and atomically append/CAS one authorization successor."""

        if not isinstance(work_record_id, str) or work_record_id == "":
            raise AuthorizationObservationError("trusted work identity was invalid")
        if (
            isinstance(installation_id, bool)
            or not isinstance(installation_id, int)
            or installation_id < 1
        ):
            raise AuthorizationObservationError("installation identity was invalid")
        if (
            isinstance(expected_authorization_version, bool)
            or not isinstance(expected_authorization_version, int)
            or expected_authorization_version < 0
        ):
            raise AuthorizationObservationError(
                "expected authorization version was invalid"
            )
        route = RepositoryRoute(owner, repository)
        work = self._load_work(work_record_id)
        if work is None or not _eligible(work):
            raise AuthorizationObservationError(
                "trusted work did not identify an eligible GitHub refresh"
            )

        installation_response = self._control_plane.get_installation(installation_id)
        relationship_response = self._control_plane.get_repository_installation(
            owner=route.owner,
            repository=route.repository,
        )
        observed_at = require_utc_datetime(
            self._clock.now(),
            "installation_observed_at",
        )
        installation = _installation_facts(
            installation_response,
            observed_at=observed_at,
        )
        if (
            installation.installation_id != installation_id
            or installation.app_id != self._expected_app_id
        ):
            raise AuthorizationObservationError(
                "installation response did not match configured authority"
            )

        selected = relationship_response.status_code == 200
        route_verified = selected
        relationship_installation_id = installation.installation_id
        relationship_account_id = installation.account.account_id
        granted_permissions = installation.permissions
        if selected:
            relationship = _installation_facts(
                relationship_response,
                observed_at=observed_at,
            )
            if relationship.app_id != self._expected_app_id:
                raise AuthorizationObservationError(
                    "repository relationship belonged to another application"
                )
            relationship_installation_id = relationship.installation_id
            relationship_account_id = relationship.account.account_id
            granted_permissions = relationship.permissions
        elif relationship_response.status_code != 404:
            raise AuthorizationObservationError(
                "repository relationship response was not classifiable"
            )

        observation = InstallationObservationV1(
            observation_id=str(self._observation_id_factory()),
            installation_id=installation.installation_id,
            app_id=installation.app_id,
            account=installation.account,
            repository_selection=installation.repository_selection,
            permissions=installation.permissions,
            suspended=installation.suspended_at is not None,
            suspended_at=installation.suspended_at,
            observed_at=observed_at,
            source_digest=_source_digest(
                installation_response,
                relationship_response,
            ),
        )
        authorization = RepositoryAuthorizationV1.derive(
            repository_id=work.repository_id,
            authorization_version=expected_authorization_version + 1,
            installation=observation,
            installation_id=relationship_installation_id,
            route=route,
            installation_account_id=relationship_account_id,
            repository_selected=selected,
            route_verified=route_verified,
            granted_permissions=granted_permissions,
            updated_at=observed_at,
        )
        with self._unit_of_work_factory() as unit_of_work:
            repository_port = unit_of_work.github_authorization
            repository_port.append_installation_observation(observation)
            if not repository_port.compare_and_swap_repository_authorization(
                expected_authorization_version=expected_authorization_version,
                replacement=authorization,
            ):
                raise AuthorizationCasConflict(
                    "repository authorization compare-and-swap conflict"
                )
            unit_of_work.commit()
        return authorization

    def _load_work(self, work_record_id: str) -> BrokerWorkIdentity | None:
        with self._unit_of_work_factory() as unit_of_work:
            return unit_of_work.github_authorization.get_work_identity(work_record_id)


def _eligible(work: BrokerWorkIdentity) -> bool:
    return (
        work.provider == GITHUB_PROVIDER
        and work.work_type == GITHUB_REFRESH_WORK_TYPE
        and work.repository_id > 0
        and work.pull_number > 0
    )


def _installation_facts(
    response: GitHubControlPlaneResponse,
    *,
    observed_at: datetime,
) -> _InstallationFacts:
    _response_provenance(response)
    if response.status_code != 200 or not isinstance(response.value, Mapping):
        raise AuthorizationObservationError("installation response was malformed")
    value = response.value
    identifier = _positive(value.get("id"), "installation id")
    app_id = _positive(value.get("app_id"), "application id")
    account_value = value.get("account")
    if not isinstance(account_value, Mapping):
        raise AuthorizationObservationError("installation account was malformed")
    account_id = _positive(account_value.get("id"), "account id")
    account_type_value = account_value.get("type")
    if not isinstance(account_type_value, str):
        raise AuthorizationObservationError("installation account type was unsupported")
    try:
        account_type = InstallationAccountType(account_type_value)
    except (TypeError, ValueError) as exc:
        raise AuthorizationObservationError(
            "installation account type was unsupported"
        ) from exc
    selection_value = value.get("repository_selection")
    if not isinstance(selection_value, str):
        raise AuthorizationObservationError(
            "installation repository selection was unsupported"
        )
    try:
        selection = RepositorySelection(selection_value)
    except (TypeError, ValueError) as exc:
        raise AuthorizationObservationError(
            "installation repository selection was unsupported"
        ) from exc
    permissions = _permissions(value.get("permissions"))
    suspended_value = value.get("suspended_at")
    suspended_at = (
        None
        if suspended_value is None
        else _github_timestamp(suspended_value, "suspended_at")
    )
    if suspended_at is not None and suspended_at > observed_at:
        raise AuthorizationObservationError(
            "installation suspension time followed observation time"
        )
    return _InstallationFacts(
        identifier,
        app_id,
        InstallationAccount(account_id, account_type),
        selection,
        permissions,
        suspended_at,
    )


def _permissions(value: object) -> RepositoryPermissions:
    if not isinstance(value, Mapping) or set(value) != {
        "metadata",
        "pull_requests",
        "checks",
        "statuses",
    }:
        raise AuthorizationObservationError(
            "installation permissions did not match the Stage-1 inventory"
        )
    converted: dict[str, GitHubPermissionLevel] = {}
    for name, level in value.items():
        if not isinstance(name, str):
            raise AuthorizationObservationError("installation permission was malformed")
        try:
            converted[name] = GitHubPermissionLevel(level)
        except (TypeError, ValueError) as exc:
            raise AuthorizationObservationError(
                "installation permission exceeded the read ceiling"
            ) from exc
    return RepositoryPermissions(
        metadata=converted["metadata"],
        pull_requests=converted["pull_requests"],
        checks=converted["checks"],
        statuses=converted["statuses"],
    )


def _response_provenance(response: GitHubControlPlaneResponse) -> None:
    if (
        not isinstance(response, GitHubControlPlaneResponse)
        or not isinstance(response.raw_sha256, str)
        or _DIGEST.fullmatch(response.raw_sha256) is None
        or isinstance(response.status_code, bool)
        or not isinstance(response.status_code, int)
    ):
        raise AuthorizationObservationError(
            "control-plane response provenance was malformed"
        )


def _source_digest(
    installation: GitHubControlPlaneResponse,
    relationship: GitHubControlPlaneResponse,
) -> str:
    _response_provenance(installation)
    _response_provenance(relationship)
    material = (
        "github-app-authorization-observation-v1\n"
        f"{installation.raw_sha256}\n"
        f"{relationship.status_code}\n"
        f"{relationship.raw_sha256}\n"
    ).encode("ascii")
    return hashlib.sha256(material).hexdigest()


def _positive(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise AuthorizationObservationError(f"{field} was not a positive integer")
    return value


def _github_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or value == "" or value != value.strip():
        raise AuthorizationObservationError(f"{field} was not a timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise AuthorizationObservationError(f"{field} was not a timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise AuthorizationObservationError(f"{field} was not UTC")
    return parsed.astimezone(UTC)
