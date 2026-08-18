"""Fail-closed GitHub App read credential broker."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import NoReturn

from github_steward.domain.acquisition import (
    GITHUB_PROVIDER,
    GITHUB_REFRESH_WORK_TYPE,
)
from github_steward.domain.github_authorization import (
    AuthorizationCapability,
    GitHubPermissionLevel,
    InstallationObservationV1,
    RepositoryAuthorizationV1,
    RepositorySelection,
)
from github_steward.domain.processing import require_utc_datetime
from github_steward.ports.clock import Clock
from github_steward.ports.github_app import (
    READ_PERMISSIONS,
    GitHubAppControlPlanePort,
    InstallationTokenRequest,
    InstallationTokenResponse,
)
from github_steward.ports.github_authorization import (
    BrokerWorkIdentity,
    GitHubAuthorizationUnitOfWorkFactory,
)
from github_steward.ports.secrets import OpaqueBearerToken

from .cache import ReadTokenCache, TokenCacheKey


class BrokerFailureCode(StrEnum):
    """Secret-free failure classification for the local broker protocol."""

    INVALID_WORK_ID = "INVALID_WORK_ID"
    WORK_NOT_FOUND = "WORK_NOT_FOUND"
    WORK_NOT_AUTHORIZED = "WORK_NOT_AUTHORIZED"
    AUTHORIZATION_NOT_FOUND = "AUTHORIZATION_NOT_FOUND"
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    INSTALLATION_NOT_FOUND = "INSTALLATION_NOT_FOUND"
    INSTALLATION_MISMATCH = "INSTALLATION_MISMATCH"
    TOKEN_RESPONSE_REJECTED = "TOKEN_RESPONSE_REJECTED"
    AUTHORIZATION_CHANGED = "AUTHORIZATION_CHANGED"
    UPSTREAM_FAILURE = "UPSTREAM_FAILURE"


class CredentialBrokerError(RuntimeError):
    """A credential-free failure safe for a bounded local response."""

    def __init__(self, code: BrokerFailureCode, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class MintReadTokenResult:
    """One opaque token bound to an exact repository authorization epoch."""

    token: OpaqueBearerToken
    repository_id: int
    authorization_version: int
    expires_at: datetime


_PERMISSIONS_DIGEST = hashlib.sha256(
    json.dumps(
        dict(READ_PERMISSIONS),
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
).hexdigest()


class GitHubReadCredentialBroker:
    """Resolve trusted work and mint only an exact one-repository read token."""

    def __init__(
        self,
        *,
        unit_of_work_factory: GitHubAuthorizationUnitOfWorkFactory,
        control_plane: GitHubAppControlPlanePort,
        clock: Clock,
        cache: ReadTokenCache | None = None,
    ) -> None:
        self._unit_of_work_factory = unit_of_work_factory
        self._control_plane = control_plane
        self._clock = clock
        self._cache = ReadTokenCache() if cache is None else cache

    def MintReadToken(self, work_record_id: str) -> MintReadTokenResult:
        """Mint or safely reuse a read token from only a trusted work identity."""

        if not isinstance(work_record_id, str) or work_record_id == "":
            raise CredentialBrokerError(
                BrokerFailureCode.INVALID_WORK_ID,
                "work_record_id must be a non-empty string",
            )
        try:
            work = self._load_work(work_record_id)
        except (TypeError, ValueError) as exc:
            raise CredentialBrokerError(
                BrokerFailureCode.INVALID_WORK_ID,
                "work_record_id was not a canonical trusted identity",
            ) from exc
        if work is None:
            raise CredentialBrokerError(
                BrokerFailureCode.WORK_NOT_FOUND,
                "trusted work record was not found",
            )
        self._require_eligible_work(work)
        authorization = self._load_authorization(work.repository_id)
        if authorization is None:
            raise CredentialBrokerError(
                BrokerFailureCode.AUTHORIZATION_NOT_FOUND,
                "repository authorization was not found",
            )
        self._require_authorized(authorization, work.repository_id)
        observation = self._load_observation(authorization.installation_observation_id)
        if observation is None:
            raise CredentialBrokerError(
                BrokerFailureCode.INSTALLATION_NOT_FOUND,
                "installation observation was not found",
            )
        self._require_installation(authorization, observation)

        key = TokenCacheKey(
            installation_id=authorization.installation_id,
            repository_id=authorization.repository_id,
            authorization_version=authorization.authorization_version,
            permissions_digest=_PERMISSIONS_DIGEST,
        )
        now = require_utc_datetime(self._clock.now(), "broker_now")
        cached = self._cache.get(key, now=now)
        if cached is not None:
            self._require_unchanged(authorization)
            return MintReadTokenResult(
                cached.token,
                authorization.repository_id,
                authorization.authorization_version,
                cached.expires_at,
            )

        try:
            response = self._control_plane.create_installation_token(
                installation_id=authorization.installation_id,
                request=InstallationTokenRequest(authorization.repository_id),
            )
        except Exception as exc:
            raise CredentialBrokerError(
                BrokerFailureCode.UPSTREAM_FAILURE,
                "installation token creation failed",
            ) from exc
        validation_now = require_utc_datetime(
            self._clock.now(), "broker_validation_now"
        )
        expires_at = self._validate_token_response(
            response,
            repository_id=authorization.repository_id,
            now=validation_now,
        )
        self._require_unchanged(authorization)
        self._cache.put(
            key,
            token=response.token,
            expires_at=expires_at,
        )
        return MintReadTokenResult(
            response.token,
            authorization.repository_id,
            authorization.authorization_version,
            expires_at,
        )

    def _load_work(self, work_record_id: str) -> BrokerWorkIdentity | None:
        with self._unit_of_work_factory() as unit_of_work:
            return unit_of_work.github_authorization.get_work_identity(work_record_id)

    def _load_authorization(
        self,
        repository_id: int,
    ) -> RepositoryAuthorizationV1 | None:
        with self._unit_of_work_factory() as unit_of_work:
            return unit_of_work.github_authorization.get_repository_authorization(
                repository_id
            )

    def _load_observation(
        self,
        observation_id: str,
    ) -> InstallationObservationV1 | None:
        with self._unit_of_work_factory() as unit_of_work:
            return unit_of_work.github_authorization.get_installation_observation(
                observation_id
            )

    @staticmethod
    def _require_eligible_work(work: BrokerWorkIdentity) -> None:
        if (
            work.provider != GITHUB_PROVIDER
            or work.work_type != GITHUB_REFRESH_WORK_TYPE
            or work.repository_id < 1
        ):
            raise CredentialBrokerError(
                BrokerFailureCode.WORK_NOT_AUTHORIZED,
                "work record is not eligible for GitHub read credentials",
            )

    @staticmethod
    def _require_authorized(
        authorization: RepositoryAuthorizationV1,
        expected_repository_id: int,
    ) -> None:
        if (
            authorization.repository_id != expected_repository_id
            or authorization.capability is not AuthorizationCapability.AUTHORIZED_READ
            or authorization.write_enabled
        ):
            raise CredentialBrokerError(
                BrokerFailureCode.AUTHORIZATION_DENIED,
                "repository read authorization was denied",
            )

    @staticmethod
    def _require_installation(
        authorization: RepositoryAuthorizationV1,
        observation: InstallationObservationV1,
    ) -> None:
        read = GitHubPermissionLevel.READ
        permission_values = (
            observation.permissions.metadata,
            observation.permissions.pull_requests,
            observation.permissions.checks,
            observation.permissions.statuses,
            authorization.granted_permissions.metadata,
            authorization.granted_permissions.pull_requests,
            authorization.granted_permissions.checks,
            authorization.granted_permissions.statuses,
        )
        if (
            observation.observation_id != authorization.installation_observation_id
            or observation.installation_id != authorization.installation_id
            or observation.account.account_id != authorization.installation_account_id
            or observation.suspended
            or observation.repository_selection
            not in {RepositorySelection.ALL, RepositorySelection.SELECTED}
            or not authorization.repository_selected
            or not authorization.route_verified
            or any(value is not read for value in permission_values)
        ):
            raise CredentialBrokerError(
                BrokerFailureCode.INSTALLATION_MISMATCH,
                "installation facts did not authorize the repository read",
            )

    def _require_unchanged(self, expected: RepositoryAuthorizationV1) -> None:
        current = self._load_authorization(expected.repository_id)
        if (
            current is None
            or current.authorization_version != expected.authorization_version
            or current.capability is not AuthorizationCapability.AUTHORIZED_READ
            or current.write_enabled
        ):
            self._cache.invalidate_repository(expected.repository_id)
            raise CredentialBrokerError(
                BrokerFailureCode.AUTHORIZATION_CHANGED,
                "repository authorization changed during token minting",
            )

    @staticmethod
    def _validate_token_response(
        response: object,
        *,
        repository_id: int,
        now: datetime,
    ) -> datetime:
        if not isinstance(response, InstallationTokenResponse):
            _reject_token()
        if not isinstance(response.token, OpaqueBearerToken):
            _reject_token()
        expires_at = _expiry(response.expires_at)
        if expires_at <= now:
            _reject_token()
        if response.permissions != READ_PERMISSIONS:
            _reject_token()
        if response.repository_ids is not None and response.repository_ids != (
            repository_id,
        ):
            _reject_token()
        if response.repository_selection is not None and (
            response.repository_selection != RepositorySelection.SELECTED.value
        ):
            _reject_token()
        return expires_at


def _expiry(value: str) -> datetime:
    if not isinstance(value, str) or value == "" or value != value.strip():
        _reject_token()
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        _reject_token()
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        _reject_token()
    return parsed.astimezone(UTC)


def _reject_token() -> NoReturn:
    raise CredentialBrokerError(
        BrokerFailureCode.TOKEN_RESPONSE_REJECTED,
        "installation token response failed validation",
    )
