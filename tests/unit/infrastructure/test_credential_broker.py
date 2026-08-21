"""Fail-closed tests for the sole MintReadToken broker operation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

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
from github_steward.infrastructure.broker.credential_broker import (
    BrokerFailureCode,
    CredentialBrokerError,
    GitHubReadCredentialBroker,
)
from github_steward.ports.github_app import (
    READ_PERMISSIONS,
    GitHubControlPlaneResponse,
    InstallationTokenRequest,
    InstallationTokenResponse,
)
from github_steward.ports.github_authorization import (
    BrokerWorkIdentity,
    GitHubAuthorizationUnitOfWorkFactory,
)
from github_steward.ports.secrets import OpaqueBearerToken

NOW = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
OBSERVATION_ID = "00000000-0000-4000-8000-000000000001"


@dataclass(frozen=True, slots=True)
class FixedClock:
    value: datetime = NOW

    def now(self) -> datetime:
        return self.value


class AdvancingClock:
    def __init__(self) -> None:
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        return NOW if self.calls == 1 else NOW + timedelta(hours=2)


READ = RepositoryPermissions(
    GitHubPermissionLevel.READ,
    GitHubPermissionLevel.READ,
    GitHubPermissionLevel.READ,
    GitHubPermissionLevel.READ,
)
NONE = RepositoryPermissions(
    GitHubPermissionLevel.NONE,
    GitHubPermissionLevel.READ,
    GitHubPermissionLevel.READ,
    GitHubPermissionLevel.READ,
)


def _observation(
    *,
    observation_id: str = OBSERVATION_ID,
    installation_id: int = 10,
    account_id: int = 20,
    suspended: bool = False,
    permissions: RepositoryPermissions = READ,
) -> InstallationObservationV1:
    return InstallationObservationV1(
        observation_id=observation_id,
        installation_id=installation_id,
        app_id=30,
        account=InstallationAccount(account_id, InstallationAccountType.ORGANIZATION),
        repository_selection=RepositorySelection.SELECTED,
        permissions=permissions,
        suspended=suspended,
        suspended_at=NOW - timedelta(minutes=1) if suspended else None,
        observed_at=NOW - timedelta(minutes=2),
        source_digest="a" * 64,
    )


def _authorization(
    observation: InstallationObservationV1,
    *,
    version: int = 3,
    selected: bool = True,
    route_verified: bool = True,
    permissions: RepositoryPermissions = READ,
) -> RepositoryAuthorizationV1:
    return RepositoryAuthorizationV1.derive(
        repository_id=123456,
        authorization_version=version,
        installation=observation,
        installation_id=observation.installation_id,
        route=RepositoryRoute("Owner", "Repository"),
        installation_account_id=observation.account.account_id,
        repository_selected=selected,
        route_verified=route_verified,
        granted_permissions=permissions,
        updated_at=NOW,
    )


class FakeAuthorizationRepository:
    def __init__(
        self,
        *,
        work: BrokerWorkIdentity | None,
        authorizations: list[RepositoryAuthorizationV1 | None],
        observation: InstallationObservationV1 | None,
    ) -> None:
        self.work = work
        self.authorizations = authorizations
        self.observation = observation
        self.authorization_reads = 0

    def get_work_identity(self, work_record_id: str) -> BrokerWorkIdentity | None:
        if self.work is None or self.work.work_record_id != work_record_id:
            return None
        return self.work

    def get_repository_authorization(
        self,
        repository_id: int,
    ) -> RepositoryAuthorizationV1 | None:
        assert repository_id == 123456
        index = min(self.authorization_reads, len(self.authorizations) - 1)
        self.authorization_reads += 1
        return self.authorizations[index]

    def get_installation_observation(
        self,
        observation_id: str,
    ) -> InstallationObservationV1 | None:
        if (
            self.observation is None
            or self.observation.observation_id != observation_id
        ):
            return None
        return self.observation


class FakeUnitOfWork:
    def __init__(self, repository: FakeAuthorizationRepository) -> None:
        self.github_authorization = repository

    def __enter__(self) -> FakeUnitOfWork:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def commit(self) -> None:
        return None

    def rollback(self) -> None:
        return None


class FakeUnitOfWorkFactory:
    def __init__(self, repository: FakeAuthorizationRepository) -> None:
        self.repository = repository

    def __call__(self) -> FakeUnitOfWork:
        return FakeUnitOfWork(self.repository)


class FakeControlPlane:
    def __init__(self, response: object) -> None:
        self.response = response
        self.requests: list[tuple[int, InstallationTokenRequest]] = []

    def get_installation(self, installation_id: int) -> GitHubControlPlaneResponse:
        raise AssertionError("broker must not perform observation operations")

    def get_repository_installation(
        self,
        *,
        owner: str,
        repository: str,
    ) -> GitHubControlPlaneResponse:
        raise AssertionError("broker must not perform observation operations")

    def create_installation_token(
        self,
        *,
        installation_id: int,
        request: InstallationTokenRequest,
    ) -> InstallationTokenResponse:
        self.requests.append((installation_id, request))
        if isinstance(self.response, Exception):
            raise self.response
        return cast(InstallationTokenResponse, self.response)


def _work(
    *,
    provider: str = "github",
    work_type: str = "REFRESH_GITHUB_PULL_REQUEST",
) -> BrokerWorkIdentity:
    return BrokerWorkIdentity("work-1", provider, work_type, 123456, 7)


def _response(
    token: str = "opaque-short",
    *,
    expires_at: str = "2026-08-18T13:00:00Z",
    permissions: tuple[tuple[str, str], ...] = READ_PERMISSIONS,
    repository_ids: tuple[int, ...] | None = (123456,),
    repository_selection: str | None = "selected",
) -> InstallationTokenResponse:
    return InstallationTokenResponse(
        OpaqueBearerToken(token),
        expires_at,
        permissions,
        repository_ids,
        repository_selection,
    )


def _broker(
    repository: FakeAuthorizationRepository,
    control: FakeControlPlane,
) -> GitHubReadCredentialBroker:
    return GitHubReadCredentialBroker(
        unit_of_work_factory=cast(
            GitHubAuthorizationUnitOfWorkFactory,
            FakeUnitOfWorkFactory(repository),
        ),
        control_plane=control,
        clock=FixedClock(),
    )


@pytest.mark.parametrize("token", ["tiny", "x" * 500])
def test_mint_resolves_scope_from_trusted_work_and_accepts_opaque_token_shapes(
    token: str,
) -> None:
    observation = _observation()
    authorization = _authorization(observation)
    repository = FakeAuthorizationRepository(
        work=_work(),
        authorizations=[authorization],
        observation=observation,
    )
    control = FakeControlPlane(_response(token))

    result = _broker(repository, control).MintReadToken("work-1")

    assert result.token.matches(token)
    assert result.repository_id == 123456
    assert result.authorization_version == 3
    assert control.requests == [(10, InstallationTokenRequest(123456))]
    assert control.requests[0][1].as_mapping() == {
        "repository_ids": [123456],
        "permissions": dict(READ_PERMISSIONS),
    }


def test_cache_reuses_only_same_authorization_epoch_and_still_rechecks() -> None:
    observation = _observation()
    authorization = _authorization(observation)
    repository = FakeAuthorizationRepository(
        work=_work(),
        authorizations=[authorization],
        observation=observation,
    )
    control = FakeControlPlane(_response())
    broker = _broker(repository, control)

    first = broker.MintReadToken("work-1")
    second = broker.MintReadToken("work-1")

    assert first.token is second.token
    assert len(control.requests) == 1
    assert repository.authorization_reads == 4


def test_authorization_change_during_mint_fails_closed() -> None:
    observation = _observation()
    version_three = _authorization(observation, version=3)
    version_four = _authorization(observation, version=4)
    repository = FakeAuthorizationRepository(
        work=_work(),
        authorizations=[version_three, version_four],
        observation=observation,
    )

    with pytest.raises(CredentialBrokerError) as raised:
        _broker(repository, FakeControlPlane(_response())).MintReadToken("work-1")

    assert raised.value.code is BrokerFailureCode.AUTHORIZATION_CHANGED
    assert "opaque-short" not in str(raised.value)


@pytest.mark.parametrize(
    ("work", "code"),
    [
        (None, BrokerFailureCode.WORK_NOT_FOUND),
        (_work(provider="synthetic"), BrokerFailureCode.WORK_NOT_AUTHORIZED),
        (
            _work(work_type="PROCESS_SYNTHETIC_OBSERVATION"),
            BrokerFailureCode.WORK_NOT_AUTHORIZED,
        ),
        (
            _work(work_type="REFRESH_GITHUB_REPOSITORY"),
            BrokerFailureCode.WORK_NOT_AUTHORIZED,
        ),
        (
            _work(work_type="REFRESH_GITHUB_AUTHORIZATION"),
            BrokerFailureCode.WORK_NOT_AUTHORIZED,
        ),
    ],
)
def test_invalid_or_ineligible_work_never_reaches_token_endpoint(
    work: BrokerWorkIdentity | None,
    code: BrokerFailureCode,
) -> None:
    observation = _observation()
    repository = FakeAuthorizationRepository(
        work=work,
        authorizations=[_authorization(observation)],
        observation=observation,
    )
    control = FakeControlPlane(_response())
    with pytest.raises(CredentialBrokerError) as raised:
        _broker(repository, control).MintReadToken("work-1")
    assert raised.value.code is code
    assert control.requests == []


def test_empty_work_id_is_rejected_before_persistence() -> None:
    repository = FakeAuthorizationRepository(
        work=None,
        authorizations=[None],
        observation=None,
    )
    with pytest.raises(CredentialBrokerError) as raised:
        _broker(repository, FakeControlPlane(_response())).MintReadToken("")
    assert raised.value.code is BrokerFailureCode.INVALID_WORK_ID


def test_malformed_persisted_work_identity_is_safely_classified() -> None:
    observation = _observation()

    class InvalidWorkRepository(FakeAuthorizationRepository):
        def get_work_identity(self, work_record_id: str) -> BrokerWorkIdentity | None:
            del work_record_id
            raise ValueError("database parser detail")

    repository = InvalidWorkRepository(
        work=_work(),
        authorizations=[_authorization(observation)],
        observation=observation,
    )
    with pytest.raises(CredentialBrokerError) as raised:
        _broker(repository, FakeControlPlane(_response())).MintReadToken("malformed")
    assert raised.value.code is BrokerFailureCode.INVALID_WORK_ID
    assert "database parser detail" not in str(raised.value)


@pytest.mark.parametrize(
    "authorization",
    [
        None,
        _authorization(_observation(), selected=False),
        _authorization(_observation(), permissions=NONE),
    ],
)
def test_missing_or_denied_authorization_fails_before_mint(
    authorization: RepositoryAuthorizationV1 | None,
) -> None:
    observation = _observation()
    repository = FakeAuthorizationRepository(
        work=_work(),
        authorizations=[authorization],
        observation=observation,
    )
    control = FakeControlPlane(_response())
    with pytest.raises(CredentialBrokerError) as raised:
        _broker(repository, control).MintReadToken("work-1")
    assert raised.value.code in {
        BrokerFailureCode.AUTHORIZATION_NOT_FOUND,
        BrokerFailureCode.AUTHORIZATION_DENIED,
    }
    assert control.requests == []


def test_missing_or_mismatched_installation_fails_before_mint() -> None:
    authorized_observation = _observation()
    authorization = _authorization(authorized_observation)
    for loaded in (
        None,
        _observation(
            observation_id=OBSERVATION_ID,
            installation_id=99,
            account_id=20,
        ),
    ):
        repository = FakeAuthorizationRepository(
            work=_work(),
            authorizations=[authorization],
            observation=loaded,
        )
        control = FakeControlPlane(_response())
        with pytest.raises(CredentialBrokerError) as raised:
            _broker(repository, control).MintReadToken("work-1")
        assert raised.value.code in {
            BrokerFailureCode.INSTALLATION_NOT_FOUND,
            BrokerFailureCode.INSTALLATION_MISMATCH,
        }
        assert control.requests == []


@pytest.mark.parametrize(
    "response",
    [
        _response(expires_at="2026-08-18T11:59:59Z"),
        _response(expires_at="not-a-time"),
        _response(expires_at=" 2026-08-18T13:00:00Z"),
        _response(expires_at="2026-08-18T13:00:00"),
        _response(permissions=(("metadata", "write"),)),
        _response(repository_ids=(999,)),
        _response(repository_ids=(123456, 999)),
        _response(repository_selection="all"),
        InstallationTokenResponse(
            cast(OpaqueBearerToken, None),
            "2026-08-18T13:00:00Z",
            READ_PERMISSIONS,
            (123456,),
            "selected",
        ),
        object(),
    ],
)
def test_token_response_expansion_or_malformed_data_fails_closed(
    response: object,
) -> None:
    observation = _observation()
    repository = FakeAuthorizationRepository(
        work=_work(),
        authorizations=[_authorization(observation)],
        observation=observation,
    )
    with pytest.raises(CredentialBrokerError) as raised:
        _broker(repository, FakeControlPlane(response)).MintReadToken("work-1")
    assert raised.value.code is BrokerFailureCode.TOKEN_RESPONSE_REJECTED


def test_token_expiry_is_rechecked_after_upstream_mint() -> None:
    observation = _observation()
    repository = FakeAuthorizationRepository(
        work=_work(),
        authorizations=[_authorization(observation)],
        observation=observation,
    )
    broker = GitHubReadCredentialBroker(
        unit_of_work_factory=cast(
            GitHubAuthorizationUnitOfWorkFactory,
            FakeUnitOfWorkFactory(repository),
        ),
        control_plane=FakeControlPlane(_response()),
        clock=AdvancingClock(),
    )
    with pytest.raises(CredentialBrokerError) as raised:
        broker.MintReadToken("work-1")
    assert raised.value.code is BrokerFailureCode.TOKEN_RESPONSE_REJECTED


def test_upstream_failure_is_classified_without_leaking_message() -> None:
    observation = _observation()
    repository = FakeAuthorizationRepository(
        work=_work(),
        authorizations=[_authorization(observation)],
        observation=observation,
    )
    with pytest.raises(CredentialBrokerError) as raised:
        _broker(
            repository,
            FakeControlPlane(RuntimeError("upstream contained opaque-short")),
        ).MintReadToken("work-1")
    assert raised.value.code is BrokerFailureCode.UPSTREAM_FAILURE
    assert "opaque-short" not in str(raised.value)
