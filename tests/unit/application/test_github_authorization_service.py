"""Application tests for validated control-plane observation and authorization CAS."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

import pytest

from github_steward.application import github_authorization
from github_steward.application.github_authorization import (
    AuthorizationCasConflict,
    AuthorizationObservationError,
    GitHubAuthorizationObservationService,
)
from github_steward.domain.github_authorization import AuthorizationCapability
from github_steward.ports.github_app import (
    GitHubControlPlaneResponse,
    InstallationTokenRequest,
    InstallationTokenResponse,
)
from github_steward.ports.github_authorization import (
    BrokerWorkIdentity,
    GitHubAuthorizationUnitOfWorkFactory,
)

NOW = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class FixedClock:
    def now(self) -> datetime:
        return NOW


def _installation(
    *,
    installation_id: int = 10,
    app_id: int = 30,
    account_id: int = 20,
    selection: str = "selected",
    metadata: str = "read",
    suspended_at: object = None,
    extra_permissions: dict[str, str] | None = None,
) -> dict[str, object]:
    permissions = {
        "metadata": metadata,
        "pull_requests": "read",
        "checks": "read",
        "statuses": "read",
    }
    if extra_permissions:
        permissions.update(extra_permissions)
    return {
        "id": installation_id,
        "app_id": app_id,
        "account": {"id": account_id, "type": "Organization", "login": "display"},
        "repository_selection": selection,
        "permissions": permissions,
        "suspended_at": suspended_at,
    }


class FakeControlPlane:
    def __init__(
        self,
        installation: GitHubControlPlaneResponse,
        relationship: GitHubControlPlaneResponse,
    ) -> None:
        self.installation = installation
        self.relationship = relationship
        self.calls: list[tuple[object, ...]] = []

    def get_installation(self, installation_id: int) -> GitHubControlPlaneResponse:
        self.calls.append(("installation", installation_id))
        return self.installation

    def get_repository_installation(
        self,
        *,
        owner: str,
        repository: str,
    ) -> GitHubControlPlaneResponse:
        self.calls.append(("relationship", owner, repository))
        return self.relationship

    def create_installation_token(
        self,
        *,
        installation_id: int,
        request: InstallationTokenRequest,
    ) -> InstallationTokenResponse:
        raise AssertionError("observation must never mint a token")


class FakeAuthorizationRepository:
    def __init__(self, *, cas_result: bool = True) -> None:
        self.work: BrokerWorkIdentity | None = BrokerWorkIdentity(
            "work-1",
            "github",
            "REFRESH_GITHUB_PULL_REQUEST",
            123456,
            7,
        )
        self.cas_result = cas_result
        self.observations: list[object] = []
        self.cas_calls: list[tuple[int, object]] = []

    def get_work_identity(self, work_record_id: str) -> BrokerWorkIdentity | None:
        if self.work is not None and self.work.work_record_id == work_record_id:
            return self.work
        return None

    def append_installation_observation(self, observation: object) -> None:
        self.observations.append(observation)

    def compare_and_swap_repository_authorization(
        self,
        *,
        expected_authorization_version: int,
        replacement: object,
    ) -> bool:
        self.cas_calls.append((expected_authorization_version, replacement))
        return self.cas_result


class FakeUnitOfWork:
    def __init__(self, repository: FakeAuthorizationRepository) -> None:
        self.github_authorization = repository
        self.committed = False

    def __enter__(self) -> FakeUnitOfWork:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        return None


class FakeUnitOfWorkFactory:
    def __init__(self, repository: FakeAuthorizationRepository) -> None:
        self.repository = repository
        self.units: list[FakeUnitOfWork] = []

    def __call__(self) -> FakeUnitOfWork:
        unit = FakeUnitOfWork(self.repository)
        self.units.append(unit)
        return unit


def _response(
    value: object,
    *,
    status: int = 200,
    digest: str = "a" * 64,
) -> GitHubControlPlaneResponse:
    return GitHubControlPlaneResponse(value, digest, status)


def _service(
    control: FakeControlPlane,
    repository: FakeAuthorizationRepository,
) -> tuple[GitHubAuthorizationObservationService, FakeUnitOfWorkFactory]:
    factory = FakeUnitOfWorkFactory(repository)
    return (
        GitHubAuthorizationObservationService(
            control_plane=control,
            unit_of_work_factory=cast(GitHubAuthorizationUnitOfWorkFactory, factory),
            clock=FixedClock(),
            expected_app_id=30,
            observation_id_factory=lambda: UUID("00000000-0000-4000-8000-000000000001"),
        ),
        factory,
    )


def test_validated_responses_append_observation_and_create_authorized_version() -> None:
    control = FakeControlPlane(
        _response(_installation()),
        _response(_installation(), digest="b" * 64),
    )
    repository = FakeAuthorizationRepository()
    service, factory = _service(control, repository)

    authorization = service.observe_for_work(
        work_record_id="work-1",
        installation_id=10,
        owner="Owner",
        repository="Repository",
        expected_authorization_version=0,
    )

    assert authorization.repository_id == 123456
    assert authorization.authorization_version == 1
    assert authorization.capability is AuthorizationCapability.AUTHORIZED_READ
    assert authorization.write_enabled is False
    assert authorization.route.full_name == "Owner/Repository"
    assert len(repository.observations) == 1
    observation = repository.observations[0]
    assert "private" not in repr(observation).casefold()
    assert "token" not in repr(observation).casefold()
    assert repository.cas_calls == [(0, authorization)]
    assert factory.units[-1].committed
    assert control.calls == [
        ("installation", 10),
        ("relationship", "Owner", "Repository"),
    ]


def test_validated_relationship_404_creates_denied_current_state() -> None:
    control = FakeControlPlane(
        _response(_installation()),
        _response({"message": "not found"}, status=404, digest="b" * 64),
    )
    repository = FakeAuthorizationRepository()
    service, _ = _service(control, repository)

    authorization = service.observe_for_work(
        work_record_id="work-1",
        installation_id=10,
        owner="Owner",
        repository="Repository",
        expected_authorization_version=4,
    )

    assert authorization.authorization_version == 5
    assert not authorization.repository_selected
    assert not authorization.route_verified
    assert authorization.capability is AuthorizationCapability.REPOSITORY_NOT_SELECTED


@pytest.mark.parametrize(
    ("installation", "capability"),
    [
        (
            _installation(suspended_at="2026-08-18T11:00:00Z"),
            AuthorizationCapability.INSTALLATION_SUSPENDED,
        ),
        (
            _installation(metadata="none"),
            AuthorizationCapability.INSUFFICIENT_PERMISSIONS,
        ),
    ],
)
def test_suspension_and_missing_read_permission_are_fact_derived(
    installation: dict[str, object],
    capability: AuthorizationCapability,
) -> None:
    control = FakeControlPlane(_response(installation), _response(installation))
    service, _ = _service(control, FakeAuthorizationRepository())
    result = service.observe_for_work(
        work_record_id="work-1",
        installation_id=10,
        owner="Owner",
        repository="Repository",
        expected_authorization_version=0,
    )
    assert result.capability is capability


def test_installation_permissions_cannot_be_expanded_by_relationship_response() -> None:
    control = FakeControlPlane(
        _response(_installation(metadata="none")),
        _response(_installation(metadata="read"), digest="b" * 64),
    )
    service, _ = _service(control, FakeAuthorizationRepository())
    result = service.observe_for_work(
        work_record_id="work-1",
        installation_id=10,
        owner="Owner",
        repository="Repository",
        expected_authorization_version=0,
    )
    assert result.capability is AuthorizationCapability.INSUFFICIENT_PERMISSIONS


def test_relationship_installation_mismatch_is_persisted_as_denied_not_authorized() -> (
    None
):
    control = FakeControlPlane(
        _response(_installation()),
        _response(_installation(installation_id=11, account_id=21)),
    )
    service, _ = _service(control, FakeAuthorizationRepository())
    result = service.observe_for_work(
        work_record_id="work-1",
        installation_id=10,
        owner="Owner",
        repository="Repository",
        expected_authorization_version=0,
    )
    assert result.capability is AuthorizationCapability.INSTALLATION_MISMATCH


@pytest.mark.parametrize(
    "installation",
    [
        _installation(app_id=31),
        _installation(metadata="write"),
        _installation(extra_permissions={"contents": "read"}),
        _installation(selection="unknown"),
        {"id": 10},
    ],
)
def test_untrusted_or_expanded_installation_response_is_rejected_before_write(
    installation: dict[str, object],
) -> None:
    control = FakeControlPlane(_response(installation), _response(installation))
    repository = FakeAuthorizationRepository()
    service, _ = _service(control, repository)
    with pytest.raises(AuthorizationObservationError):
        service.observe_for_work(
            work_record_id="work-1",
            installation_id=10,
            owner="Owner",
            repository="Repository",
            expected_authorization_version=0,
        )
    assert repository.observations == []


def test_invalid_work_and_cas_conflict_fail_closed() -> None:
    control = FakeControlPlane(
        _response(_installation()),
        _response(_installation()),
    )
    missing = FakeAuthorizationRepository()
    missing.work = None
    service, _ = _service(control, missing)
    with pytest.raises(AuthorizationObservationError):
        service.observe_for_work(
            work_record_id="missing",
            installation_id=10,
            owner="Owner",
            repository="Repo",
            expected_authorization_version=0,
        )
    assert control.calls == []

    conflict = FakeAuthorizationRepository(cas_result=False)
    conflict_service, factory = _service(control, conflict)
    with pytest.raises(AuthorizationCasConflict):
        conflict_service.observe_for_work(
            work_record_id="work-1",
            installation_id=10,
            owner="Owner",
            repository="Repo",
            expected_authorization_version=9,
        )
    assert not factory.units[-1].committed


@pytest.mark.parametrize(
    "response",
    [
        GitHubControlPlaneResponse(_installation(), "invalid", 200),
        GitHubControlPlaneResponse(_installation(), "a" * 64, True),
        GitHubControlPlaneResponse(_installation(), "a" * 64, 500),
    ],
)
def test_control_plane_provenance_and_status_are_strict(
    response: GitHubControlPlaneResponse,
) -> None:
    service, _ = _service(
        FakeControlPlane(response, _response(_installation())),
        FakeAuthorizationRepository(),
    )
    with pytest.raises(AuthorizationObservationError):
        service.observe_for_work(
            work_record_id="work-1",
            installation_id=10,
            owner="Owner",
            repository="Repo",
            expected_authorization_version=0,
        )


@pytest.mark.parametrize("expected_app_id", [0, -1, True, "30"])
def test_service_requires_positive_numeric_configured_app_identity(
    expected_app_id: object,
) -> None:
    with pytest.raises(ValueError, match="expected_app_id"):
        GitHubAuthorizationObservationService(
            control_plane=FakeControlPlane(
                _response(_installation()),
                _response(_installation()),
            ),
            unit_of_work_factory=cast(
                GitHubAuthorizationUnitOfWorkFactory,
                FakeUnitOfWorkFactory(FakeAuthorizationRepository()),
            ),
            clock=FixedClock(),
            expected_app_id=expected_app_id,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("work_record_id", "installation_id", "expected_version"),
    [
        ("", 10, 0),
        (1, 10, 0),
        ("work-1", 0, 0),
        ("work-1", True, 0),
        ("work-1", 10, -1),
        ("work-1", 10, True),
    ],
)
def test_observation_call_rejects_invalid_authority_inputs(
    work_record_id: object,
    installation_id: object,
    expected_version: object,
) -> None:
    control = FakeControlPlane(_response(_installation()), _response(_installation()))
    service, _ = _service(control, FakeAuthorizationRepository())
    with pytest.raises(AuthorizationObservationError):
        service.observe_for_work(
            work_record_id=work_record_id,  # type: ignore[arg-type]
            installation_id=installation_id,  # type: ignore[arg-type]
            owner="Owner",
            repository="Repo",
            expected_authorization_version=expected_version,  # type: ignore[arg-type]
        )
    assert control.calls == []


@pytest.mark.parametrize(
    "work",
    [
        BrokerWorkIdentity("work-1", "github", "REFRESH_GITHUB_PULL_REQUEST", 0, 7),
        BrokerWorkIdentity(
            "work-1", "github", "REFRESH_GITHUB_PULL_REQUEST", 123456, 0
        ),
    ],
)
def test_non_positive_trusted_work_subject_is_ineligible(
    work: BrokerWorkIdentity,
) -> None:
    repository = FakeAuthorizationRepository()
    repository.work = work
    control = FakeControlPlane(_response(_installation()), _response(_installation()))
    service, _ = _service(control, repository)
    with pytest.raises(AuthorizationObservationError, match="eligible GitHub refresh"):
        service.observe_for_work(
            work_record_id="work-1",
            installation_id=10,
            owner="Owner",
            repository="Repo",
            expected_authorization_version=0,
        )
    assert control.calls == []


def test_relationship_app_mismatch_and_unclassifiable_status_fail_closed() -> None:
    for relationship in (
        _response(_installation(app_id=31), digest="b" * 64),
        _response({"message": "unavailable"}, status=500, digest="b" * 64),
    ):
        service, _ = _service(
            FakeControlPlane(_response(_installation()), relationship),
            FakeAuthorizationRepository(),
        )
        with pytest.raises(AuthorizationObservationError):
            service.observe_for_work(
                work_record_id="work-1",
                installation_id=10,
                owner="Owner",
                repository="Repo",
                expected_authorization_version=0,
            )


@pytest.mark.parametrize(
    "installation",
    [
        _installation(installation_id=0),
        {**_installation(), "account": []},
        {**_installation(), "account": {"id": 20, "type": 1}},
        {**_installation(), "account": {"id": 20, "type": "Enterprise"}},
        {**_installation(), "repository_selection": 1},
        _installation(suspended_at="2026-08-18T12:00:01Z"),
    ],
)
def test_installation_fact_shapes_and_future_suspension_are_rejected(
    installation: dict[str, object],
) -> None:
    service, _ = _service(
        FakeControlPlane(_response(installation), _response(_installation())),
        FakeAuthorizationRepository(),
    )
    with pytest.raises(AuthorizationObservationError):
        service.observe_for_work(
            work_record_id="work-1",
            installation_id=10,
            owner="Owner",
            repository="Repo",
            expected_authorization_version=0,
        )


class _NonStringItemsPermissions(Mapping[object, object]):
    def __getitem__(self, key: object) -> object:
        return "read"

    def __iter__(self) -> Iterator[object]:
        return iter(("metadata", "pull_requests", "checks", "statuses"))

    def __len__(self) -> int:
        return 4

    def items(self) -> object:  # type: ignore[override]
        return ((1, "read"),)


def test_permission_item_names_remain_defensively_type_checked() -> None:
    with pytest.raises(AuthorizationObservationError, match="permission was malformed"):
        github_authorization._permissions(_NonStringItemsPermissions())


@pytest.mark.parametrize(
    "response",
    [
        object(),
        GitHubControlPlaneResponse(_installation(), cast(str, 1), 200),
        GitHubControlPlaneResponse(_installation(), "a" * 64, cast(int, "200")),
    ],
)
def test_control_plane_provenance_rejects_non_protocol_shapes(response: object) -> None:
    with pytest.raises(AuthorizationObservationError, match="provenance"):
        github_authorization._response_provenance(response)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        " 2026-08-18T12:00:00Z",
        "not-a-time",
        "2026-08-18T12:00:00",
        "2026-08-18T13:00:00+01:00",
    ],
)
def test_github_timestamp_requires_strict_utc_text(value: object) -> None:
    with pytest.raises(AuthorizationObservationError):
        github_authorization._github_timestamp(value, "timestamp")
