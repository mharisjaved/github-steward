"""Authorization-epoch checks around the unchanged coherent acquisition port."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Self, cast
from uuid import UUID

import pytest

from github_steward.adapters.canonicalization.rfc8785 import (
    digest_payload,
    envelope_payload,
)
from github_steward.application.authenticated_acquisition import (
    AuthorizationBoundAcquisition,
    AuthorizationBoundGitHubEvidence,
)
from github_steward.application.preparedness import (
    CoherentRecordedAcquisitionService,
    DeterministicPreparednessPipeline,
)
from github_steward.domain.acquisition import (
    SEMANTIC_FACETS,
    CoherentAnalysisView,
    PullRequestAnchor,
    RepositoryTarget,
    RequestedReviewers,
)
from github_steward.domain.canonical import Digest
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
)
from github_steward.domain.preparedness import (
    PreparednessReasonCode,
    ProfileReference,
    PullRequestIdentity,
)
from github_steward.ports.github import (
    CoherentAcquisitionFailure,
    CoherentAcquisitionResult,
    EvidenceFacet,
    RecordedFacet,
    RecordedGitHubResponse,
)
from github_steward.ports.github_authorization import (
    GitHubAuthorizationUnitOfWorkFactory,
)
from github_steward.ports.persistence import ProcessingUnitOfWork

NOW = datetime(2026, 8, 18, 12, tzinfo=UTC)
TARGET = RepositoryTarget("Owner", "Repo", 4)
HEAD = "a" * 40


def _result(repository_id: int = 77) -> CoherentAcquisitionResult:
    view = CoherentAnalysisView(
        analysis_view_id="11111111-1111-5111-8111-111111111111",
        anchor=PullRequestAnchor(
            repository_id=repository_id,
            pull_number=4,
            pull_request_id=404,
            head_sha=HEAD,
            base_repository_id=repository_id,
            base_ref="main",
            base_sha="b" * 40,
            state="open",
            draft=False,
            updated_at=NOW,
            changed_files=0,
            commit_count=0,
        ),
        files=(),
        commits=(),
        files_digest="c" * 64,
        commits_digest="d" * 64,
        requested_reviewers=RequestedReviewers(),
        check_suite_count=0,
        check_runs=(),
        commit_statuses=(),
        reviews=(),
        acquisition_configuration_digest="e" * 64,
        evidence_sealed_at=NOW,
        raw_digest_inventory={"anchor_a": ("f" * 64,)},
        semantic_digest_inventory={facet: "0" * 64 for facet in SEMANTIC_FACETS},
    )
    return CoherentAcquisitionResult(
        view=view,
        view_envelope=envelope_payload(view.as_mapping()),
        attempts=1,
        facet_envelopes={},
    )


def _permissions() -> RepositoryPermissions:
    return RepositoryPermissions(
        metadata=GitHubPermissionLevel.READ,
        pull_requests=GitHubPermissionLevel.READ,
        checks=GitHubPermissionLevel.READ,
        statuses=GitHubPermissionLevel.READ,
    )


def _authorization(
    version: int = 7,
    *,
    selected: bool = True,
    owner: str = "Owner",
    repository: str = "Repo",
) -> RepositoryAuthorizationV1:
    installation = InstallationObservationV1(
        observation_id="22222222-2222-5222-8222-222222222222",
        installation_id=10,
        app_id=11,
        account=InstallationAccount(12, InstallationAccountType.ORGANIZATION),
        repository_selection=RepositorySelection.ALL,
        permissions=_permissions(),
        suspended=False,
        suspended_at=None,
        observed_at=NOW,
        source_digest="1" * 64,
    )
    return RepositoryAuthorizationV1.derive(
        repository_id=77,
        authorization_version=version,
        installation=installation,
        installation_id=10,
        route=RepositoryRoute(owner, repository),
        installation_account_id=12,
        repository_selected=selected,
        route_verified=True,
        granted_permissions=_permissions(),
        updated_at=NOW,
    )


class _FakeAcquisition:
    def __init__(
        self,
        result: CoherentAcquisitionResult,
        on_acquire: Callable[[], None] | None = None,
    ) -> None:
        self.result = result
        self.on_acquire = on_acquire
        self.calls: list[RepositoryTarget] = []

    def acquire(self, target: RepositoryTarget) -> CoherentAcquisitionResult:
        self.calls.append(target)
        if self.on_acquire is not None:
            self.on_acquire()
        return self.result


class _FakeAuthorizationRepository:
    def __init__(self, authorization: RepositoryAuthorizationV1 | None) -> None:
        self.authorization = authorization
        self.reads: list[int] = []

    def get_repository_authorization(
        self,
        repository_id: int,
    ) -> RepositoryAuthorizationV1 | None:
        self.reads.append(repository_id)
        return self.authorization


class _FakeAuthorizationUnit:
    def __init__(self, repository: _FakeAuthorizationRepository) -> None:
        self.github_authorization = repository
        self.entered = 0
        self.exited = 0
        self.commits = 0

    def __enter__(self) -> Self:
        self.entered += 1
        return self

    def __exit__(self, *args: object) -> None:
        self.exited += 1

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        return None


class _FakeAuthorizationFactory:
    def __init__(self, unit: _FakeAuthorizationUnit) -> None:
        self.unit = unit

    def __call__(self) -> _FakeAuthorizationUnit:
        return self.unit


class _CountingClock:
    def __init__(self) -> None:
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        return NOW


class _SequencedEvidence:
    """Stable GS-I4 evidence with an optional exact mutation point."""

    def __init__(
        self,
        repository: _FakeAuthorizationRepository,
        *,
        mutation: str | None = None,
    ) -> None:
        self.repository = repository
        self.mutation = mutation
        self.calls: list[str] = []
        self.anchor_calls = 0
        self.facet_calls = {facet: 0 for facet in EvidenceFacet}

    def read_anchor(self, target: RepositoryTarget) -> RecordedGitHubResponse:
        assert target == TARGET
        self.calls.append("anchor")
        self.anchor_calls += 1
        response = self._recorded(
            {
                "id": 404,
                "number": 4,
                "state": "open",
                "draft": False,
                "updated_at": "2026-08-18T11:59:00Z",
                "changed_files": 0,
                "commits": 0,
                "head": {"sha": HEAD},
                "base": {
                    "ref": "main",
                    "sha": "b" * 40,
                    "repo": {"id": 77, "full_name": "Owner/Repo"},
                },
            },
            f"anchor-{self.anchor_calls}",
        )
        if self.mutation == "final_c" and self.anchor_calls == 3:
            self.repository.authorization = _authorization(version=8)
        return response

    def read_facet(
        self,
        target: RepositoryTarget,
        *,
        head_sha: str,
        facet: EvidenceFacet,
    ) -> RecordedFacet:
        assert target == TARGET
        assert head_sha == HEAD
        self.calls.append(facet.value)
        self.facet_calls[facet] += 1
        value: object
        total_count: int | None = 0
        if facet is EvidenceFacet.REQUESTED_REVIEWERS:
            value = {"users": [], "teams": []}
            total_count = None
        elif facet is EvidenceFacet.CHECK_SUITE_COUNT:
            value = {"total_count": 0}
        else:
            value = []
        response = RecordedFacet(
            value=value,
            raw_responses=(
                self._recorded(value, f"{facet.value}-{self.facet_calls[facet]}"),
            ),
            total_count=total_count,
            complete=True,
        )
        if (
            self.mutation == "final_facet"
            and facet is EvidenceFacet.COMMIT_STATUSES
            and self.facet_calls[facet] == 2
        ):
            self.repository.authorization = _authorization(version=8)
        return response

    @staticmethod
    def _recorded(value: object, label: str) -> RecordedGitHubResponse:
        return RecordedGitHubResponse(
            value=value,
            raw_sha256=hashlib.sha256(label.encode()).hexdigest(),
            response_bytes=100,
        )


def _authorization_factory(
    repository: _FakeAuthorizationRepository,
) -> tuple[GitHubAuthorizationUnitOfWorkFactory, _FakeAuthorizationUnit]:
    unit = _FakeAuthorizationUnit(repository)
    return (
        cast(
            GitHubAuthorizationUnitOfWorkFactory,
            _FakeAuthorizationFactory(unit),
        ),
        unit,
    )


def _epoch_bound_kernel(
    repository: _FakeAuthorizationRepository,
    evidence: _SequencedEvidence,
    clock: _CountingClock,
) -> tuple[AuthorizationBoundAcquisition, _FakeAuthorizationUnit]:
    factory, unit = _authorization_factory(repository)
    pre_seal = AuthorizationBoundGitHubEvidence(
        evidence=evidence,
        authorization_uow_factory=factory,
        repository_id=77,
        authorization_version=7,
    )
    kernel = CoherentRecordedAcquisitionService(
        evidence=pre_seal,
        clock=clock,
        envelope_factory=envelope_payload,
        acquisition_configuration_digest=digest_payload(
            {"api_version": "2026-03-10", "per_page": 100, "attempts": 2}
        ),
    )
    return (
        AuthorizationBoundAcquisition(
            acquisition=kernel,
            authorization_uow_factory=factory,
            repository_id=77,
            authorization_version=7,
        ),
        unit,
    )


def _service(
    acquisition: _FakeAcquisition,
    repository: _FakeAuthorizationRepository,
    *,
    version: int = 7,
) -> tuple[AuthorizationBoundAcquisition, _FakeAuthorizationUnit]:
    unit = _FakeAuthorizationUnit(repository)
    factory = cast(
        GitHubAuthorizationUnitOfWorkFactory,
        _FakeAuthorizationFactory(unit),
    )
    return (
        AuthorizationBoundAcquisition(
            acquisition=acquisition,
            authorization_uow_factory=factory,
            repository_id=77,
            authorization_version=version,
        ),
        unit,
    )


def test_pre_and_post_epoch_boundaries_preserve_exact_gs_i4_sequence() -> None:
    repository = _FakeAuthorizationRepository(_authorization())
    evidence = _SequencedEvidence(repository)
    clock = _CountingClock()
    service, unit = _epoch_bound_kernel(repository, evidence, clock)

    result = service.acquire(TARGET)

    expected_pass = [facet.value for facet in EvidenceFacet]
    assert evidence.calls == [
        "anchor",
        *expected_pass,
        "anchor",
        *expected_pass,
        "anchor",
    ]
    assert result.attempts == 1
    assert result.view.anchor.repository_id == 77
    assert clock.calls == 1
    assert repository.reads == [77] * 18
    assert unit.entered == 18
    assert unit.exited == 18
    assert unit.commits == 0


@pytest.mark.parametrize(
    ("mutation", "expected_evidence_reads"),
    [("final_facet", 16), ("final_c", 17)],
)
def test_epoch_change_at_final_read_fails_before_coherent_seal(
    mutation: str,
    expected_evidence_reads: int,
) -> None:
    repository = _FakeAuthorizationRepository(_authorization())
    evidence = _SequencedEvidence(repository, mutation=mutation)
    clock = _CountingClock()
    service, unit = _epoch_bound_kernel(repository, evidence, clock)

    with pytest.raises(CoherentAcquisitionFailure) as raised:
        service.acquire(TARGET)

    assert raised.value.reason is PreparednessReasonCode.EVIDENCE_PERMISSION_DENIED
    assert clock.calls == 0
    assert len(evidence.calls) == expected_evidence_reads
    assert repository.reads == [77] * expected_evidence_reads
    assert unit.entered == expected_evidence_reads
    assert unit.exited == expected_evidence_reads
    assert unit.commits == 0


def test_unchanged_authorization_epoch_returns_exact_coherent_result() -> None:
    result = _result()
    acquisition = _FakeAcquisition(result)
    repository = _FakeAuthorizationRepository(_authorization())
    service, unit = _service(acquisition, repository)

    assert service.acquire(TARGET) is result
    assert acquisition.calls == [TARGET]
    assert repository.reads == [77]
    assert unit.entered == 1
    assert unit.exited == 1
    assert unit.commits == 0


def test_n_to_n_plus_one_during_acquisition_fails_closed() -> None:
    repository = _FakeAuthorizationRepository(_authorization())

    def advance_epoch() -> None:
        repository.authorization = _authorization(version=8)

    acquisition = _FakeAcquisition(_result(), advance_epoch)
    service, _ = _service(acquisition, repository, version=7)

    with pytest.raises(CoherentAcquisitionFailure) as raised:
        service.acquire(TARGET)
    assert raised.value.reason is PreparednessReasonCode.EVIDENCE_PERMISSION_DENIED
    assert "token" not in str(raised.value).casefold()


@pytest.mark.parametrize("condition", ["missing", "capability", "route", "write"])
def test_every_epoch_allow_condition_fails_closed(condition: str) -> None:
    authorization: RepositoryAuthorizationV1 | None = _authorization()
    if condition == "missing":
        authorization = None
    elif condition == "capability":
        authorization = _authorization(selected=False)
        assert (
            authorization.capability is AuthorizationCapability.REPOSITORY_NOT_SELECTED
        )
    elif condition == "route":
        authorization = _authorization(owner="Other")
    else:
        assert authorization is not None
        object.__setattr__(authorization, "write_enabled", True)

    service, _ = _service(
        _FakeAcquisition(_result()),
        _FakeAuthorizationRepository(authorization),
    )
    with pytest.raises(CoherentAcquisitionFailure) as raised:
        service.acquire(TARGET)
    assert raised.value.reason is PreparednessReasonCode.EVIDENCE_PERMISSION_DENIED


def test_observed_repository_substitution_fails_before_authorization_read() -> None:
    repository = _FakeAuthorizationRepository(_authorization())
    service, unit = _service(_FakeAcquisition(_result(repository_id=78)), repository)
    with pytest.raises(CoherentAcquisitionFailure):
        service.acquire(TARGET)
    assert repository.reads == []
    assert unit.entered == 0


def test_epoch_failure_enters_no_gs_i4_persistence_transaction() -> None:
    repository = _FakeAuthorizationRepository(_authorization(version=8))
    service, _ = _service(_FakeAcquisition(_result()), repository, version=7)
    persistence_calls = 0

    def forbidden_persistence() -> ProcessingUnitOfWork:
        nonlocal persistence_calls
        persistence_calls += 1
        raise AssertionError("GS-I4 persistence must not begin after epoch failure")

    class ForbiddenClock:
        def now(self) -> datetime:
            raise AssertionError("evaluation clock must not be read")

    pipeline = DeterministicPreparednessPipeline(
        acquisition=service,
        unit_of_work_factory=forbidden_persistence,
        evaluation_clock=ForbiddenClock(),
        envelope_factory=envelope_payload,
    )
    outcome = pipeline.assess(
        target=TARGET,
        expected_identity=PullRequestIdentity(
            77,
            404,
            4,
            HEAD,
            77,
            "main",
            "b" * 40,
        ),
        profile_reference=ProfileReference(
            UUID("33333333-3333-5333-8333-333333333333"),
            1,
            Digest("2" * 64),
        ),
    )
    assert outcome.assessment is None
    assert (
        outcome.acquisition_failure is PreparednessReasonCode.EVIDENCE_PERMISSION_DENIED
    )
    assert persistence_calls == 0


@pytest.mark.parametrize(
    ("repository_id", "authorization_version"),
    [(0, 1), (True, 1), (77, 0), (77, True)],
)
def test_constructor_rejects_invalid_epoch_binding(
    repository_id: int,
    authorization_version: int,
) -> None:
    repository = _FakeAuthorizationRepository(_authorization())
    unit = _FakeAuthorizationUnit(repository)
    factory = cast(
        GitHubAuthorizationUnitOfWorkFactory,
        _FakeAuthorizationFactory(unit),
    )
    with pytest.raises(ValueError):
        AuthorizationBoundAcquisition(
            acquisition=_FakeAcquisition(_result()),
            authorization_uow_factory=factory,
            repository_id=repository_id,
            authorization_version=authorization_version,
        )
