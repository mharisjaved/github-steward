"""Authorization-epoch boundary around the unchanged GS-I4 evidence kernel."""

from __future__ import annotations

from typing import NoReturn

from github_steward.domain.acquisition import RepositoryTarget
from github_steward.domain.github_authorization import (
    AuthorizationCapability,
    RepositoryAuthorizationV1,
)
from github_steward.domain.preparedness import PreparednessReasonCode
from github_steward.ports.github import (
    CoherentAcquisitionFailure,
    CoherentAcquisitionPort,
    CoherentAcquisitionResult,
    EvidenceFacet,
    GitHubEvidencePort,
    RecordedFacet,
    RecordedGitHubResponse,
)
from github_steward.ports.github_authorization import (
    GitHubAuthorizationUnitOfWorkFactory,
)


class _AuthorizationEpochGuard:
    """Reload and require the exact repository authorization used to mint."""

    __slots__ = (
        "_authorization_uow_factory",
        "_authorization_version",
        "_repository_id",
    )

    def __init__(
        self,
        *,
        authorization_uow_factory: GitHubAuthorizationUnitOfWorkFactory,
        repository_id: int,
        authorization_version: int,
    ) -> None:
        if (
            isinstance(repository_id, bool)
            or not isinstance(repository_id, int)
            or repository_id < 1
        ):
            raise ValueError("repository_id must be a positive integer")
        if (
            isinstance(authorization_version, bool)
            or not isinstance(authorization_version, int)
            or authorization_version < 1
        ):
            raise ValueError("authorization_version must be a positive integer")
        self._authorization_uow_factory = authorization_uow_factory
        self._repository_id = repository_id
        self._authorization_version = authorization_version

    def require(
        self,
        target: RepositoryTarget,
        *,
        observed_repository_id: int | None = None,
    ) -> None:
        """Fail closed unless the current state is the exact bound read epoch."""

        if (
            observed_repository_id is not None
            and observed_repository_id != self._repository_id
        ):
            self._deny()
        with self._authorization_uow_factory() as unit:
            authorization = unit.github_authorization.get_repository_authorization(
                self._repository_id
            )
        if not self._allows_exact_epoch(authorization, target):
            self._deny()

    def _allows_exact_epoch(
        self,
        authorization: RepositoryAuthorizationV1 | None,
        target: RepositoryTarget,
    ) -> bool:
        return bool(
            isinstance(authorization, RepositoryAuthorizationV1)
            and authorization.repository_id == self._repository_id
            and authorization.authorization_version == self._authorization_version
            and authorization.route.owner == target.owner
            and authorization.route.repository == target.repository
            and authorization.capability is AuthorizationCapability.AUTHORIZED_READ
            and authorization.write_enabled is False
        )

    @staticmethod
    def _deny() -> NoReturn:
        raise CoherentAcquisitionFailure(
            PreparednessReasonCode.EVIDENCE_PERMISSION_DENIED,
            "repository authorization changed or no longer permits authenticated read",
        )


class AuthorizationBoundGitHubEvidence:
    """Recheck the mint epoch after every read and before GS-I4 sees evidence."""

    __slots__ = ("_evidence", "_guard")

    def __init__(
        self,
        *,
        evidence: GitHubEvidencePort,
        authorization_uow_factory: GitHubAuthorizationUnitOfWorkFactory,
        repository_id: int,
        authorization_version: int,
    ) -> None:
        self._evidence = evidence
        self._guard = _AuthorizationEpochGuard(
            authorization_uow_factory=authorization_uow_factory,
            repository_id=repository_id,
            authorization_version=authorization_version,
        )

    def read_anchor(self, target: RepositoryTarget) -> RecordedGitHubResponse:
        """Return an anchor only if authorization remains at the minted epoch."""

        response = self._evidence.read_anchor(target)
        self._guard.require(target)
        return response

    def read_facet(
        self,
        target: RepositoryTarget,
        *,
        head_sha: str,
        facet: EvidenceFacet,
    ) -> RecordedFacet:
        """Return a facet only if authorization remains at the minted epoch."""

        response = self._evidence.read_facet(
            target,
            head_sha=head_sha,
            facet=facet,
        )
        self._guard.require(target)
        return response


class AuthorizationBoundAcquisition:
    """Defend the persistence boundary with a final authorization-epoch check."""

    __slots__ = ("_acquisition", "_guard")

    def __init__(
        self,
        *,
        acquisition: CoherentAcquisitionPort,
        authorization_uow_factory: GitHubAuthorizationUnitOfWorkFactory,
        repository_id: int,
        authorization_version: int,
    ) -> None:
        self._acquisition = acquisition
        self._guard = _AuthorizationEpochGuard(
            authorization_uow_factory=authorization_uow_factory,
            repository_id=repository_id,
            authorization_version=authorization_version,
        )

    def acquire(self, target: RepositoryTarget) -> CoherentAcquisitionResult:
        """Acquire, then recheck before GS-I4 persistence or pointer promotion."""

        acquired = self._acquisition.acquire(target)
        self._guard.require(
            target,
            observed_repository_id=acquired.view.anchor.repository_id,
        )
        return acquired
