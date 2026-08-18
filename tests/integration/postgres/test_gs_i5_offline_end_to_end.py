"""Strongest offline proof of the GS-I5 authenticated-read chain."""

from __future__ import annotations

import json
import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Thread
from uuid import uuid4

import httpx
import jwt
import sqlalchemy as sa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy.engine import Engine

from github_steward.adapters.canonicalization.rfc8785 import (
    digest_payload,
    envelope_payload,
)
from github_steward.adapters.github.authenticated_rest import (
    AuthenticatedGitHubEvidenceAdapter,
)
from github_steward.adapters.postgres.metadata import (
    delivery_inbox,
    preparedness_assessment,
    work_record,
)
from github_steward.adapters.postgres.unit_of_work import PostgresUnitOfWork
from github_steward.application.authenticated_acquisition import (
    AuthorizationBoundAcquisition,
    AuthorizationBoundGitHubEvidence,
)
from github_steward.application.preparedness import (
    CoherentRecordedAcquisitionService,
    DeterministicPreparednessPipeline,
)
from github_steward.domain.acquisition import (
    GITHUB_PROVIDER,
    GITHUB_REFRESH_WORK_TYPE,
    RepositoryTarget,
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
from github_steward.domain.preparedness import (
    AcquisitionConfigurationIdentity,
    PreparednessProfile,
    PreparednessVerdict,
    PullRequestIdentity,
)
from github_steward.infrastructure.broker.app_control_plane import (
    GitHubAppControlPlaneClient,
)
from github_steward.infrastructure.broker.credential_broker import (
    GitHubReadCredentialBroker,
)
from github_steward.infrastructure.broker.jwt_signer import GitHubAppJwtSigner
from github_steward.infrastructure.broker.unix_socket import (
    UnixBrokerClient,
    UnixBrokerServer,
)

NOW = datetime(2026, 8, 18, 12, tzinfo=UTC)
REPOSITORY_ID = 8_151_001
PULL_NUMBER = 51
PULL_REQUEST_ID = 8_151_051
INSTALLATION_ID = 8_151_101
HEAD = "a" * 40
BASE = "b" * 40
TARGET = RepositoryTarget("offline-owner", "offline-repository", PULL_NUMBER)
CONFIGURATION = digest_payload(
    {"api_version": "2026-03-10", "per_page": 100, "attempts": 2}
)
READ = RepositoryPermissions(
    GitHubPermissionLevel.READ,
    GitHubPermissionLevel.READ,
    GitHubPermissionLevel.READ,
    GitHubPermissionLevel.READ,
)


class FixedClock:
    def now(self) -> datetime:
        return NOW


def _persist_trusted_work_and_authorization(engine: Engine) -> str:
    observation = InstallationObservationV1(
        observation_id=str(uuid4()),
        installation_id=INSTALLATION_ID,
        app_id=8_151_201,
        account=InstallationAccount(
            8_151_301,
            InstallationAccountType.ORGANIZATION,
        ),
        repository_selection=RepositorySelection.SELECTED,
        permissions=READ,
        suspended=False,
        suspended_at=None,
        observed_at=NOW,
        source_digest="c" * 64,
    )
    authorization = RepositoryAuthorizationV1.derive(
        repository_id=REPOSITORY_ID,
        authorization_version=1,
        installation=observation,
        installation_id=INSTALLATION_ID,
        route=RepositoryRoute(TARGET.owner, TARGET.repository),
        installation_account_id=observation.account.account_id,
        repository_selected=True,
        route_verified=True,
        granted_permissions=READ,
        updated_at=NOW,
    )
    with PostgresUnitOfWork(engine) as unit:
        unit.github_authorization.append_installation_observation(observation)
        assert unit.github_authorization.compare_and_swap_repository_authorization(
            expected_authorization_version=0,
            replacement=authorization,
        )
        unit.commit()

    delivery_id = uuid4()
    work_id = uuid4()
    with engine.begin() as connection:
        connection.execute(
            delivery_inbox.insert().values(
                delivery_id=delivery_id,
                provider=GITHUB_PROVIDER,
                provider_delivery_id=f"gs-i5-offline-{delivery_id}",
                payload_digest="d" * 64,
                received_at=NOW,
                payload_schema_id="github-steward/github-refresh/v1",
                payload_schema_version=1,
                canonical_payload={
                    "entity_kind": "github_pull_request",
                    "entity_id": f"{REPOSITORY_ID}:{PULL_NUMBER}",
                },
                payload_digest_format="jcs-sha256/v1",
            )
        )
        connection.execute(
            work_record.insert().values(
                work_record_id=work_id,
                delivery_id=delivery_id,
                work_type=GITHUB_REFRESH_WORK_TYPE,
                state="AVAILABLE",
                available_at=NOW,
            )
        )
    return str(work_id)


def _control_plane() -> tuple[GitHubAppControlPlaneClient, list[dict[str, object]]]:
    key = rsa.generate_private_key(public_exponent=65_537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    jwt_claims: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.raw_path == (
            f"/app/installations/{INSTALLATION_ID}/access_tokens".encode()
        )
        authorization = request.headers["Authorization"]
        assert authorization.startswith("Bearer ")
        decoded = jwt.decode(
            authorization.removeprefix("Bearer "),
            public_pem,
            algorithms=["RS256"],
            options={"verify_exp": False, "verify_iat": False},
        )
        jwt_claims.append(decoded)
        assert json.loads(request.content) == {
            "repository_ids": [REPOSITORY_ID],
            "permissions": {
                "metadata": "read",
                "pull_requests": "read",
                "checks": "read",
                "statuses": "read",
            },
        }
        opaque_token = "offline-" + secrets.token_urlsafe(384)
        return httpx.Response(
            201,
            json={
                "token": opaque_token,
                "expires_at": (NOW + timedelta(hours=1))
                .isoformat()
                .replace("+00:00", "Z"),
                "permissions": {
                    "metadata": "read",
                    "pull_requests": "read",
                    "checks": "read",
                    "statuses": "read",
                },
                "repositories": [{"id": REPOSITORY_ID}],
                "repository_selection": "selected",
            },
        )

    signer = GitHubAppJwtSigner(
        client_id="offline-client-id",
        private_key_pem=private_pem,
        clock=FixedClock(),
    )
    return (
        GitHubAppControlPlaneClient(
            jwt_provider=signer,
            transport=httpx.MockTransport(handler),
        ),
        jwt_claims,
    )


def _repository_responses() -> dict[str, object]:
    return {
        f"/repos/{TARGET.owner}/{TARGET.repository}/pulls/{PULL_NUMBER}": {
            "id": PULL_REQUEST_ID,
            "number": PULL_NUMBER,
            "state": "open",
            "draft": False,
            "updated_at": "2026-08-18T11:59:00Z",
            "changed_files": 0,
            "commits": 0,
            "head": {"sha": HEAD},
            "base": {
                "ref": "main",
                "sha": BASE,
                "repo": {
                    "id": REPOSITORY_ID,
                    "full_name": f"{TARGET.owner}/{TARGET.repository}",
                },
            },
        },
        f"/repos/{TARGET.owner}/{TARGET.repository}/pulls/{PULL_NUMBER}/files?per_page=100": [],
        f"/repos/{TARGET.owner}/{TARGET.repository}/pulls/{PULL_NUMBER}/commits?per_page=100": [],
        f"/repos/{TARGET.owner}/{TARGET.repository}/pulls/{PULL_NUMBER}/reviews?per_page=100": [],
        f"/repos/{TARGET.owner}/{TARGET.repository}/pulls/{PULL_NUMBER}/requested_reviewers?per_page=100": {
            "users": [],
            "teams": [],
        },
        f"/repos/{TARGET.owner}/{TARGET.repository}/commits/{HEAD}/check-suites": {
            "total_count": 0,
            "check_suites": [],
        },
        f"/repos/{TARGET.owner}/{TARGET.repository}/commits/{HEAD}/check-runs?filter=latest&per_page=100": {
            "total_count": 0,
            "check_runs": [],
        },
        f"/repos/{TARGET.owner}/{TARGET.repository}/commits/{HEAD}/statuses?per_page=100": [],
    }


def test_offline_authenticated_read_reaches_existing_assessment(
    postgres_engine: Engine,
    tmp_path: Path,
) -> None:
    work_id = _persist_trusted_work_and_authorization(postgres_engine)
    control_plane, jwt_claims = _control_plane()
    broker = GitHubReadCredentialBroker(
        unit_of_work_factory=lambda: PostgresUnitOfWork(postgres_engine),
        control_plane=control_plane,
        clock=FixedClock(),
    )
    socket_path = tmp_path / "gs-i5.sock"
    ready = Event()
    server_errors: list[BaseException] = []
    server = UnixBrokerServer(
        socket_path=socket_path,
        broker=broker,
        allowed_uids=frozenset({os.getuid()}),
        allowed_gids=frozenset({os.getgid()}),
    )

    def serve() -> None:
        try:
            server.serve_once(ready=ready.set)
        except BaseException as exc:
            server_errors.append(exc)
            ready.set()

    thread = Thread(target=serve)
    thread.start()
    assert ready.wait(2)
    assert server_errors == []
    minted = UnixBrokerClient(socket_path=socket_path).MintReadToken(work_id)
    thread.join(timeout=2)
    control_plane.close()
    assert not thread.is_alive()
    assert server_errors == []
    assert not socket_path.exists()
    assert minted.repository_id == REPOSITORY_ID
    assert minted.authorization_version == 1
    assert jwt_claims == [
        {
            "iat": int((NOW - timedelta(seconds=60)).timestamp()),
            "exp": int((NOW + timedelta(seconds=540)).timestamp()),
            "iss": "offline-client-id",
        }
    ]

    responses = _repository_responses()
    repository_requests: list[str] = []

    def repository_handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.scheme == "https"
        assert request.url.host == "api.github.com"
        assert minted.token.matches(
            request.headers["Authorization"].removeprefix("Bearer ")
        )
        target = request.url.raw_path.decode("ascii")
        repository_requests.append(target)
        return httpx.Response(200, json=responses[target])

    evidence = AuthenticatedGitHubEvidenceAdapter(
        authorization=minted.token,
        repository_id=minted.repository_id,
        owner=TARGET.owner,
        repository=TARGET.repository,
        transport=httpx.MockTransport(repository_handler),
        maximum_attempts=1,
    )
    epoch_bound_evidence = AuthorizationBoundGitHubEvidence(
        evidence=evidence,
        authorization_uow_factory=lambda: PostgresUnitOfWork(postgres_engine),
        repository_id=minted.repository_id,
        authorization_version=minted.authorization_version,
    )
    coherent = CoherentRecordedAcquisitionService(
        evidence=epoch_bound_evidence,
        clock=FixedClock(),
        envelope_factory=envelope_payload,
        acquisition_configuration_digest=CONFIGURATION,
    )
    epoch_bound = AuthorizationBoundAcquisition(
        acquisition=coherent,
        authorization_uow_factory=lambda: PostgresUnitOfWork(postgres_engine),
        repository_id=minted.repository_id,
        authorization_version=minted.authorization_version,
    )
    pipeline = DeterministicPreparednessPipeline(
        acquisition=epoch_bound,
        unit_of_work_factory=lambda: PostgresUnitOfWork(postgres_engine),
        evaluation_clock=FixedClock(),
        envelope_factory=envelope_payload,
    )
    profile = pipeline.register_profile(
        PreparednessProfile(
            profile_id=uuid4(),
            version=1,
            repository_id=REPOSITORY_ID,
            required_checks=(),
            required_statuses=(),
            accepted_check_conclusions=("success",),
            block_on_current_head_changes_requested=True,
            acquisition_configuration=AcquisitionConfigurationIdentity(
                1,
                CONFIGURATION,
            ),
            effective_from=NOW - timedelta(minutes=1),
        )
    ).reference
    try:
        outcome = pipeline.assess(
            target=TARGET,
            expected_identity=PullRequestIdentity(
                repository_id=REPOSITORY_ID,
                pull_request_id=PULL_REQUEST_ID,
                pull_number=PULL_NUMBER,
                head_sha=HEAD,
                base_repository_id=REPOSITORY_ID,
                base_ref="main",
                base_sha=BASE,
            ),
            profile_reference=profile,
        )
    finally:
        evidence.close()

    assert outcome.assessment is not None
    assert outcome.assessment.verdict is PreparednessVerdict.READY_FOR_HUMAN_REVIEW
    assert outcome.assessment_id is not None
    assert len(repository_requests) == 17
    anchor_path = f"/repos/{TARGET.owner}/{TARGET.repository}/pulls/{PULL_NUMBER}"
    assert repository_requests[0] == anchor_path
    assert repository_requests[8] == anchor_path
    assert repository_requests[16] == anchor_path
    with postgres_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(preparedness_assessment)
                .where(preparedness_assessment.c.assessment_id == outcome.assessment_id)
            )
            == 1
        )
    assert repr(minted.token) == "<redacted bearer secret>"
