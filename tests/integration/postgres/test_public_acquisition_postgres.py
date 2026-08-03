"""GS-I3 acquisition reuses GS-I2 atomic inbox/work persistence."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import httpx
import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from github_steward.adapters.canonicalization.rfc8785 import envelope_payload
from github_steward.adapters.github.public_rest import (
    PolicyEnforcingTransport,
    PublicGitHubRestClient,
)
from github_steward.adapters.postgres.metadata import delivery_inbox, work_record
from github_steward.adapters.postgres.unit_of_work import PostgresUnitOfWork
from github_steward.application.local_processing import SyntheticReceiptService
from github_steward.application.public_acquisition import (
    PublicPullRequestAcquisitionService,
)
from github_steward.domain.acquisition import (
    AcquisitionError,
    AcquisitionOutcome,
    RepositoryTarget,
)
from github_steward.domain.processing import FaultPoint
from github_steward.ports.github import GitHubReadPort, GitHubResponse, RequestAudit

HEAD = "a" * 40
BASE = "b" * 40


class FixedClock:
    def now(self) -> datetime:
        return datetime(2026, 8, 3, tzinfo=UTC)


def _response(value: object, path: str) -> GitHubResponse:
    raw = json.dumps(value, sort_keys=True).encode()
    return GitHubResponse(value, hashlib.sha256(raw).hexdigest(), None, path)


class StableGitHub:
    def __init__(
        self,
        *,
        title: str = "GS-I3",
        review_url: str | None = None,
    ) -> None:
        root = "/repos/Harry5174/github-steward"
        self.primary = f"{root}/pulls/1"
        self.values = {
            self.primary: _response(
                {
                    "id": 101,
                    "number": 1,
                    "state": "open",
                    "draft": False,
                    "title": title,
                    "updated_at": "2026-08-03T01:02:03Z",
                    "changed_files": 1,
                    "commits": 1,
                    "head": {"sha": HEAD},
                    "base": {
                        "sha": BASE,
                        "repo": {
                            "id": 77,
                            "full_name": "Harry5174/github-steward",
                        },
                    },
                },
                self.primary,
            ),
            f"{self.primary}/files?per_page=100": _response(
                [
                    {
                        "sha": "c" * 40,
                        "filename": "x.py",
                        "status": "modified",
                        "additions": 2,
                        "deletions": 1,
                        "changes": 3,
                    }
                ],
                "files",
            ),
            f"{self.primary}/commits?per_page=100": _response(
                [{"sha": HEAD}], "commits"
            ),
            f"{self.primary}/reviews?per_page=100": _response(
                (
                    []
                    if review_url is None
                    else [
                        {
                            "id": 9,
                            "state": "APPROVED",
                            "commit_id": HEAD,
                            "pull_request_url": review_url,
                        }
                    ]
                ),
                "reviews",
            ),
            f"{root}/commits/{HEAD}/check-suites": _response(
                {"total_count": 0, "check_suites": []}, "suites"
            ),
            f"{root}/commits/{HEAD}/check-runs?filter=latest&per_page=100": _response(
                {
                    "total_count": 1,
                    "check_runs": [
                        {
                            "id": 1,
                            "name": "test",
                            "status": "completed",
                            "head_sha": HEAD,
                        }
                    ],
                },
                "checks",
            ),
        }
        self.requested: list[str] = []

    @property
    def audit(self) -> tuple[RequestAudit, ...]:
        return tuple(
            RequestAudit("GET", "api.github.com", path, "ACQUIRED")
            for path in self.requested
        )

    def get(self, path_or_url: str) -> GitHubResponse:
        self.requested.append(path_or_url)
        return self.values[path_or_url]


def _service(
    engine: Engine,
    *,
    fault: object | None = None,
    github: GitHubReadPort | None = None,
) -> PublicPullRequestAcquisitionService:
    def inject(point: FaultPoint) -> None:
        if point is fault:
            raise RuntimeError("injected transaction fault")

    receipt = SyntheticReceiptService(
        unit_of_work_factory=lambda: PostgresUnitOfWork(engine, inject),
        clock=FixedClock(),
        envelope_factory=envelope_payload,
    )
    return PublicPullRequestAcquisitionService(
        github=github or StableGitHub(title="fault" if fault is not None else "GS-I3"),
        receipt=receipt,
        envelope_factory=envelope_payload,
    )


def _counts(engine: Engine) -> tuple[int, int]:
    with engine.connect() as connection:
        return (
            int(
                connection.scalar(
                    sa.select(sa.func.count()).select_from(delivery_inbox)
                )
            ),
            int(connection.scalar(sa.select(sa.func.count()).select_from(work_record))),
        )


def test_atomic_success_and_identical_replay(postgres_engine: Engine) -> None:
    before = _counts(postgres_engine)
    target = RepositoryTarget("Harry5174", "github-steward", 1)
    created = _service(postgres_engine).acquire(target)
    replay = _service(postgres_engine).acquire(target)
    assert created.durable_intake == "CREATED"
    assert replay.durable_intake == "DUPLICATE_SAME_DIGEST"
    assert replay.delivery_identity == created.delivery_identity
    after = _counts(postgres_engine)
    assert after == (before[0] + 1, before[1] + 1)


def test_changed_snapshot_creates_distinct_atomic_intake(
    postgres_engine: Engine,
) -> None:
    before = _counts(postgres_engine)
    target = RepositoryTarget("Harry5174", "github-steward", 1)
    first = _service(
        postgres_engine,
        github=StableGitHub(title="changed snapshot one"),
    ).acquire(target)
    changed = _service(
        postgres_engine,
        github=StableGitHub(title="changed snapshot two"),
    ).acquire(target)
    assert changed.durable_intake == "CREATED"
    assert changed.snapshot_digest != first.snapshot_digest
    assert changed.delivery_identity != first.delivery_identity
    assert _counts(postgres_engine) == (before[0] + 2, before[1] + 2)


def test_fault_rolls_back_delivery_and_work(postgres_engine: Engine) -> None:
    before = _counts(postgres_engine)
    with pytest.raises(AcquisitionError) as raised:
        _service(postgres_engine, fault=FaultPoint.AFTER_INBOX_INSERT).acquire(
            RepositoryTarget("Harry5174", "github-steward", 1)
        )
    assert raised.value.outcome is AcquisitionOutcome.PERSISTENCE_FAILURE
    assert _counts(postgres_engine) == before


def test_malformed_review_relationship_persists_nothing(
    postgres_engine: Engine,
) -> None:
    before = _counts(postgres_engine)
    github = StableGitHub(
        review_url=("https://evil.example/repos/Harry5174/github-steward/pulls/1")
    )
    with pytest.raises(AcquisitionError) as raised:
        _service(postgres_engine, github=github).acquire(
            RepositoryTarget("Harry5174", "github-steward", 1)
        )
    assert raised.value.outcome is AcquisitionOutcome.MALFORMED_RESPONSE
    assert _counts(postgres_engine) == before


def test_redirect_rejection_persists_nothing(postgres_engine: Engine) -> None:
    before = _counts(postgres_engine)
    requests: list[httpx.Request] = []

    def redirect(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            302,
            content=b"{}",
            headers={"Location": "https://evil.example/redirected"},
        )

    github = PublicGitHubRestClient(
        transport=httpx.MockTransport(redirect),
        maximum_attempts=1,
    )
    try:
        with pytest.raises(AcquisitionError) as raised:
            _service(postgres_engine, github=github).acquire(
                RepositoryTarget("Harry5174", "github-steward", 1)
            )
    finally:
        github.close()
    assert raised.value.outcome is AcquisitionOutcome.MALFORMED_RESPONSE
    assert len(requests) == 1
    assert _counts(postgres_engine) == before


class CredentialAttemptGitHub:
    @property
    def audit(self) -> tuple[RequestAudit, ...]:
        return ()

    def get(self, path_or_url: str) -> GitHubResponse:
        del path_or_url
        delegated = httpx.MockTransport(
            lambda _: pytest.fail("credential request must not be delegated")
        )
        policy = PolicyEnforcingTransport(delegated)
        try:
            request = httpx.Request(
                "GET",
                "https://api.github.com/repos/Harry5174/github-steward/pulls/1",
                headers={
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2026-03-10",
                    "User-Agent": "github-steward",
                    "Authorization": "credential-attempt",
                },
            )
            policy.handle_request(request)
            raise AssertionError("credential request unexpectedly passed policy")
        finally:
            policy.close()


def test_transport_policy_credential_rejection_persists_nothing(
    postgres_engine: Engine,
) -> None:
    before = _counts(postgres_engine)
    with pytest.raises(AcquisitionError) as raised:
        _service(postgres_engine, github=CredentialAttemptGitHub()).acquire(
            RepositoryTarget("Harry5174", "github-steward", 1)
        )
    assert raised.value.outcome is AcquisitionOutcome.MALFORMED_RESPONSE
    assert _counts(postgres_engine) == before
