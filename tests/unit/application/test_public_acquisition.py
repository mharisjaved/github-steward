"""Offline orchestration tests for complete, stable public PR snapshots."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Callable, Mapping
from typing import cast

import pytest

from github_steward.adapters.canonicalization.rfc8785 import envelope_payload
from github_steward.application.public_acquisition import (
    PublicPullRequestAcquisitionService,
)
from github_steward.domain.acquisition import (
    AcquisitionError,
    AcquisitionOutcome,
    RepositoryTarget,
)
from github_steward.ports.github import GitHubResponse, RequestAudit
from github_steward.ports.persistence import (
    DeliveryId,
    DeliveryIngressOutcome,
    DeliveryIngressResult,
    WorkRecordId,
)

HEAD_A = "a" * 40
HEAD_B = "b" * 40
HEAD_C = "c" * 40
BASE = "d" * 40
TARGET = RepositoryTarget("Harry5174", "github-steward", 1)


def _response(
    value: object,
    path: str,
    *,
    next_url: str | None = None,
) -> GitHubResponse:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return GitHubResponse(value, hashlib.sha256(raw).hexdigest(), next_url, path)


def _primary(
    head: str = HEAD_A,
    *,
    changed_files: int = 1,
    commits: int = 1,
    title: str = "GS-I3",
    updated_at: str = "2026-08-03T01:02:03Z",
) -> dict[str, object]:
    return {
        "id": 101,
        "number": 1,
        "state": "open",
        "draft": False,
        "title": title,
        "updated_at": updated_at,
        "changed_files": changed_files,
        "commits": commits,
        "head": {"sha": head},
        "base": {
            "sha": BASE,
            "repo": {"id": 77, "full_name": "Harry5174/github-steward"},
        },
    }


class FakeGitHub:
    def __init__(self, responses: Mapping[str, list[GitHubResponse]]) -> None:
        self.responses = {key: list(values) for key, values in responses.items()}
        self.requested: list[str] = []

    @property
    def audit(self) -> tuple[RequestAudit, ...]:
        return tuple(
            RequestAudit("GET", "api.github.com", path, "ACQUIRED")
            for path in self.requested
        )

    def get(self, path_or_url: str) -> GitHubResponse:
        self.requested.append(path_or_url)
        values = self.responses.get(path_or_url, [])
        if not values:
            raise AssertionError(f"unexpected request: {path_or_url}")
        return values.pop(0)


class FakeReceipt:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Mapping[str, object]]] = []
        self.outcome = DeliveryIngressOutcome.CREATED
        self.failure: Exception | None = None

    def receive(
        self, *, provider_delivery_id: str, mapping: Mapping[str, object]
    ) -> DeliveryIngressResult:
        self.calls.append((provider_delivery_id, mapping))
        if self.failure is not None:
            raise self.failure
        return DeliveryIngressResult(
            self.outcome,
            DeliveryId("11111111-1111-1111-1111-111111111111"),
            WorkRecordId("22222222-2222-2222-2222-222222222222"),
        )


def _paths(head: str = HEAD_A) -> dict[str, str]:
    root = "/repos/Harry5174/github-steward"
    primary = f"{root}/pulls/1"
    return {
        "primary": primary,
        "files": f"{primary}/files?per_page=100",
        "commits": f"{primary}/commits?per_page=100",
        "reviews": f"{primary}/reviews?per_page=100",
        "suites": f"{root}/commits/{head}/check-suites",
        "checks": f"{root}/commits/{head}/check-runs?filter=latest&per_page=100",
    }


def _responses(
    *,
    first: dict[str, object] | None = None,
    second: dict[str, object] | None = None,
    files: list[object] | None = None,
    commits: list[object] | None = None,
    reviews: list[object] | None = None,
    checks: list[object] | None = None,
    check_suite_total: int = 0,
    check_total: int | None = None,
) -> dict[str, list[GitHubResponse]]:
    first = first or _primary()
    second = second or first
    head = cast(dict[str, object], first["head"])["sha"]
    assert isinstance(head, str)
    paths = _paths(head)
    files = (
        files
        if files is not None
        else [
            {
                "sha": "e" * 40,
                "filename": "x.py",
                "status": "modified",
                "additions": 2,
                "deletions": 1,
                "changes": 3,
            }
        ]
    )
    commits = commits if commits is not None else [{"sha": HEAD_A}]
    reviews = (
        reviews
        if reviews is not None
        else [
            {
                "id": 9,
                "state": "APPROVED",
                "commit_id": head,
                "pull_request_url": "https://api.github.com/repos/"
                "Harry5174/github-steward/pulls/1",
            }
        ]
    )
    checks = (
        checks
        if checks is not None
        else [{"id": 12, "name": "test", "status": "completed", "head_sha": head}]
    )
    return {
        paths["primary"]: [
            _response(first, paths["primary"]),
            _response(second, paths["primary"]),
        ],
        paths["files"]: [_response(files, paths["files"])],
        paths["commits"]: [_response(commits, paths["commits"])],
        paths["reviews"]: [_response(reviews, paths["reviews"])],
        paths["suites"]: [
            _response(
                {"total_count": check_suite_total, "check_suites": []},
                paths["suites"],
            )
        ],
        paths["checks"]: [
            _response(
                {
                    "total_count": len(checks) if check_total is None else check_total,
                    "check_runs": checks,
                },
                paths["checks"],
            )
        ],
    }


def _service(
    github: FakeGitHub, receipt: FakeReceipt
) -> PublicPullRequestAcquisitionService:
    return PublicPullRequestAcquisitionService(
        github=github,
        receipt=receipt,
        envelope_factory=envelope_payload,
    )


def test_stable_acquisition_exact_paths_and_durable_mapping() -> None:
    github = FakeGitHub(_responses())
    receipt = FakeReceipt()
    result = _service(github, receipt).acquire(TARGET)
    expected = _paths()
    assert github.requested == [
        expected["primary"],
        expected["files"],
        expected["commits"],
        expected["reviews"],
        expected["suites"],
        expected["checks"],
        expected["primary"],
    ]
    assert result.outcome is AcquisitionOutcome.ACQUIRED
    assert result.pagination == {
        "files": 1,
        "commits": 1,
        "reviews": 1,
        "check_suites": 0,
        "check_runs": 1,
        "responses": 7,
    }
    identity, mapping = receipt.calls[0]
    assert identity == result.delivery_identity
    assert mapping["entity_id"] == "77:1"
    assert mapping["observed_at"] == "2026-08-03T01:02:03.000000Z"
    assert mapping["sequence"] == 1785718923
    observation = cast(dict[str, object], mapping["observation"])
    snapshot = cast(dict[str, object], observation["snapshot"])
    raw_responses = cast(list[dict[str, str]], snapshot["raw_responses"])
    assert [item["kind"] for item in raw_responses].count("check_suites") == 1
    completeness = cast(dict[str, object], snapshot["completeness"])
    assert cast(dict[str, int], completeness["counts"])["check_suites"] == 0
    assert result.as_mapping()["completeness"] == "COMPLETE"


def test_pagination_follows_only_next_link() -> None:
    paths = _paths()
    next_url = "https://api.github.com/page/two"
    responses = _responses(first=_primary(changed_files=2), files=[])
    responses[paths["files"]] = [
        _response(
            [
                {
                    "sha": "e" * 40,
                    "filename": "one",
                    "status": "added",
                    "additions": 1,
                    "deletions": 0,
                    "changes": 1,
                }
            ],
            paths["files"],
            next_url=next_url,
        )
    ]
    responses[next_url] = [
        _response(
            [
                {
                    "sha": "f" * 40,
                    "filename": "two",
                    "status": "added",
                    "additions": 1,
                    "deletions": 0,
                    "changes": 1,
                }
            ],
            "/page/two",
        )
    ]
    github = FakeGitHub(responses)
    result = _service(github, FakeReceipt()).acquire(TARGET)
    assert next_url in github.requested
    assert result.pagination["files"] == 2


def test_successful_consistency_retry_discards_first_attempt() -> None:
    paths_a = _paths(HEAD_A)
    paths_b = _paths(HEAD_B)
    changed = _primary(HEAD_B, updated_at="2026-08-03T01:03:03Z")
    responses: defaultdict[str, list[GitHubResponse]] = defaultdict(list)
    for path, values in _responses(first=_primary(), second=changed).items():
        responses[path].extend(values)
    second_attempt = _responses(
        first=changed,
        second=changed,
        commits=[{"sha": HEAD_B}],
    )
    for path, values in second_attempt.items():
        responses[path].extend(values)
    github = FakeGitHub(responses)
    receipt = FakeReceipt()
    result = _service(github, receipt).acquire(TARGET)
    assert result.head_sha == HEAD_B
    assert paths_a["checks"] in github.requested
    assert paths_b["checks"] in github.requested
    assert len(receipt.calls) == 1


def test_repeated_concurrent_change_persists_nothing() -> None:
    changed_b = _primary(HEAD_B, updated_at="2026-08-03T01:03:03Z")
    changed_c = _primary(HEAD_C, updated_at="2026-08-03T01:04:03Z")
    responses: defaultdict[str, list[GitHubResponse]] = defaultdict(list)
    for path, values in _responses(first=_primary(), second=changed_b).items():
        responses[path].extend(values)
    for path, values in _responses(
        first=changed_b,
        second=changed_c,
        commits=[{"sha": HEAD_B}],
    ).items():
        responses[path].extend(values)
    receipt = FakeReceipt()
    with pytest.raises(AcquisitionError) as raised:
        _service(FakeGitHub(responses), receipt).acquire(TARGET)
    assert raised.value.outcome is AcquisitionOutcome.CONCURRENT_CHANGE
    assert receipt.calls == []


@pytest.mark.parametrize(
    ("primary", "outcome"),
    [
        (_primary(changed_files=3001), AcquisitionOutcome.UNSUPPORTED_UPSTREAM_LIMIT),
        (_primary(commits=251), AcquisitionOutcome.UNSUPPORTED_UPSTREAM_LIMIT),
    ],
)
def test_primary_metadata_limit_rejection(
    primary: dict[str, object], outcome: AcquisitionOutcome
) -> None:
    github = FakeGitHub(_responses(first=primary))
    receipt = FakeReceipt()
    with pytest.raises(AcquisitionError) as raised:
        _service(github, receipt).acquire(TARGET)
    assert raised.value.outcome is outcome
    assert receipt.calls == []


def test_check_run_limit_rejection() -> None:
    github = FakeGitHub(_responses(check_total=1001))
    receipt = FakeReceipt()
    with pytest.raises(AcquisitionError) as raised:
        _service(github, receipt).acquire(TARGET)
    assert raised.value.outcome is AcquisitionOutcome.UNSUPPORTED_UPSTREAM_LIMIT
    assert receipt.calls == []


@pytest.mark.parametrize(
    ("suite_total", "outcome"),
    [
        (999, AcquisitionOutcome.ACQUIRED),
        (1000, AcquisitionOutcome.ACQUIRED),
        (1001, AcquisitionOutcome.UNSUPPORTED_UPSTREAM_LIMIT),
    ],
)
def test_check_suite_boundary(suite_total: int, outcome: AcquisitionOutcome) -> None:
    receipt = FakeReceipt()
    service = _service(
        FakeGitHub(_responses(check_suite_total=suite_total)),
        receipt,
    )
    if outcome is AcquisitionOutcome.ACQUIRED:
        result = service.acquire(TARGET)
        assert result.pagination["check_suites"] == suite_total
        assert len(receipt.calls) == 1
    else:
        with pytest.raises(AcquisitionError) as raised:
            service.acquire(TARGET)
        assert raised.value.outcome is outcome
        assert receipt.calls == []


@pytest.mark.parametrize(
    "body",
    [
        [],
        {"total_count": "1", "check_suites": []},
        {"total_count": 1},
        {"total_count": 1, "check_suites": {}},
    ],
)
def test_check_suite_shape_rejection_persists_nothing(body: object) -> None:
    paths = _paths()
    responses = _responses()
    responses[paths["suites"]] = [_response(body, paths["suites"])]
    receipt = FakeReceipt()
    with pytest.raises(AcquisitionError) as raised:
        _service(FakeGitHub(responses), receipt).acquire(TARGET)
    assert raised.value.outcome is AcquisitionOutcome.MALFORMED_RESPONSE
    assert receipt.calls == []


@pytest.mark.parametrize(
    "responses",
    [
        _responses(files=[]),
        _responses(commits=[]),
        _responses(check_total=2),
    ],
)
def test_incomplete_counts_persist_nothing(
    responses: dict[str, list[GitHubResponse]],
) -> None:
    receipt = FakeReceipt()
    with pytest.raises(AcquisitionError) as raised:
        _service(FakeGitHub(responses), receipt).acquire(TARGET)
    assert raised.value.outcome is AcquisitionOutcome.INCOMPLETE_ACQUISITION
    assert receipt.calls == []


def test_cyclic_pagination_is_incomplete() -> None:
    paths = _paths()
    responses = _responses()
    responses[paths["files"]] = [_response([], paths["files"], next_url=paths["files"])]
    with pytest.raises(AcquisitionError) as raised:
        _service(FakeGitHub(responses), FakeReceipt()).acquire(TARGET)
    assert raised.value.outcome is AcquisitionOutcome.INCOMPLETE_ACQUISITION


@pytest.mark.parametrize(
    "mutate",
    [
        lambda data: [],
        lambda data: {**data, "draft": "false"},
        lambda data: {**data, "number": 2},
        lambda data: {**data, "updated_at": "not-a-time"},
    ],
)
def test_primary_shape_and_identity_validation(
    mutate: Callable[[dict[str, object]], object],
) -> None:
    bad = mutate(_primary())
    paths = _paths()
    github = FakeGitHub({paths["primary"]: [_response(bad, paths["primary"])]})
    with pytest.raises(AcquisitionError) as raised:
        _service(github, FakeReceipt()).acquire(TARGET)
    assert raised.value.outcome is AcquisitionOutcome.MALFORMED_RESPONSE


@pytest.mark.parametrize(
    ("collection", "items"),
    [
        ("commits", [{"sha": "bad"}]),
        (
            "reviews",
            [
                {
                    "id": 1,
                    "state": "APPROVED",
                    "pull_request_url": "https://api.github.com/wrong",
                }
            ],
        ),
        (
            "checks",
            [{"id": 1, "name": "test", "status": "completed", "head_sha": HEAD_B}],
        ),
        ("reviews", [{"id": "bad"}]),
    ],
)
def test_collection_relationship_validation(
    collection: str, items: list[object]
) -> None:
    receipt = FakeReceipt()
    with pytest.raises(AcquisitionError) as raised:
        if collection == "commits":
            responses = _responses(commits=items)
        elif collection == "reviews":
            responses = _responses(reviews=items)
        else:
            responses = _responses(checks=items)
        _service(FakeGitHub(responses), receipt).acquire(TARGET)
    assert raised.value.outcome is AcquisitionOutcome.MALFORMED_RESPONSE
    assert receipt.calls == []


@pytest.mark.parametrize("collection", ["files", "commits", "reviews", "checks"])
def test_non_object_collection_entries_persist_nothing(collection: str) -> None:
    receipt = FakeReceipt()
    if collection == "files":
        responses = _responses(files=[None])
    elif collection == "commits":
        responses = _responses(commits=[None])
    elif collection == "reviews":
        responses = _responses(reviews=[None])
    else:
        responses = _responses(checks=[None])
    with pytest.raises(AcquisitionError) as raised:
        _service(FakeGitHub(responses), receipt).acquire(TARGET)
    assert raised.value.outcome is AcquisitionOutcome.MALFORMED_RESPONSE
    assert receipt.calls == []


def test_multiple_reviews_and_null_commit_relationship_are_valid() -> None:
    reviews: list[object] = [
        {"id": 1, "state": "COMMENTED", "commit_id": None},
        {"id": 2, "state": "APPROVED", "commit_id": HEAD_A},
    ]
    result = _service(FakeGitHub(_responses(reviews=reviews)), FakeReceipt()).acquire(
        TARGET
    )
    assert result.pagination["reviews"] == 2


@pytest.mark.parametrize(
    ("collection", "items"),
    [
        ("files", [{"sha": "e" * 40, "filename": "x.py"}]),
        (
            "files",
            [
                {
                    "sha": "e" * 40,
                    "filename": "x.py",
                    "status": "modified",
                    "additions": "2",
                    "deletions": 1,
                    "changes": 3,
                }
            ],
        ),
        ("reviews", [{"id": 1, "state": 2}]),
        ("reviews", [{"id": 1, "state": "APPROVED", "commit_id": "bad"}]),
        ("checks", [{"id": 1, "name": "", "status": "completed", "head_sha": HEAD_A}]),
        ("checks", [{"id": 1, "name": "test", "head_sha": HEAD_A}]),
    ],
)
def test_required_collection_item_fields_and_types(
    collection: str, items: list[object]
) -> None:
    receipt = FakeReceipt()
    if collection == "files":
        responses = _responses(files=items)
    elif collection == "reviews":
        responses = _responses(reviews=items)
    else:
        responses = _responses(checks=items)
    with pytest.raises(AcquisitionError) as raised:
        _service(FakeGitHub(responses), receipt).acquire(TARGET)
    assert raised.value.outcome is AcquisitionOutcome.MALFORMED_RESPONSE
    assert receipt.calls == []


def test_canonical_snapshot_and_delivery_identity_are_deterministic() -> None:
    first_receipt = FakeReceipt()
    first = _service(FakeGitHub(_responses()), first_receipt).acquire(TARGET)
    second_receipt = FakeReceipt()
    second_receipt.outcome = DeliveryIngressOutcome.DUPLICATE_SAME_DIGEST
    second = _service(FakeGitHub(_responses()), second_receipt).acquire(TARGET)
    assert first.snapshot_digest == second.snapshot_digest
    assert first.delivery_identity == second.delivery_identity
    assert second.durable_intake == "DUPLICATE_SAME_DIGEST"

    changed = _primary(title="changed")
    third = _service(
        FakeGitHub(_responses(first=changed, second=changed)), FakeReceipt()
    ).acquire(TARGET)
    assert third.snapshot_digest != first.snapshot_digest
    assert third.delivery_identity != first.delivery_identity


def test_persistence_failure_is_classified() -> None:
    receipt = FakeReceipt()
    receipt.failure = RuntimeError("database unavailable with secret details")
    with pytest.raises(AcquisitionError) as raised:
        _service(FakeGitHub(_responses()), receipt).acquire(TARGET)
    assert raised.value.outcome is AcquisitionOutcome.PERSISTENCE_FAILURE
    assert str(raised.value) == "durable intake transaction failed"


def test_direct_collection_bounds_and_shapes() -> None:
    paths = _paths()
    oversized = [None] * 3001
    github = FakeGitHub({paths["files"]: [_response(oversized, paths["files"])]})
    service = _service(github, FakeReceipt())
    with pytest.raises(AcquisitionError) as raised:
        service._list_pages(paths["files"], "files", 3000)
    assert raised.value.outcome is AcquisitionOutcome.UNSUPPORTED_UPSTREAM_LIMIT

    bad = FakeGitHub({paths["files"]: [_response({}, paths["files"])]})
    with pytest.raises(AcquisitionError) as malformed:
        _service(bad, FakeReceipt())._list_pages(paths["files"], "files", 3000)
    assert malformed.value.outcome is AcquisitionOutcome.MALFORMED_RESPONSE


def test_page_count_bound_is_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    from github_steward.application import public_acquisition

    monkeypatch.setattr(public_acquisition, "MAX_PAGES", 0)
    service = _service(FakeGitHub({}), FakeReceipt())
    with pytest.raises(AcquisitionError) as raised:
        service._list_pages("/first", "files", None)
    assert raised.value.outcome is AcquisitionOutcome.INCOMPLETE_ACQUISITION

    with pytest.raises(AcquisitionError) as checks:
        service._check_pages("/checks")
    assert checks.value.outcome is AcquisitionOutcome.INCOMPLETE_ACQUISITION


def test_check_pagination_consistency_and_item_bounds() -> None:
    first = "/checks"
    second = "https://api.github.com/checks?page=2"
    inconsistent = FakeGitHub(
        {
            first: [
                _response(
                    {"total_count": 1, "check_runs": []},
                    first,
                    next_url=second,
                )
            ],
            second: [_response({"total_count": 0, "check_runs": []}, second)],
        }
    )
    with pytest.raises(AcquisitionError) as changed:
        _service(inconsistent, FakeReceipt())._check_pages(first)
    assert changed.value.outcome is AcquisitionOutcome.INCOMPLETE_ACQUISITION

    too_many = FakeGitHub(
        {
            first: [
                _response(
                    {
                        "total_count": 1000,
                        "check_runs": [{"id": number} for number in range(1001)],
                    },
                    first,
                )
            ]
        }
    )
    with pytest.raises(AcquisitionError) as oversized:
        _service(too_many, FakeReceipt())._check_pages(first)
    assert oversized.value.outcome is AcquisitionOutcome.UNSUPPORTED_UPSTREAM_LIMIT


def test_required_string_cannot_be_empty() -> None:
    primary = _primary()
    base = cast(dict[str, object], primary["base"])
    repo = cast(dict[str, object], base["repo"])
    repo["full_name"] = ""
    paths = _paths()
    github = FakeGitHub({paths["primary"]: [_response(primary, paths["primary"])]})
    with pytest.raises(AcquisitionError) as raised:
        _service(github, FakeReceipt()).acquire(TARGET)
    assert raised.value.outcome is AcquisitionOutcome.MALFORMED_RESPONSE
