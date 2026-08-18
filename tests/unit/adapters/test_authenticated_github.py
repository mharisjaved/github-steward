"""Adversarial offline tests for repository-bound authenticated evidence GETs."""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, cast

import httpx
import pytest

from github_steward.adapters.canonicalization.rfc8785 import (
    digest_payload,
    envelope_payload,
)
from github_steward.adapters.github import authenticated_rest, public_rest
from github_steward.adapters.github.authenticated_rest import (
    AuthenticatedGitHubEvidenceAdapter,
)
from github_steward.application.preparedness import CoherentRecordedAcquisitionService
from github_steward.domain.acquisition import (
    AcquisitionError,
    AcquisitionOutcome,
    RepositoryTarget,
)
from github_steward.ports.github import (
    EvidenceFacet,
    GitHubEvidencePort,
    RecordedGitHubEvidencePort,
)
from github_steward.ports.secrets import OpaqueBearerToken

TARGET = RepositoryTarget("Owner", "Repo", 4)
HEAD = "a" * 40
SHORT_SECRET = "".join(("legacy", "-", "shape"))
LONG_SECRET = "stateless-" + "x" * 768


def _json(value: object, *, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(
        200,
        content=json.dumps(value, separators=(",", ":")).encode(),
        headers=headers,
    )


def _anchor(repository_id: int = 77) -> dict[str, object]:
    return {
        "number": 4,
        "base": {
            "repo": {
                "id": repository_id,
                "full_name": "Owner/Repo",
            }
        },
    }


def _adapter(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    secret: str = SHORT_SECRET,
    maximum_attempts: int = 1,
    maximum_response_bytes: int = authenticated_rest.MAX_RESPONSE_BYTES,
) -> tuple[AuthenticatedGitHubEvidenceAdapter, OpaqueBearerToken]:
    token = OpaqueBearerToken(secret)
    adapter = AuthenticatedGitHubEvidenceAdapter(
        authorization=token,
        repository_id=77,
        owner="Owner",
        repository="Repo",
        transport=httpx.MockTransport(handler),
        maximum_attempts=maximum_attempts,
        maximum_response_bytes=maximum_response_bytes,
    )
    return adapter, token


@pytest.mark.parametrize("secret", [SHORT_SECRET, LONG_SECRET], ids=["short", "long"])
def test_all_eight_exact_get_kinds_accept_opaque_bearers(secret: str) -> None:
    requested: list[str] = []
    token = OpaqueBearerToken(secret)
    responses: dict[str, object] = {
        "/repos/Owner/Repo/pulls/4": _anchor(),
        "/repos/Owner/Repo/pulls/4/files?per_page=100": [{"file": 1}],
        "/repos/Owner/Repo/pulls/4/commits?per_page=100": [{"commit": 1}],
        "/repos/Owner/Repo/pulls/4/reviews?per_page=100": [{"review": 1}],
        "/repos/Owner/Repo/pulls/4/requested_reviewers?per_page=100": {
            "users": [{"id": 1}],
            "teams": [{"id": 2}],
        },
        f"/repos/Owner/Repo/commits/{HEAD}/check-suites": {
            "total_count": 1,
            "check_suites": [{}],
        },
        f"/repos/Owner/Repo/commits/{HEAD}/check-runs?filter=latest&per_page=100": {
            "total_count": 1,
            "check_runs": [{"check": 1}],
        },
        f"/repos/Owner/Repo/commits/{HEAD}/statuses?per_page=100": [{"status": 1}],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.scheme == "https"
        assert request.url.host == "api.github.com"
        assert token.matches(request.headers["Authorization"].removeprefix("Bearer "))
        assert request.headers["Accept"] == "application/vnd.github+json"
        assert request.headers["X-GitHub-Api-Version"] == "2026-03-10"
        assert request.headers["User-Agent"] == "github-steward"
        assert request.extensions["timeout"] == {
            "connect": 5.0,
            "read": 15.0,
            "write": 5.0,
            "pool": 5.0,
        }
        assert request.content == b""
        raw_target = request.url.raw_path.decode("ascii")
        requested.append(raw_target)
        return _json(responses[raw_target])

    adapter = AuthenticatedGitHubEvidenceAdapter(
        authorization=token,
        repository_id=77,
        owner="Owner",
        repository="Repo",
        transport=httpx.MockTransport(handler),
        maximum_attempts=1,
    )
    try:
        assert adapter.read_anchor(TARGET).value == _anchor()
        facets = {
            facet: adapter.read_facet(TARGET, head_sha=HEAD, facet=facet)
            for facet in EvidenceFacet
        }
    finally:
        adapter.close()

    assert list(facets) == list(EvidenceFacet)
    assert facets[EvidenceFacet.CHECK_SUITE_COUNT].total_count == 1
    assert facets[EvidenceFacet.CHECK_RUNS].total_count == 1
    assert len(requested) == 8
    assert not any(
        hasattr(adapter, method) for method in ("get", "post", "put", "patch", "delete")
    )
    assert secret not in repr(adapter)


def test_git_hub_evidence_protocol_retains_recorded_compatibility_alias() -> None:
    assert RecordedGitHubEvidencePort is GitHubEvidencePort


def test_authenticated_adapter_supplies_the_unchanged_gs_i4_coherent_kernel() -> None:
    stable_anchor = {
        "id": 404,
        "number": 4,
        "state": "open",
        "draft": False,
        "updated_at": "2026-08-18T11:59:00Z",
        "changed_files": 1,
        "commits": 1,
        "head": {"sha": HEAD},
        "base": {
            "ref": "main",
            "sha": "b" * 40,
            "repo": {"id": 77, "full_name": "Owner/Repo"},
        },
    }
    paths: dict[str, object] = {
        "/repos/Owner/Repo/pulls/4": stable_anchor,
        "/repos/Owner/Repo/pulls/4/files?per_page=100": [
            {
                "sha": "c" * 40,
                "filename": "src/example.py",
                "status": "modified",
                "additions": 2,
                "deletions": 1,
                "changes": 3,
            }
        ],
        "/repos/Owner/Repo/pulls/4/commits?per_page=100": [{"sha": HEAD}],
        "/repos/Owner/Repo/pulls/4/reviews?per_page=100": [
            {
                "id": 21,
                "user": {"id": 22, "login": "reviewer"},
                "commit_id": HEAD,
                "state": "APPROVED",
                "submitted_at": "2026-08-18T11:58:00Z",
                "pull_request_url": ("https://api.github.com/repos/Owner/Repo/pulls/4"),
            }
        ],
        "/repos/Owner/Repo/pulls/4/requested_reviewers?per_page=100": {
            "users": [{"id": 23, "login": "requested"}],
            "teams": [{"id": 24, "slug": "core"}],
        },
        f"/repos/Owner/Repo/commits/{HEAD}/check-suites": {
            "total_count": 1,
            "check_suites": [{}],
        },
        f"/repos/Owner/Repo/commits/{HEAD}/check-runs?filter=latest&per_page=100": {
            "total_count": 1,
            "check_runs": [
                {
                    "id": 25,
                    "head_sha": HEAD,
                    "app": {"id": 26},
                    "name": "tests",
                    "status": "completed",
                    "conclusion": "success",
                    "started_at": "2026-08-18T11:56:00Z",
                    "completed_at": "2026-08-18T11:57:00Z",
                }
            ],
        },
        f"/repos/Owner/Repo/commits/{HEAD}/statuses?per_page=100": [
            {
                "id": 27,
                "sha": HEAD,
                "context": "CI/Test",
                "state": "success",
                "updated_at": "2026-08-18T11:57:00Z",
            }
        ],
    }
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        target = request.url.raw_path.decode("ascii")
        requests.append(target)
        return _json(paths[target])

    class FixedClock:
        def now(self) -> datetime:
            return datetime(2026, 8, 18, 12, tzinfo=UTC)

    adapter, _ = _adapter(handler)
    service = CoherentRecordedAcquisitionService(
        evidence=adapter,
        clock=FixedClock(),
        envelope_factory=envelope_payload,
        acquisition_configuration_digest=digest_payload(
            {"api_version": "2026-03-10", "per_page": 100, "attempts": 2}
        ),
    )
    try:
        result = service.acquire(TARGET)
    finally:
        adapter.close()
    assert result.attempts == 1
    assert result.view.anchor.repository_id == 77
    assert len(result.view.files) == 1
    assert len(result.view.commits) == 1
    assert len(result.view.reviews) == 1
    assert len(result.view.check_runs) == 1
    assert len(result.view.commit_statuses) == 1
    assert len(requests) == 17
    assert SHORT_SECRET not in repr(result.view.as_mapping())


def test_exact_pagination_successor_aggregates_values_and_provenance() -> None:
    first = "/repos/Owner/Repo/pulls/4/files?per_page=100"
    second = first + "&page=2"
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        target = request.url.raw_path.decode("ascii")
        calls.append(target)
        if target == first:
            return _json(
                [{"page": 1}],
                headers={
                    "Link": (
                        f'<https://api.github.com{second}>; rel="next", '
                        f'<https://api.github.com{second}>; rel="last"'
                    )
                },
            )
        assert target == second
        return _json(
            [{"page": 2}],
            headers={"Link": f'<https://api.github.com{first}&page=1>; rel="prev"'},
        )

    adapter, _ = _adapter(handler)
    try:
        facet = adapter.read_facet(TARGET, head_sha=HEAD, facet=EvidenceFacet.FILES)
    finally:
        adapter.close()
    assert facet.value == [{"page": 1}, {"page": 2}]
    assert len(facet.raw_responses) == 2
    assert calls == [first, second]


def test_requested_reviewers_and_check_runs_paginate_with_stable_shapes() -> None:
    reviewers = "/repos/Owner/Repo/pulls/4/requested_reviewers?per_page=100"
    checks = f"/repos/Owner/Repo/commits/{HEAD}/check-runs?filter=latest&per_page=100"

    def handler(request: httpx.Request) -> httpx.Response:
        target = request.url.raw_path.decode("ascii")
        if target == reviewers:
            return _json(
                {"users": [{"id": 1}], "teams": []},
                headers={
                    "Link": (f'<https://api.github.com{reviewers}&page=2>; rel="next"')
                },
            )
        if target == reviewers + "&page=2":
            return _json({"users": [], "teams": [{"id": 2}]})
        if target == checks:
            return _json(
                {"total_count": 2, "check_runs": [{"id": 1}]},
                headers={
                    "Link": f'<https://api.github.com{checks}&page=2>; rel="next"'
                },
            )
        assert target == checks + "&page=2"
        return _json({"total_count": 2, "check_runs": [{"id": 2}]})

    adapter, _ = _adapter(handler)
    try:
        requested = adapter.read_facet(
            TARGET,
            head_sha=HEAD,
            facet=EvidenceFacet.REQUESTED_REVIEWERS,
        )
        check_runs = adapter.read_facet(
            TARGET,
            head_sha=HEAD,
            facet=EvidenceFacet.CHECK_RUNS,
        )
    finally:
        adapter.close()
    assert requested.value == {"users": [{"id": 1}], "teams": [{"id": 2}]}
    assert check_runs.value == [{"id": 1}, {"id": 2}]
    assert check_runs.total_count == 2


def test_requested_reviewer_page_cannot_exceed_exact_per_page_bound() -> None:
    adapter, _ = _adapter(
        lambda _: _json({"users": [{"id": index} for index in range(101)], "teams": []})
    )
    try:
        with pytest.raises(AcquisitionError, match="per_page=100"):
            adapter.read_facet(
                TARGET,
                head_sha=HEAD,
                facet=EvidenceFacet.REQUESTED_REVIEWERS,
            )
    finally:
        adapter.close()


@pytest.mark.parametrize(
    "link",
    [
        (
            "<https://evil.example/repos/Owner/Repo/pulls/4/files?per_page=100&page=2>"
            '; rel="next"'
        ),
        (
            "<http://api.github.com/repos/Owner/Repo/pulls/4/files?per_page=100&page=2>"
            '; rel="next"'
        ),
        (
            "<https://api.github.com/repos/Other/Repo/pulls/4/files?per_page=100&page=2>"
            '; rel="next"'
        ),
        (
            "<https://api.github.com/repos/Owner/Repo/pulls/5/files?per_page=100&page=2>"
            '; rel="next"'
        ),
        (
            "<https://api.github.com/repos/Owner/Repo/pulls/4/commits?per_page=100&page=2>"
            '; rel="next"'
        ),
        (
            "<https://api.github.com/repos/Owner/Repo/pulls/4/files?page=2&per_page=100>"
            '; rel="next"'
        ),
        (
            "<https://api.github.com/repos/Owner/Repo/pulls/4/files?per_page=100&page=3>"
            '; rel="next"'
        ),
        (
            "<https://api.github.com/repos/Owner/Repo/pulls/4/files?per_page=100&page=%32>"
            '; rel="next"'
        ),
        (
            "<https://api.github.com/repos/Owner/Repo/pulls/4/files?per_page=100&page=2>"
            '; rel="next last"'
        ),
        (
            "<https://api.github.com/repos/Owner/Repo/pulls/4/files?per_page=100>"
            '; rel="next"'
        ),
        (
            "<https://api.github.com/repos/Owner/Repo/pulls/4/files?per_page=100&other=2>"
            '; rel="next"'
        ),
        (
            "<https://api.github.com/repos/Owner/Repo/pulls/4/files?per_page=100&page=0>"
            '; rel="next"'
        ),
        (
            "<https://api.github.com/repos/Owner/Repo/pulls/4/files?per_page=100&page=101>"
            '; rel="next"'
        ),
        (
            "<https://api.github.com/repos/Owner/Repo/pulls/4/files?per_page=100&page=2#>"
            '; rel="next"'
        ),
        (
            "<https://api.github.com/repos/Owner/Repo/pulls/4/files?per_page=100&page=2>"
            '; next="true"'
        ),
        (
            "<https://api.github.com/repos/Owner/Repo/pulls/4/files?per_page=100&page=2>"
            '; rel="last last"'
        ),
        "not-a-link",
        (
            "<https://api.github.com/repos/Owner/Repo/pulls/4/files?per_page=100&page=2>"
            '; rel="next", '
            "<https://api.github.com/repos/Owner/Repo/pulls/4/files?per_page=100&page=2>"
            '; rel="next"'
        ),
        (
            "<https://api.github.com/repos/Owner/Repo/pulls/4/files?per_page=100&page=2>"
            '; rel="last"'
        ),
    ],
)
def test_pagination_identity_substitution_fails_before_second_request(
    link: str,
) -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _json([], headers={"Link": link})

    adapter, _ = _adapter(handler)
    try:
        with pytest.raises(AcquisitionError) as raised:
            adapter.read_facet(TARGET, head_sha=HEAD, facet=EvidenceFacet.FILES)
    finally:
        adapter.close()
    assert raised.value.outcome is AcquisitionOutcome.MALFORMED_RESPONSE
    assert calls == 1


def test_non_ascii_pagination_url_and_header_are_rejected() -> None:
    adapter, _ = _adapter(lambda _: _json([]))
    origin = adapter._pull_endpoint(
        TARGET,
        authenticated_rest._EndpointKind.PULL_FILES,
        "/files",
        paginatable=True,
    )
    try:
        with pytest.raises(AcquisitionError, match="canonical ASCII URL"):
            authenticated_rest._parse_link_target(
                "https://api.github.com/repos/Owner/Repo/pulls/4/filés"
                "?per_page=100&page=2",
                origin,
            )
        with pytest.raises(AcquisitionError, match="header was not ASCII"):
            authenticated_rest._next_endpoint("rélation", origin)
    finally:
        adapter.close()


@pytest.mark.parametrize(
    "raw",
    [
        b"\xff",
        b"{",
        b'{"outer":{"same":1,"same":2}}',
        b'{"fraction":1.5}',
        b'{"not_finite":NaN}',
        b'{"unsafe":9007199254740992}',
    ],
)
def test_strict_json_rejects_malformed_or_ambiguous_responses(raw: bytes) -> None:
    adapter, _ = _adapter(lambda _: httpx.Response(200, content=raw))
    try:
        with pytest.raises(AcquisitionError) as raised:
            adapter.read_anchor(TARGET)
    finally:
        adapter.close()
    assert raised.value.outcome is AcquisitionOutcome.MALFORMED_RESPONSE


def test_repository_id_and_route_are_bound_before_evidence_can_be_used() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return _json(_anchor(repository_id=78))

    adapter, _ = _adapter(handler)
    try:
        with pytest.raises(AcquisitionError, match="repository id"):
            adapter.read_anchor(TARGET)
        with pytest.raises(AcquisitionError, match="authorized repository route"):
            adapter.read_anchor(RepositoryTarget("Other", "Repo", 4))
    finally:
        adapter.close()
    assert len(calls) == 1


@pytest.mark.parametrize(
    "anchor",
    [
        [],
        {"number": 4, "base": {"repo": {"id": 0, "full_name": "Owner/Repo"}}},
        {"number": True, "base": {"repo": {"id": 77, "full_name": "Owner/Repo"}}},
        {"number": 5, "base": {"repo": {"id": 77, "full_name": "Owner/Repo"}}},
        {"number": 4, "base": {"repo": {"id": 77, "full_name": "Other/Repo"}}},
    ],
)
def test_anchor_shape_route_and_positive_identity_fail_closed(anchor: object) -> None:
    adapter, _ = _adapter(lambda _: _json(anchor))
    try:
        with pytest.raises(AcquisitionError):
            adapter.read_anchor(TARGET)
    finally:
        adapter.close()


@pytest.mark.parametrize("head", ["A" * 40, "a" * 39, "a" * 41, True])
def test_noncanonical_head_is_rejected_before_transport(head: object) -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return _json([])

    adapter, _ = _adapter(handler)
    try:
        with pytest.raises(AcquisitionError, match="head SHA"):
            adapter.read_facet(
                TARGET,
                head_sha=cast(str, head),
                facet=EvidenceFacet.COMMIT_STATUSES,
            )
    finally:
        adapter.close()
    assert calls == []


def test_response_and_link_header_bounds_fail_closed() -> None:
    adapter, _ = _adapter(
        lambda _: httpx.Response(200, content=b"[]"),
        maximum_response_bytes=1,
    )
    try:
        with pytest.raises(AcquisitionError) as body_failure:
            adapter.read_facet(TARGET, head_sha=HEAD, facet=EvidenceFacet.FILES)
    finally:
        adapter.close()
    assert body_failure.value.outcome is AcquisitionOutcome.INCOMPLETE_ACQUISITION

    oversized = "x" * (authenticated_rest.MAX_LINK_HEADER_BYTES + 1)
    adapter, _ = _adapter(
        lambda _: _json([], headers={"Link": oversized}),
    )
    try:
        with pytest.raises(AcquisitionError, match="Link header exceeded"):
            adapter.read_facet(TARGET, head_sha=HEAD, facet=EvidenceFacet.FILES)
    finally:
        adapter.close()


def test_redirect_and_nonpaginatable_link_are_never_followed() -> None:
    requests: list[httpx.Request] = []

    def redirect(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            302,
            content=b"{}",
            headers={"Location": "https://evil.example/redirect"},
        )

    adapter, _ = _adapter(redirect)
    try:
        with pytest.raises(AcquisitionError) as raised:
            adapter.read_anchor(TARGET)
    finally:
        adapter.close()
    assert raised.value.outcome is AcquisitionOutcome.MALFORMED_RESPONSE
    assert len(requests) == 1

    adapter, _ = _adapter(
        lambda _: _json(
            _anchor(),
            headers={
                "Link": (
                    '<https://api.github.com/repos/Owner/Repo/pulls/4>; rel="next"'
                )
            },
        )
    )
    try:
        with pytest.raises(AcquisitionError, match="non-paginatable"):
            adapter.read_anchor(TARGET)
    finally:
        adapter.close()


def test_check_run_total_change_and_suite_shape_fail_closed() -> None:
    checks = f"/repos/Owner/Repo/commits/{HEAD}/check-runs?filter=latest&per_page=100"

    def handler(request: httpx.Request) -> httpx.Response:
        target = request.url.raw_path.decode("ascii")
        if target == checks:
            return _json(
                {"total_count": 2, "check_runs": [{"id": 1}]},
                headers={
                    "Link": f'<https://api.github.com{checks}&page=2>; rel="next"'
                },
            )
        return _json({"total_count": 3, "check_runs": [{"id": 2}]})

    adapter, _ = _adapter(handler)
    try:
        with pytest.raises(AcquisitionError, match="changed between pages"):
            adapter.read_facet(TARGET, head_sha=HEAD, facet=EvidenceFacet.CHECK_RUNS)
    finally:
        adapter.close()

    adapter, _ = _adapter(lambda _: _json({"total_count": -1, "check_suites": []}))
    try:
        with pytest.raises(AcquisitionError, match="nonnegative"):
            adapter.read_facet(
                TARGET,
                head_sha=HEAD,
                facet=EvidenceFacet.CHECK_SUITE_COUNT,
            )
    finally:
        adapter.close()

    adapter, _ = _adapter(lambda _: _json({"total_count": 1}))
    try:
        with pytest.raises(AcquisitionError, match="check_suites"):
            adapter.read_facet(
                TARGET,
                head_sha=HEAD,
                facet=EvidenceFacet.CHECK_SUITE_COUNT,
            )
    finally:
        adapter.close()


@pytest.mark.parametrize(
    ("status", "headers", "outcome"),
    [
        (401, {}, AcquisitionOutcome.FORBIDDEN),
        (403, {}, AcquisitionOutcome.FORBIDDEN),
        (403, {"X-RateLimit-Remaining": "0"}, AcquisitionOutcome.RATE_LIMITED),
        (404, {}, AcquisitionOutcome.NOT_FOUND),
        (422, {}, AcquisitionOutcome.UNPROCESSABLE),
        (429, {}, AcquisitionOutcome.RATE_LIMITED),
        (500, {}, AcquisitionOutcome.UPSTREAM_SERVER_ERROR),
        (206, {}, AcquisitionOutcome.INCOMPLETE_ACQUISITION),
    ],
)
def test_http_failures_are_classified_without_credential_leakage(
    status: int,
    headers: dict[str, str],
    outcome: AcquisitionOutcome,
) -> None:
    adapter, _ = _adapter(
        lambda _: httpx.Response(status, content=b"{}", headers=headers)
    )
    try:
        with pytest.raises(AcquisitionError) as raised:
            adapter.read_anchor(TARGET)
    finally:
        adapter.close()
    assert raised.value.outcome is outcome
    assert SHORT_SECRET not in str(raised.value)
    assert SHORT_SECRET not in repr(raised.value)


def test_server_retry_can_recover_but_transport_and_timeout_are_bounded() -> None:
    calls = 0

    def recover(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(503, content=b"{}")
        return _json(_anchor())

    adapter, _ = _adapter(recover, maximum_attempts=2)
    try:
        assert adapter.read_anchor(TARGET).value == _anchor()
    finally:
        adapter.close()
    assert calls == 2

    for exception, outcome in (
        (httpx.ConnectError("offline"), AcquisitionOutcome.TRANSPORT_ERROR),
        (httpx.ReadTimeout("slow"), AcquisitionOutcome.TIMEOUT),
    ):

        def fail(
            _: httpx.Request,
            failure: httpx.RequestError = exception,
        ) -> httpx.Response:
            raise failure

        adapter, _ = _adapter(
            fail,
            maximum_attempts=1,
        )
        try:
            with pytest.raises(AcquisitionError) as raised:
                adapter.read_anchor(TARGET)
        finally:
            adapter.close()
        assert raised.value.outcome is outcome


@pytest.mark.parametrize(
    "failure",
    [httpx.ConnectError("offline-once"), httpx.ReadTimeout("slow-once")],
)
def test_one_transport_uncertainty_can_recover_within_exact_retry_bound(
    failure: httpx.RequestError,
) -> None:
    calls = 0

    def recover(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise failure
        return _json(_anchor())

    adapter, _ = _adapter(recover, maximum_attempts=2)
    try:
        assert adapter.read_anchor(TARGET).value == _anchor()
    finally:
        adapter.close()
    assert calls == 2


@pytest.mark.parametrize(
    "value",
    [
        "bad value",
        "bad\nvalue",
    ],
)
def test_invalid_authorization_never_reaches_transport_or_error_text(
    value: str,
) -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return _json({})

    adapter = AuthenticatedGitHubEvidenceAdapter(
        authorization=OpaqueBearerToken(value),
        repository_id=77,
        owner="Owner",
        repository="Repo",
        transport=httpx.MockTransport(handler),
        maximum_attempts=1,
    )
    try:
        with pytest.raises(AcquisitionError) as raised:
            adapter.read_anchor(TARGET)
    finally:
        adapter.close()
    assert raised.value.outcome is AcquisitionOutcome.FORBIDDEN
    assert calls == []
    assert str(value) not in str(raised.value)


def test_authenticated_adapter_rejects_non_installation_secret_capabilities() -> None:
    with pytest.raises(ValueError, match="opaque installation token"):
        AuthenticatedGitHubEvidenceAdapter(
            authorization=cast(OpaqueBearerToken, object()),
            repository_id=77,
            owner="Owner",
            repository="Repo",
            transport=httpx.MockTransport(lambda _: pytest.fail("must not be called")),
        )


def test_final_transport_rejects_bearer_and_request_substitution() -> None:
    delegated: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        delegated.append(request)
        return _json({})

    adapter, _ = _adapter(handler)
    endpoint = adapter._pull_endpoint(
        TARGET,
        authenticated_rest._EndpointKind.PULL_REQUEST,
        "",
    )
    policy = authenticated_rest._AuthenticatedPolicyTransport(
        httpx.MockTransport(handler)
    )
    mutations = (
        lambda request: request.headers.__setitem__(
            "Authorization", "Bearer substituted"
        ),
        lambda request: request.headers.__setitem__("X-Untrusted", "true"),
        lambda request: setattr(request, "method", "POST"),
        lambda request: setattr(
            request,
            "url",
            httpx.URL("https://evil.example/repos/Owner/Repo/pulls/4"),
        ),
    )
    try:
        for mutate in mutations:
            request = adapter._request_value(endpoint)
            mutate(request)
            with pytest.raises(AcquisitionError):
                policy.handle_request(request)
    finally:
        policy.close()
        adapter.close()
    assert delegated == []


def test_final_transport_rejects_body_duplicate_and_altered_headers() -> None:
    delegated: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        delegated.append(request)
        return _json({})

    adapter, _ = _adapter(handler)
    endpoint = adapter._pull_endpoint(
        TARGET,
        authenticated_rest._EndpointKind.PULL_REQUEST,
        "",
    )
    policy = authenticated_rest._AuthenticatedPolicyTransport(
        httpx.MockTransport(handler)
    )
    try:
        original = adapter._request_value(endpoint)
        body = httpx.Request(
            "GET",
            endpoint.absolute_url,
            headers=dict(original.headers),
            content=b"unexpected",
        )
        body.extensions.update(original.extensions)

        original = adapter._request_value(endpoint)
        duplicates = httpx.Request(
            "GET",
            endpoint.absolute_url,
            headers=[
                *original.headers.multi_items(),
                ("Authorization", original.headers["Authorization"]),
            ],
        )
        duplicates.extensions.update(original.extensions)

        altered = adapter._request_value(endpoint)
        altered.headers["Accept"] = "application/json"
        invalid_scheme = adapter._request_value(endpoint)
        invalid_scheme.headers["Authorization"] = "Token substituted"
        for request in (body, duplicates, altered, invalid_scheme):
            with pytest.raises(AcquisitionError):
                policy.handle_request(request)
    finally:
        policy.close()
        adapter.close()
    assert delegated == []


def test_context_manager_invalid_facet_and_internal_inventory_guards() -> None:
    with _adapter(lambda _: _json(_anchor()))[0] as adapter:
        assert adapter.read_anchor(TARGET).value == _anchor()

    adapter, _ = _adapter(lambda _: _json([]))
    try:
        with pytest.raises(AcquisitionError, match="not enumerated"):
            adapter.read_facet(
                TARGET,
                head_sha=HEAD,
                facet=cast(EvidenceFacet, "files"),
            )
        with pytest.raises(RuntimeError, match="inventory"):
            adapter._list_endpoint(
                TARGET,
                HEAD,
                EvidenceFacet.REQUESTED_REVIEWERS,
            )
    finally:
        adapter.close()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"repository_id": 0},
        {"repository_id": True},
        {"maximum_attempts": 0},
        {"maximum_attempts": True},
        {"maximum_response_bytes": 0},
        {"maximum_response_bytes": True},
    ],
)
def test_constructor_rejects_invalid_identity_and_bounds(
    kwargs: dict[str, object],
) -> None:
    arguments: dict[str, object] = {
        "authorization": OpaqueBearerToken(SHORT_SECRET),
        "repository_id": 77,
        "owner": "Owner",
        "repository": "Repo",
        "transport": httpx.MockTransport(lambda _: _json({})),
        "maximum_attempts": 1,
        "maximum_response_bytes": 100,
    }
    arguments.update(kwargs)
    constructor = cast(
        Callable[..., AuthenticatedGitHubEvidenceAdapter],
        AuthenticatedGitHubEvidenceAdapter,
    )
    with pytest.raises(ValueError):
        constructor(**arguments)


def test_constructor_does_not_accept_external_client_or_event_hooks() -> None:
    parameters = inspect.signature(AuthenticatedGitHubEvidenceAdapter).parameters
    assert "client" not in parameters
    assert "event_hooks" not in parameters


def test_project_owned_construction_disables_environment_and_client_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:1")
    client_configuration: dict[str, object] = {}
    transport_configuration: dict[str, object] = {}
    original_client = httpx.Client
    original_transport = httpx.HTTPTransport

    def client_spy(**kwargs: object) -> httpx.Client:
        client_configuration.update(kwargs)
        return original_client(**cast(Any, kwargs))

    def transport_spy(**kwargs: object) -> httpx.HTTPTransport:
        transport_configuration.update(kwargs)
        return original_transport(**cast(Any, kwargs))

    monkeypatch.setattr(
        "github_steward.adapters.github.authenticated_rest.httpx.Client",
        client_spy,
    )
    monkeypatch.setattr(
        "github_steward.adapters.github.authenticated_rest.httpx.HTTPTransport",
        transport_spy,
    )
    with AuthenticatedGitHubEvidenceAdapter(
        authorization=OpaqueBearerToken(SHORT_SECRET),
        repository_id=77,
        owner="Owner",
        repository="Repo",
    ):
        pass

    assert client_configuration["trust_env"] is False
    assert client_configuration["follow_redirects"] is False
    assert client_configuration["auth"] is None
    assert client_configuration["cookies"] is None
    assert client_configuration["params"] is None
    assert client_configuration["event_hooks"] == {}
    assert client_configuration["proxy"] is None
    assert client_configuration["timeout"] is public_rest.REQUEST_TIMEOUT
    assert client_configuration["limits"] is public_rest.REQUEST_LIMITS
    assert isinstance(
        client_configuration["transport"],
        authenticated_rest._AuthenticatedPolicyTransport,
    )
    assert transport_configuration == {
        "trust_env": False,
        "proxy": None,
        "limits": public_rest.REQUEST_LIMITS,
        "retries": 0,
    }
