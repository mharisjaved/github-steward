"""Offline transport-boundary tests for anonymous public GitHub reads."""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx
import pytest

from github_steward.adapters.github.public_rest import PublicGitHubRestClient
from github_steward.domain.acquisition import (
    API_VERSION,
    AcquisitionError,
    AcquisitionOutcome,
)


def _client(
    handler: Callable[[httpx.Request], httpx.Response],
    **bounds: int,
) -> tuple[httpx.Client, PublicGitHubRestClient]:
    http = httpx.Client(transport=httpx.MockTransport(handler))
    return http, PublicGitHubRestClient(http, **bounds)


def test_exact_headers_get_only_and_pagination_link() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url == httpx.URL("https://api.github.com/example?page=1")
        assert request.headers["Accept"] == "application/vnd.github+json"
        assert request.headers["X-GitHub-Api-Version"] == API_VERSION
        assert request.headers["User-Agent"] == "github-steward"
        assert "Authorization" not in request.headers
        assert request.extensions["timeout"] == {
            "connect": 5.0,
            "read": 15.0,
            "write": 5.0,
            "pool": 5.0,
        }
        return httpx.Response(
            200,
            content=b'[{"id":1}]',
            headers={
                "Link": '<https://api.github.com/example?page=2>; rel="next", '
                '<https://api.github.com/example?page=2>; rel="last"'
            },
        )

    http, github = _client(handler)
    try:
        result = github.get("/example?page=1")
    finally:
        http.close()
    assert result.value == [{"id": 1}]
    assert result.next_url == "https://api.github.com/example?page=2"
    assert result.path == "/example?page=1"
    assert len(result.raw_sha256) == 64
    assert github.audit[0].method == "GET"
    assert github.audit[0].host == "api.github.com"
    assert not any(hasattr(github, name) for name in ("post", "put", "patch", "delete"))


@pytest.mark.parametrize(
    "raw",
    [
        b"\xff",
        b"{",
        b'{"outer":{"same":1,"same":2}}',
        b'{"value":1.5}',
        b'{"value":NaN}',
        b'{"value":9007199254740992}',
    ],
)
def test_rejects_non_strict_json(raw: bytes) -> None:
    http, github = _client(lambda _: httpx.Response(200, content=raw))
    try:
        with pytest.raises(AcquisitionError) as raised:
            github.get("/bad")
    finally:
        http.close()
    assert raised.value.outcome is AcquisitionOutcome.MALFORMED_RESPONSE


@pytest.mark.parametrize(
    "link",
    [
        '<https://evil.example/page>; rel="next"',
        "not-a-link",
        '<http://api.github.com/page>; rel="next"',
        '<https://api.github.com/a>; rel="next", '
        '<https://api.github.com/b>; rel="next"',
        '<https://evil.example/page>; rel="last"',
    ],
)
def test_rejects_bad_pagination_links(link: str) -> None:
    http, github = _client(
        lambda _: httpx.Response(200, json=[], headers={"Link": link})
    )
    try:
        with pytest.raises(AcquisitionError) as raised:
            github.get("/page")
    finally:
        http.close()
    assert raised.value.outcome is AcquisitionOutcome.MALFORMED_RESPONSE


@pytest.mark.parametrize(
    ("status", "headers", "outcome"),
    [
        (403, {}, AcquisitionOutcome.FORBIDDEN),
        (403, {"X-RateLimit-Remaining": "0"}, AcquisitionOutcome.RATE_LIMITED),
        (403, {"Retry-After": "60"}, AcquisitionOutcome.RATE_LIMITED),
        (429, {}, AcquisitionOutcome.RATE_LIMITED),
        (404, {}, AcquisitionOutcome.NOT_FOUND),
        (422, {}, AcquisitionOutcome.UNPROCESSABLE),
        (500, {}, AcquisitionOutcome.UPSTREAM_SERVER_ERROR),
        (206, {}, AcquisitionOutcome.INCOMPLETE_ACQUISITION),
        (201, {}, AcquisitionOutcome.MALFORMED_RESPONSE),
        (302, {}, AcquisitionOutcome.MALFORMED_RESPONSE),
    ],
)
def test_classifies_http_failures(
    status: int,
    headers: dict[str, str],
    outcome: AcquisitionOutcome,
) -> None:
    http, github = _client(
        lambda _: httpx.Response(status, content=b"{}", headers=headers),
        maximum_attempts=1,
    )
    try:
        with pytest.raises(AcquisitionError) as raised:
            github.get("/failure")
    finally:
        http.close()
    assert raised.value.outcome is outcome
    assert github.audit[-1].classification == outcome.value


def test_timeout_is_bounded_and_classified() -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ReadTimeout("offline timeout", request=request)

    http, github = _client(handler, maximum_attempts=2)
    try:
        with pytest.raises(AcquisitionError) as raised:
            github.get("/timeout")
    finally:
        http.close()
    assert attempts == 2
    assert raised.value.outcome is AcquisitionOutcome.TIMEOUT


def test_server_failure_retry_can_recover() -> None:
    attempts = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(503 if attempts == 1 else 200, json={"ok": True})

    http, github = _client(handler, maximum_attempts=2)
    try:
        assert github.get("/retry").value == {"ok": True}
    finally:
        http.close()
    assert [item.classification for item in github.audit] == [
        AcquisitionOutcome.UPSTREAM_SERVER_ERROR.value,
        AcquisitionOutcome.ACQUIRED.value,
    ]


def test_transport_failure_is_bounded_and_classified() -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ConnectError("offline transport", request=request)

    http, github = _client(handler, maximum_attempts=2)
    try:
        with pytest.raises(AcquisitionError) as raised:
            github.get("/transport")
    finally:
        http.close()
    assert attempts == 2
    assert raised.value.outcome is AcquisitionOutcome.TRANSPORT_ERROR


def test_response_size_is_bounded() -> None:
    http, github = _client(
        lambda _: httpx.Response(200, content=b"[]"), maximum_response_bytes=1
    )
    try:
        with pytest.raises(AcquisitionError) as raised:
            github.get("/large")
    finally:
        http.close()
    assert raised.value.outcome is AcquisitionOutcome.INCOMPLETE_ACQUISITION


@pytest.mark.parametrize(
    "target",
    [
        "http://api.github.com/path",
        "https://evil.example/path",
        "https://user@api.github.com/path",
        "https://api.github.com:444/path",
        "https://api.github.com:bad/path",
        "https://api.github.com/path#fragment",
        "malformed",
    ],
)
def test_rejects_non_public_targets_before_transport(target: str) -> None:
    called = False

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={})

    http, github = _client(handler)
    try:
        with pytest.raises(AcquisitionError):
            github.get(target)
    finally:
        http.close()
    assert not called


def test_constructor_rejects_nonpositive_bounds() -> None:
    http = httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200)))
    try:
        with pytest.raises(ValueError):
            PublicGitHubRestClient(http, maximum_attempts=0)
        with pytest.raises(ValueError):
            PublicGitHubRestClient(http, maximum_response_bytes=0)
    finally:
        http.close()


def test_raw_digest_is_over_authoritative_encoding() -> None:
    variants = [json.dumps({"id": 1}).encode(), b'{  "id" : 1 }']
    digests: list[str] = []
    for raw in variants:

        def handler(_: httpx.Request, body: bytes = raw) -> httpx.Response:
            return httpx.Response(200, content=body)

        http, github = _client(handler)
        try:
            digests.append(github.get("/digest").raw_sha256)
        finally:
            http.close()
    assert digests[0] != digests[1]
