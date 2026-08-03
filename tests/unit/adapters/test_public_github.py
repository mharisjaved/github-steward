"""Offline transport-boundary tests for anonymous public GitHub reads."""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from typing import Any, cast

import httpx
import pytest

from github_steward.adapters.github import public_rest
from github_steward.adapters.github.public_rest import (
    PolicyEnforcingTransport,
    PublicGitHubRestClient,
)
from github_steward.domain.acquisition import (
    API_VERSION,
    AcquisitionError,
    AcquisitionOutcome,
)

HEAD = "a" * 40
PULL_URL = "https://api.github.com/repos/Harry5174/github-steward/pulls/1"
FILES_URL = PULL_URL + "/files?per_page=100"
CHECKS_URL = (
    "https://api.github.com/repos/Harry5174/github-steward/commits/"
    f"{HEAD}/check-runs?filter=latest&per_page=100"
)
SUITES_URL = (
    f"https://api.github.com/repos/Harry5174/github-steward/commits/{HEAD}/check-suites"
)
APP_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": API_VERSION,
    "User-Agent": "github-steward",
}


def _client(
    handler: Callable[[httpx.Request], httpx.Response],
    **bounds: int,
) -> PublicGitHubRestClient:
    return PublicGitHubRestClient(
        transport=httpx.MockTransport(handler),
        **bounds,
    )


def _policy_request(
    *,
    method: str = "GET",
    url: str = PULL_URL,
    headers: dict[str, str] | None = None,
    content: bytes | None = None,
) -> httpx.Request:
    approved = dict(APP_HEADERS)
    if headers is not None:
        approved.update(headers)
    if content is None:
        return httpx.Request(method, url, headers=approved)
    return httpx.Request(method, url, headers=approved, content=content)


def test_exact_headers_get_only_and_pagination_link() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url == httpx.URL(FILES_URL)
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
                "Link": f'<{FILES_URL}&page=2>; rel="next", '
                f'<{FILES_URL}&page=2>; rel="last"'
            },
        )

    github = _client(handler)
    try:
        result = github.get(FILES_URL.removeprefix("https://api.github.com"))
    finally:
        github.close()
    assert result.value == [{"id": 1}]
    assert result.next_url == FILES_URL + "&page=2"
    assert result.path == FILES_URL.removeprefix("https://api.github.com")
    assert len(result.raw_sha256) == 64
    audit = github.audit[0]
    assert audit.method == "GET"
    assert audit.host == "api.github.com"
    assert audit.scheme == "https"
    assert audit.port_classification == "default_https"
    assert audit.query == (("per_page", "100"),)
    assert audit.application_headers == (
        "accept",
        "user-agent",
        "x-github-api-version",
    )
    assert audit.credentials_absent
    assert audit.raw_response_sha256 == result.raw_sha256
    assert not any(hasattr(github, name) for name in ("post", "put", "patch", "delete"))


@pytest.mark.parametrize(
    "final_request",
    [
        _policy_request(headers={"Authorization": "hostile"}),
        _policy_request(headers={"Cookie": "session=hostile"}),
        _policy_request(headers={"Proxy-Authorization": "hostile"}),
        _policy_request(url="https://evil.example/repos/o/r/pulls/1"),
        _policy_request(url="http://api.github.com/repos/o/r/pulls/1"),
        _policy_request(url="https://user@api.github.com/repos/o/r/pulls/1"),
        _policy_request(url="https://api.github.com:444/repos/o/r/pulls/1"),
        _policy_request(url=PULL_URL + "#fragment"),
        _policy_request(url=PULL_URL + "?unexpected=true"),
        _policy_request(content=b"hostile-body"),
        _policy_request(method="POST"),
        _policy_request(headers={"X-Untrusted": "hostile"}),
    ],
    ids=[
        "authorization",
        "cookie",
        "proxy-authorization",
        "off-host",
        "http",
        "user-info",
        "unexpected-port",
        "fragment",
        "unexpected-query",
        "request-body",
        "non-get",
        "unexpected-header",
    ],
)
def test_policy_transport_rejects_final_hostile_request(
    final_request: httpx.Request,
) -> None:
    delegated: list[httpx.Request] = []

    def handler(value: httpx.Request) -> httpx.Response:
        delegated.append(value)
        return httpx.Response(200, json={})

    transport = PolicyEnforcingTransport(httpx.MockTransport(handler))
    with pytest.raises(AcquisitionError) as raised:
        transport.handle_request(final_request)
    transport.close()
    assert raised.value.outcome is AcquisitionOutcome.MALFORMED_RESPONSE
    assert delegated == []


def test_policy_transport_delegates_one_valid_request() -> None:
    delegated: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        delegated.append(request)
        return httpx.Response(200, json={})

    transport = PolicyEnforcingTransport(httpx.MockTransport(handler))
    response = transport.handle_request(_policy_request())
    transport.close()
    assert response.status_code == 200
    assert len(delegated) == 1
    assert delegated[0].url == httpx.URL(PULL_URL)


def test_external_client_and_event_hooks_cannot_enter_production_path() -> None:
    calls: list[httpx.Request] = []

    def poison(request: httpx.Request) -> None:
        calls.append(request)
        request.headers["Authorization"] = "hook-auth"
        request.url = httpx.URL("https://evil.example/redirected")

    hostile = httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={})),
        auth=("user", "password"),
        cookies={"session": "hostile"},
        params={"hostile": "query"},
        follow_redirects=True,
        event_hooks={"request": [poison]},
    )
    constructor = cast(Any, PublicGitHubRestClient)
    try:
        with pytest.raises(TypeError):
            constructor(hostile)
        with pytest.raises(TypeError):
            constructor(event_hooks={"request": [poison]})
    finally:
        hostile.close()
    assert calls == []
    assert "client" not in inspect.signature(PublicGitHubRestClient).parameters
    assert "event_hooks" not in inspect.signature(PublicGitHubRestClient).parameters


def test_project_owned_construction_disables_environment_and_client_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:1")
    captured_client: dict[str, object] = {}
    captured_transport: dict[str, object] = {}
    original_client = httpx.Client
    original_transport = httpx.HTTPTransport

    def client_spy(**kwargs: object) -> httpx.Client:
        captured_client.update(kwargs)
        return original_client(**cast(Any, kwargs))

    def transport_spy(**kwargs: object) -> httpx.HTTPTransport:
        captured_transport.update(kwargs)
        return original_transport(**cast(Any, kwargs))

    monkeypatch.setattr(
        "github_steward.adapters.github.public_rest.httpx.Client", client_spy
    )
    monkeypatch.setattr(
        "github_steward.adapters.github.public_rest.httpx.HTTPTransport",
        transport_spy,
    )
    with PublicGitHubRestClient():
        pass

    assert captured_client["trust_env"] is False
    assert captured_client["follow_redirects"] is False
    assert captured_client["auth"] is None
    assert captured_client["cookies"] is None
    assert captured_client["params"] is None
    assert captured_client["event_hooks"] == {}
    assert captured_client["proxy"] is None
    assert captured_client["timeout"] is public_rest.REQUEST_TIMEOUT
    assert captured_client["limits"] is public_rest.REQUEST_LIMITS
    assert isinstance(captured_client["transport"], PolicyEnforcingTransport)
    assert captured_transport == {
        "trust_env": False,
        "proxy": None,
        "limits": public_rest.REQUEST_LIMITS,
        "retries": 0,
    }


def test_redirect_is_classified_and_never_followed() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            302,
            content=b"{}",
            headers={"Location": "https://evil.example/redirected"},
        )

    github = _client(handler, maximum_attempts=3)
    try:
        with pytest.raises(AcquisitionError) as raised:
            github.get(PULL_URL)
    finally:
        github.close()
    assert raised.value.outcome is AcquisitionOutcome.MALFORMED_RESPONSE
    assert len(requests) == 1
    assert requests[0].url.host == "api.github.com"
    assert len(github.audit) == 1
    assert github.audit[0].classification == AcquisitionOutcome.MALFORMED_RESPONSE


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
    github = _client(lambda _: httpx.Response(200, content=raw))
    try:
        with pytest.raises(AcquisitionError) as raised:
            github.get(PULL_URL)
    finally:
        github.close()
    assert raised.value.outcome is AcquisitionOutcome.MALFORMED_RESPONSE


@pytest.mark.parametrize(
    "link",
    [
        '<https://evil.example/repos/o/r/pulls/1/files?per_page=100>; rel="next"',
        "not-a-link",
        '<http://api.github.com/repos/o/r/pulls/1/files?per_page=100>; rel="next"',
        f'<{FILES_URL}&page=2>; rel="next", <{FILES_URL}&page=3>; rel="next"',
        '<https://evil.example/repos/o/r/pulls/1/files?per_page=100>; rel="last"',
        f'<{FILES_URL}&page=%32>; rel="next"',
        f'<{FILES_URL}&extra=true>; rel="next"',
    ],
)
def test_rejects_bad_pagination_links(link: str) -> None:
    github = _client(lambda _: httpx.Response(200, json=[], headers={"Link": link}))
    try:
        with pytest.raises(AcquisitionError) as raised:
            github.get(FILES_URL)
    finally:
        github.close()
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
    github = _client(
        lambda _: httpx.Response(status, content=b"{}", headers=headers),
        maximum_attempts=1,
    )
    try:
        with pytest.raises(AcquisitionError) as raised:
            github.get(PULL_URL)
    finally:
        github.close()
    assert raised.value.outcome is outcome
    assert github.audit[-1].classification == outcome.value


def test_timeout_is_bounded_and_classified() -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ReadTimeout("offline timeout", request=request)

    github = _client(handler, maximum_attempts=2)
    try:
        with pytest.raises(AcquisitionError) as raised:
            github.get(PULL_URL)
    finally:
        github.close()
    assert attempts == 2
    assert raised.value.outcome is AcquisitionOutcome.TIMEOUT


def test_server_failure_retry_can_recover() -> None:
    attempts = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(503 if attempts == 1 else 200, json={"ok": True})

    github = _client(handler, maximum_attempts=2)
    try:
        assert github.get(PULL_URL).value == {"ok": True}
    finally:
        github.close()
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

    github = _client(handler, maximum_attempts=2)
    try:
        with pytest.raises(AcquisitionError) as raised:
            github.get(PULL_URL)
    finally:
        github.close()
    assert attempts == 2
    assert raised.value.outcome is AcquisitionOutcome.TRANSPORT_ERROR


def test_response_size_is_bounded() -> None:
    github = _client(
        lambda _: httpx.Response(200, content=b"[]"), maximum_response_bytes=1
    )
    try:
        with pytest.raises(AcquisitionError) as raised:
            github.get(PULL_URL)
    finally:
        github.close()
    assert raised.value.outcome is AcquisitionOutcome.INCOMPLETE_ACQUISITION


@pytest.mark.parametrize(
    "target",
    [
        "http://api.github.com/repos/o/r/pulls/1",
        "https://evil.example/repos/o/r/pulls/1",
        "https://api.github.com.evil.example/repos/o/r/pulls/1",
        "https://user@api.github.com/repos/o/r/pulls/1",
        "https://api.github.com:444/repos/o/r/pulls/1",
        "https://api.github.com:bad/repos/o/r/pulls/1",
        PULL_URL + "#fragment",
        PULL_URL + "/suffix",
        PULL_URL + "?unexpected=true",
        PULL_URL + "?bad",
        PULL_URL + "?one=1;two=2",
        FILES_URL + "&per_page=100",
        FILES_URL + "&page=0",
        FILES_URL + "&page=01",
        FILES_URL + "&page=not-a-number",
        PULL_URL.replace("/pulls/1", "/pulls/%31"),
        "https://api.github.com/not-an-endpoint",
        "https://api.github.com/repos/o!/r/pulls/1",
        "https://api.github.com/repos/o/r/commits/bad/check-suites",
        "https://api.github.com/repos/o/r/commits/" + HEAD + "/unknown",
        "malformed",
    ],
)
def test_rejects_non_public_targets_before_transport(target: str) -> None:
    called = False

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={})

    github = _client(handler)
    try:
        with pytest.raises(AcquisitionError):
            github.get(target)
    finally:
        github.close()
    assert not called


@pytest.mark.parametrize(
    "target",
    [
        PULL_URL,
        FILES_URL,
        FILES_URL + "&page=2",
        CHECKS_URL,
        CHECKS_URL + "&page=2",
        SUITES_URL,
        "https://api.github.com:443/repos/Harry5174/github-steward/pulls/1",
    ],
)
def test_allowed_endpoint_shapes_reach_transport(target: str) -> None:
    github = _client(lambda _: httpx.Response(200, json={}))
    try:
        assert github.get(target).value == {}
    finally:
        github.close()


def test_constructor_rejects_nonpositive_bounds() -> None:
    transport = httpx.MockTransport(lambda _: httpx.Response(200))
    with pytest.raises(ValueError):
        PublicGitHubRestClient(transport=transport, maximum_attempts=0)
    with pytest.raises(ValueError):
        PublicGitHubRestClient(transport=transport, maximum_response_bytes=0)
    transport.close()


def test_raw_digest_is_over_authoritative_encoding() -> None:
    variants = [json.dumps({"id": 1}).encode(), b'{  "id" : 1 }']
    digests: list[str] = []
    for raw in variants:

        def handler(_: httpx.Request, body: bytes = raw) -> httpx.Response:
            return httpx.Response(200, content=body)

        github = _client(handler)
        try:
            digests.append(github.get(PULL_URL).raw_sha256)
        finally:
            github.close()
    assert digests[0] != digests[1]
