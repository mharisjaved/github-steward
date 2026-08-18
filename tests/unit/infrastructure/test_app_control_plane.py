"""Offline adversarial tests for the broker-owned GitHub App control plane."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import cast

import httpx
import pytest

from github_steward.domain.acquisition import API_VERSION
from github_steward.infrastructure.broker import app_control_plane
from github_steward.infrastructure.broker.app_control_plane import (
    ControlPlanePolicyTransport,
    GitHubAppControlPlaneClient,
    GitHubControlPlaneError,
)
from github_steward.infrastructure.broker.jwt_signer import _BrokerAppJwt
from github_steward.ports.github_app import InstallationTokenRequest


class FakeJwtProvider:
    def __init__(self) -> None:
        self.calls = 0

    def issue(self) -> _BrokerAppJwt:
        self.calls += 1
        return _BrokerAppJwt("signed-app-jwt")


def _client(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    maximum_response_bytes: int = 2 * 1024 * 1024,
) -> tuple[GitHubAppControlPlaneClient, FakeJwtProvider]:
    provider = FakeJwtProvider()
    return (
        GitHubAppControlPlaneClient(
            jwt_provider=provider,
            transport=httpx.MockTransport(handler),
            maximum_response_bytes=maximum_response_bytes,
        ),
        provider,
    )


def test_exact_installation_and_repository_relationship_gets() -> None:
    requested: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request)
        assert request.method == "GET"
        assert request.headers["Authorization"] == "Bearer signed-app-jwt"
        assert request.headers["Accept"] == "application/vnd.github+json"
        assert request.headers["X-GitHub-Api-Version"] == API_VERSION
        return httpx.Response(200, json={"id": 10})

    client, jwt_provider = _client(handler)
    with client:
        installation = client.get_installation(10)
        relationship = client.get_repository_installation(
            owner="Owner",
            repository="Repository",
        )

    assert [request.url.raw_path for request in requested] == [
        b"/app/installations/10",
        b"/repos/Owner/Repository/installation",
    ]
    assert installation.value == {"id": 10}
    assert relationship.status_code == 200
    assert jwt_provider.calls == 2
    assert not any(
        hasattr(client, name) for name in ("get", "post", "put", "patch", "delete")
    )


def test_repository_relationship_404_is_a_valid_denial_fact() -> None:
    client, _ = _client(
        lambda _: httpx.Response(404, content=b'{"message":"not found"}')
    )
    try:
        response = client.get_repository_installation(owner="Owner", repository="Repo")
    finally:
        client.close()
    assert response.status_code == 404
    assert response.value == {"message": "not found"}


@pytest.mark.parametrize("token", ["short", "x" * 512])
def test_token_post_has_exact_one_repository_read_body_and_opaque_response(
    token: str,
) -> None:
    seen: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.raw_path == b"/app/installations/10/access_tokens"
        assert request.headers["Authorization"] == "Bearer signed-app-jwt"
        seen.append(cast(dict[str, object], json.loads(request.content)))
        return httpx.Response(
            201,
            json={
                "token": token,
                "expires_at": "2026-08-18T13:00:00Z",
                "permissions": {
                    "metadata": "read",
                    "pull_requests": "read",
                    "checks": "read",
                    "statuses": "read",
                },
                "repositories": [{"id": 123456, "name": "display-only"}],
                "repository_selection": "selected",
            },
        )

    client, _ = _client(handler)
    try:
        response = client.create_installation_token(
            installation_id=10,
            request=InstallationTokenRequest(123456),
        )
    finally:
        client.close()

    assert seen == [
        {
            "repository_ids": [123456],
            "permissions": {
                "metadata": "read",
                "pull_requests": "read",
                "checks": "read",
                "statuses": "read",
            },
        }
    ]
    assert response.token.matches(token)
    assert token not in repr(response)
    assert response.repository_ids == (123456,)


@pytest.mark.parametrize(
    "response",
    [
        b'{"token":"a","token":"b","expires_at":"x","permissions":{}}',
        b"\xff",
        b'{"token":"a","expires_at":"x","permissions":{},"unknown":1}',
        b'{"token":"","expires_at":"x","permissions":{}}',
        b'{"token":"a","expires_at":"","permissions":{}}',
        b'{"token":"a","expires_at":"x","permissions":[]}',
        b'{"token":"a","expires_at":"x","permissions":{"metadata":1}}',
        b'{"token":"a","expires_at":"x","permissions":{},"repositories":{}}',
        b'{"token":"a","expires_at":"x","permissions":{},"repositories":[1]}',
        b'{"token":"a","expires_at":"x","permissions":{},"repositories":[{"id":true}]}',
        b'{"token":"a","expires_at":"x","permissions":{},"repository_selection":1}',
    ],
)
def test_token_response_strict_validation_rejects_malformed_or_unknown_data(
    response: bytes,
) -> None:
    client, _ = _client(lambda _: httpx.Response(201, content=response))
    try:
        with pytest.raises(GitHubControlPlaneError):
            client.create_installation_token(
                installation_id=10,
                request=InstallationTokenRequest(123456),
            )
    finally:
        client.close()


@pytest.mark.parametrize("status", [201, 302, 403, 500])
def test_installation_get_rejects_every_non_200_status(status: int) -> None:
    client, _ = _client(lambda _: httpx.Response(status, json={"message": "no"}))
    try:
        with pytest.raises(GitHubControlPlaneError):
            client.get_installation(10)
    finally:
        client.close()


def test_control_plane_response_body_is_bounded() -> None:
    client, _ = _client(
        lambda _: httpx.Response(200, content=b'{"id":10}'),
        maximum_response_bytes=4,
    )
    try:
        with pytest.raises(GitHubControlPlaneError):
            client.get_installation(10)
    finally:
        client.close()


def test_control_plane_configuration_and_token_request_types_are_strict() -> None:
    with pytest.raises(ValueError, match="maximum_response_bytes"):
        GitHubAppControlPlaneClient(
            jwt_provider=FakeJwtProvider(),
            transport=httpx.MockTransport(
                lambda _: pytest.fail("transport must not be called")
            ),
            maximum_response_bytes=0,
        )

    client, provider = _client(lambda _: pytest.fail("transport must not be called"))
    try:
        with pytest.raises(TypeError, match="InstallationTokenRequest"):
            client.create_installation_token(
                installation_id=10,
                request=cast(InstallationTokenRequest, object()),
            )
    finally:
        client.close()
    assert provider.calls == 0


@pytest.mark.parametrize(
    ("owner", "repository"),
    [("", "repo"), ("owner/name", "repo"), ("owner", "repo%2fother")],
)
def test_route_names_are_canonical_before_http(owner: str, repository: str) -> None:
    client, provider = _client(lambda _: pytest.fail("transport must not be called"))
    try:
        with pytest.raises(ValueError):
            client.get_repository_installation(owner=owner, repository=repository)
    finally:
        client.close()
    assert provider.calls == 0


@pytest.mark.parametrize("installation_id", [0, -1, True])
def test_numeric_installation_identity_is_required(installation_id: int) -> None:
    client, provider = _client(lambda _: pytest.fail("transport must not be called"))
    try:
        with pytest.raises(ValueError):
            client.get_installation(installation_id)
    finally:
        client.close()
    assert provider.calls == 0


def test_malformed_json_and_transport_failures_have_safe_errors() -> None:
    malformed, _ = _client(lambda _: httpx.Response(200, content=b"not-json"))
    try:
        with pytest.raises(GitHubControlPlaneError) as malformed_error:
            malformed.get_installation(10)
    finally:
        malformed.close()
    assert "signed-app-jwt" not in str(malformed_error.value)

    def timeout(_: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("secret transport detail")

    timed, _ = _client(timeout)
    try:
        with pytest.raises(GitHubControlPlaneError) as timeout_error:
            timed.get_installation(10)
    finally:
        timed.close()
    assert "secret transport detail" not in str(timeout_error.value)

    def transport_failure(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("secret connection detail")

    failed, _ = _client(transport_failure)
    try:
        with pytest.raises(GitHubControlPlaneError) as transport_error:
            failed.get_installation(10)
    finally:
        failed.close()
    assert "secret connection detail" not in str(transport_error.value)


def _bound_request(
    *,
    method: str = "GET",
    url: str = "https://api.github.com/app/installations/10",
    authorization: str = "Bearer signed-app-jwt",
    body: bytes = b"",
) -> httpx.Request:
    operation = app_control_plane._BoundOperation(
        "GET",
        "/app/installations/10",
        app_control_plane._OperationKind.INSTALLATION,
        b"",
    )
    request = httpx.Request(
        method,
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": authorization,
            "User-Agent": "github-steward",
            "X-GitHub-Api-Version": API_VERSION,
        },
        content=body,
    )
    request.extensions[app_control_plane._BOUND_OPERATION] = (
        app_control_plane._RequestBinding(
            operation,
            hashlib.sha256(b"Bearer signed-app-jwt").digest(),
        )
    )
    return request


@pytest.mark.parametrize(
    "final_request",
    [
        _bound_request(method="POST"),
        _bound_request(url="http://api.github.com/app/installations/10"),
        _bound_request(url="https://evil.example/app/installations/10"),
        _bound_request(url="https://api.github.com:444/app/installations/10"),
        _bound_request(url="https://user@api.github.com/app/installations/10"),
        _bound_request(url="https://api.github.com/app/installations/11"),
        _bound_request(url="https://api.github.com/app/installations/10?x=1"),
        _bound_request(url="https://api.github.com/app/installations/10#x"),
        _bound_request(authorization=""),
        _bound_request(authorization="Bearer substituted"),
        _bound_request(body=b"unexpected"),
    ],
)
def test_final_transport_policy_rejects_request_substitution(
    final_request: httpx.Request,
) -> None:
    delegated: list[httpx.Request] = []

    def delegate(received: httpx.Request) -> httpx.Response:
        delegated.append(received)
        return httpx.Response(200, json={})

    transport = ControlPlanePolicyTransport(httpx.MockTransport(delegate))
    with pytest.raises(GitHubControlPlaneError):
        transport.handle_request(final_request)
    transport.close()
    assert delegated == []


def test_unbound_final_request_is_rejected() -> None:
    transport = ControlPlanePolicyTransport(
        httpx.MockTransport(lambda _: httpx.Response(200, json={}))
    )
    with pytest.raises(GitHubControlPlaneError):
        transport.handle_request(
            httpx.Request("GET", "https://api.github.com/app/installations/10")
        )
    transport.close()


def test_final_transport_rejects_duplicate_authorization_headers() -> None:
    original = _bound_request()
    duplicate = httpx.Request(
        "GET",
        str(original.url),
        headers=[
            *original.headers.multi_items(),
            ("Authorization", "Bearer signed-app-jwt"),
        ],
    )
    duplicate.extensions.update(original.extensions)
    transport = ControlPlanePolicyTransport(
        httpx.MockTransport(lambda _: pytest.fail("transport must not be called"))
    )
    try:
        with pytest.raises(GitHubControlPlaneError, match="headers were rejected"):
            transport.handle_request(duplicate)
    finally:
        transport.close()


def test_control_plane_rejects_non_broker_jwt_capability() -> None:
    class InvalidIssuer:
        def issue(self) -> _BrokerAppJwt:
            return cast(_BrokerAppJwt, object())

    client = GitHubAppControlPlaneClient(
        jwt_provider=InvalidIssuer(),
        transport=httpx.MockTransport(lambda _: pytest.fail("must not be called")),
    )
    try:
        with pytest.raises(GitHubControlPlaneError, match="issuance failed"):
            client.get_installation(10)
    finally:
        client.close()


def test_final_transport_rejects_unexpected_headers() -> None:
    extra_header = _bound_request()
    extra_header.headers["X-Unexpected"] = "value"
    transport = ControlPlanePolicyTransport(
        httpx.MockTransport(lambda _: pytest.fail("transport must not be called"))
    )
    try:
        with pytest.raises(GitHubControlPlaneError, match="headers were rejected"):
            transport.handle_request(extra_header)
    finally:
        transport.close()


def test_token_parser_rejects_non_string_mapping_keys() -> None:
    with pytest.raises(GitHubControlPlaneError, match="response was malformed"):
        app_control_plane._token_response({1: "not-a-json-object-key"})


@pytest.mark.parametrize("repository_id", [0, True, "123"])
def test_installation_token_request_requires_positive_numeric_repository_id(
    repository_id: object,
) -> None:
    with pytest.raises(ValueError, match="repository_id"):
        InstallationTokenRequest(repository_id)  # type: ignore[arg-type]
