"""Exact GitHub App control-plane HTTP kept inside the broker boundary."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import TracebackType
from typing import Protocol

import httpx

from github_steward.adapters.github.public_rest import parse_strict_json
from github_steward.domain.acquisition import API_VERSION, AcquisitionError
from github_steward.ports.github_app import (
    GitHubAppControlPlanePort,
    GitHubControlPlaneResponse,
    InstallationTokenRequest,
    InstallationTokenResponse,
)
from github_steward.ports.secrets import OpaqueBearerToken

from .jwt_signer import _BrokerAppJwt

API_ORIGIN = "https://api.github.com"
MAX_CONTROL_RESPONSE_BYTES = 2 * 1024 * 1024
REQUEST_TIMEOUT = httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=5.0)
REQUEST_LIMITS = httpx.Limits(
    max_connections=2,
    max_keepalive_connections=1,
    keepalive_expiry=5.0,
)
_NAME = re.compile(r"[A-Za-z0-9_.-]+\Z")
_BOUND_OPERATION = "github_steward.github_app_operation"
_COMMON_HEADERS = {
    "accept": "application/vnd.github+json",
    "user-agent": "github-steward",
    "x-github-api-version": API_VERSION,
}


class GitHubControlPlaneError(RuntimeError):
    """A credential-free, fail-closed control-plane error."""


class _AppJwtIssuer(Protocol):
    def issue(self) -> _BrokerAppJwt: ...


class _OperationKind(StrEnum):
    INSTALLATION = "installation"
    REPOSITORY_INSTALLATION = "repository_installation"
    CREATE_TOKEN = "create_token"


@dataclass(frozen=True, slots=True)
class _BoundOperation:
    method: str
    path: str
    kind: _OperationKind
    body: bytes


@dataclass(frozen=True, slots=True)
class _RequestBinding:
    operation: _BoundOperation
    authorization_sha256: bytes


def _positive(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _route_name(value: str, name: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise ValueError(f"{name} was not a canonical GitHub route name")
    return value


def _validate_final_request(request: httpx.Request) -> None:
    binding = request.extensions.get(_BOUND_OPERATION)
    if not isinstance(binding, _RequestBinding):
        raise GitHubControlPlaneError("control-plane request was not operation-bound")
    bound = binding.operation
    url = request.url
    try:
        port = url.port
    except ValueError as exc:  # pragma: no cover - HTTPX normalizes ports
        raise GitHubControlPlaneError("control-plane authority was malformed") from exc
    if (
        url.scheme != "https"
        or url.host != "api.github.com"
        or url.netloc != b"api.github.com"
        or port is not None
        or url.userinfo != b""
        or url.fragment != ""
        or url.query != b""
        or request.url.raw_path != bound.path.encode("ascii")
        or request.method != bound.method
        or request.read() != bound.body
    ):
        raise GitHubControlPlaneError("control-plane request identity was rejected")
    header_items = [
        (name.lower(), value) for name, value in request.headers.multi_items()
    ]
    names = [name for name, _ in header_items]
    if len(names) != len(set(names)):
        raise GitHubControlPlaneError("control-plane request headers were rejected")
    headers = dict(header_items)
    authorization = headers.pop("authorization", "")
    if not authorization.startswith("Bearer ") or authorization == "Bearer ":
        raise GitHubControlPlaneError("control-plane authentication was absent")
    try:
        authorization_digest = hashlib.sha256(authorization.encode("ascii")).digest()
    except UnicodeEncodeError as exc:  # pragma: no cover - HTTPX rejects non-ASCII
        raise GitHubControlPlaneError(
            "control-plane authentication was invalid"
        ) from exc
    if not hmac.compare_digest(
        authorization_digest,
        binding.authorization_sha256,
    ):
        raise GitHubControlPlaneError("control-plane authentication was substituted")
    expected = {"host": "api.github.com", **_COMMON_HEADERS}
    if bound.method == "POST":
        expected.update(
            {
                "content-length": str(len(bound.body)),
                "content-type": "application/json",
            }
        )
    if headers != expected:
        raise GitHubControlPlaneError("control-plane request headers were rejected")


class ControlPlanePolicyTransport(httpx.BaseTransport):
    """Revalidate the final request immediately before transport delegation."""

    def __init__(self, transport: httpx.BaseTransport) -> None:
        self._transport = transport

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        _validate_final_request(request)
        return self._transport.handle_request(request)

    def close(self) -> None:
        self._transport.close()


class GitHubAppControlPlaneClient(GitHubAppControlPlanePort):
    """Expose only the three exact control-plane operations GS-I5 requires."""

    def __init__(
        self,
        *,
        jwt_provider: _AppJwtIssuer,
        transport: httpx.BaseTransport | None = None,
        maximum_response_bytes: int = MAX_CONTROL_RESPONSE_BYTES,
    ) -> None:
        if maximum_response_bytes < 1:
            raise ValueError("maximum_response_bytes must be positive")
        underlying = transport or httpx.HTTPTransport(
            trust_env=False,
            proxy=None,
            limits=REQUEST_LIMITS,
            retries=0,
        )
        self._client = httpx.Client(
            transport=ControlPlanePolicyTransport(underlying),
            trust_env=False,
            follow_redirects=False,
            auth=None,
            cookies=None,
            params=None,
            event_hooks={},
            proxy=None,
            timeout=REQUEST_TIMEOUT,
            limits=REQUEST_LIMITS,
        )
        self._jwt_provider = jwt_provider
        self._maximum_response_bytes = maximum_response_bytes

    def __enter__(self) -> GitHubAppControlPlaneClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def get_installation(self, installation_id: int) -> GitHubControlPlaneResponse:
        identifier = _positive(installation_id, "installation_id")
        operation = _BoundOperation(
            "GET",
            f"/app/installations/{identifier}",
            _OperationKind.INSTALLATION,
            b"",
        )
        return self._request_json(operation)

    def get_repository_installation(
        self,
        *,
        owner: str,
        repository: str,
    ) -> GitHubControlPlaneResponse:
        checked_owner = _route_name(owner, "owner")
        checked_repository = _route_name(repository, "repository")
        operation = _BoundOperation(
            "GET",
            f"/repos/{checked_owner}/{checked_repository}/installation",
            _OperationKind.REPOSITORY_INSTALLATION,
            b"",
        )
        return self._request_json(operation, accepted_statuses=(200, 404))

    def create_installation_token(
        self,
        *,
        installation_id: int,
        request: InstallationTokenRequest,
    ) -> InstallationTokenResponse:
        identifier = _positive(installation_id, "installation_id")
        if not isinstance(request, InstallationTokenRequest):
            raise TypeError("request must be InstallationTokenRequest")
        body = json.dumps(
            request.as_mapping(),
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        operation = _BoundOperation(
            "POST",
            f"/app/installations/{identifier}/access_tokens",
            _OperationKind.CREATE_TOKEN,
            body,
        )
        decoded = self._request_json(operation, accepted_statuses=(201,)).value
        return _token_response(decoded)

    def _request_json(
        self,
        operation: _BoundOperation,
        *,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> GitHubControlPlaneResponse:
        jwt_secret = self._jwt_provider.issue()
        if not isinstance(jwt_secret, _BrokerAppJwt):
            raise GitHubControlPlaneError("GitHub App JWT issuance failed")
        authorization = jwt_secret._control_plane_authorization_header()
        request = httpx.Request(
            operation.method,
            API_ORIGIN + operation.path,
            headers={
                "Accept": _COMMON_HEADERS["accept"],
                "Authorization": authorization,
                "User-Agent": _COMMON_HEADERS["user-agent"],
                "X-GitHub-Api-Version": _COMMON_HEADERS["x-github-api-version"],
                **(
                    {"Content-Type": "application/json"}
                    if operation.method == "POST"
                    else {}
                ),
            },
            content=operation.body,
        )
        request.extensions["timeout"] = REQUEST_TIMEOUT.as_dict()
        request.extensions[_BOUND_OPERATION] = _RequestBinding(
            operation,
            hashlib.sha256(authorization.encode("ascii")).digest(),
        )
        try:
            response = self._client.send(
                request,
                stream=True,
                auth=None,
                follow_redirects=False,
            )
            try:
                raw = self._bounded_body(response.iter_bytes())
                if response.status_code not in accepted_statuses:
                    raise GitHubControlPlaneError(
                        "GitHub control-plane request was not successful"
                    )
                try:
                    value = parse_strict_json(raw)
                except AcquisitionError as exc:
                    raise GitHubControlPlaneError(
                        "GitHub control-plane response was malformed"
                    ) from exc
                return GitHubControlPlaneResponse(
                    value=value,
                    raw_sha256=hashlib.sha256(raw).hexdigest(),
                    status_code=response.status_code,
                )
            finally:
                response.close()
        except httpx.TimeoutException as exc:
            raise GitHubControlPlaneError(
                "GitHub control-plane request timed out"
            ) from exc
        except httpx.TransportError as exc:
            raise GitHubControlPlaneError(
                "GitHub control-plane transport failed"
            ) from exc

    def _bounded_body(self, chunks: Iterable[bytes]) -> bytes:
        body = bytearray()
        for chunk in chunks:
            body.extend(chunk)
            if len(body) > self._maximum_response_bytes:
                raise GitHubControlPlaneError(
                    "GitHub control-plane response exceeded the size bound"
                )
        return bytes(body)


def _token_response(value: object) -> InstallationTokenResponse:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise GitHubControlPlaneError("installation token response was malformed")
    allowed = {
        "token",
        "expires_at",
        "permissions",
        "repositories",
        "repository_selection",
        "single_file",
        "has_multiple_single_files",
        "single_file_paths",
    }
    if set(value) - allowed:
        raise GitHubControlPlaneError("installation token response had unknown fields")
    token = value.get("token")
    expires_at = value.get("expires_at")
    permissions = value.get("permissions")
    if (
        not isinstance(token, str)
        or token == ""
        or not isinstance(expires_at, str)
        or expires_at == ""
        or not isinstance(permissions, Mapping)
    ):
        raise GitHubControlPlaneError("installation token response was incomplete")
    normalized_permissions: list[tuple[str, str]] = []
    for key, permission in permissions.items():
        if not isinstance(key, str) or not isinstance(permission, str):
            raise GitHubControlPlaneError(
                "installation token permissions were malformed"
            )
        normalized_permissions.append((key, permission))
    repositories = value.get("repositories")
    repository_ids: tuple[int, ...] | None = None
    if repositories is not None:
        if not isinstance(repositories, list):
            raise GitHubControlPlaneError(
                "installation token repositories were malformed"
            )
        parsed: list[int] = []
        for repository in repositories:
            if not isinstance(repository, Mapping):
                raise GitHubControlPlaneError(
                    "installation token repository entry was malformed"
                )
            identifier = repository.get("id")
            if isinstance(identifier, bool) or not isinstance(identifier, int):
                raise GitHubControlPlaneError(
                    "installation token repository identity was malformed"
                )
            parsed.append(_positive(identifier, "repository id"))
        repository_ids = tuple(parsed)
    selection = value.get("repository_selection")
    if selection is not None and not isinstance(selection, str):
        raise GitHubControlPlaneError("repository_selection was malformed")
    return InstallationTokenResponse(
        token=OpaqueBearerToken(token),
        expires_at=expires_at,
        permissions=tuple(sorted(normalized_permissions)),
        repository_ids=repository_ids,
        repository_selection=selection,
    )
