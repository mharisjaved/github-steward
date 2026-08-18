"""Credential-contained, GET-only GitHub evidence adapter for GS-I5."""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from types import TracebackType
from typing import Final, NoReturn, cast
from urllib.parse import urlsplit

import httpx

from github_steward.adapters.github.public_rest import (
    API_ORIGIN,
    REQUEST_LIMITS,
    REQUEST_TIMEOUT,
    parse_strict_json,
)
from github_steward.domain.acquisition import (
    API_VERSION,
    MAX_PAGES,
    AcquisitionError,
    AcquisitionOutcome,
    RepositoryTarget,
)
from github_steward.ports.github import (
    EvidenceFacet,
    RecordedFacet,
    RecordedGitHubResponse,
)
from github_steward.ports.secrets import OpaqueBearerToken

MAX_RESPONSE_BYTES: Final = 8 * 1024 * 1024
MAX_LINK_HEADER_BYTES: Final = 16 * 1024
_AUTHENTICATED_ENDPOINT_EXTENSION: Final = (
    "github_steward.authenticated_evidence_endpoint"
)
_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")
_APPROVED_HEADERS: Final = {
    "accept": "application/vnd.github+json",
    "x-github-api-version": API_VERSION,
    "user-agent": "github-steward",
}


class _EndpointKind(StrEnum):
    PULL_REQUEST = "pull_request"
    PULL_FILES = "pull_files"
    PULL_COMMITS = "pull_commits"
    PULL_REVIEWS = "pull_reviews"
    REQUESTED_REVIEWERS = "requested_reviewers"
    CHECK_SUITE_COUNT = "check_suite_count"
    CHECK_RUNS = "check_runs"
    COMMIT_STATUSES = "commit_statuses"


@dataclass(frozen=True, slots=True)
class _Endpoint:
    kind: _EndpointKind
    owner: str
    repository: str
    path: str
    invariant_query: tuple[tuple[str, str], ...]
    paginatable: bool
    page: int = 1
    page_explicit: bool = False

    @property
    def query(self) -> tuple[tuple[str, str], ...]:
        if not self.page_explicit:
            return self.invariant_query
        return (*self.invariant_query, ("page", str(self.page)))

    @property
    def raw_target(self) -> str:
        query = "&".join(f"{key}={value}" for key, value in self.query)
        return self.path if query == "" else f"{self.path}?{query}"

    @property
    def absolute_url(self) -> str:
        return f"{API_ORIGIN}{self.raw_target}"

    def explicit_page(self, page: int) -> _Endpoint:
        return replace(self, page=page, page_explicit=True)


@dataclass(frozen=True, slots=True)
class _RequestBinding:
    endpoint: _Endpoint
    authorization_sha256: bytes


@dataclass(frozen=True, slots=True)
class _Page:
    recorded: RecordedGitHubResponse
    next_endpoint: _Endpoint | None


def _reject(message: str) -> NoReturn:
    raise AcquisitionError(AcquisitionOutcome.MALFORMED_RESPONSE, message)


def _authorization_header(provider: OpaqueBearerToken) -> str:
    """Extract once inside authenticated HTTP code and validate header safety."""

    value = provider._authorization_header_value()
    secret = value.removeprefix("Bearer ")
    if secret == "" or any(
        ord(character) < 0x21 or ord(character) > 0x7E for character in secret
    ):
        raise AcquisitionError(
            AcquisitionOutcome.FORBIDDEN,
            "authenticated GitHub credential was invalid",
        )
    return value


def _validate_final_request(request: httpx.Request) -> None:
    """Revalidate the exact credential-bound GET immediately before delegation."""

    binding = request.extensions.get(_AUTHENTICATED_ENDPOINT_EXTENSION)
    if request.method != "GET" or not isinstance(binding, _RequestBinding):
        _reject("authenticated transport rejected an unbound or non-GET request")
    endpoint = binding.endpoint
    try:
        authority = request.url.netloc.decode("ascii")
    except UnicodeDecodeError:  # pragma: no cover - HTTPX normalizes authorities
        _reject("authenticated request authority was not ASCII")
    if any(
        (
            request.url.scheme != "https",
            authority != "api.github.com",
            request.url.host != "api.github.com",
            request.url.port is not None,
            bool(request.url.userinfo),
            request.url.fragment != "",
            request.url.raw_path.decode("ascii", errors="ignore")
            != endpoint.raw_target,
            str(request.url) != endpoint.absolute_url,
        )
    ):
        _reject("authenticated transport rejected endpoint identity substitution")
    if request.read() != b"":
        _reject("authenticated transport rejected a request body")

    header_items = [
        (name.lower(), value) for name, value in request.headers.multi_items()
    ]
    names = [name for name, _ in header_items]
    if len(names) != len(set(names)):
        _reject("authenticated transport rejected duplicate request headers")
    headers = dict(header_items)
    expected_names = {"host", "authorization", *_APPROVED_HEADERS}
    if set(headers) != expected_names:
        _reject("authenticated transport rejected unexpected request headers")
    if headers["host"] != "api.github.com" or any(
        headers[name] != value for name, value in _APPROVED_HEADERS.items()
    ):
        _reject("authenticated transport rejected altered request headers")
    authorization = headers["authorization"]
    if not authorization.startswith("Bearer "):
        _reject("authenticated transport rejected an invalid credential header")
    actual_digest = hashlib.sha256(authorization.encode("ascii")).digest()
    if not hmac.compare_digest(actual_digest, binding.authorization_sha256):
        _reject("authenticated transport rejected credential substitution")


class _AuthenticatedPolicyTransport(httpx.BaseTransport):
    """Keep the bearer inside an exact request and reject final-request drift."""

    def __init__(self, transport: httpx.BaseTransport) -> None:
        self._transport = transport

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        _validate_final_request(request)
        return self._transport.handle_request(request)

    def close(self) -> None:
        self._transport.close()


def _parse_link_target(target: str, origin: _Endpoint) -> _Endpoint:
    try:
        target.encode("ascii")
        parsed = urlsplit(target)
        port = parsed.port
    except (UnicodeEncodeError, ValueError):
        _reject("pagination target was not a canonical ASCII URL")
    if any(
        (
            parsed.scheme != "https",
            parsed.netloc != "api.github.com",
            parsed.hostname != "api.github.com",
            port is not None,
            parsed.username is not None,
            parsed.password is not None,
            parsed.fragment != "",
            parsed.path != origin.path,
            "%" in target,
            "\\" in target,
        )
    ):
        _reject("pagination target changed immutable endpoint identity")
    components = parsed.query.split("&") if parsed.query else []
    if len(components) != len(origin.invariant_query) + 1:
        _reject("pagination query did not preserve endpoint invariants")
    expected_prefix = [f"{key}={value}" for key, value in origin.invariant_query]
    if components[: len(expected_prefix)] != expected_prefix:
        _reject("pagination query changed endpoint invariants")
    page_component = components[-1]
    if not page_component.startswith("page="):
        _reject("pagination target omitted the page identity")
    page_text = page_component.removeprefix("page=")
    if re.fullmatch(r"[1-9][0-9]*", page_text) is None or int(page_text) > MAX_PAGES:
        _reject("pagination page was outside the accepted bound")
    candidate = origin.explicit_page(int(page_text))
    if target != candidate.absolute_url:
        _reject("pagination target was not byte-for-byte canonical")
    return candidate


def _next_endpoint(value: str | None, origin: _Endpoint) -> _Endpoint | None:
    if value is None:
        return None
    if not origin.paginatable:
        _reject("non-paginatable evidence endpoint returned a Link header")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        _reject("pagination Link header was not ASCII")
    if len(encoded) > MAX_LINK_HEADER_BYTES:
        _reject("pagination Link header exceeded its bound")

    matches: list[_Endpoint] = []
    forward_reference = False
    for part in value.split(","):
        sections = [section.strip() for section in part.split(";")]
        if (
            len(sections) != 2
            or not sections[0].startswith("<")
            or not sections[0].endswith(">")
        ):
            _reject("pagination Link header was malformed")
        relation = re.fullmatch(r'rel="([a-z]+(?: [a-z]+)*)"', sections[1])
        if relation is None:
            _reject("pagination relation was malformed")
        relations = tuple(relation.group(1).split(" "))
        if len(relations) != len(set(relations)):
            _reject("pagination relation was duplicated")
        endpoint = _parse_link_target(sections[0][1:-1], origin)
        if endpoint.page > origin.page:
            forward_reference = True
        if "next" in relations:
            if relations != ("next",):
                _reject("pagination next relation was ambiguous")
            if origin.page >= MAX_PAGES or endpoint.page != origin.page + 1:
                _reject("pagination next page was not the exact successor")
            matches.append(endpoint)
    if len(matches) > 1:
        _reject("pagination response contained multiple next links")
    if not matches and forward_reference:
        _reject("pagination response omitted the required next successor")
    return matches[0] if matches else None


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        _reject(f"{label} was not a JSON object")
    return cast(Mapping[str, object], value)


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        _reject(f"{label} was not a JSON array")
    return cast(list[object], value)


def _positive(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        _reject(f"{label} was not a positive integer")
    return value


def _nonnegative(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _reject(f"{label} was not a nonnegative integer")
    return value


class AuthenticatedGitHubEvidenceAdapter:
    """Supply all GS-I4 evidence facets using one repository-bound bearer."""

    __slots__ = (
        "_authorization",
        "_client",
        "_maximum_attempts",
        "_maximum_response_bytes",
        "_owner",
        "_repository",
        "_repository_id",
    )

    def __init__(
        self,
        *,
        authorization: OpaqueBearerToken,
        repository_id: int,
        owner: str,
        repository: str,
        transport: httpx.BaseTransport | None = None,
        maximum_attempts: int = 3,
        maximum_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        if (
            isinstance(repository_id, bool)
            or not isinstance(repository_id, int)
            or repository_id < 1
        ):
            raise ValueError("repository_id must be a positive integer")
        if not isinstance(authorization, OpaqueBearerToken):
            raise ValueError("authorization must be an opaque installation token")
        RepositoryTarget(owner, repository, 1)
        if (
            isinstance(maximum_attempts, bool)
            or not isinstance(maximum_attempts, int)
            or maximum_attempts < 1
            or isinstance(maximum_response_bytes, bool)
            or not isinstance(maximum_response_bytes, int)
            or maximum_response_bytes < 1
        ):
            raise ValueError("authenticated adapter bounds must be positive integers")
        underlying = transport or httpx.HTTPTransport(
            trust_env=False,
            proxy=None,
            limits=REQUEST_LIMITS,
            retries=0,
        )
        self._client = httpx.Client(
            transport=_AuthenticatedPolicyTransport(underlying),
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
        self._authorization = authorization
        self._repository_id = repository_id
        self._owner = owner
        self._repository = repository
        self._maximum_attempts = maximum_attempts
        self._maximum_response_bytes = maximum_response_bytes

    def __repr__(self) -> str:
        return (
            "AuthenticatedGitHubEvidenceAdapter("
            f"repository_id={self._repository_id}, authorization=<redacted>)"
        )

    def __enter__(self) -> AuthenticatedGitHubEvidenceAdapter:
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

    def read_anchor(self, target: RepositoryTarget) -> RecordedGitHubResponse:
        self._require_target(target)
        endpoint = self._pull_endpoint(target, _EndpointKind.PULL_REQUEST, "")
        page = self._request(endpoint)
        self._validate_anchor(page.recorded.value, target)
        return page.recorded

    def read_facet(
        self,
        target: RepositoryTarget,
        *,
        head_sha: str,
        facet: EvidenceFacet,
    ) -> RecordedFacet:
        self._require_target(target)
        if not isinstance(facet, EvidenceFacet):
            raise AcquisitionError(
                AcquisitionOutcome.MALFORMED_RESPONSE,
                "evidence facet was not enumerated",
            )
        if not isinstance(head_sha, str) or _SHA.fullmatch(head_sha) is None:
            raise AcquisitionError(
                AcquisitionOutcome.MALFORMED_RESPONSE,
                "evidence head SHA was not canonical",
            )
        if facet is EvidenceFacet.CHECK_SUITE_COUNT:
            return self._read_check_suite_count(target, head_sha)
        if facet is EvidenceFacet.CHECK_RUNS:
            return self._read_check_runs(target, head_sha)
        if facet is EvidenceFacet.REQUESTED_REVIEWERS:
            return self._read_requested_reviewers(target)
        endpoint = self._list_endpoint(target, head_sha, facet)
        return self._read_list_facet(endpoint, facet.value)

    def _require_target(self, target: RepositoryTarget) -> None:
        if not isinstance(target, RepositoryTarget) or (
            target.owner != self._owner or target.repository != self._repository
        ):
            raise AcquisitionError(
                AcquisitionOutcome.MALFORMED_RESPONSE,
                "requested route did not match the authorized repository route",
            )

    def _validate_anchor(self, value: object, target: RepositoryTarget) -> None:
        body = _mapping(value, "pull-request anchor")
        base = _mapping(body.get("base"), "pull-request base")
        repository = _mapping(base.get("repo"), "pull-request base repository")
        observed_id = _positive(repository.get("id"), "observed repository id")
        observed_route = repository.get("full_name")
        observed_number = _positive(body.get("number"), "observed pull number")
        if observed_id != self._repository_id:
            _reject("observed repository id did not match token authorization")
        if (
            not isinstance(observed_route, str)
            or observed_route.casefold()
            != f"{self._owner}/{self._repository}".casefold()
            or observed_number != target.pull_number
        ):
            _reject("observed pull-request route did not match authorization")

    def _pull_endpoint(
        self,
        target: RepositoryTarget,
        kind: _EndpointKind,
        suffix: str,
        *,
        paginatable: bool = False,
    ) -> _Endpoint:
        path = (
            f"/repos/{self._owner}/{self._repository}/pulls/"
            f"{target.pull_number}{suffix}"
        )
        query = (("per_page", "100"),) if paginatable else ()
        return _Endpoint(
            kind,
            self._owner,
            self._repository,
            path,
            query,
            paginatable,
        )

    def _head_endpoint(
        self,
        kind: _EndpointKind,
        head_sha: str,
        suffix: str,
        *,
        query: tuple[tuple[str, str], ...] = (),
        paginatable: bool = False,
    ) -> _Endpoint:
        return _Endpoint(
            kind,
            self._owner,
            self._repository,
            f"/repos/{self._owner}/{self._repository}/commits/{head_sha}{suffix}",
            query,
            paginatable,
        )

    def _list_endpoint(
        self,
        target: RepositoryTarget,
        head_sha: str,
        facet: EvidenceFacet,
    ) -> _Endpoint:
        pull = {
            EvidenceFacet.FILES: (_EndpointKind.PULL_FILES, "/files"),
            EvidenceFacet.COMMITS: (_EndpointKind.PULL_COMMITS, "/commits"),
            EvidenceFacet.REVIEWS: (_EndpointKind.PULL_REVIEWS, "/reviews"),
        }
        if facet in pull:
            kind, suffix = pull[facet]
            return self._pull_endpoint(
                target,
                kind,
                suffix,
                paginatable=True,
            )
        if facet is EvidenceFacet.COMMIT_STATUSES:
            return self._head_endpoint(
                _EndpointKind.COMMIT_STATUSES,
                head_sha,
                "/statuses",
                query=(("per_page", "100"),),
                paginatable=True,
            )
        raise RuntimeError("internal evidence endpoint inventory was incomplete")

    def _read_list_facet(self, endpoint: _Endpoint, label: str) -> RecordedFacet:
        values: list[object] = []
        raw: list[RecordedGitHubResponse] = []
        current: _Endpoint | None = endpoint
        while current is not None:
            page = self._request(current)
            values.extend(_list(page.recorded.value, label))
            raw.append(page.recorded)
            current = page.next_endpoint
        return RecordedFacet(values, tuple(raw), None, True)

    def _read_requested_reviewers(self, target: RepositoryTarget) -> RecordedFacet:
        endpoint = self._pull_endpoint(
            target,
            _EndpointKind.REQUESTED_REVIEWERS,
            "/requested_reviewers",
            paginatable=True,
        )
        users: list[object] = []
        teams: list[object] = []
        raw: list[RecordedGitHubResponse] = []
        current: _Endpoint | None = endpoint
        while current is not None:
            page = self._request(current)
            body = _mapping(page.recorded.value, "requested-reviewers response")
            page_users = _list(body.get("users"), "requested users")
            page_teams = _list(body.get("teams"), "requested teams")
            if len(page_users) + len(page_teams) > 100:
                _reject("requested-reviewers page exceeded per_page=100")
            users.extend(page_users)
            teams.extend(page_teams)
            raw.append(page.recorded)
            current = page.next_endpoint
        return RecordedFacet({"users": users, "teams": teams}, tuple(raw), None, True)

    def _read_check_suite_count(
        self,
        target: RepositoryTarget,
        head_sha: str,
    ) -> RecordedFacet:
        del target
        endpoint = self._head_endpoint(
            _EndpointKind.CHECK_SUITE_COUNT,
            head_sha,
            "/check-suites",
        )
        page = self._request(endpoint)
        body = _mapping(page.recorded.value, "check-suite response")
        total = _nonnegative(body.get("total_count"), "check-suite total_count")
        _list(body.get("check_suites"), "check_suites")
        return RecordedFacet(body, (page.recorded,), total, True)

    def _read_check_runs(
        self,
        target: RepositoryTarget,
        head_sha: str,
    ) -> RecordedFacet:
        del target
        endpoint = self._head_endpoint(
            _EndpointKind.CHECK_RUNS,
            head_sha,
            "/check-runs",
            query=(("filter", "latest"), ("per_page", "100")),
            paginatable=True,
        )
        values: list[object] = []
        raw: list[RecordedGitHubResponse] = []
        expected_total: int | None = None
        current: _Endpoint | None = endpoint
        while current is not None:
            page = self._request(current)
            body = _mapping(page.recorded.value, "check-runs response")
            page_total = _nonnegative(body.get("total_count"), "check-run total_count")
            if expected_total is not None and expected_total != page_total:
                _reject("check-run total_count changed between pages")
            expected_total = page_total
            values.extend(_list(body.get("check_runs"), "check_runs"))
            raw.append(page.recorded)
            current = page.next_endpoint
        return RecordedFacet(values, tuple(raw), expected_total or 0, True)

    def _request(self, endpoint: _Endpoint) -> _Page:
        last_timeout: httpx.TimeoutException | None = None
        for attempt in range(self._maximum_attempts):  # pragma: no branch
            try:
                request = self._request_value(endpoint)
                response = self._client.send(
                    request,
                    stream=True,
                    auth=None,
                    follow_redirects=False,
                )
                try:
                    raw = self._bounded_body(response.iter_bytes())
                    outcome = self._classification(response)
                    if (
                        response.status_code >= 500
                        and attempt + 1 < self._maximum_attempts
                    ):
                        continue
                    if outcome is not AcquisitionOutcome.ACQUIRED:
                        raise AcquisitionError(
                            outcome,
                            f"GitHub returned HTTP {response.status_code}",
                        )
                    value = parse_strict_json(raw)
                    next_endpoint = _next_endpoint(
                        response.headers.get("Link"), endpoint
                    )
                    return _Page(
                        RecordedGitHubResponse(
                            value,
                            hashlib.sha256(raw).hexdigest(),
                            len(raw),
                        ),
                        next_endpoint,
                    )
                finally:
                    response.close()
            except httpx.TimeoutException as exc:
                last_timeout = exc
                if attempt + 1 == self._maximum_attempts:
                    break
            except httpx.TransportError:
                if attempt + 1 == self._maximum_attempts:
                    raise AcquisitionError(
                        AcquisitionOutcome.TRANSPORT_ERROR,
                        "authenticated GitHub transport failed",
                    ) from None
        raise AcquisitionError(
            AcquisitionOutcome.TIMEOUT,
            "authenticated GitHub request timed out",
        ) from last_timeout

    def _request_value(self, endpoint: _Endpoint) -> httpx.Request:
        authorization = _authorization_header(self._authorization)
        request = httpx.Request(
            "GET",
            endpoint.absolute_url,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "github-steward",
                "Authorization": authorization,
            },
        )
        request.extensions["timeout"] = REQUEST_TIMEOUT.as_dict()
        request.extensions[_AUTHENTICATED_ENDPOINT_EXTENSION] = _RequestBinding(
            endpoint,
            hashlib.sha256(authorization.encode("ascii")).digest(),
        )
        return request

    def _bounded_body(self, chunks: Iterable[bytes]) -> bytes:
        body = bytearray()
        for chunk in chunks:
            body.extend(chunk)
            if len(body) > self._maximum_response_bytes:
                raise AcquisitionError(
                    AcquisitionOutcome.INCOMPLETE_ACQUISITION,
                    "authenticated GitHub response exceeded its byte bound",
                )
        return bytes(body)

    @staticmethod
    def _classification(response: httpx.Response) -> AcquisitionOutcome:
        status = response.status_code
        if status == 403 and (
            response.headers.get("X-RateLimit-Remaining") == "0"
            or response.headers.get("Retry-After") is not None
        ):
            return AcquisitionOutcome.RATE_LIMITED
        if status == 429:
            return AcquisitionOutcome.RATE_LIMITED
        if status in {401, 403}:
            return AcquisitionOutcome.FORBIDDEN
        if status == 404:
            return AcquisitionOutcome.NOT_FOUND
        if status == 422:
            return AcquisitionOutcome.UNPROCESSABLE
        if status >= 500:
            return AcquisitionOutcome.UPSTREAM_SERVER_ERROR
        if status == 200:
            return AcquisitionOutcome.ACQUIRED
        if status == 206:
            return AcquisitionOutcome.INCOMPLETE_ACQUISITION
        return AcquisitionOutcome.MALFORMED_RESPONSE
