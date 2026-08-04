"""Bounded anonymous GET-only adapter for api.github.com."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from types import TracebackType
from typing import NoReturn
from urllib.parse import urlsplit

import httpx

from github_steward.domain.acquisition import (
    API_VERSION,
    MAX_PAGES,
    AcquisitionError,
    AcquisitionOutcome,
)
from github_steward.domain.canonical import MAX_SAFE_INTEGER, MIN_SAFE_INTEGER
from github_steward.ports.github import GitHubResponse, RequestAudit

API_ORIGIN = "https://api.github.com"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
REQUEST_TIMEOUT = httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=5.0)
REQUEST_LIMITS = httpx.Limits(
    max_connections=4,
    max_keepalive_connections=2,
    keepalive_expiry=5.0,
)
_APPROVED_HEADERS = {
    "accept": "application/vnd.github+json",
    "x-github-api-version": API_VERSION,
    "user-agent": "github-steward",
}
_CREDENTIAL_HEADERS = {"authorization", "cookie", "proxy-authorization"}
_NAME = re.compile(r"[A-Za-z0-9_.-]+\Z")
_POSITIVE_DECIMAL = re.compile(r"[1-9][0-9]*\Z")
_RELATION = re.compile(r'rel="([a-z]+(?: [a-z]+)*)"\Z')
_ENDPOINT_EXTENSION = "github_steward.canonical_endpoint"


class _EndpointKind(StrEnum):
    PULL_REQUEST = "pull_request"
    PULL_FILES = "pull_files"
    PULL_COMMITS = "pull_commits"
    PULL_REVIEWS = "pull_reviews"
    CHECK_SUITES = "check_suites"
    CHECK_RUNS = "check_runs"


@dataclass(frozen=True, slots=True)
class _CanonicalEndpoint:
    """Exact serialized target and semantic identity for one allowed endpoint."""

    scheme: str
    hostname: str
    port: int | None
    kind: _EndpointKind
    owner: str
    repository: str
    pull_number: int | None
    head_sha: str | None
    canonical_path: str
    paginatable: bool
    page: int
    page_explicit: bool
    per_page: int | None
    invariant_query: tuple[tuple[str, str], ...]
    allowed_query_keys: tuple[str, ...]
    query: tuple[tuple[str, str], ...]
    raw_target: bytes

    @property
    def absolute_url(self) -> str:
        return API_ORIGIN + self.raw_target.decode("ascii")

    @property
    def pagination_identity(self) -> tuple[object, ...]:
        return (
            self.scheme,
            self.hostname,
            self.port,
            self.kind,
            self.owner,
            self.repository,
            self.pull_number,
            self.head_sha,
            self.canonical_path,
            self.paginatable,
            self.per_page,
            self.invariant_query,
            self.allowed_query_keys,
        )

    @property
    def semantic_identity(self) -> tuple[tuple[str, str], ...]:
        identity = [
            ("owner", self.owner),
            ("repository", self.repository),
            ("endpoint_kind", self.kind.value),
        ]
        if self.pull_number is not None:
            identity.append(("pull_number", str(self.pull_number)))
        if self.head_sha is not None:
            identity.append(("head_sha", self.head_sha))
        return tuple(identity)


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


def _reject_number(_: str) -> object:
    raise ValueError("non-integer JSON number")


def _parse_integer(value: str) -> int:
    parsed = int(value)
    if not MIN_SAFE_INTEGER <= parsed <= MAX_SAFE_INTEGER:
        raise ValueError("JSON integer outside exact canonical range")
    return parsed


def parse_strict_json(raw: bytes) -> object:
    """Decode authoritative bytes with nested duplicate-key rejection."""

    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_int=_parse_integer,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AcquisitionError(
            AcquisitionOutcome.MALFORMED_RESPONSE,
            "response was not strict canonical-compatible JSON",
        ) from exc


def _name(value: str) -> bool:
    return _NAME.fullmatch(value) is not None


def _positive_decimal(value: str) -> bool:
    return _POSITIVE_DECIMAL.fullmatch(value) is not None


def _reject_policy(message: str) -> NoReturn:
    raise AcquisitionError(AcquisitionOutcome.MALFORMED_RESPONSE, message)


def _query_pairs(raw_query: bytes) -> tuple[tuple[str, str], ...]:
    if raw_query == b"":
        return ()
    if b"%" in raw_query or b";" in raw_query:
        _reject_policy("request query was not canonical")
    pairs: list[tuple[str, str]] = []
    for component in raw_query.split(b"&"):
        if component.count(b"=") != 1:
            _reject_policy("request query was malformed")
        key_bytes, value_bytes = component.split(b"=", 1)
        key = key_bytes.decode("ascii")
        value = value_bytes.decode("ascii")
        if key == "" or value == "" or any(existing == key for existing, _ in pairs):
            _reject_policy("request query contained an empty or duplicate key")
        pairs.append((key, value))
    return tuple(pairs)


def _positive_integer(value: str, *, maximum: int | None = None) -> int:
    if not _positive_decimal(value):
        _reject_policy("request identity contained a noncanonical integer")
    try:
        parsed = int(value)
    except ValueError as exc:
        raise AcquisitionError(
            AcquisitionOutcome.MALFORMED_RESPONSE,
            "request identity integer was too large",
        ) from exc
    if maximum is not None and parsed > maximum:
        _reject_policy("request page exceeded the accepted bound")
    return parsed


def _paged_query(
    pairs: tuple[tuple[str, str], ...],
    invariants: tuple[tuple[str, str], ...],
) -> tuple[int, bool, tuple[str, ...]]:
    if pairs[: len(invariants)] != invariants or len(pairs) not in {
        len(invariants),
        len(invariants) + 1,
    }:
        _reject_policy("request query did not match endpoint invariants")
    page = 1
    explicit = False
    if len(pairs) == len(invariants) + 1:
        key, value = pairs[-1]
        if key != "page":
            _reject_policy("request query contained an unknown key")
        page = _positive_integer(value, maximum=MAX_PAGES)
        explicit = True
    return page, explicit, (*tuple(key for key, _ in invariants), "page")


def _parse_raw_endpoint(
    raw_target: bytes,
    *,
    scheme: str,
    authority: str,
    hostname: str | None,
    port: int | None,
    has_userinfo: bool,
    fragment: str,
) -> _CanonicalEndpoint:
    """Parse one raw HTTPX request target without decoding aliases."""

    if scheme != "https" or hostname != "api.github.com":
        _reject_policy("request authority was not HTTPS api.github.com")
    if authority != "api.github.com":
        _reject_policy("request authority was not canonical")
    if port is not None or has_userinfo or fragment != "":
        _reject_policy("request authority contained userinfo, port, or fragment")
    try:
        raw_target.decode("ascii")
    except UnicodeDecodeError as exc:
        raise AcquisitionError(
            AcquisitionOutcome.MALFORMED_RESPONSE,
            "request target was not ASCII",
        ) from exc
    if raw_target.count(b"?") > 1:
        _reject_policy("request target contained ambiguous query separators")
    raw_path, separator, raw_query = raw_target.partition(b"?")
    if (
        not raw_path.startswith(b"/")
        or b"%" in raw_path
        or b"\\" in raw_path
        or b"//" in raw_path
        or b"#" in raw_path
    ):
        _reject_policy("request path was not canonical")
    path = raw_path.decode("ascii")
    parts = path.split("/")
    if len(parts) not in {6, 7} or parts[0] != "" or parts[1] != "repos":
        _reject_policy("request path was not an enumerated endpoint")
    owner, repository = parts[2], parts[3]
    if (
        not _name(owner)
        or not _name(repository)
        or owner in {".", ".."}
        or repository in {".", ".."}
    ):
        _reject_policy("request repository identity was not canonical")

    pairs = _query_pairs(raw_query)
    kind: _EndpointKind
    pull_number: int | None = None
    head_sha: str | None = None
    paginatable = False
    page = 1
    page_explicit = False
    per_page: int | None = None
    invariants: tuple[tuple[str, str], ...] = ()
    allowed_query_keys: tuple[str, ...] = ()
    if parts[4] == "pulls":
        pull_number = _positive_integer(parts[5])
        if len(parts) == 6:
            kind = _EndpointKind.PULL_REQUEST
            if pairs:
                _reject_policy("pull-request endpoint did not allow a query")
        else:
            collection_kinds = {
                "files": _EndpointKind.PULL_FILES,
                "commits": _EndpointKind.PULL_COMMITS,
                "reviews": _EndpointKind.PULL_REVIEWS,
            }
            try:
                kind = collection_kinds[parts[6]]
            except KeyError as exc:
                raise AcquisitionError(
                    AcquisitionOutcome.MALFORMED_RESPONSE,
                    "request pull collection was not enumerated",
                ) from exc
            paginatable = True
            per_page = 100
            invariants = (("per_page", "100"),)
            page, page_explicit, allowed_query_keys = _paged_query(pairs, invariants)
    elif parts[4] == "commits" and len(parts) == 7:
        head_sha = parts[5]
        if len(head_sha) != 40 or any(
            character not in "0123456789abcdef" for character in head_sha
        ):
            _reject_policy("request head SHA was not canonical")
        if parts[6] == "check-suites":
            kind = _EndpointKind.CHECK_SUITES
            if pairs:
                _reject_policy("check-suite endpoint did not allow a query")
        elif parts[6] == "check-runs":
            kind = _EndpointKind.CHECK_RUNS
            paginatable = True
            per_page = 100
            invariants = (("filter", "latest"), ("per_page", "100"))
            page, page_explicit, allowed_query_keys = _paged_query(pairs, invariants)
        else:
            _reject_policy("request check endpoint was not enumerated")
    else:
        _reject_policy("request path was not an enumerated endpoint")

    pull_suffixes = {
        _EndpointKind.PULL_REQUEST: "",
        _EndpointKind.PULL_FILES: "/files",
        _EndpointKind.PULL_COMMITS: "/commits",
        _EndpointKind.PULL_REVIEWS: "/reviews",
    }
    check_suffixes = {
        _EndpointKind.CHECK_SUITES: "/check-suites",
        _EndpointKind.CHECK_RUNS: "/check-runs",
    }
    if pull_number is not None:
        canonical_path = (
            f"/repos/{owner}/{repository}/pulls/{pull_number}{pull_suffixes[kind]}"
        )
    else:
        canonical_path = (
            f"/repos/{owner}/{repository}/commits/{head_sha}{check_suffixes[kind]}"
        )
    canonical_pairs = invariants + ((("page", str(page)),) if page_explicit else ())
    canonical_query = "&".join(f"{key}={value}" for key, value in canonical_pairs)
    expected_target = canonical_path.encode("ascii") + (
        b"?" + canonical_query.encode("ascii") if canonical_query else b""
    )
    if raw_target != expected_target or (separator and not canonical_query):
        _reject_policy("request target was not byte-for-byte canonical")
    return _CanonicalEndpoint(
        scheme="https",
        hostname="api.github.com",
        port=None,
        kind=kind,
        owner=owner,
        repository=repository,
        pull_number=pull_number,
        head_sha=head_sha,
        canonical_path=canonical_path,
        paginatable=paginatable,
        page=page,
        page_explicit=page_explicit,
        per_page=per_page,
        invariant_query=invariants,
        allowed_query_keys=allowed_query_keys,
        query=canonical_pairs,
        raw_target=expected_target,
    )


def _parse_endpoint(path_or_url: str) -> _CanonicalEndpoint:
    """Parse an original request or Link target before HTTPX can normalize it."""

    try:
        encoded = path_or_url.encode("ascii")
        parsed = urlsplit(path_or_url)
        parsed_port = parsed.port
    except (UnicodeEncodeError, ValueError) as exc:
        raise AcquisitionError(
            AcquisitionOutcome.MALFORMED_RESPONSE,
            "request target was not a canonical ASCII URL",
        ) from exc
    if path_or_url.startswith("/"):
        endpoint = _parse_raw_endpoint(
            encoded,
            scheme=parsed.scheme or "https",
            authority=parsed.netloc or "api.github.com",
            hostname=parsed.hostname or "api.github.com",
            port=parsed_port,
            has_userinfo=parsed.username is not None or parsed.password is not None,
            fragment=parsed.fragment,
        )
        return endpoint

    target_text = parsed.path
    if parsed.query or "?" in path_or_url.partition("#")[0]:
        target_text += f"?{parsed.query}"
    endpoint = _parse_raw_endpoint(
        target_text.encode("ascii"),
        scheme=parsed.scheme,
        authority=parsed.netloc,
        hostname=parsed.hostname,
        port=parsed_port,
        has_userinfo=parsed.username is not None or parsed.password is not None,
        fragment=parsed.fragment,
    )
    if path_or_url != endpoint.absolute_url:
        _reject_policy("absolute request URL was not canonical")
    return endpoint


def _parse_request_endpoint(request: httpx.Request) -> _CanonicalEndpoint:
    try:
        authority = request.url.netloc.decode("ascii")
    except UnicodeDecodeError as exc:  # pragma: no cover - HTTPX normalizes hosts
        raise AcquisitionError(
            AcquisitionOutcome.MALFORMED_RESPONSE,
            "request authority was not ASCII",
        ) from exc
    return _parse_raw_endpoint(
        request.url.raw_path,
        scheme=request.url.scheme,
        authority=authority,
        hostname=request.url.host,
        port=request.url.port,
        has_userinfo=bool(request.url.userinfo),
        fragment=request.url.fragment,
    )


def _next_link(
    value: str | None, origin: _CanonicalEndpoint
) -> _CanonicalEndpoint | None:
    if value is None:
        return None
    if not origin.paginatable:
        _reject_policy("non-paginatable endpoint returned a Link header")
    matches: list[_CanonicalEndpoint] = []
    for part in value.split(","):
        sections = [item.strip() for item in part.split(";")]
        if (
            len(sections) != 2
            or not sections[0].startswith("<")
            or not sections[0].endswith(">")
        ):
            _reject_policy("malformed pagination Link header")
        target = sections[0][1:-1]
        relation_match = _RELATION.fullmatch(sections[1])
        if relation_match is None:
            _reject_policy("pagination relation was malformed")
        relations = tuple(relation_match.group(1).split(" "))
        if len(set(relations)) != len(relations):
            _reject_policy("pagination relation was duplicated")
        if target.startswith("/"):
            _reject_policy("pagination link was not an absolute URL")
        endpoint = _parse_endpoint(target)
        if endpoint.pagination_identity != origin.pagination_identity:
            _reject_policy("pagination link changed immutable endpoint identity")
        if "next" in relations:
            if relations != ("next",):
                _reject_policy("pagination next relation was ambiguous")
            if (
                not endpoint.page_explicit
                or origin.page >= MAX_PAGES
                or endpoint.page != origin.page + 1
            ):
                _reject_policy("pagination next page was not the exact successor")
            matches.append(endpoint)
    if len(matches) > 1:
        _reject_policy("multiple next pagination links")
    return matches[0] if matches else None


def _validate_final_request(request: httpx.Request) -> None:
    """Fail closed over the request immediately before transport delegation."""

    if request.method != "GET":
        _reject_policy("transport policy permits only GET")
    intended = request.extensions.get(_ENDPOINT_EXTENSION)
    if not isinstance(intended, _CanonicalEndpoint):
        _reject_policy("transport policy rejected an unbound request")
    actual = _parse_request_endpoint(request)
    if actual != intended or request.url.raw_path != intended.raw_target:
        _reject_policy("transport policy rejected endpoint identity substitution")
    if request.read() != b"":
        _reject_policy("transport policy rejected a request body")
    headers = {name.lower(): value for name, value in request.headers.items()}
    if any(name in headers for name in _CREDENTIAL_HEADERS):
        _reject_policy("transport policy rejected credential-bearing headers")
    expected = {"host": "api.github.com", **_APPROVED_HEADERS}
    if headers != expected:
        _reject_policy("transport policy rejected unexpected request headers")


class PolicyEnforcingTransport(httpx.BaseTransport):
    """Validate the final request before a real or fake transport can receive it."""

    def __init__(self, transport: httpx.BaseTransport) -> None:
        self._transport = transport

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        _validate_final_request(request)
        return self._transport.handle_request(request)

    def close(self) -> None:
        self._transport.close()


class PublicGitHubRestClient:
    """Project-owned synchronous client with a GET-only public surface."""

    def __init__(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        maximum_attempts: int = 3,
        maximum_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        if maximum_attempts < 1 or maximum_response_bytes < 1:
            raise ValueError("adapter bounds must be positive")
        underlying = transport or httpx.HTTPTransport(
            trust_env=False,
            proxy=None,
            limits=REQUEST_LIMITS,
            retries=0,
        )
        self._client = httpx.Client(
            transport=PolicyEnforcingTransport(underlying),
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
        self._maximum_attempts = maximum_attempts
        self._maximum_response_bytes = maximum_response_bytes
        self._audit: list[RequestAudit] = []

    def __enter__(self) -> PublicGitHubRestClient:
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

    @property
    def audit(self) -> tuple[RequestAudit, ...]:
        return tuple(self._audit)

    def get(self, path_or_url: str) -> GitHubResponse:
        endpoint = self._validated_endpoint(path_or_url)
        last_timeout: httpx.TimeoutException | None = None
        for attempt in range(self._maximum_attempts):  # pragma: no branch
            try:
                request = self._anonymous_request(endpoint)
                response = self._client.send(
                    request,
                    stream=True,
                    auth=None,
                    follow_redirects=False,
                )
                try:
                    raw = self._bounded_body(response.iter_bytes())
                    classification = self._classification(response)
                    if (
                        response.status_code >= 500
                        and attempt + 1 < self._maximum_attempts
                    ):
                        self._record(endpoint, classification, raw, None)
                        continue
                    if classification != AcquisitionOutcome.ACQUIRED.value:
                        self._record(endpoint, classification, raw, None)
                        self._raise_status(response, classification)
                    try:
                        parsed = parse_strict_json(raw)
                        next_endpoint = _next_link(
                            response.headers.get("Link"), endpoint
                        )
                    except AcquisitionError as exc:
                        self._record(endpoint, exc.outcome.value, raw, None)
                        raise
                    self._record(endpoint, classification, raw, next_endpoint)
                    return GitHubResponse(
                        value=parsed,
                        raw_sha256=hashlib.sha256(raw).hexdigest(),
                        next_url=(
                            next_endpoint.absolute_url
                            if next_endpoint is not None
                            else None
                        ),
                        path=endpoint.raw_target.decode("ascii"),
                    )
                finally:
                    response.close()
            except httpx.TimeoutException as exc:
                last_timeout = exc
                self._record(endpoint, AcquisitionOutcome.TIMEOUT.value, None, None)
                if attempt + 1 == self._maximum_attempts:
                    break
            except httpx.TransportError as exc:
                self._record(
                    endpoint,
                    AcquisitionOutcome.TRANSPORT_ERROR.value,
                    None,
                    None,
                )
                if attempt + 1 == self._maximum_attempts:
                    raise AcquisitionError(
                        AcquisitionOutcome.TRANSPORT_ERROR,
                        "GitHub transport failed",
                    ) from exc
        raise AcquisitionError(
            AcquisitionOutcome.TIMEOUT, "GitHub request timed out"
        ) from last_timeout

    @staticmethod
    def _anonymous_request(endpoint: _CanonicalEndpoint) -> httpx.Request:
        request = httpx.Request(
            "GET",
            endpoint.absolute_url,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "github-steward",
            },
        )
        request.extensions["timeout"] = REQUEST_TIMEOUT.as_dict()
        request.extensions[_ENDPOINT_EXTENSION] = endpoint
        return request

    @staticmethod
    def _validated_endpoint(path_or_url: str) -> _CanonicalEndpoint:
        return _parse_endpoint(path_or_url)

    def _bounded_body(self, chunks: Iterable[bytes]) -> bytes:
        body = bytearray()
        for chunk in chunks:
            body.extend(chunk)
            if len(body) > self._maximum_response_bytes:
                raise AcquisitionError(
                    AcquisitionOutcome.INCOMPLETE_ACQUISITION,
                    "GitHub response exceeded the configured size bound",
                )
        return bytes(body)

    def _record(
        self,
        endpoint: _CanonicalEndpoint,
        classification: str,
        raw_response: bytes | None,
        next_endpoint: _CanonicalEndpoint | None,
    ) -> None:
        self._audit.append(
            RequestAudit(
                method="GET",
                host="api.github.com",
                path=endpoint.canonical_path,
                classification=classification,
                scheme="https",
                port_classification="default_https",
                query=endpoint.query,
                application_headers=tuple(sorted(_APPROVED_HEADERS)),
                credentials_absent=True,
                raw_response_sha256=(
                    hashlib.sha256(raw_response).hexdigest()
                    if raw_response is not None
                    else None
                ),
                raw_target=endpoint.raw_target.decode("ascii"),
                endpoint_kind=endpoint.kind.value,
                semantic_identity=endpoint.semantic_identity,
                current_page=endpoint.page,
                next_page=(next_endpoint.page if next_endpoint is not None else None),
            )
        )

    @staticmethod
    def _classification(response: httpx.Response) -> str:
        status = response.status_code
        if status == 403 and (
            response.headers.get("X-RateLimit-Remaining") == "0"
            or response.headers.get("Retry-After") is not None
        ):
            return AcquisitionOutcome.RATE_LIMITED.value
        if status == 429:
            return AcquisitionOutcome.RATE_LIMITED.value
        mapping = {
            403: AcquisitionOutcome.FORBIDDEN,
            404: AcquisitionOutcome.NOT_FOUND,
            422: AcquisitionOutcome.UNPROCESSABLE,
        }
        if status in mapping:
            return mapping[status].value
        if status >= 500:
            return AcquisitionOutcome.UPSTREAM_SERVER_ERROR.value
        if status == 200:
            return AcquisitionOutcome.ACQUIRED.value
        if status == 206:
            return AcquisitionOutcome.INCOMPLETE_ACQUISITION.value
        return AcquisitionOutcome.MALFORMED_RESPONSE.value

    @staticmethod
    def _raise_status(response: httpx.Response, classification: str) -> None:
        outcome = AcquisitionOutcome(classification)
        raise AcquisitionError(outcome, f"GitHub returned HTTP {response.status_code}")
