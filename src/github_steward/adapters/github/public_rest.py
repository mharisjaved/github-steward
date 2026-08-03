"""Bounded anonymous GET-only adapter for api.github.com."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from types import TracebackType
from urllib.parse import parse_qsl, urlsplit

import httpx

from github_steward.domain.acquisition import (
    API_VERSION,
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


def _next_link(value: str | None) -> str | None:
    if value is None:
        return None
    matches: list[str] = []
    for part in value.split(","):
        sections = [item.strip() for item in part.split(";")]
        if (
            len(sections) < 2
            or not sections[0].startswith("<")
            or not sections[0].endswith(">")
        ):
            raise AcquisitionError(
                AcquisitionOutcome.MALFORMED_RESPONSE,
                "malformed pagination Link header",
            )
        target = sections[0][1:-1]
        if not _is_allowed_url(target):
            raise AcquisitionError(
                AcquisitionOutcome.MALFORMED_RESPONSE,
                "pagination link did not match an allowed GitHub endpoint",
            )
        relations = {item for item in sections[1:] if item.startswith("rel=")}
        if 'rel="next"' in relations:
            matches.append(target)
    if len(matches) > 1:
        raise AcquisitionError(
            AcquisitionOutcome.MALFORMED_RESPONSE,
            "multiple next pagination links",
        )
    return matches[0] if matches else None


def _name(value: str) -> bool:
    return _NAME.fullmatch(value) is not None


def _positive_decimal(value: str) -> bool:
    return _POSITIVE_DECIMAL.fullmatch(value) is not None


def _query_pairs(query: str) -> tuple[tuple[str, str], ...] | None:
    if "%" in query or ";" in query:
        return None
    try:
        pairs = tuple(parse_qsl(query, keep_blank_values=True, strict_parsing=True))
    except ValueError:
        return None
    if len({key for key, _ in pairs}) != len(pairs):
        return None
    return pairs


def _allowed_endpoint(path: str, query: str) -> bool:
    if "%" in path or "\\" in path or "//" in path:
        return False
    parts = path.split("/")
    if len(parts) < 6 or parts[0] != "" or parts[1] != "repos":
        return False
    owner, repository = parts[2], parts[3]
    if (
        not _name(owner)
        or not _name(repository)
        or owner in {".", ".."}
        or repository
        in {
            ".",
            "..",
        }
    ):
        return False
    pairs = _query_pairs(query)
    if pairs is None:
        return False
    parameters = dict(pairs)
    if parts[4] == "pulls" and _positive_decimal(parts[5]):
        if len(parts) == 6:
            return not parameters
        if len(parts) == 7 and parts[6] in {"files", "commits", "reviews"}:
            return parameters.get("per_page") == "100" and (
                set(parameters) == {"per_page"}
                or (
                    set(parameters) == {"per_page", "page"}
                    and _positive_decimal(parameters["page"])
                )
            )
        return False
    if (
        parts[4] == "commits"
        and len(parts) == 7
        and len(parts[5]) == 40
        and all(character in "0123456789abcdef" for character in parts[5])
    ):
        if parts[6] == "check-suites":
            return not parameters
        if parts[6] == "check-runs":
            required = {"filter": "latest", "per_page": "100"}
            return all(
                parameters.get(key) == value for key, value in required.items()
            ) and (
                set(parameters) == set(required)
                or (
                    set(parameters) == {*required, "page"}
                    and _positive_decimal(parameters["page"])
                )
            )
    return False


def _is_allowed_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return False
    checks = (
        parsed.scheme == "https",
        parsed.netloc in {"api.github.com", "api.github.com:443"},
        parsed.hostname == "api.github.com",
        port in (None, 443),
        parsed.username is None,
        parsed.password is None,
        not parsed.fragment,
        _allowed_endpoint(parsed.path, parsed.query),
    )
    return all(checks)


def _reject_policy(message: str) -> None:
    raise AcquisitionError(AcquisitionOutcome.MALFORMED_RESPONSE, message)


def _validate_final_request(request: httpx.Request) -> None:
    """Fail closed over the request immediately before transport delegation."""

    if request.method != "GET":
        _reject_policy("transport policy permits only GET")
    url = request.url
    if url.scheme != "https" or url.host != "api.github.com":
        _reject_policy("transport policy permits only HTTPS api.github.com")
    if url.userinfo or url.port not in (None, 443) or url.fragment:
        _reject_policy("transport policy rejected request authority")
    query = url.query.decode("ascii", errors="strict")
    if not _allowed_endpoint(url.path, query):
        _reject_policy("transport policy rejected endpoint or query")
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
        url = self._validated_url(path_or_url)
        last_timeout: httpx.TimeoutException | None = None
        for attempt in range(self._maximum_attempts):  # pragma: no branch
            try:
                request = self._anonymous_request(url)
                response = self._client.send(
                    request,
                    stream=True,
                    auth=None,
                    follow_redirects=False,
                )
                try:
                    raw = self._bounded_body(response.iter_bytes())
                    classification = self._classification(response)
                    self._record(url, classification, raw)
                    if (
                        response.status_code >= 500
                        and attempt + 1 < self._maximum_attempts
                    ):
                        continue
                    self._raise_status(response, classification)
                    parsed = parse_strict_json(raw)
                    next_url = _next_link(response.headers.get("Link"))
                    if next_url is not None:
                        self._validated_url(next_url)
                    return GitHubResponse(
                        value=parsed,
                        raw_sha256=hashlib.sha256(raw).hexdigest(),
                        next_url=next_url,
                        path=urlsplit(url).path
                        + (f"?{urlsplit(url).query}" if urlsplit(url).query else ""),
                    )
                finally:
                    response.close()
            except httpx.TimeoutException as exc:
                last_timeout = exc
                self._record(url, AcquisitionOutcome.TIMEOUT.value, None)
                if attempt + 1 == self._maximum_attempts:
                    break
            except httpx.TransportError as exc:
                self._record(url, AcquisitionOutcome.TRANSPORT_ERROR.value, None)
                if attempt + 1 == self._maximum_attempts:
                    raise AcquisitionError(
                        AcquisitionOutcome.TRANSPORT_ERROR,
                        "GitHub transport failed",
                    ) from exc
        raise AcquisitionError(
            AcquisitionOutcome.TIMEOUT, "GitHub request timed out"
        ) from last_timeout

    @staticmethod
    def _anonymous_request(url: str) -> httpx.Request:
        request = httpx.Request(
            "GET",
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "github-steward",
            },
        )
        request.extensions["timeout"] = REQUEST_TIMEOUT.as_dict()
        return request

    def _validated_url(self, path_or_url: str) -> str:
        url = API_ORIGIN + path_or_url if path_or_url.startswith("/") else path_or_url
        if not _is_allowed_url(url):
            raise AcquisitionError(
                AcquisitionOutcome.MALFORMED_RESPONSE,
                "request target did not match an allowed GitHub endpoint",
            )
        return url

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
        self, url: str, classification: str, raw_response: bytes | None
    ) -> None:
        parsed = urlsplit(url)
        pairs = _query_pairs(parsed.query)
        if pairs is None:  # pragma: no cover - URL policy already established
            raise AssertionError("validated query became invalid")
        self._audit.append(
            RequestAudit(
                method="GET",
                host="api.github.com",
                path=parsed.path,
                classification=classification,
                scheme="https",
                port_classification=(
                    "explicit_https" if parsed.port == 443 else "default_https"
                ),
                query=pairs,
                application_headers=tuple(sorted(_APPROVED_HEADERS)),
                credentials_absent=True,
                raw_response_sha256=(
                    hashlib.sha256(raw_response).hexdigest()
                    if raw_response is not None
                    else None
                ),
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
        if classification == AcquisitionOutcome.ACQUIRED.value:
            return
        outcome = AcquisitionOutcome(classification)
        raise AcquisitionError(outcome, f"GitHub returned HTTP {response.status_code}")
