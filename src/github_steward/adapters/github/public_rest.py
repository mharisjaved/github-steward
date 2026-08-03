"""Bounded anonymous GET-only adapter for api.github.com."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from urllib.parse import urlsplit

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
        if not _is_public_url(target):
            raise AcquisitionError(
                AcquisitionOutcome.MALFORMED_RESPONSE,
                "pagination link must be HTTPS api.github.com",
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


def _is_public_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        return (
            parsed.scheme == "https"
            and parsed.hostname == "api.github.com"
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
            and parsed.path.startswith("/")
            and not parsed.fragment
        )
    except ValueError:
        return False


class PublicGitHubRestClient:
    """Strict synchronous client with a deliberately GET-only public surface."""

    def __init__(
        self,
        client: httpx.Client,
        *,
        maximum_attempts: int = 3,
        maximum_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        if maximum_attempts < 1 or maximum_response_bytes < 1:
            raise ValueError("adapter bounds must be positive")
        self._client = client
        self._maximum_attempts = maximum_attempts
        self._maximum_response_bytes = maximum_response_bytes
        self._audit: list[RequestAudit] = []

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
                    self._record(url, classification)
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
                self._record(url, AcquisitionOutcome.TIMEOUT.value)
                if attempt + 1 == self._maximum_attempts:
                    break
            except httpx.TransportError as exc:
                self._record(url, AcquisitionOutcome.TRANSPORT_ERROR.value)
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
        if not _is_public_url(url):
            raise AcquisitionError(
                AcquisitionOutcome.MALFORMED_RESPONSE,
                "request target must be HTTPS api.github.com",
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

    def _record(self, url: str, classification: str) -> None:
        parsed = urlsplit(url)
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        self._audit.append(RequestAudit("GET", "api.github.com", path, classification))

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
