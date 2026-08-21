"""Bounded, exact-byte GitHub webhook authentication at the ASGI boundary."""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Sequence
from enum import StrEnum
from typing import Protocol, cast

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect, Request
from starlette.responses import Response
from starlette.routing import Route

from github_steward.application.webhook_ingress import WebhookDurabilityError
from github_steward.domain.webhook import (
    DEFAULT_MAX_BODY_BYTES as DEFAULT_MAX_BODY_BYTES,
)
from github_steward.domain.webhook import HARD_MAX_BODY_BYTES as HARD_MAX_BODY_BYTES
from github_steward.domain.webhook import WebhookHeaders

_DELIVERY_HEADER = b"x-github-delivery"
_EVENT_HEADER = b"x-github-event"
_SIGNATURE_HEADER = b"x-hub-signature-256"
_DELIVERY_ID = re.compile(
    rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
_EVENT_NAME = re.compile(rb"[a-z][a-z0-9_]{0,63}")
_SHA256_SIGNATURE = re.compile(rb"sha256=[0-9a-f]{64}")

type RawHeaders = Sequence[tuple[bytes, bytes]]


class GitHubWebhookIngress(Protocol):
    """Only the synchronous application operation exposed to the web adapter."""

    def receive(self, *, headers: WebhookHeaders, raw_body: bytes) -> object:
        """Durably classify one already-authenticated delivery."""


class WebhookBoundaryOutcome(StrEnum):
    """Stable HTTP classifications which never contain input or secret material."""

    ACCEPTED = "ACCEPTED"
    MALFORMED_HEADERS = "MALFORMED_HEADERS"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    BODY_TOO_LARGE = "BODY_TOO_LARGE"
    DURABILITY_UNAVAILABLE = "DURABILITY_UNAVAILABLE"


_RESPONSE_STATUS = {
    WebhookBoundaryOutcome.ACCEPTED: 202,
    WebhookBoundaryOutcome.MALFORMED_HEADERS: 400,
    WebhookBoundaryOutcome.AUTHENTICATION_FAILED: 403,
    WebhookBoundaryOutcome.BODY_TOO_LARGE: 413,
    WebhookBoundaryOutcome.DURABILITY_UNAVAILABLE: 503,
}


class _BodyTooLarge(Exception):
    pass


class _MalformedHeaders(Exception):
    pass


class _AuthenticationFailed(Exception):
    pass


def response_status(outcome: WebhookBoundaryOutcome) -> int:
    """Return the single stable status associated with a boundary outcome."""

    return _RESPONSE_STATUS[outcome]


def verify_hmac_sha256(
    *,
    secret: bytes,
    raw_body: bytes,
    supplied_signature: bytes,
) -> bool:
    """Verify an exact GitHub SHA-256 signature without constructing an expected one."""

    if _SHA256_SIGNATURE.fullmatch(supplied_signature) is None:
        return False
    supplied_digest = bytes.fromhex(supplied_signature[7:].decode("ascii"))
    expected_digest = hmac.new(secret, raw_body, hashlib.sha256).digest()
    return hmac.compare_digest(supplied_digest, expected_digest)


async def _read_bounded_body(request: Request, maximum: int) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        if len(chunk) > maximum - len(body):
            raise _BodyTooLarge
        body.extend(chunk)
    return bytes(body)


def _raw_headers(request: Request) -> RawHeaders:
    return cast(RawHeaders, request.scope["headers"])


def _values(headers: RawHeaders, name: bytes) -> tuple[bytes, ...]:
    return tuple(value for key, value in headers if key.lower() == name)


def _one_header(
    headers: RawHeaders,
    name: bytes,
    *,
    authentication: bool,
) -> bytes:
    values = _values(headers, name)
    if len(values) != 1:
        if authentication:
            raise _AuthenticationFailed
        raise _MalformedHeaders
    return values[0]


def _validated_headers(raw_headers: RawHeaders) -> tuple[WebhookHeaders, bytes]:
    signature = _one_header(raw_headers, _SIGNATURE_HEADER, authentication=True)
    if _SHA256_SIGNATURE.fullmatch(signature) is None:
        raise _AuthenticationFailed
    delivery = _one_header(raw_headers, _DELIVERY_HEADER, authentication=False)
    event = _one_header(raw_headers, _EVENT_HEADER, authentication=False)
    if _DELIVERY_ID.fullmatch(delivery) is None:
        raise _MalformedHeaders
    if _EVENT_NAME.fullmatch(event) is None:
        raise _MalformedHeaders
    return (
        WebhookHeaders(
            provider_delivery_id=delivery.decode("ascii"),
            event=event.decode("ascii"),
        ),
        signature,
    )


def _validate_configuration(secret: bytes, maximum: int) -> tuple[bytes, int]:
    if not isinstance(secret, bytes) or not secret:
        raise ValueError("webhook secret must be non-empty bytes")
    if (
        isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or maximum < 1
        or maximum > HARD_MAX_BODY_BYTES
    ):
        raise ValueError("webhook body limit is outside the application ceiling")
    return bytes(secret), maximum


class GitHubWebhookBoundary:
    """One secret-contained boundary enforcing authentication before application use."""

    def __init__(
        self,
        *,
        secret: bytes,
        ingress: GitHubWebhookIngress,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    ) -> None:
        self._secret, self._max_body_bytes = _validate_configuration(
            secret,
            max_body_bytes,
        )
        self._ingress = ingress

    async def __call__(self, request: Request) -> Response:
        """Read, authenticate, durably classify, and only then acknowledge."""

        try:
            raw_body = await _read_bounded_body(request, self._max_body_bytes)
        except _BodyTooLarge:
            return _response(WebhookBoundaryOutcome.BODY_TOO_LARGE)
        except ClientDisconnect:
            return _response(WebhookBoundaryOutcome.MALFORMED_HEADERS)

        try:
            headers, signature = _validated_headers(_raw_headers(request))
        except _MalformedHeaders:
            return _response(WebhookBoundaryOutcome.MALFORMED_HEADERS)
        except _AuthenticationFailed:
            return _response(WebhookBoundaryOutcome.AUTHENTICATION_FAILED)

        if not verify_hmac_sha256(
            secret=self._secret,
            raw_body=raw_body,
            supplied_signature=signature,
        ):
            return _response(WebhookBoundaryOutcome.AUTHENTICATION_FAILED)

        try:
            await run_in_threadpool(
                self._ingress.receive,
                headers=headers,
                raw_body=raw_body,
            )
        except WebhookDurabilityError:
            return _response(WebhookBoundaryOutcome.DURABILITY_UNAVAILABLE)
        return _response(WebhookBoundaryOutcome.ACCEPTED)


def _response(outcome: WebhookBoundaryOutcome) -> Response:
    return Response(status_code=response_status(outcome))


def create_github_webhook_app(
    *,
    secret: bytes,
    ingress: GitHubWebhookIngress,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> Starlette:
    """Compose the sole GS-I6 inbound route without any GitHub client."""

    endpoint = GitHubWebhookBoundary(
        secret=secret,
        ingress=ingress,
        max_body_bytes=max_body_bytes,
    )
    return Starlette(
        routes=[
            Route(
                "/webhooks/github",
                endpoint=endpoint.__call__,
                methods=["POST"],
                name="github-webhook",
            )
        ]
    )
