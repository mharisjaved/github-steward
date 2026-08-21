"""Direct-ASGI adversarial tests for verified GitHub webhook ingress."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from dataclasses import dataclass
from typing import cast

import pytest
from starlette.types import ASGIApp, Message, Scope

from github_steward.adapters.web.github_webhook import create_github_webhook_app
from github_steward.application.webhook_ingress import WebhookDurabilityError
from github_steward.domain.webhook import WebhookHeaders

SECRET = b"synthetic-integration-webhook-secret"
BODY = b'{"hook_id":1,"zen":"Keep it logically awesome."}'


@dataclass(frozen=True, slots=True)
class Invocation:
    status: int
    response_body: bytes
    receive_calls: int


class RecordingIngress:
    def __init__(self, failure: Exception | None = None) -> None:
        self.calls: list[tuple[WebhookHeaders, bytes]] = []
        self.failure = failure

    def receive(self, *, headers: WebhookHeaders, raw_body: bytes) -> object:
        self.calls.append((headers, raw_body))
        if self.failure is not None:
            raise self.failure
        return object()


def _signature(body: bytes = BODY, secret: bytes = SECRET) -> bytes:
    return b"sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest().encode()


def _headers(
    *,
    body: bytes = BODY,
    secret: bytes = SECRET,
    delivery: bytes = b"01234567-89ab-cdef-0123-456789abcdef",
    event: bytes = b"ping",
) -> list[tuple[bytes, bytes]]:
    return [
        (b"x-github-delivery", delivery),
        (b"x-github-event", event),
        (b"x-hub-signature-256", _signature(body, secret)),
    ]


def _invoke(
    app: ASGIApp,
    *,
    chunks: list[bytes] | None = None,
    headers: list[tuple[bytes, bytes]] | None = None,
    method: str = "POST",
    disconnect: bool = False,
) -> Invocation:
    body_chunks = [BODY] if chunks is None else chunks
    request_headers = _headers() if headers is None else headers

    async def execute() -> Invocation:
        messages: list[Message] = []
        receive_calls = 0

        async def receive() -> Message:
            nonlocal receive_calls
            receive_calls += 1
            if disconnect:
                return {"type": "http.disconnect"}
            index = receive_calls - 1
            if index >= len(body_chunks):
                raise AssertionError("ASGI boundary read beyond the supplied body")
            return {
                "type": "http.request",
                "body": body_chunks[index],
                "more_body": index < len(body_chunks) - 1,
            }

        async def send(message: Message) -> None:
            messages.append(message)

        scope = cast(
            Scope,
            {
                "type": "http",
                "asgi": {"version": "3.0", "spec_version": "2.3"},
                "http_version": "1.1",
                "method": method,
                "scheme": "http",
                "path": "/webhooks/github",
                "raw_path": b"/webhooks/github",
                "query_string": b"",
                "root_path": "",
                "headers": request_headers,
                "client": ("127.0.0.1", 49152),
                "server": ("127.0.0.1", 8000),
            },
        )
        await app(scope, receive, send)
        start = next(
            message for message in messages if message["type"] == "http.response.start"
        )
        response_body = b"".join(
            message.get("body", b"")
            for message in messages
            if message["type"] == "http.response.body"
        )
        return Invocation(int(start["status"]), response_body, receive_calls)

    return asyncio.run(execute())


def _app(ingress: RecordingIngress, *, maximum: int = 1024) -> ASGIApp:
    return create_github_webhook_app(
        secret=SECRET,
        ingress=ingress,
        max_body_bytes=maximum,
    )


def test_exact_raw_body_is_authenticated_before_threadpooled_ingress() -> None:
    ingress = RecordingIngress()
    result = _invoke(_app(ingress))

    assert result == Invocation(202, b"", 1)
    assert len(ingress.calls) == 1
    headers, raw_body = ingress.calls[0]
    assert headers.provider_delivery_id == "01234567-89ab-cdef-0123-456789abcdef"
    assert headers.event == "ping"
    assert raw_body == BODY


@pytest.mark.parametrize("mutation", [BODY + b"x", BODY + b" ", b" " + BODY])
def test_one_byte_or_whitespace_body_mutation_fails_authentication(
    mutation: bytes,
) -> None:
    ingress = RecordingIngress()
    result = _invoke(
        _app(ingress),
        chunks=[mutation],
        headers=_headers(body=BODY),
    )
    assert result.status == 403
    assert result.response_body == b""
    assert ingress.calls == []


@pytest.mark.parametrize(
    "signature_header",
    [
        None,
        (b"x-hub-signature-256", b"sha1=" + b"0" * 40),
        (b"x-hub-signature-256", b"sha256=" + b"0" * 63),
        (b"x-hub-signature-256", b"sha256=" + b"A" * 64),
    ],
    ids=["missing", "legacy-sha1", "short-sha256", "uppercase-sha256"],
)
def test_missing_legacy_or_malformed_signature_is_forbidden(
    signature_header: tuple[bytes, bytes] | None,
) -> None:
    ingress = RecordingIngress()
    headers = _headers()[:2]
    if signature_header is not None:
        headers.append(signature_header)
    result = _invoke(_app(ingress), headers=headers)
    assert result.status == 403
    assert ingress.calls == []


def test_legacy_signature_header_alone_is_forbidden() -> None:
    ingress = RecordingIngress()
    headers = [
        *_headers()[:2],
        (b"x-hub-signature", b"sha1=" + b"0" * 40),
    ]

    result = _invoke(_app(ingress), headers=headers)

    assert result.status == 403
    assert result.response_body == b""
    assert ingress.calls == []


def test_wrong_secret_and_duplicate_signature_are_forbidden() -> None:
    wrong = _headers(secret=b"different-synthetic-secret")
    duplicate = [*_headers(), (b"X-Hub-Signature-256", _signature())]
    for headers in (wrong, duplicate):
        ingress = RecordingIngress()
        assert _invoke(_app(ingress), headers=headers).status == 403
        assert ingress.calls == []


def test_missing_signature_remains_forbidden_with_malformed_identity() -> None:
    ingress = RecordingIngress()
    headers = [(b"x-github-delivery", b"not-a-uuid")]
    assert _invoke(_app(ingress), headers=headers).status == 403
    assert ingress.calls == []


@pytest.mark.parametrize(
    "headers",
    [
        _headers()[1:],
        [_headers()[0], *_headers()[2:]],
        [*_headers(), (b"X-GitHub-Delivery", b"second")],
        [*_headers(), (b"X-GitHub-Event", b"ping")],
        _headers(delivery=b"contains whitespace"),
        _headers(delivery=b"delivery-1"),
        _headers(delivery=b"x" * 129),
        _headers(event=b"Pull_Request"),
        _headers(event=b"bad-event"),
        _headers(event=b"\xff"),
    ],
)
def test_missing_duplicate_or_malformed_identity_headers_return_400(
    headers: list[tuple[bytes, bytes]],
) -> None:
    ingress = RecordingIngress()
    result = _invoke(_app(ingress), headers=headers)
    assert result.status == 400
    assert result.response_body == b""
    assert ingress.calls == []


def test_body_is_fully_read_before_headers_are_rejected() -> None:
    ingress = RecordingIngress()
    result = _invoke(
        _app(ingress),
        chunks=[BODY[:10], BODY[10:]],
        headers=_headers()[1:],
    )
    assert result.status == 400
    assert result.receive_calls == 2
    assert ingress.calls == []


def test_oversized_stream_stops_before_receiving_later_chunks() -> None:
    ingress = RecordingIngress()
    result = _invoke(
        _app(ingress, maximum=6),
        chunks=[b"1234", b"5678", b"must-not-be-read"],
        headers=_headers(body=b"12345678must-not-be-read"),
    )
    assert result == Invocation(413, b"", 2)
    assert ingress.calls == []


def test_client_disconnect_during_bounded_read_returns_400() -> None:
    ingress = RecordingIngress()
    result = _invoke(_app(ingress), disconnect=True)
    assert result.status == 400
    assert ingress.calls == []


def test_only_safe_durability_failure_maps_to_503() -> None:
    ingress = RecordingIngress(WebhookDurabilityError("durable commit unavailable"))
    result = _invoke(_app(ingress))
    assert result.status == 503
    assert result.response_body == b""
    assert len(ingress.calls) == 1


def test_unexpected_application_failure_is_not_mislabeled_as_durability() -> None:
    ingress = RecordingIngress(RuntimeError("unexpected"))
    with pytest.raises(RuntimeError, match="unexpected"):
        _invoke(_app(ingress))


def test_unknown_but_well_formed_event_reaches_authenticated_classification() -> None:
    ingress = RecordingIngress()
    headers = _headers(event=b"issue_comment")
    result = _invoke(_app(ingress), headers=headers)
    assert result.status == 202
    assert ingress.calls[0][0].event == "issue_comment"


def test_route_is_post_only() -> None:
    ingress = RecordingIngress()
    result = _invoke(_app(ingress), method="GET")
    assert result.status == 405
    assert ingress.calls == []
