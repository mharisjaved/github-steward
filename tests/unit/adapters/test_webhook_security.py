"""Reachable-branch tests for the compact webhook authentication boundary."""

from __future__ import annotations

import hashlib
import hmac

import pytest

from github_steward.adapters.web.github_webhook import (
    DEFAULT_MAX_BODY_BYTES,
    HARD_MAX_BODY_BYTES,
    GitHubWebhookBoundary,
    WebhookBoundaryOutcome,
    response_status,
    verify_hmac_sha256,
)

SECRET = b"synthetic-unit-webhook-secret"
BODY = b'{"zen":"exact bytes"}'


class UnusedIngress:
    def receive(self, **_: object) -> object:
        raise AssertionError("unit boundary configuration must not call ingress")


def _signature(body: bytes = BODY, secret: bytes = SECRET) -> bytes:
    return b"sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest().encode()


def test_body_limit_constants_match_the_exact_gs_i6_contract() -> None:
    assert DEFAULT_MAX_BODY_BYTES == 8 * 1024 * 1024
    assert HARD_MAX_BODY_BYTES == 25 * 1024 * 1024


def test_exact_byte_hmac_sha256_uses_constant_result_contract() -> None:
    signature = _signature()
    assert verify_hmac_sha256(
        secret=SECRET,
        raw_body=BODY,
        supplied_signature=signature,
    )
    assert not verify_hmac_sha256(
        secret=SECRET,
        raw_body=BODY + b" ",
        supplied_signature=signature,
    )
    assert not verify_hmac_sha256(
        secret=b"different-synthetic-secret",
        raw_body=BODY,
        supplied_signature=signature,
    )


@pytest.mark.parametrize(
    "malformed",
    [
        b"",
        b"sha1=" + b"0" * 40,
        b"sha256=" + b"0" * 63,
        b"sha256=" + b"G" * 64,
        b"sha256=" + b"0" * 64 + b"suffix",
    ],
    ids=[
        "missing",
        "legacy-sha1",
        "short-sha256",
        "nonhex-sha256",
        "suffixed-sha256",
    ],
)
def test_malformed_or_legacy_signatures_fail_closed(malformed: bytes) -> None:
    assert not verify_hmac_sha256(
        secret=SECRET,
        raw_body=BODY,
        supplied_signature=malformed,
    )


@pytest.mark.parametrize(
    ("outcome", "status"),
    [
        (WebhookBoundaryOutcome.ACCEPTED, 202),
        (WebhookBoundaryOutcome.MALFORMED_HEADERS, 400),
        (WebhookBoundaryOutcome.AUTHENTICATION_FAILED, 403),
        (WebhookBoundaryOutcome.BODY_TOO_LARGE, 413),
        (WebhookBoundaryOutcome.DURABILITY_UNAVAILABLE, 503),
    ],
)
def test_response_mapping_is_complete_and_stable(
    outcome: WebhookBoundaryOutcome,
    status: int,
) -> None:
    assert response_status(outcome) == status


@pytest.mark.parametrize("secret", [b"", bytearray(b"not-bytes"), "not-bytes"])
def test_boundary_requires_nonempty_immutable_secret(secret: object) -> None:
    with pytest.raises(ValueError, match="secret"):
        GitHubWebhookBoundary(
            secret=secret,  # type: ignore[arg-type]
            ingress=UnusedIngress(),
        )


@pytest.mark.parametrize(
    "maximum",
    [True, False, 0, -1, HARD_MAX_BODY_BYTES + 1, 1.5, "1024"],
)
def test_boundary_enforces_positive_integer_hard_ceiling(maximum: object) -> None:
    with pytest.raises(ValueError, match="ceiling"):
        GitHubWebhookBoundary(
            secret=SECRET,
            ingress=UnusedIngress(),
            max_body_bytes=maximum,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "maximum",
    [1, DEFAULT_MAX_BODY_BYTES, HARD_MAX_BODY_BYTES],
)
def test_boundary_accepts_limits_through_the_hard_ceiling(maximum: int) -> None:
    boundary = GitHubWebhookBoundary(
        secret=SECRET,
        ingress=UnusedIngress(),
        max_body_bytes=maximum,
    )
    assert boundary is not None
