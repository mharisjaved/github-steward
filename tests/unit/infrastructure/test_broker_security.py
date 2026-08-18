"""Security-critical tests for opaque secrets, JWT signing, and token caching."""

from __future__ import annotations

import pickle
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from github_steward.infrastructure.broker import jwt_signer
from github_steward.infrastructure.broker.cache import (
    CACHE_SAFETY_MARGIN,
    ReadTokenCache,
    TokenCacheKey,
)
from github_steward.infrastructure.broker.jwt_signer import GitHubAppJwtSigner
from github_steward.ports.secrets import OpaqueBearerToken

NOW = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class FixedClock:
    value: datetime

    def now(self) -> datetime:
        return self.value


def _private_key() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private, public


def test_jwt_signer_uses_exact_rs256_claim_contract_and_redacts_key() -> None:
    private, public = _private_key()
    signer = GitHubAppJwtSigner(
        client_id="Iv1.client-id",
        private_key_pem=private,
        clock=FixedClock(NOW),
    )
    secret = signer.issue()
    encoded = secret._control_plane_authorization_header().removeprefix("Bearer ")
    header = jwt.get_unverified_header(encoded)
    claims = jwt.decode(
        encoded,
        public,
        algorithms=["RS256"],
        issuer="Iv1.client-id",
        options={"verify_exp": False, "verify_iat": False},
    )

    assert header["alg"] == "RS256"
    assert claims == {
        "iat": int((NOW - timedelta(seconds=60)).timestamp()),
        "exp": int((NOW + timedelta(seconds=540)).timestamp()),
        "iss": "Iv1.client-id",
    }
    assert claims["exp"] - claims["iat"] == 600
    assert bytes(private[:30]).decode("ascii") not in repr(signer)
    assert encoded not in repr(secret)
    assert encoded not in str(secret)
    with pytest.raises(TypeError):
        pickle.dumps(secret)
    with pytest.raises(TypeError):
        pickle.dumps(signer)


@pytest.mark.parametrize(
    ("client_id", "private_key"),
    [("", b"key"), ("client", b""), (1, b"key"), ("client", "key")],
)
def test_jwt_signer_rejects_invalid_configuration(
    client_id: object,
    private_key: object,
) -> None:
    with pytest.raises(ValueError):
        GitHubAppJwtSigner(
            client_id=client_id,  # type: ignore[arg-type]
            private_key_pem=private_key,  # type: ignore[arg-type]
            clock=FixedClock(NOW),
        )

    with pytest.raises(ValueError, match="non-empty string"):
        jwt_signer._BrokerAppJwt("")


def test_jwt_signer_fails_closed_if_lifetime_ceiling_would_be_exceeded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private, _ = _private_key()

    def constrained_duration(*, seconds: int = 0, minutes: int = 0) -> timedelta:
        if minutes:
            return timedelta(seconds=599)
        return timedelta(seconds=seconds)

    monkeypatch.setattr(jwt_signer, "timedelta", constrained_duration)
    signer = GitHubAppJwtSigner(
        client_id="Iv1.client-id",
        private_key_pem=private,
        clock=FixedClock(NOW),
    )
    with pytest.raises(RuntimeError, match="ten-minute ceiling"):
        signer.issue()


def test_jwt_signer_rejects_invalid_library_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private, _ = _private_key()
    monkeypatch.setattr(jwt, "encode", lambda *_args, **_kwargs: "")
    signer = GitHubAppJwtSigner(
        client_id="Iv1.client-id",
        private_key_pem=private,
        clock=FixedClock(NOW),
    )
    with pytest.raises(RuntimeError, match="invalid value"):
        signer.issue()


@pytest.mark.parametrize(
    "value",
    [
        "ghs_legacy",
        "github_pat_" + "x" * 300,
    ],
)
def test_opaque_token_supports_short_and_long_shapes_without_structure_assumptions(
    value: str,
) -> None:
    token = OpaqueBearerToken(value)
    assert token.matches(value)
    assert not token.matches(value + "x")
    assert repr(token) == "<redacted bearer secret>"
    assert str(token) == "<redacted bearer secret>"
    assert value not in repr(token)
    with pytest.raises(TypeError):
        pickle.dumps(token)
    assert not hasattr(token, "value")
    assert not hasattr(token, "__dict__")


@pytest.mark.parametrize("value", ["", 1, None])
def test_opaque_token_rejects_empty_or_nontext_values(value: object) -> None:
    with pytest.raises(ValueError):
        OpaqueBearerToken(value)  # type: ignore[arg-type]


def test_cache_requires_more_than_the_exact_five_minute_margin() -> None:
    cache = ReadTokenCache()
    key = TokenCacheKey(10, 20, 3, "a" * 64)
    token = OpaqueBearerToken("opaque")
    expires_at = NOW + timedelta(minutes=10)
    cache.put(key, token=token, expires_at=expires_at)

    assert cache.get(key, now=expires_at - CACHE_SAFETY_MARGIN - timedelta(seconds=1))
    assert cache.get(key, now=expires_at - CACHE_SAFETY_MARGIN) is None
    assert len(cache) == 0


def test_cache_key_binds_installation_repository_epoch_and_permissions() -> None:
    cache = ReadTokenCache()
    original = TokenCacheKey(1, 2, 3, "a" * 64)
    cache.put(
        original,
        token=OpaqueBearerToken("opaque"),
        expires_at=NOW + timedelta(hours=1),
    )

    assert cache.get(original, now=NOW) is not None
    for changed in (
        TokenCacheKey(9, 2, 3, "a" * 64),
        TokenCacheKey(1, 9, 3, "a" * 64),
        TokenCacheKey(1, 2, 9, "a" * 64),
        TokenCacheKey(1, 2, 3, "b" * 64),
    ):
        assert cache.get(changed, now=NOW) is None
    cache.invalidate_repository(2)
    assert cache.get(original, now=NOW) is None


def test_cache_rejects_naive_time() -> None:
    cache = ReadTokenCache()
    key = TokenCacheKey(1, 2, 3, "a" * 64)
    with pytest.raises(ValueError):
        cache.put(
            key,
            token=OpaqueBearerToken("opaque"),
            expires_at=datetime(2026, 1, 1),
        )
    with pytest.raises(ValueError):
        cache.get(key, now=datetime(2026, 1, 1))
