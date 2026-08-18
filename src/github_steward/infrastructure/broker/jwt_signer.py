"""GitHub App RS256 JWT signing contained by the broker boundary."""

from __future__ import annotations

from datetime import timedelta
from typing import NoReturn

import jwt

from github_steward.domain.processing import require_utc_datetime
from github_steward.ports.clock import Clock


class _BrokerAppJwt:
    """A non-serializable App JWT capability confined to broker-owned modules."""

    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str) or value == "":
            raise ValueError("GitHub App JWT must be a non-empty string")
        self.__value = value

    def __repr__(self) -> str:
        return "<redacted GitHub App JWT>"

    def __str__(self) -> str:
        return "<redacted GitHub App JWT>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("GitHub App JWTs cannot be serialized")

    def _control_plane_authorization_header(self) -> str:
        return f"Bearer {self.__value}"


class GitHubAppJwtSigner:
    """Sign GitHub App JWTs with an injected clock and broker-owned key."""

    __slots__ = ("__private_key_pem", "_client_id", "_clock")

    def __init__(
        self,
        *,
        client_id: str,
        private_key_pem: bytes,
        clock: Clock,
    ) -> None:
        if not isinstance(client_id, str) or client_id == "":
            raise ValueError("GitHub App client_id must be non-empty")
        if not isinstance(private_key_pem, bytes) or private_key_pem == b"":
            raise ValueError("GitHub App private key PEM must be non-empty bytes")
        self._client_id = client_id
        self.__private_key_pem = private_key_pem
        self._clock = clock

    def __repr__(self) -> str:
        return "GitHubAppJwtSigner(client_id=<configured>, private_key=<redacted>)"

    def __reduce__(self) -> NoReturn:
        raise TypeError("GitHub App JWT signers cannot be serialized")

    def issue(self) -> _BrokerAppJwt:
        """Create the exact GitHub App JWT without exposing it as a plain result."""

        now = require_utc_datetime(self._clock.now(), "jwt_now")
        issued_at = now - timedelta(seconds=60)
        expires_at = now + timedelta(seconds=540)
        if expires_at - issued_at > timedelta(minutes=10):
            raise RuntimeError("GitHub App JWT exceeded the ten-minute ceiling")
        encoded = jwt.encode(
            {
                "iat": int(issued_at.timestamp()),
                "exp": int(expires_at.timestamp()),
                "iss": self._client_id,
            },
            self.__private_key_pem,
            algorithm="RS256",
        )
        if not isinstance(encoded, str) or encoded == "":
            raise RuntimeError("JWT signer returned an invalid value")
        return _BrokerAppJwt(encoded)
