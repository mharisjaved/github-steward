"""Opaque in-memory secrets shared only by authenticated security boundaries."""

from __future__ import annotations

import hmac
from typing import Final, NoReturn

_REDACTION: Final = "<redacted bearer secret>"


class OpaqueBearerToken:
    """An opaque bearer value with deliberately redacted ordinary representations."""

    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str) or value == "":
            raise ValueError("bearer token must be a non-empty string")
        self.__value = value

    def __repr__(self) -> str:
        return _REDACTION

    def __str__(self) -> str:
        return _REDACTION

    def __reduce__(self) -> NoReturn:
        raise TypeError("bearer tokens cannot be serialized")

    def matches(self, candidate: str) -> bool:
        """Support secret-safe tests and boundary checks without exposing the value."""

        return isinstance(candidate, str) and hmac.compare_digest(
            self.__value,
            candidate,
        )

    def _authorization_header_value(self) -> str:
        """Extract only for an authenticated HTTP Authorization header."""

        return f"Bearer {self.__value}"

    def _authorized_broker_wire_value(self) -> str:
        """Extract only for the UID/GID-authorized local broker response."""

        return self.__value
