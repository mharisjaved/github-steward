"""Project-owned strict boundary over the selected RFC 8785 implementation."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from decimal import Decimal
from enum import Enum
from fractions import Fraction
from typing import Final

import rfc8785

from github_steward.domain.canonical import (
    CanonicalEnvelope,
    CanonicalValue,
    Digest,
)
from github_steward.domain.errors import CanonicalizationError

MIN_SAFE_INTEGER: Final = -(2**53) + 1
MAX_SAFE_INTEGER: Final = (2**53) - 1


def _validate_string(value: str) -> str:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise CanonicalizationError("strings must contain valid Unicode scalars")
    return value


def _normalize(value: object, active: set[int]) -> CanonicalValue:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not MIN_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise CanonicalizationError("integer is outside the exact JCS safe range")
        return value
    if isinstance(value, str):
        return _validate_string(value)
    if isinstance(value, float):
        raise CanonicalizationError("float values are prohibited")
    if isinstance(value, (Decimal, Fraction)):
        raise CanonicalizationError(f"{type(value).__name__} values are prohibited")
    if isinstance(value, Enum):
        raise CanonicalizationError("Enum objects must be converted before JCS")
    if isinstance(value, (bytes, bytearray, memoryview, set, frozenset)):
        raise CanonicalizationError(f"{type(value).__name__} values are prohibited")

    identity = id(value)
    if isinstance(value, (list, tuple)):
        if identity in active:
            raise CanonicalizationError("cyclic sequences are prohibited")
        active.add(identity)
        try:
            return [_normalize(item, active) for item in value]
        finally:
            active.remove(identity)

    if isinstance(value, Mapping):
        if type(value).__module__.startswith("sqlalchemy"):
            raise CanonicalizationError("SQLAlchemy rows are prohibited")
        if identity in active:
            raise CanonicalizationError("cyclic mappings are prohibited")
        active.add(identity)
        try:
            normalized: dict[str, CanonicalValue] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise CanonicalizationError("mapping keys must be strings")
                normalized[_validate_string(key)] = _normalize(item, active)
            return normalized
        finally:
            active.remove(identity)

    raise CanonicalizationError(
        f"{type(value).__name__} must be converted before the JCS boundary"
    )


def canonicalize(payload: object) -> bytes:
    """Validate a constructed Python value and return canonical UTF-8 bytes."""

    normalized = _normalize(payload, set())
    try:
        canonical = rfc8785.dumps(normalized)
    except (rfc8785.CanonicalizationError, UnicodeError) as exc:
        raise CanonicalizationError("RFC 8785 canonicalization failed") from exc
    if not isinstance(canonical, bytes):
        raise CanonicalizationError("RFC 8785 adapter did not return bytes")
    return canonical


def digest_payload(payload: object) -> Digest:
    """Hash only the canonicalized payload."""

    return Digest(value=hashlib.sha256(canonicalize(payload)).hexdigest())


def envelope_payload(payload: object) -> CanonicalEnvelope:
    """Normalize and envelope a payload with its payload-only digest."""

    normalized = _normalize(payload, set())
    return CanonicalEnvelope(payload=normalized, digest=digest_payload(normalized))
