"""Value-oriented canonical envelope contracts."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import Enum
from fractions import Fraction
from types import MappingProxyType
from typing import Final

from github_steward.domain.errors import CanonicalizationError, DomainValidationError

DIGEST_FORMAT: Final = "jcs-sha256/v1"
MIN_SAFE_INTEGER: Final = -(2**53) + 1
MAX_SAFE_INTEGER: Final = (2**53) - 1
_DIGEST_PATTERN: Final = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP_PATTERN: Final = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})T"
    r"(?P<time>\d{2}:\d{2}:\d{2})\.(?P<fraction>\d{6})Z$"
)

type CanonicalScalar = bool | int | str | None
type CanonicalValue = (
    CanonicalScalar | tuple[CanonicalValue, ...] | Mapping[str, CanonicalValue]
)
type JsonCanonicalValue = (
    CanonicalScalar | list[JsonCanonicalValue] | dict[str, JsonCanonicalValue]
)


def _validate_string(value: str) -> str:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise CanonicalizationError("strings must contain valid Unicode scalars")
    return value


def _freeze(value: object, active: set[int]) -> CanonicalValue:
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
            return tuple(_freeze(item, active) for item in value)
        finally:
            active.remove(identity)

    if isinstance(value, Mapping):
        if type(value).__module__.startswith("sqlalchemy"):
            raise CanonicalizationError("SQLAlchemy rows are prohibited")
        if identity in active:
            raise CanonicalizationError("cyclic mappings are prohibited")
        active.add(identity)
        try:
            frozen: dict[str, CanonicalValue] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise CanonicalizationError("mapping keys must be strings")
                frozen[_validate_string(key)] = _freeze(item, active)
            return MappingProxyType(frozen)
        finally:
            active.remove(identity)

    raise CanonicalizationError(
        f"{type(value).__name__} must be converted before the JCS boundary"
    )


def freeze_canonical_value(value: object) -> CanonicalValue:
    """Copy, validate, and recursively freeze one canonical value."""

    return _freeze(value, set())


def to_json_compatible(value: CanonicalValue) -> JsonCanonicalValue:
    """Return a detached mutable JSON-shaped copy of an immutable value."""

    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, tuple):
        return [to_json_compatible(item) for item in value]
    return {key: to_json_compatible(item) for key, item in value.items()}


def validate_digest_timestamp(value: str) -> str:
    """Return an exact fixed-precision UTC timestamp or fail closed."""

    match = _TIMESTAMP_PATTERN.fullmatch(value)
    if match is None:
        raise DomainValidationError(
            "digest timestamp must use YYYY-MM-DDTHH:MM:SS.ffffffZ"
        )
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise DomainValidationError("digest timestamp is not a valid UTC time") from exc
    return value


@dataclass(frozen=True, slots=True)
class Digest:
    """A versioned lowercase SHA-256 digest."""

    value: str
    format: str = DIGEST_FORMAT

    def __post_init__(self) -> None:
        if self.format != DIGEST_FORMAT:
            raise DomainValidationError(f"digest format must be {DIGEST_FORMAT}")
        if _DIGEST_PATTERN.fullmatch(self.value) is None:
            raise DomainValidationError(
                "digest value must be 64 lowercase hexadecimal characters"
            )

    def as_mapping(self) -> MappingProxyType[str, str]:
        """Expose a read-only JSON-shaped digest."""

        return MappingProxyType({"format": self.format, "value": self.value})


@dataclass(frozen=True, slots=True, init=False)
class CanonicalEnvelope:
    """A payload and its payload-only digest."""

    payload: CanonicalValue
    digest: Digest

    def __init__(self, payload: object, digest: Digest) -> None:
        object.__setattr__(self, "payload", freeze_canonical_value(payload))
        object.__setattr__(self, "digest", digest)

    def as_mapping(self) -> dict[str, object]:
        """Return a detached JSON-compatible envelope shape."""

        return {
            "payload": to_json_compatible(self.payload),
            "digest": dict(self.digest.as_mapping()),
        }
