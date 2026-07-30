"""Value-oriented canonical envelope contracts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Final

from github_steward.domain.errors import DomainValidationError

DIGEST_FORMAT: Final = "jcs-sha256/v1"
_DIGEST_PATTERN: Final = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP_PATTERN: Final = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})T"
    r"(?P<time>\d{2}:\d{2}:\d{2})\.(?P<fraction>\d{6})Z$"
)

type CanonicalScalar = bool | int | str | None
type CanonicalValue = CanonicalScalar | list[CanonicalValue] | dict[str, CanonicalValue]


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


@dataclass(frozen=True, slots=True)
class CanonicalEnvelope:
    """A payload and its payload-only digest."""

    payload: CanonicalValue
    digest: Digest

    def as_mapping(self) -> dict[str, object]:
        """Return the required envelope shape."""

        return {
            "payload": self.payload,
            "digest": dict(self.digest.as_mapping()),
        }
