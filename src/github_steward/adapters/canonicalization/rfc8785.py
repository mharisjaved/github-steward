"""Project-owned strict boundary over the selected RFC 8785 implementation."""

from __future__ import annotations

import hashlib
from typing import Final

import rfc8785

from github_steward.domain.canonical import (
    MAX_SAFE_INTEGER as DOMAIN_MAX_SAFE_INTEGER,
)
from github_steward.domain.canonical import (
    MIN_SAFE_INTEGER as DOMAIN_MIN_SAFE_INTEGER,
)
from github_steward.domain.canonical import (
    CanonicalEnvelope,
    Digest,
    freeze_canonical_value,
    to_json_compatible,
)
from github_steward.domain.errors import CanonicalizationError

MIN_SAFE_INTEGER: Final = DOMAIN_MIN_SAFE_INTEGER
MAX_SAFE_INTEGER: Final = DOMAIN_MAX_SAFE_INTEGER


def canonicalize(payload: object) -> bytes:
    """Validate a constructed Python value and return canonical UTF-8 bytes."""

    normalized = freeze_canonical_value(payload)
    try:
        canonical = rfc8785.dumps(to_json_compatible(normalized))
    except (rfc8785.CanonicalizationError, UnicodeError) as exc:
        raise CanonicalizationError("RFC 8785 canonicalization failed") from exc
    if not isinstance(canonical, bytes):
        raise CanonicalizationError("RFC 8785 adapter did not return bytes")
    return canonical


def digest_payload(payload: object) -> Digest:
    """Hash only the canonicalized payload."""

    return Digest(value=hashlib.sha256(canonicalize(payload)).hexdigest())


def envelope_payload(payload: object) -> CanonicalEnvelope:
    """Copy and freeze a payload, then bind it to its payload-only digest."""

    normalized = freeze_canonical_value(payload)
    return CanonicalEnvelope(payload=normalized, digest=digest_payload(normalized))
