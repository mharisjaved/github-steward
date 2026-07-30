"""Domain-level canonical value tests."""

from __future__ import annotations

import pytest

from github_steward.domain.canonical import DIGEST_FORMAT, CanonicalEnvelope, Digest
from github_steward.domain.errors import DomainValidationError


def test_digest_and_envelope_are_value_oriented() -> None:
    digest = Digest("0" * 64)
    envelope = CanonicalEnvelope({"a": 1}, digest)
    assert digest.format == DIGEST_FORMAT
    assert envelope.as_mapping() == {
        "payload": {"a": 1},
        "digest": {"format": DIGEST_FORMAT, "value": "0" * 64},
    }


@pytest.mark.parametrize(
    "value",
    [
        "A" * 64,
        "0" * 63,
        "0" * 65,
        "g" * 64,
    ],
)
def test_digest_rejects_non_lowercase_sha256(value: str) -> None:
    with pytest.raises(DomainValidationError):
        Digest(value)


def test_digest_rejects_unknown_format() -> None:
    with pytest.raises(DomainValidationError):
        Digest("0" * 64, format="sha256")
