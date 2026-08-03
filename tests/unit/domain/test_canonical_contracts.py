"""Domain-level canonical value tests."""

from __future__ import annotations

import operator
from collections.abc import Mapping, MutableMapping
from typing import cast

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


def test_envelope_copies_and_deeply_freezes_caller_owned_payload() -> None:
    source = {"items": [{"value": 1}]}
    envelope = CanonicalEnvelope(source, Digest("0" * 64))

    source["items"][0]["value"] = 2
    source["items"].append({"value": 3})

    assert envelope.as_mapping()["payload"] == {"items": [{"value": 1}]}
    assert isinstance(envelope.payload, Mapping)
    with pytest.raises(TypeError):
        operator.setitem(
            cast(MutableMapping[str, object], envelope.payload),
            "replacement",
            2,
        )
    items = envelope.payload["items"]
    assert isinstance(items, tuple)
    with pytest.raises(AttributeError):
        operator.methodcaller("append", 2)(items)


def test_envelope_mapping_export_is_detached_at_every_nested_level() -> None:
    envelope = CanonicalEnvelope(
        {"items": [{"value": 1}]},
        Digest("0" * 64),
    )

    exported = envelope.as_mapping()
    payload = exported["payload"]
    assert isinstance(payload, dict)
    items = payload["items"]
    assert isinstance(items, list)
    item = items[0]
    assert isinstance(item, dict)
    item["value"] = 2
    items.append({"value": 3})

    assert envelope.as_mapping()["payload"] == {"items": [{"value": 1}]}
