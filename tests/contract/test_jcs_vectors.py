"""Official and project-owned JCS vectors."""

from __future__ import annotations

import hashlib

from github_steward.adapters.canonicalization.rfc8785 import (
    canonicalize,
    digest_payload,
    envelope_payload,
)


def test_official_rfc8785_property_sorting_vector() -> None:
    payload = {
        "\u20ac": "Euro Sign",
        "\r": "Carriage Return",
        "\ufb33": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\U0001f600": "Emoji: Grinning Face",
        "\u0080": "Control",
        "\u00f6": "Latin Small Letter O With Diaeresis",
    }
    expected = (
        b'{"\\r":"Carriage Return","1":"One",'
        b'"\xc2\x80":"Control","\xc3\xb6":"Latin Small Letter O With Diaeresis",'
        b'"\xe2\x82\xac":"Euro Sign",'
        b'"\xf0\x9f\x98\x80":"Emoji: Grinning Face",'
        b'"\xef\xac\xb3":"Hebrew Letter Dalet With Dagesh"}'
    )
    assert canonicalize(payload) == expected


def test_project_golden_vector_and_ordered_sequence() -> None:
    payload = {"z": None, "a": (3, 2, 1)}
    expected = b'{"a":[3,2,1],"z":null}'
    assert canonicalize(payload) == expected
    assert canonicalize(payload) == canonicalize({"a": [3, 2, 1], "z": None})


def test_payload_only_digest_and_lowercase_output() -> None:
    payload = {"b": True, "a": "x"}
    canonical = b'{"a":"x","b":true}'
    digest = digest_payload(payload)
    assert canonicalize(payload) == canonical
    assert digest.value == hashlib.sha256(canonical).hexdigest()
    assert digest.value == digest.value.lower()
    envelope = envelope_payload(payload)
    assert envelope.digest == digest
    assert canonicalize(envelope.as_mapping()) != canonical


def test_null_and_omission_are_distinct() -> None:
    assert digest_payload({"value": None}) != digest_payload({})


def test_semantic_array_order_is_preserved() -> None:
    assert canonicalize({"v": ["a", "b"]}) != canonicalize({"v": ["b", "a"]})


def test_utf8_and_repeated_output_are_deterministic() -> None:
    payload = {"emoji": "\U0001f642", "word": "café"}
    first = canonicalize(payload)
    assert first.decode("utf-8") == '{"emoji":"🙂","word":"café"}'
    assert all(canonicalize(payload) == first for _ in range(10))
