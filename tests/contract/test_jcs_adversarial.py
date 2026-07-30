"""Adversarial tests for the strict project-owned JCS boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from fractions import Fraction
from uuid import UUID

import pytest

from github_steward.adapters.canonicalization.rfc8785 import (
    MAX_SAFE_INTEGER,
    MIN_SAFE_INTEGER,
    canonicalize,
)
from github_steward.domain.canonical import validate_digest_timestamp
from github_steward.domain.errors import CanonicalizationError, DomainValidationError


class ExampleEnum(Enum):
    VALUE = "value"


@dataclass
class ExampleDataclass:
    value: str


class ExampleObject:
    pass


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (MIN_SAFE_INTEGER, b"-9007199254740991"),
        (MAX_SAFE_INTEGER, b"9007199254740991"),
        (True, b"true"),
        (False, b"false"),
    ],
)
def test_safe_integer_boundaries_and_boolean_distinction(
    value: object,
    expected: bytes,
) -> None:
    assert canonicalize(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        MIN_SAFE_INTEGER - 1,
        MAX_SAFE_INTEGER + 1,
        0.0,
        float("nan"),
        float("inf"),
        Decimal("1"),
        Fraction(1, 2),
        b"{}",
        bytearray(b"{}"),
        memoryview(b"{}"),
        {"a"},
        frozenset({"a"}),
        datetime(2026, 1, 1),
        date(2026, 1, 1),
        UUID("00000000-0000-0000-0000-000000000000"),
        ExampleEnum.VALUE,
        ExampleDataclass("value"),
        ExampleObject(),
    ],
)
def test_every_unsupported_category_fails(value: object) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize(value)


def test_non_string_mapping_key_fails() -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize({1: "value"})


@pytest.mark.parametrize("value", ["\ud800", "prefix\udfff", {"\ud800": "x"}])
def test_lone_surrogates_fail(value: object) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize(value)


def test_json_text_is_a_string_and_is_never_parsed() -> None:
    assert canonicalize('{"duplicate":1,"duplicate":2}') == (
        b'"{\\"duplicate\\":1,\\"duplicate\\":2}"'
    )


def test_cyclic_values_fail_closed() -> None:
    sequence: list[object] = []
    sequence.append(sequence)
    with pytest.raises(CanonicalizationError):
        canonicalize(sequence)
    mapping: dict[str, object] = {}
    mapping["self"] = mapping
    with pytest.raises(CanonicalizationError):
        canonicalize(mapping)


@pytest.mark.parametrize(
    "value",
    [
        "2026-07-30T12:34:56.000000Z",
        "2000-02-29T00:00:00.999999Z",
    ],
)
def test_exact_digest_timestamp_policy_accepts(value: str) -> None:
    assert validate_digest_timestamp(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "2026-07-30t12:34:56.000000z",
        "2026-07-30T12:34:56Z",
        "2026-07-30T12:34:56.000Z",
        "2026-07-30T12:34:56.000000+00:00",
        "2026-07-30T12:34:60.000000Z",
        "2026-02-29T12:34:56.000000Z",
    ],
)
def test_exact_digest_timestamp_policy_rejects(value: str) -> None:
    with pytest.raises(DomainValidationError):
        validate_digest_timestamp(value)
