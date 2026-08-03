"""Domain tests for bounded acquisition identities."""

from __future__ import annotations

import pytest

from github_steward.domain.acquisition import (
    AcquisitionError,
    AcquisitionOutcome,
    RepositoryTarget,
    poll_delivery_identity,
    require_sha,
)
from github_steward.domain.errors import DomainValidationError


def test_repository_target_and_delivery_identity() -> None:
    target = RepositoryTarget("Harry5174", "github-steward", 1)
    assert target.full_name == "Harry5174/github-steward"
    digest = "a" * 64
    assert poll_delivery_identity(77, 1, digest) == f"github-public-pr:77:1:{digest}"
    assert require_sha("b" * 40, "head") == "b" * 40


@pytest.mark.parametrize(
    "arguments",
    [
        ("", "repo", 1),
        ("owner", "bad/repo", 1),
        ("owner", "repo", 0),
        ("owner", "repo", True),
    ],
)
def test_repository_target_rejects_invalid_values(
    arguments: tuple[str, str, int],
) -> None:
    with pytest.raises(DomainValidationError):
        RepositoryTarget(*arguments)


@pytest.mark.parametrize(
    "arguments",
    [
        (0, 1, "a" * 64),
        (True, 1, "a" * 64),
        (1, 0, "a" * 64),
        (1, True, "a" * 64),
        (1, 1, "bad"),
    ],
)
def test_delivery_identity_rejects_invalid_values(
    arguments: tuple[int, int, str],
) -> None:
    with pytest.raises(DomainValidationError):
        poll_delivery_identity(*arguments)


def test_require_sha_is_classified() -> None:
    with pytest.raises(AcquisitionError) as raised:
        require_sha("ABC", "head")
    assert raised.value.outcome is AcquisitionOutcome.MALFORMED_RESPONSE
