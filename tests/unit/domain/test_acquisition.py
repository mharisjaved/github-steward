"""Domain tests for bounded acquisition identities."""

from __future__ import annotations

from uuid import uuid5

import pytest

from github_steward.domain.acquisition import (
    API_VERSION,
    COHERENT_ATTEMPTS,
    GITHUB_REFRESH_WORK_TYPE,
    GITHUB_WORK_IDENTITY_NAMESPACE,
    MAX_CHECK_RUNS,
    MAX_CHECK_SUITES,
    MAX_COMMITS,
    MAX_FILES,
    MAX_PAGES,
    MAX_RESPONSE_BYTES,
    PER_PAGE,
    AcquisitionError,
    AcquisitionOutcome,
    RepositoryTarget,
    github_work_record_id,
    github_work_subject,
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
    work = github_work_record_id("delivery-1")
    assert work == str(
        uuid5(
            GITHUB_WORK_IDENTITY_NAMESPACE,
            f"work:delivery-1:{GITHUB_REFRESH_WORK_TYPE}",
        )
    )
    assert github_work_subject(123, 7) == "123:7"


def test_exact_github_acquisition_configuration_ceiling() -> None:
    assert (
        API_VERSION,
        PER_PAGE,
        MAX_PAGES,
        MAX_RESPONSE_BYTES,
        MAX_FILES,
        MAX_COMMITS,
        MAX_CHECK_SUITES,
        MAX_CHECK_RUNS,
        COHERENT_ATTEMPTS,
    ) == ("2026-03-10", 100, 100, 8_388_608, 3_000, 250, 1_000, 1_000, 2)


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


@pytest.mark.parametrize(
    ("repository_id", "pull_number"),
    [(True, 1), (1, 0)],
)
def test_github_work_subject_rejects_nonpositive_or_boolean_identity(
    repository_id: int,
    pull_number: int,
) -> None:
    with pytest.raises(DomainValidationError):
        github_work_subject(repository_id, pull_number)


def test_github_work_record_rejects_empty_delivery_identity() -> None:
    with pytest.raises(DomainValidationError):
        github_work_record_id("")
