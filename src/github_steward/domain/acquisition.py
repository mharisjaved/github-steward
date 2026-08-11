"""Stable contracts for public, read-only GitHub acquisition."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from github_steward.domain.errors import DomainValidationError

API_VERSION: Final = "2026-03-10"
SNAPSHOT_SCHEMA_ID: Final = "github.pull_request_snapshot.v1"
PER_PAGE: Final = 100
MAX_RESPONSE_BYTES: Final = 8_388_608
MAX_FILES: Final = 3_000
MAX_COMMITS: Final = 250
MAX_CHECK_RUNS: Final = 1_000
MAX_CHECK_SUITES: Final = 1_000
MAX_PAGES: Final = 100
COHERENT_ATTEMPTS: Final = 2
_NAME: Final = re.compile(r"^[A-Za-z0-9_.-]+$")
_SHA: Final = re.compile(r"^[0-9a-f]{40}$")


class AcquisitionOutcome(StrEnum):
    """Complete safe outcome vocabulary for the acquisition boundary."""

    ACQUIRED = "ACQUIRED"
    FORBIDDEN = "FORBIDDEN"
    RATE_LIMITED = "RATE_LIMITED"
    NOT_FOUND = "NOT_FOUND"
    UNPROCESSABLE = "UNPROCESSABLE"
    UPSTREAM_SERVER_ERROR = "UPSTREAM_SERVER_ERROR"
    TRANSPORT_ERROR = "TRANSPORT_ERROR"
    TIMEOUT = "TIMEOUT"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    INCOMPLETE_ACQUISITION = "INCOMPLETE_ACQUISITION"
    UNSUPPORTED_UPSTREAM_LIMIT = "UNSUPPORTED_UPSTREAM_LIMIT"
    CONCURRENT_CHANGE = "CONCURRENT_CHANGE"
    PERSISTENCE_FAILURE = "PERSISTENCE_FAILURE"


class AcquisitionError(RuntimeError):
    """A classified failure whose message is safe for operator diagnostics."""

    def __init__(self, outcome: AcquisitionOutcome, message: str) -> None:
        super().__init__(message)
        self.outcome = outcome


@dataclass(frozen=True, slots=True)
class RepositoryTarget:
    """Validated public repository and pull-request identity."""

    owner: str
    repository: str
    pull_number: int

    def __post_init__(self) -> None:
        if not _NAME.fullmatch(self.owner):
            raise DomainValidationError("owner is not a valid GitHub name")
        if not _NAME.fullmatch(self.repository):
            raise DomainValidationError("repository is not a valid GitHub name")
        if isinstance(self.pull_number, bool) or self.pull_number < 1:
            raise DomainValidationError("pull_number must be a positive integer")

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.repository}"


def require_sha(value: object, field: str) -> str:
    """Return one exact lowercase Git object id or fail closed."""

    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise AcquisitionError(
            AcquisitionOutcome.MALFORMED_RESPONSE,
            f"{field} must be a 40-character lowercase SHA",
        )
    return value


def poll_delivery_identity(repo_id: int, pull_number: int, digest: str) -> str:
    """Derive a stable source-and-snapshot delivery identity."""

    if isinstance(repo_id, bool) or not isinstance(repo_id, int) or repo_id < 1:
        raise DomainValidationError("repo_id must be a positive integer")
    if isinstance(pull_number, bool) or pull_number < 1:
        raise DomainValidationError("pull_number must be a positive integer")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise DomainValidationError("snapshot digest must be lowercase SHA-256")
    return f"github-public-pr:{repo_id}:{pull_number}:{digest}"
