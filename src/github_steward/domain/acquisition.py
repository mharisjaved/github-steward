"""Stable contracts for public, read-only GitHub acquisition."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final, Self, cast
from uuid import UUID, uuid5

from github_steward.domain.canonical import DIGEST_FORMAT, MAX_SAFE_INTEGER
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
GITHUB_PROVIDER: Final = "github"
GITHUB_REFRESH_WORK_TYPE: Final = "REFRESH_GITHUB_PULL_REQUEST"
GITHUB_WORK_IDENTITY_NAMESPACE: Final = UUID("15200e7d-6747-5b89-bf26-870ce9894353")
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


def github_work_subject(repository_id: int, pull_number: int) -> str:
    """Return the numeric semantic subject for one GitHub refresh."""

    if (
        isinstance(repository_id, bool)
        or not isinstance(repository_id, int)
        or repository_id < 1
    ):
        raise DomainValidationError("repository_id must be a positive integer")
    if (
        isinstance(pull_number, bool)
        or not isinstance(pull_number, int)
        or pull_number < 1
    ):
        raise DomainValidationError("pull_number must be a positive integer")
    return f"{repository_id}:{pull_number}"


def github_work_record_id(delivery_identifier: str) -> str:
    """Derive a GitHub refresh work identifier without route-name identity."""

    if not isinstance(delivery_identifier, str) or delivery_identifier == "":
        raise DomainValidationError("delivery_identifier must be a non-empty string")
    return str(
        uuid5(
            GITHUB_WORK_IDENTITY_NAMESPACE,
            f"work:{delivery_identifier}:{GITHUB_REFRESH_WORK_TYPE}",
        )
    )


_DIGEST: Final = re.compile(r"^[0-9a-f]{64}$")
_CHECK_LIFECYCLE: Final = {"queued": 0, "in_progress": 1, "completed": 2}
_REVIEW_STATES: Final = {
    "APPROVED",
    "CHANGES_REQUESTED",
    "COMMENTED",
    "PENDING",
    "DISMISSED",
}
SEMANTIC_FACETS: Final = (
    "anchor",
    "files",
    "commits",
    "reviews",
    "requested_reviewers",
    "check_suite_count",
    "check_runs",
    "commit_statuses",
)


class EvidenceNormalizationError(DomainValidationError):
    """Evidence could alter a decision but cannot be normalized safely."""


class RequestedReviewerAmbiguityError(EvidenceNormalizationError):
    """A numeric requested-reviewer identity had conflicting route material."""


class SourceOrderRelation(StrEnum):
    """Candidate relation to the observation currently pointed at."""

    REPLAY = "REPLAY"
    PROGRESSION = "PROGRESSION"
    REGRESSION = "REGRESSION"
    INCOMPARABLE = "INCOMPARABLE"


class _FacetOrder(StrEnum):
    EQUAL = "equal"
    ADVANCE = "advance"
    REGRESS = "regress"
    INCOMPARABLE = "incomparable"


@dataclass(frozen=True, slots=True, order=True)
class RequestedUser:
    user_id: int
    login: str

    def __post_init__(self) -> None:
        _positive(self.user_id, "user_id")
        _text(self.login, "login")

    def as_mapping(self) -> dict[str, object]:
        return {"user_id": self.user_id, "login": self.login}


@dataclass(frozen=True, slots=True, order=True)
class RequestedTeam:
    team_id: int
    slug: str

    def __post_init__(self) -> None:
        _positive(self.team_id, "team_id")
        _text(self.slug, "slug")

    def as_mapping(self) -> dict[str, object]:
        return {"team_id": self.team_id, "slug": self.slug}


@dataclass(frozen=True, slots=True, init=False)
class RequestedReviewers:
    users: tuple[RequestedUser, ...]
    teams: tuple[RequestedTeam, ...]

    def __init__(
        self,
        users: Iterable[RequestedUser] = (),
        teams: Iterable[RequestedTeam] = (),
    ) -> None:
        object.__setattr__(self, "users", _unique_numeric(users, "user_id", "user"))
        object.__setattr__(self, "teams", _unique_numeric(teams, "team_id", "team"))

    def as_mapping(self) -> dict[str, object]:
        return {
            "users": [item.as_mapping() for item in self.users],
            "teams": [item.as_mapping() for item in self.teams],
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> Self:
        _keys(value, {"users", "teams"}, "requested reviewers")
        return cls(
            (
                RequestedUser(
                    _positive(item["user_id"], "user_id"),
                    _text(item["login"], "login"),
                )
                for raw in _list(value["users"], "requested users")
                for item in [_object(raw, "requested user")]
                if not _keys(item, {"user_id", "login"}, "requested user")
            ),
            (
                RequestedTeam(
                    _positive(item["team_id"], "team_id"),
                    _text(item["slug"], "slug"),
                )
                for raw in _list(value["teams"], "requested teams")
                for item in [_object(raw, "requested team")]
                if not _keys(item, {"team_id", "slug"}, "requested team")
            ),
        )


@dataclass(frozen=True, slots=True, order=True)
class FileEvidence:
    sha: str
    filename: str
    status: str
    additions: int
    deletions: int
    changes: int

    def __post_init__(self) -> None:
        _sha(self.sha, "file sha")
        _text(self.filename, "filename")
        _text(self.status, "file status")
        _nonnegative(self.additions, "additions")
        _nonnegative(self.deletions, "deletions")
        _nonnegative(self.changes, "changes")

    def as_mapping(self) -> dict[str, object]:
        return {
            "sha": self.sha,
            "filename": self.filename,
            "status": self.status,
            "additions": self.additions,
            "deletions": self.deletions,
            "changes": self.changes,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> Self:
        _keys(
            value,
            {"sha", "filename", "status", "additions", "deletions", "changes"},
            "file",
        )
        return cls(
            _sha(value["sha"], "file sha"),
            _text(value["filename"], "filename"),
            _text(value["status"], "file status"),
            _nonnegative(value["additions"], "additions"),
            _nonnegative(value["deletions"], "deletions"),
            _nonnegative(value["changes"], "changes"),
        )


@dataclass(frozen=True, slots=True, order=True)
class CommitEvidence:
    sha: str

    def __post_init__(self) -> None:
        _sha(self.sha, "commit sha")

    def as_mapping(self) -> dict[str, object]:
        return {"sha": self.sha}

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> Self:
        _keys(value, {"sha"}, "commit")
        return cls(_sha(value["sha"], "commit sha"))


@dataclass(frozen=True, slots=True)
class NormalizedCommitStatus:
    status_id: int
    head_sha: str
    context: str = field(compare=False)
    state: str
    updated_at: datetime

    def __post_init__(self) -> None:
        _positive(self.status_id, "status_id")
        _sha(self.head_sha, "status head_sha")
        _text(self.context, "status context")
        _text(self.state, "status state")
        _utc(self.updated_at, "status updated_at")

    @property
    def context_key(self) -> str:
        return self.context.casefold()

    def as_mapping(self) -> dict[str, object]:
        """Return decision-relevant status material, excluding display casing."""

        return {
            "status_id": self.status_id,
            "head_sha": self.head_sha,
            "context_key": self.context_key,
            "state": self.state,
            "updated_at": _timestamp(self.updated_at),
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> Self:
        _keys(
            value,
            {"status_id", "head_sha", "context_key", "state", "updated_at"},
            "commit status",
        )
        context = _text(value["context_key"], "status context_key")
        if context != context.casefold():
            raise EvidenceNormalizationError("status context_key was not casefold()")
        return cls(
            _positive(value["status_id"], "status_id"),
            _sha(value["head_sha"], "status head_sha"),
            context,
            _text(value["state"], "status state"),
            _parse_timestamp(value["updated_at"], "status updated_at"),
        )


@dataclass(frozen=True, slots=True)
class NormalizedCheckRun:
    check_run_id: int
    head_sha: str
    producer_app_id: int
    check_name: str
    status: str
    conclusion: str | None
    started_at: datetime | None
    completed_at: datetime | None

    def __post_init__(self) -> None:
        _positive(self.check_run_id, "check_run_id")
        _sha(self.head_sha, "check head_sha")
        _positive(self.producer_app_id, "producer_app_id")
        _text(self.check_name, "check_name")
        if self.status not in _CHECK_LIFECYCLE:
            raise EvidenceNormalizationError("check status was not recognized")
        if self.conclusion is not None:
            _text(self.conclusion, "check conclusion")
        if self.started_at is not None:
            _utc(self.started_at, "check started_at")
        if self.completed_at is not None:
            _utc(self.completed_at, "check completed_at")
        if (
            self.started_at is not None
            and self.completed_at is not None
            and self.completed_at < self.started_at
        ):
            raise EvidenceNormalizationError(
                "check completed_at must not precede started_at"
            )
        if self.status != "completed" and (
            self.conclusion is not None or self.completed_at is not None
        ):
            raise EvidenceNormalizationError(
                "non-completed check carried terminal material"
            )
        if self.status == "completed" and self.conclusion is None:
            raise EvidenceNormalizationError("completed check lacked conclusion")

    @property
    def required_identity(self) -> tuple[int, str]:
        return self.producer_app_id, self.check_name

    def as_mapping(self) -> dict[str, object]:
        return {
            "check_run_id": self.check_run_id,
            "head_sha": self.head_sha,
            "producer_app_id": self.producer_app_id,
            "check_name": self.check_name,
            "status": self.status,
            "conclusion": self.conclusion,
            "started_at": _optional_timestamp(self.started_at),
            "completed_at": _optional_timestamp(self.completed_at),
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> Self:
        _keys(
            value,
            {
                "check_run_id",
                "head_sha",
                "producer_app_id",
                "check_name",
                "status",
                "conclusion",
                "started_at",
                "completed_at",
            },
            "check run",
        )
        return cls(
            _positive(value["check_run_id"], "check_run_id"),
            _sha(value["head_sha"], "check head_sha"),
            _positive(value["producer_app_id"], "producer_app_id"),
            _text(value["check_name"], "check_name"),
            _text(value["status"], "check status"),
            _optional_text(value["conclusion"], "check conclusion"),
            _optional_parsed_timestamp(value["started_at"], "check started_at"),
            _optional_parsed_timestamp(value["completed_at"], "check completed_at"),
        )


@dataclass(frozen=True, slots=True)
class NormalizedReview:
    review_id: int
    reviewer_id: int
    commit_id: str | None
    state: str
    submitted_at: datetime | None
    dismisses_review_id: int | None = None

    def __post_init__(self) -> None:
        _positive(self.review_id, "review_id")
        _positive(self.reviewer_id, "reviewer_id")
        if self.commit_id is not None:
            _sha(self.commit_id, "review commit_id")
        if self.state not in _REVIEW_STATES:
            raise EvidenceNormalizationError("review state was not recognized")
        if self.submitted_at is not None:
            _utc(self.submitted_at, "review submitted_at")
        if self.dismisses_review_id is not None:
            _positive(self.dismisses_review_id, "dismisses_review_id")

    def as_mapping(self) -> dict[str, object]:
        return {
            "review_id": self.review_id,
            "reviewer_id": self.reviewer_id,
            "commit_id": self.commit_id,
            "state": self.state,
            "submitted_at": _optional_timestamp(self.submitted_at),
            "dismisses_review_id": self.dismisses_review_id,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> Self:
        _keys(
            value,
            {
                "review_id",
                "reviewer_id",
                "commit_id",
                "state",
                "submitted_at",
                "dismisses_review_id",
            },
            "review",
        )
        dismissed = value["dismisses_review_id"]
        return cls(
            _positive(value["review_id"], "review_id"),
            _positive(value["reviewer_id"], "reviewer_id"),
            _optional_sha(value["commit_id"], "review commit_id"),
            _text(value["state"], "review state"),
            _optional_parsed_timestamp(value["submitted_at"], "review submitted_at"),
            None if dismissed is None else _positive(dismissed, "dismisses_review_id"),
        )


@dataclass(frozen=True, slots=True, order=True)
class ReducedReviewOpinion:
    reviewer_id: int
    review_id: int
    state: str


@dataclass(frozen=True, slots=True)
class PullRequestAnchor:
    repository_id: int
    pull_number: int
    pull_request_id: int
    head_sha: str
    base_repository_id: int
    base_ref: str
    base_sha: str
    state: str
    draft: bool
    updated_at: datetime
    changed_files: int
    commit_count: int

    def __post_init__(self) -> None:
        _positive(self.repository_id, "repository_id")
        _positive(self.pull_number, "pull_number")
        _positive(self.pull_request_id, "pull_request_id")
        _sha(self.head_sha, "head_sha")
        _positive(self.base_repository_id, "base_repository_id")
        _text(self.base_ref, "base_ref")
        _sha(self.base_sha, "base_sha")
        _text(self.state, "anchor state")
        if not isinstance(self.draft, bool):
            raise EvidenceNormalizationError("draft must be boolean")
        _utc(self.updated_at, "anchor updated_at")
        _nonnegative(self.changed_files, "changed_files")
        _nonnegative(self.commit_count, "commit_count")

    def as_mapping(self) -> dict[str, object]:
        return {
            "repository_id": self.repository_id,
            "pull_number": self.pull_number,
            "pull_request_id": self.pull_request_id,
            "head_sha": self.head_sha,
            "base": {
                "repository_id": self.base_repository_id,
                "ref": self.base_ref,
                "sha": self.base_sha,
            },
            "state": self.state,
            "draft": self.draft,
            "updated_at": _timestamp(self.updated_at),
            "changed_files": self.changed_files,
            "commit_count": self.commit_count,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> Self:
        _keys(
            value,
            {
                "repository_id",
                "pull_number",
                "pull_request_id",
                "head_sha",
                "base",
                "state",
                "draft",
                "updated_at",
                "changed_files",
                "commit_count",
            },
            "anchor",
        )
        base = _object(value["base"], "base")
        _keys(base, {"repository_id", "ref", "sha"}, "base")
        draft = value["draft"]
        if not isinstance(draft, bool):
            raise EvidenceNormalizationError("draft must be boolean")
        return cls(
            _positive(value["repository_id"], "repository_id"),
            _positive(value["pull_number"], "pull_number"),
            _positive(value["pull_request_id"], "pull_request_id"),
            _sha(value["head_sha"], "head_sha"),
            _positive(base["repository_id"], "base repository_id"),
            _text(base["ref"], "base_ref"),
            _sha(base["sha"], "base_sha"),
            _text(value["state"], "anchor state"),
            draft,
            _parse_timestamp(value["updated_at"], "anchor updated_at"),
            _nonnegative(value["changed_files"], "changed_files"),
            _nonnegative(value["commit_count"], "commit_count"),
        )


@dataclass(frozen=True, slots=True, init=False)
class CoherentAnalysisView:
    analysis_view_id: str
    anchor: PullRequestAnchor
    files: tuple[FileEvidence, ...]
    commits: tuple[CommitEvidence, ...]
    files_digest: str
    commits_digest: str
    requested_reviewers: RequestedReviewers
    check_suite_count: int
    check_runs: tuple[NormalizedCheckRun, ...]
    commit_statuses: tuple[NormalizedCommitStatus, ...]
    reviews: tuple[NormalizedReview, ...]
    acquisition_configuration_digest: str
    evidence_sealed_at: datetime
    raw_digest_inventory: tuple[tuple[str, tuple[str, ...]], ...]
    semantic_digest_inventory: tuple[tuple[str, str], ...]
    digest_algorithm: str

    def __init__(
        self,
        *,
        analysis_view_id: str,
        anchor: PullRequestAnchor,
        files: Iterable[FileEvidence],
        commits: Iterable[CommitEvidence],
        files_digest: str,
        commits_digest: str,
        requested_reviewers: RequestedReviewers,
        check_suite_count: int,
        check_runs: Iterable[NormalizedCheckRun],
        commit_statuses: Iterable[NormalizedCommitStatus],
        reviews: Iterable[NormalizedReview],
        acquisition_configuration_digest: str,
        evidence_sealed_at: datetime,
        raw_digest_inventory: Mapping[str, Sequence[str]]
        | Iterable[tuple[str, Sequence[str]]],
        semantic_digest_inventory: Mapping[str, str] | Iterable[tuple[str, str]],
        digest_algorithm: str = DIGEST_FORMAT,
    ) -> None:
        _text(analysis_view_id, "analysis_view_id")
        if not isinstance(anchor, PullRequestAnchor):
            raise EvidenceNormalizationError("anchor must be PullRequestAnchor")
        normalized_files = tuple(files)
        normalized_commits = tuple(commits)
        if not all(isinstance(item, FileEvidence) for item in normalized_files):
            raise EvidenceNormalizationError("files contained an invalid value")
        if not all(isinstance(item, CommitEvidence) for item in normalized_commits):
            raise EvidenceNormalizationError("commits contained an invalid value")
        normalized_files = tuple(sorted(normalized_files))
        _digest(files_digest, "files_digest")
        _digest(commits_digest, "commits_digest")
        if not isinstance(requested_reviewers, RequestedReviewers):
            raise EvidenceNormalizationError(
                "requested_reviewers must be RequestedReviewers"
            )
        _nonnegative(check_suite_count, "check_suite_count")
        checks = normalize_check_runs(check_runs)
        statuses = normalize_commit_statuses(commit_statuses)
        normalized_reviews = normalize_reviews(reviews)
        _digest(acquisition_configuration_digest, "acquisition digest")
        _utc(evidence_sealed_at, "evidence_sealed_at")
        if digest_algorithm != DIGEST_FORMAT:
            raise EvidenceNormalizationError(
                f"digest_algorithm must be {DIGEST_FORMAT}"
            )
        raw_items = (
            raw_digest_inventory.items()
            if isinstance(raw_digest_inventory, Mapping)
            else raw_digest_inventory
        )
        raw: dict[str, tuple[str, ...]] = {}
        for role, values in raw_items:
            _text(role, "raw digest role")
            digests = tuple(values)
            if not digests:
                raise EvidenceNormalizationError("raw digest inventory was empty")
            for value in digests:
                _digest(value, "raw digest")
            if role in raw and raw[role] != digests:
                raise EvidenceNormalizationError("raw digest role was duplicated")
            raw[role] = digests
        semantic_items = (
            semantic_digest_inventory.items()
            if isinstance(semantic_digest_inventory, Mapping)
            else semantic_digest_inventory
        )
        semantic = dict(semantic_items)
        if set(semantic) != set(SEMANTIC_FACETS):
            raise EvidenceNormalizationError(
                "semantic digest inventory did not contain every required facet"
            )
        for value in semantic.values():
            _digest(value, "semantic digest")

        object.__setattr__(self, "analysis_view_id", analysis_view_id)
        object.__setattr__(self, "anchor", anchor)
        object.__setattr__(self, "files", normalized_files)
        object.__setattr__(self, "commits", normalized_commits)
        object.__setattr__(self, "files_digest", files_digest)
        object.__setattr__(self, "commits_digest", commits_digest)
        object.__setattr__(self, "requested_reviewers", requested_reviewers)
        object.__setattr__(self, "check_suite_count", check_suite_count)
        object.__setattr__(self, "check_runs", checks)
        object.__setattr__(self, "commit_statuses", statuses)
        object.__setattr__(self, "reviews", normalized_reviews)
        object.__setattr__(
            self, "acquisition_configuration_digest", acquisition_configuration_digest
        )
        object.__setattr__(self, "evidence_sealed_at", evidence_sealed_at)
        object.__setattr__(self, "raw_digest_inventory", tuple(sorted(raw.items())))
        object.__setattr__(
            self, "semantic_digest_inventory", tuple(sorted(semantic.items()))
        )
        object.__setattr__(self, "digest_algorithm", digest_algorithm)

    def as_mapping(self) -> dict[str, object]:
        return {
            "schema": "github-steward/coherent-analysis-view/v1",
            "analysis_view_id": self.analysis_view_id,
            "digest_algorithm": self.digest_algorithm,
            "anchor": self.anchor.as_mapping(),
            "facets": {
                "files": [item.as_mapping() for item in self.files],
                "commits": [item.as_mapping() for item in self.commits],
                "reviews": [item.as_mapping() for item in self.reviews],
                "requested_reviewers": self.requested_reviewers.as_mapping(),
                "check_suite_count": self.check_suite_count,
                "check_runs": [item.as_mapping() for item in self.check_runs],
                "commit_statuses": [item.as_mapping() for item in self.commit_statuses],
            },
            "files_digest": self.files_digest,
            "commits_digest": self.commits_digest,
            "acquisition_configuration_digest": self.acquisition_configuration_digest,
            "evidence_sealed_at": _timestamp(self.evidence_sealed_at),
            "raw_digest_inventory": {
                role: list(values) for role, values in self.raw_digest_inventory
            },
            "semantic_digest_inventory": dict(self.semantic_digest_inventory),
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> Self:
        _keys(
            value,
            {
                "schema",
                "analysis_view_id",
                "digest_algorithm",
                "anchor",
                "facets",
                "files_digest",
                "commits_digest",
                "acquisition_configuration_digest",
                "evidence_sealed_at",
                "raw_digest_inventory",
                "semantic_digest_inventory",
            },
            "coherent analysis view",
        )
        if value["schema"] != "github-steward/coherent-analysis-view/v1":
            raise EvidenceNormalizationError("analysis view schema was not v1")
        facets = _object(value["facets"], "facets")
        _keys(
            facets,
            {
                "files",
                "commits",
                "reviews",
                "requested_reviewers",
                "check_suite_count",
                "check_runs",
                "commit_statuses",
            },
            "facets",
        )
        raw_inventory = _object(value["raw_digest_inventory"], "raw inventory")
        semantic_inventory = _object(
            value["semantic_digest_inventory"], "semantic inventory"
        )
        return cls(
            analysis_view_id=_text(value["analysis_view_id"], "analysis_view_id"),
            anchor=PullRequestAnchor.from_mapping(_object(value["anchor"], "anchor")),
            files=(
                FileEvidence.from_mapping(_object(item, "file"))
                for item in _list(facets["files"], "files")
            ),
            commits=(
                CommitEvidence.from_mapping(_object(item, "commit"))
                for item in _list(facets["commits"], "commits")
            ),
            files_digest=_digest(value["files_digest"], "files_digest"),
            commits_digest=_digest(value["commits_digest"], "commits_digest"),
            requested_reviewers=RequestedReviewers.from_mapping(
                _object(facets["requested_reviewers"], "requested reviewers")
            ),
            check_suite_count=_nonnegative(
                facets["check_suite_count"], "check_suite_count"
            ),
            check_runs=(
                NormalizedCheckRun.from_mapping(_object(item, "check run"))
                for item in _list(facets["check_runs"], "check runs")
            ),
            commit_statuses=(
                NormalizedCommitStatus.from_mapping(_object(item, "commit status"))
                for item in _list(facets["commit_statuses"], "commit statuses")
            ),
            reviews=(
                NormalizedReview.from_mapping(_object(item, "review"))
                for item in _list(facets["reviews"], "reviews")
            ),
            acquisition_configuration_digest=_digest(
                value["acquisition_configuration_digest"], "acquisition digest"
            ),
            evidence_sealed_at=_parse_timestamp(
                value["evidence_sealed_at"], "evidence_sealed_at"
            ),
            raw_digest_inventory={
                role: tuple(
                    _digest(item, "raw digest") for item in _list(items, "raw digests")
                )
                for role, items in raw_inventory.items()
            },
            semantic_digest_inventory={
                role: _digest(digest, "semantic digest")
                for role, digest in semantic_inventory.items()
            },
            digest_algorithm=_text(value["digest_algorithm"], "digest_algorithm"),
        )


def normalize_commit_statuses(
    statuses: Iterable[NormalizedCommitStatus],
) -> tuple[NormalizedCommitStatus, ...]:
    unique_by_id: dict[int, NormalizedCommitStatus] = {}
    for status in statuses:
        if not isinstance(status, NormalizedCommitStatus):
            raise EvidenceNormalizationError(
                "commit status collection contained an invalid value"
            )
        previous = unique_by_id.get(status.status_id)
        if previous is not None and _status_semantic_key(previous) != (
            _status_semantic_key(status)
        ):
            raise EvidenceNormalizationError(
                "commit status had contradictory immutable identity"
            )
        if previous is None or status.context < previous.context:
            unique_by_id[status.status_id] = status
    unique = tuple(unique_by_id.values())
    return tuple(
        sorted(
            unique,
            key=lambda item: (item.context_key, item.updated_at, item.status_id),
        )
    )


def latest_commit_statuses(
    statuses: Iterable[NormalizedCommitStatus],
) -> Mapping[str, NormalizedCommitStatus]:
    latest: dict[str, NormalizedCommitStatus] = {}
    for status in normalize_commit_statuses(statuses):
        # Normalization sorts each context by its exact remote watermark.
        latest[status.context_key] = status
    return latest


def normalize_check_runs(
    checks: Iterable[NormalizedCheckRun],
) -> tuple[NormalizedCheckRun, ...]:
    unique = _unique_immutable(checks, "check_run_id", "check run")
    return tuple(
        sorted(
            unique,
            key=lambda item: (item.producer_app_id, item.check_name, item.check_run_id),
        )
    )


def normalize_reviews(
    reviews: Iterable[NormalizedReview],
) -> tuple[NormalizedReview, ...]:
    unique = _unique_immutable(reviews, "review_id", "review")
    return tuple(sorted(unique, key=lambda item: item.review_id))


def reduce_current_head_reviews(
    reviews: Iterable[NormalizedReview],
    head_sha: str,
) -> tuple[ReducedReviewOpinion, ...]:
    """Reduce current-head opinion history; neutral events never clear opinions."""

    _sha(head_sha, "head_sha")
    current = [
        review for review in normalize_reviews(reviews) if review.commit_id == head_sha
    ]
    if any(review.commit_id is None for review in normalize_reviews(reviews)):
        raise EvidenceNormalizationError(
            "review without commit_id could hide a blocker"
        )
    if any(review.submitted_at is None for review in current):
        raise EvidenceNormalizationError(
            "current-head review lacked deterministic remote ordering"
        )
    ordered = sorted(
        current,
        key=lambda item: (cast(datetime, item.submitted_at), item.review_id),
    )
    active: dict[int, NormalizedReview] = {}
    opinions_by_id: dict[int, NormalizedReview] = {}
    for review in ordered:
        if review.state in {"APPROVED", "CHANGES_REQUESTED"}:
            if review.dismisses_review_id is not None:
                raise EvidenceNormalizationError(
                    "opinion review also dismissed a review"
                )
            active[review.reviewer_id] = review
            opinions_by_id[review.review_id] = review
        elif review.state in {"COMMENTED", "PENDING"}:
            if review.dismisses_review_id is not None:
                raise EvidenceNormalizationError("neutral review carried dismissal")
        else:  # NormalizedReview restricts the remaining state to DISMISSED.
            target_id = review.dismisses_review_id
            if target_id is None:
                raise EvidenceNormalizationError(
                    "dismissal did not identify its target"
                )
            target = opinions_by_id.get(target_id)
            if target is None or target.reviewer_id != review.reviewer_id:
                raise EvidenceNormalizationError("dismissal target was ambiguous")
            if active.get(review.reviewer_id) == target:
                del active[review.reviewer_id]
    return tuple(
        ReducedReviewOpinion(reviewer, review.review_id, review.state)
        for reviewer, review in sorted(active.items())
    )


def compare_source_order(
    current: CoherentAnalysisView,
    candidate: CoherentAnalysisView,
) -> SourceOrderRelation:
    """Compare candidate evidence to current evidence without local-time ordering."""

    if (
        current.anchor.repository_id,
        current.anchor.pull_number,
        current.anchor.pull_request_id,
    ) != (
        candidate.anchor.repository_id,
        candidate.anchor.pull_number,
        candidate.anchor.pull_request_id,
    ):
        return SourceOrderRelation.INCOMPARABLE
    if current.anchor.head_sha != candidate.anchor.head_sha:
        if candidate.anchor.updated_at > current.anchor.updated_at:
            return SourceOrderRelation.PROGRESSION
        if candidate.anchor.updated_at < current.anchor.updated_at:
            return SourceOrderRelation.REGRESSION
        return SourceOrderRelation.INCOMPARABLE

    anchor_relation = _compare_anchor(current.anchor, candidate.anchor)
    relations = [
        anchor_relation,
        _FacetOrder.EQUAL
        if current.files_digest == candidate.files_digest
        else _FacetOrder.INCOMPARABLE,
        _FacetOrder.EQUAL
        if current.commits_digest == candidate.commits_digest
        else _FacetOrder.INCOMPARABLE,
        _compare_statuses(current.commit_statuses, candidate.commit_statuses),
        _compare_checks(current.check_runs, candidate.check_runs),
        _compare_reviews(current.reviews, candidate.reviews),
        _compare_requested_reviewers(
            current.requested_reviewers,
            candidate.requested_reviewers,
            anchor_relation,
        ),
        _compare_count(current.check_suite_count, candidate.check_suite_count),
    ]
    return _aggregate(relations)


def _compare_anchor(
    current: PullRequestAnchor, candidate: PullRequestAnchor
) -> _FacetOrder:
    if current == candidate:
        return _FacetOrder.EQUAL
    if candidate.updated_at > current.updated_at:
        return _FacetOrder.ADVANCE
    if candidate.updated_at < current.updated_at:
        return _FacetOrder.REGRESS
    return _FacetOrder.INCOMPARABLE


def _compare_statuses(
    current_values: Sequence[NormalizedCommitStatus],
    candidate_values: Sequence[NormalizedCommitStatus],
) -> _FacetOrder:
    current_by_id = {item.status_id: item for item in current_values}
    candidate_by_id = {item.status_id: item for item in candidate_values}
    if any(
        _status_semantic_key(current_by_id[identifier])
        != _status_semantic_key(candidate_by_id[identifier])
        for identifier in set(current_by_id) & set(candidate_by_id)
    ):
        return _FacetOrder.INCOMPARABLE
    relations: list[_FacetOrder] = []
    contexts = {
        item.context_key for item in (*tuple(current_values), *tuple(candidate_values))
    }
    for context in sorted(contexts):
        before_values = {
            item.status_id: item
            for item in current_values
            if item.context_key == context
        }
        after_values = {
            item.status_id: item
            for item in candidate_values
            if item.context_key == context
        }
        removed = set(before_values) - set(after_values)
        added = set(after_values) - set(before_values)
        if not removed and not added:
            relations.append(_FacetOrder.EQUAL)
            continue
        if not before_values:
            relations.append(_FacetOrder.ADVANCE)
            continue
        if not after_values:
            relations.append(_FacetOrder.REGRESS)
            continue
        before = max(
            before_values.values(), key=lambda item: (item.updated_at, item.status_id)
        )
        after = max(
            after_values.values(), key=lambda item: (item.updated_at, item.status_id)
        )
        before_key = before.updated_at, before.status_id
        after_key = after.updated_at, after.status_id
        if removed:
            if not added or after_key < before_key:
                relations.append(_FacetOrder.REGRESS)
            else:
                relations.append(_FacetOrder.INCOMPARABLE)
            continue
        if all(
            (after_values[identifier].updated_at, identifier) > before_key
            for identifier in added
        ):
            relations.append(_FacetOrder.ADVANCE)
        else:
            # An older immutable status appearing behind an unchanged watermark
            # does not carry enough remote order to prove progression.
            relations.append(_FacetOrder.INCOMPARABLE)
    return _aggregate_facet(relations)


def _status_semantic_key(status: NormalizedCommitStatus) -> tuple[object, ...]:
    return (
        status.status_id,
        status.head_sha,
        status.context_key,
        status.state,
        status.updated_at,
    )


def _compare_checks(
    current_values: Sequence[NormalizedCheckRun],
    candidate_values: Sequence[NormalizedCheckRun],
) -> _FacetOrder:
    current_by_id = {item.check_run_id: item for item in current_values}
    candidate_by_id = {item.check_run_id: item for item in candidate_values}
    relations: list[_FacetOrder] = []
    for identifier in set(current_by_id) & set(candidate_by_id):
        relation = _compare_same_check_run(
            current_by_id[identifier], candidate_by_id[identifier]
        )
        if relation is _FacetOrder.INCOMPARABLE:
            return _FacetOrder.INCOMPARABLE
        relations.append(relation)

    identities = {
        item.required_identity
        for item in (*tuple(current_values), *tuple(candidate_values))
    }
    for identity in sorted(identities):
        try:
            previous_check = _latest_check(
                [item for item in current_values if item.required_identity == identity]
            )
            candidate_check = _latest_check(
                [
                    item
                    for item in candidate_values
                    if item.required_identity == identity
                ]
            )
        except EvidenceNormalizationError:
            return _FacetOrder.INCOMPARABLE
        if previous_check is None:
            relations.append(_FacetOrder.ADVANCE)
        elif candidate_check is None:
            relations.append(_FacetOrder.REGRESS)
        elif previous_check.check_run_id == candidate_check.check_run_id:
            # The shared immutable run was already compared above. This relation
            # only records that it remains the selected generation.
            relations.append(_FacetOrder.EQUAL)
        else:
            before_key = _generation_key(previous_check)
            after_key = _generation_key(candidate_check)
            if before_key is None or after_key is None:
                relations.append(_FacetOrder.INCOMPARABLE)
            elif after_key > before_key:
                relations.append(_FacetOrder.ADVANCE)
            else:
                relations.append(_FacetOrder.REGRESS)
    return _aggregate_facet(relations)


def _compare_same_check_run(
    before: NormalizedCheckRun,
    after: NormalizedCheckRun,
) -> _FacetOrder:
    if (
        before.required_identity != after.required_identity
        or before.head_sha != after.head_sha
    ):
        return _FacetOrder.INCOMPARABLE
    before_rank = _CHECK_LIFECYCLE[before.status]
    after_rank = _CHECK_LIFECYCLE[after.status]
    if before.started_at is not None and after.started_at is not None:
        if before.started_at != after.started_at:
            return _FacetOrder.INCOMPARABLE
    elif before.started_at is None and after.started_at is not None:
        if after_rank <= before_rank:
            return _FacetOrder.INCOMPARABLE
    elif (
        before.started_at is not None
        and after.started_at is None
        and after_rank >= before_rank
    ):
        return _FacetOrder.INCOMPARABLE
    if before == after:
        return _FacetOrder.EQUAL
    if after_rank > before_rank:
        return _FacetOrder.ADVANCE
    if after_rank < before_rank:
        return _FacetOrder.REGRESS
    return _FacetOrder.INCOMPARABLE


def _latest_check(values: Sequence[NormalizedCheckRun]) -> NormalizedCheckRun | None:
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    keys = [_generation_key(item) for item in values]
    if any(key is None for key in keys):
        raise EvidenceNormalizationError("check generation order was unprovable")
    return max(
        values, key=lambda item: cast(tuple[datetime, int], _generation_key(item))
    )


def _generation_key(value: NormalizedCheckRun) -> tuple[datetime, int] | None:
    remote_time = value.started_at
    if remote_time is None:
        return None
    return remote_time, value.check_run_id


def _compare_reviews(
    current_values: Sequence[NormalizedReview],
    candidate_values: Sequence[NormalizedReview],
) -> _FacetOrder:
    if not _review_history_is_orderable(
        current_values
    ) or not _review_history_is_orderable(candidate_values):
        return _FacetOrder.INCOMPARABLE
    current = {item.review_id: item for item in current_values}
    candidate = {item.review_id: item for item in candidate_values}
    common = set(current) & set(candidate)
    if any(current[item] != candidate[item] for item in common):
        return _FacetOrder.INCOMPARABLE
    disappeared = set(current) - set(candidate)
    added = set(candidate) - set(current)
    if disappeared and added:
        return _FacetOrder.INCOMPARABLE
    if disappeared:
        return _FacetOrder.REGRESS
    if not added:
        return _FacetOrder.EQUAL
    additions = [candidate[item] for item in added]
    current_keys = [
        (cast(datetime, item.submitted_at), item.review_id) for item in current.values()
    ]
    if current_keys and min(
        (cast(datetime, item.submitted_at), item.review_id) for item in additions
    ) <= max(current_keys):
        return _FacetOrder.INCOMPARABLE
    return _FacetOrder.ADVANCE


def _review_history_is_orderable(values: Sequence[NormalizedReview]) -> bool:
    try:
        normalized = normalize_reviews(values)
        if any(item.commit_id is None for item in normalized):
            return False
        for head_sha in {cast(str, item.commit_id) for item in normalized}:
            reduce_current_head_reviews(normalized, head_sha)
    except EvidenceNormalizationError:
        return False
    return True


def _compare_requested_reviewers(
    current: RequestedReviewers,
    candidate: RequestedReviewers,
    anchor_relation: _FacetOrder,
) -> _FacetOrder:
    current_identity = (
        tuple(item.user_id for item in current.users),
        tuple(item.team_id for item in current.teams),
    )
    candidate_identity = (
        tuple(item.user_id for item in candidate.users),
        tuple(item.team_id for item in candidate.teams),
    )
    if current_identity == candidate_identity:
        return _FacetOrder.EQUAL
    if anchor_relation is _FacetOrder.ADVANCE:
        return _FacetOrder.ADVANCE
    return _FacetOrder.INCOMPARABLE


def _compare_count(current: int, candidate: int) -> _FacetOrder:
    if candidate == current:
        return _FacetOrder.EQUAL
    if candidate > current:
        return _FacetOrder.ADVANCE
    return _FacetOrder.REGRESS


def _aggregate(values: Sequence[_FacetOrder]) -> SourceOrderRelation:
    relation = _aggregate_facet(values)
    return {
        _FacetOrder.EQUAL: SourceOrderRelation.REPLAY,
        _FacetOrder.ADVANCE: SourceOrderRelation.PROGRESSION,
        _FacetOrder.REGRESS: SourceOrderRelation.REGRESSION,
        _FacetOrder.INCOMPARABLE: SourceOrderRelation.INCOMPARABLE,
    }[relation]


def _aggregate_facet(values: Sequence[_FacetOrder]) -> _FacetOrder:
    if _FacetOrder.INCOMPARABLE in values:
        return _FacetOrder.INCOMPARABLE
    advances = _FacetOrder.ADVANCE in values
    regressions = _FacetOrder.REGRESS in values
    if advances and regressions:
        return _FacetOrder.INCOMPARABLE
    if advances:
        return _FacetOrder.ADVANCE
    if regressions:
        return _FacetOrder.REGRESS
    return _FacetOrder.EQUAL


def _unique_numeric[ItemT](
    values: Iterable[ItemT],
    attribute: str,
    label: str,
) -> tuple[ItemT, ...]:
    unique: dict[int, ItemT] = {}
    for value in values:
        identifier = cast(int, getattr(value, attribute, None))
        previous = unique.get(identifier)
        if previous is not None and previous != value:
            raise RequestedReviewerAmbiguityError(
                f"conflicting duplicate numeric {label} identity"
            )
        unique[identifier] = value
    return tuple(unique[key] for key in sorted(unique))


def _unique_immutable[ItemT](
    values: Iterable[ItemT],
    attribute: str,
    label: str,
) -> tuple[ItemT, ...]:
    unique: dict[int, ItemT] = {}
    for value in values:
        identifier = cast(int, getattr(value, attribute, None))
        previous = unique.get(identifier)
        if previous is not None and previous != value:
            raise EvidenceNormalizationError(
                f"contradictory immutable {label} identity"
            )
        unique[identifier] = value
    return tuple(unique.values())


def _keys(value: Mapping[str, object], expected: set[str], label: str) -> bool:
    if set(value) != expected:
        raise EvidenceNormalizationError(f"{label} keys were not exact")
    return False


def _object(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise EvidenceNormalizationError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, (list, tuple)):
        raise EvidenceNormalizationError(f"{label} must be an array")
    return list(cast(Sequence[object], value))


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or value == "":
        raise EvidenceNormalizationError(f"{label} must be non-empty text")
    return value


def _optional_text(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _text(value, label)


def _positive(value: object, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > MAX_SAFE_INTEGER
    ):
        raise EvidenceNormalizationError(f"{label} must be a positive JCS-safe integer")
    return value


def _nonnegative(value: object, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > MAX_SAFE_INTEGER
    ):
        raise EvidenceNormalizationError(
            f"{label} must be a nonnegative JCS-safe integer"
        )
    return value


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise EvidenceNormalizationError(f"{label} must be a lowercase 40-hex SHA")
    return value


def _optional_sha(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _sha(value, label)


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise EvidenceNormalizationError(f"{label} must be lowercase SHA-256")
    return value


def _utc(value: object, label: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise EvidenceNormalizationError(f"{label} must be timezone-aware UTC")
    return value


def _timestamp(value: datetime) -> str:
    return _utc(value, "timestamp").astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _optional_timestamp(value: datetime | None) -> str | None:
    return None if value is None else _timestamp(value)


def _parse_timestamp(value: object, label: str) -> datetime:
    text = _text(value, label)
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise EvidenceNormalizationError(
            f"{label} was not a fixed UTC timestamp"
        ) from exc
    return parsed


def _optional_parsed_timestamp(value: object, label: str) -> datetime | None:
    return None if value is None else _parse_timestamp(value, label)
