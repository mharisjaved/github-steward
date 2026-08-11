"""Deterministic, fail-closed GS-I4 preparedness contracts."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final, cast
from uuid import UUID, uuid5

from github_steward.domain.canonical import (
    DIGEST_FORMAT,
    MAX_SAFE_INTEGER,
    CanonicalValue,
    Digest,
    freeze_canonical_value,
    to_json_compatible,
)
from github_steward.domain.errors import DomainValidationError

PREPAREDNESS_PROFILE_SCHEMA_ID: Final = "github-steward/preparedness-profile/v1"
PREPAREDNESS_ASSESSMENT_SCHEMA_ID: Final = "github-steward/preparedness-assessment/v1"
PREPAREDNESS_FRESHNESS_SECONDS: Final = 600
PREPAREDNESS_IDENTITY_NAMESPACE: Final = UUID("7a711868-68ca-5cab-bc89-2528753d43bc")
ACCEPTED_CHECK_CONCLUSIONS: Final = frozenset({"neutral", "skipped", "success"})
_KNOWN_UNSUCCESSFUL_CHECK_CONCLUSIONS: Final = frozenset(
    {
        "action_required",
        "cancelled",
        "failure",
        "stale",
        "startup_failure",
        "timed_out",
    }
)
_SHA: Final = re.compile(r"^[0-9a-f]{40}$")


class PreparednessVerdict(StrEnum):
    """The complete PreparednessAssessment v1 verdict vocabulary."""

    READY_FOR_HUMAN_REVIEW = "READY_FOR_HUMAN_REVIEW"
    NOT_READY = "NOT_READY"
    INDETERMINATE = "INDETERMINATE"


class FreshnessResult(StrEnum):
    """Deterministic evidence-clock classification."""

    FRESH = "FRESH"
    STALE = "STALE"
    CLOCK_ANOMALY = "CLOCK_ANOMALY"


class PreparednessReasonCode(StrEnum):
    """Stable deterministic assessment reason vocabulary."""

    EVIDENCE_INCOMPLETE = "EVIDENCE_INCOMPLETE"
    EVIDENCE_UNSTABLE = "EVIDENCE_UNSTABLE"
    EVIDENCE_STALE = "EVIDENCE_STALE"
    EVIDENCE_CLOCK_ANOMALY = "EVIDENCE_CLOCK_ANOMALY"
    EVIDENCE_PERMISSION_DENIED = "EVIDENCE_PERMISSION_DENIED"
    EVIDENCE_RATE_LIMITED = "EVIDENCE_RATE_LIMITED"
    EVIDENCE_CAP_EXCEEDED = "EVIDENCE_CAP_EXCEEDED"
    EVIDENCE_ROUTE_FAILURE = "EVIDENCE_ROUTE_FAILURE"
    EVIDENCE_MALFORMED_RESPONSE = "EVIDENCE_MALFORMED_RESPONSE"
    EVIDENCE_PAGINATION_UNCERTAIN = "EVIDENCE_PAGINATION_UNCERTAIN"
    EVIDENCE_TRANSPORT_UNCERTAIN = "EVIDENCE_TRANSPORT_UNCERTAIN"
    EVIDENCE_TOTAL_COUNT_INCONSISTENT = "EVIDENCE_TOTAL_COUNT_INCONSISTENT"
    EVIDENCE_COHERENCE_UNCERTAIN = "EVIDENCE_COHERENCE_UNCERTAIN"
    EVIDENCE_IDENTITY_MISMATCH = "EVIDENCE_IDENTITY_MISMATCH"
    ACQUISITION_CONFIGURATION_MISMATCH = "ACQUISITION_CONFIGURATION_MISMATCH"
    PROFILE_REPOSITORY_MISMATCH = "PROFILE_REPOSITORY_MISMATCH"
    PROFILE_NOT_APPLICABLE = "PROFILE_NOT_APPLICABLE"
    CHECK_AMBIGUITY = "CHECK_AMBIGUITY"
    STATUS_AMBIGUITY = "STATUS_AMBIGUITY"
    REVIEW_AMBIGUITY = "REVIEW_AMBIGUITY"
    REQUESTED_REVIEWER_AMBIGUITY = "REQUESTED_REVIEWER_AMBIGUITY"

    PR_CLOSED = "PR_CLOSED"
    PR_DRAFT = "PR_DRAFT"
    REQUIRED_CHECK_MISSING = "REQUIRED_CHECK_MISSING"
    REQUIRED_CHECK_PENDING = "REQUIRED_CHECK_PENDING"
    REQUIRED_CHECK_UNSUCCESSFUL = "REQUIRED_CHECK_UNSUCCESSFUL"
    REQUIRED_STATUS_MISSING = "REQUIRED_STATUS_MISSING"
    REQUIRED_STATUS_PENDING = "REQUIRED_STATUS_PENDING"
    REQUIRED_STATUS_FAILURE = "REQUIRED_STATUS_FAILURE"
    REQUIRED_STATUS_ERROR = "REQUIRED_STATUS_ERROR"
    CURRENT_HEAD_CHANGES_REQUESTED = "CURRENT_HEAD_CHANGES_REQUESTED"


_INDETERMINATE_REASONS: Final = frozenset(
    {
        PreparednessReasonCode.EVIDENCE_INCOMPLETE,
        PreparednessReasonCode.EVIDENCE_UNSTABLE,
        PreparednessReasonCode.EVIDENCE_STALE,
        PreparednessReasonCode.EVIDENCE_CLOCK_ANOMALY,
        PreparednessReasonCode.EVIDENCE_PERMISSION_DENIED,
        PreparednessReasonCode.EVIDENCE_RATE_LIMITED,
        PreparednessReasonCode.EVIDENCE_CAP_EXCEEDED,
        PreparednessReasonCode.EVIDENCE_ROUTE_FAILURE,
        PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE,
        PreparednessReasonCode.EVIDENCE_PAGINATION_UNCERTAIN,
        PreparednessReasonCode.EVIDENCE_TRANSPORT_UNCERTAIN,
        PreparednessReasonCode.EVIDENCE_TOTAL_COUNT_INCONSISTENT,
        PreparednessReasonCode.EVIDENCE_COHERENCE_UNCERTAIN,
        PreparednessReasonCode.EVIDENCE_IDENTITY_MISMATCH,
        PreparednessReasonCode.ACQUISITION_CONFIGURATION_MISMATCH,
        PreparednessReasonCode.PROFILE_REPOSITORY_MISMATCH,
        PreparednessReasonCode.PROFILE_NOT_APPLICABLE,
        PreparednessReasonCode.CHECK_AMBIGUITY,
        PreparednessReasonCode.STATUS_AMBIGUITY,
        PreparednessReasonCode.REVIEW_AMBIGUITY,
        PreparednessReasonCode.REQUESTED_REVIEWER_AMBIGUITY,
    }
)
_REASON_RANK: Final = {
    reason: rank for rank, reason in enumerate(PreparednessReasonCode)
}


@dataclass(frozen=True, slots=True, order=True)
class ProfileIdentity:
    """An exact version of one stable logical profile UUID."""

    profile_id: UUID
    version: int

    def __post_init__(self) -> None:
        if not isinstance(self.profile_id, UUID):
            raise DomainValidationError("profile_id must be a UUID")
        _positive_integer(self.version, "profile version")

    def as_mapping(self) -> dict[str, object]:
        return {"profile_id": str(self.profile_id), "version": self.version}


@dataclass(frozen=True, slots=True, order=True)
class RequiredCheck:
    """One exact GitHub check identity."""

    producer_app_id: int
    check_name: str

    def __post_init__(self) -> None:
        _positive_integer(self.producer_app_id, "producer_app_id")
        _nonempty_text(self.check_name, "check_name")

    def as_mapping(self) -> dict[str, object]:
        return {
            "producer_app_id": self.producer_app_id,
            "check_name": self.check_name,
        }


@dataclass(frozen=True, slots=True, order=True)
class RequiredStatus:
    """One status requirement retaining its exact display context."""

    context: str
    context_key: str = ""

    def __post_init__(self) -> None:
        _nonempty_text(self.context, "status context")
        calculated = self.context.casefold()
        if self.context_key not in ("", calculated):
            raise DomainValidationError("context_key must equal context.casefold()")
        object.__setattr__(self, "context_key", calculated)

    def as_mapping(self) -> dict[str, object]:
        return {"context": self.context, "context_key": self.context_key}


@dataclass(frozen=True, slots=True)
class PullRequestIdentity:
    """Expected or observed semantic repository and pull-request identity."""

    repository_id: int
    pull_request_id: int
    pull_number: int
    head_sha: str
    base_repository_id: int
    base_ref: str
    base_sha: str

    def __post_init__(self) -> None:
        _positive_integer(self.repository_id, "repository_id")
        _positive_integer(self.pull_request_id, "pull_request_id")
        _positive_integer(self.pull_number, "pull_number")
        _sha(self.head_sha, "head_sha")
        _positive_integer(self.base_repository_id, "base_repository_id")
        _nonempty_text(self.base_ref, "base_ref")
        _sha(self.base_sha, "base_sha")

    def as_mapping(self) -> dict[str, object]:
        return {
            "repository_id": self.repository_id,
            "pull_request_id": self.pull_request_id,
            "pull_number": self.pull_number,
            "head_sha": self.head_sha,
            "base": {
                "repository_id": self.base_repository_id,
                "ref": self.base_ref,
                "sha": self.base_sha,
            },
        }


@dataclass(frozen=True, slots=True)
class CommitStatusEvidence:
    """One normalized exact-head commit status."""

    status_id: int
    head_sha: str
    context: str
    state: str
    updated_at: datetime
    context_key: str = ""

    def __post_init__(self) -> None:
        _positive_integer(self.status_id, "status_id")
        _sha(self.head_sha, "status head_sha")
        _nonempty_text(self.context, "status context")
        _nonempty_text(self.state, "status state")
        _utc_datetime(self.updated_at, "status updated_at")
        calculated = self.context.casefold()
        if self.context_key not in ("", calculated):
            raise DomainValidationError("context_key must equal context.casefold()")
        object.__setattr__(self, "context_key", calculated)


@dataclass(frozen=True, slots=True)
class CheckRunEvidence:
    """One normalized exact-head check-run generation."""

    check_run_id: int
    head_sha: str
    producer_app_id: int
    check_name: str
    status: str
    conclusion: str | None
    started_at: datetime | None
    completed_at: datetime | None = None

    def __post_init__(self) -> None:
        _positive_integer(self.check_run_id, "check_run_id")
        _sha(self.head_sha, "check-run head_sha")
        _positive_integer(self.producer_app_id, "producer_app_id")
        _nonempty_text(self.check_name, "check_name")
        _nonempty_text(self.status, "check status")
        if self.conclusion is not None:
            _nonempty_text(self.conclusion, "check conclusion")
        if self.started_at is not None:
            _utc_datetime(self.started_at, "check started_at")
        if self.completed_at is not None:
            _utc_datetime(self.completed_at, "check completed_at")
        if (
            self.started_at is not None
            and self.completed_at is not None
            and self.completed_at < self.started_at
        ):
            raise DomainValidationError(
                "check completed_at must not precede started_at"
            )

    @property
    def identity(self) -> RequiredCheck:
        return RequiredCheck(self.producer_app_id, self.check_name)


@dataclass(frozen=True, slots=True)
class ReviewEvidence:
    """One normalized review opinion, neutral event, or dismissal event."""

    review_id: int
    reviewer_id: int
    commit_id: str | None
    state: str
    submitted_at: datetime | None
    dismisses_review_id: int | None = None

    def __post_init__(self) -> None:
        _positive_integer(self.review_id, "review_id")
        _positive_integer(self.reviewer_id, "reviewer_id")
        if self.commit_id is not None:
            _nonempty_text(self.commit_id, "review commit_id")
        _nonempty_text(self.state, "review state")
        if self.submitted_at is not None:
            _utc_datetime(self.submitted_at, "review submitted_at")
        if self.dismisses_review_id is not None:
            _positive_integer(self.dismisses_review_id, "dismisses_review_id")


@dataclass(frozen=True, slots=True)
class PreparednessProfile:
    """Exact immutable PreparednessProfile v1 value."""

    profile_id: UUID
    version: int
    repository_id: int
    required_checks: tuple[RequiredCheck, ...]
    required_statuses: tuple[RequiredStatus, ...]
    block_on_changes_requested: bool
    acquisition_configuration_digest: Digest
    effective_from: datetime
    predecessor: ProfileIdentity | None = None

    def __post_init__(self) -> None:
        identity = ProfileIdentity(self.profile_id, self.version)
        _positive_integer(self.repository_id, "repository_id")
        if not isinstance(self.block_on_changes_requested, bool):
            raise DomainValidationError("block_on_changes_requested must be boolean")
        if not isinstance(self.acquisition_configuration_digest, Digest):
            raise DomainValidationError(
                "acquisition_configuration_digest must be a Digest"
            )
        _utc_datetime(self.effective_from, "effective_from")

        checks = tuple(self.required_checks)
        statuses = tuple(self.required_statuses)
        if not all(isinstance(item, RequiredCheck) for item in checks):
            raise DomainValidationError("required_checks must contain RequiredCheck")
        if not all(isinstance(item, RequiredStatus) for item in statuses):
            raise DomainValidationError("required_statuses must contain RequiredStatus")
        if len(set(checks)) != len(checks):
            raise DomainValidationError("required check identities must be unique")
        status_keys = [item.context_key for item in statuses]
        if len(set(status_keys)) != len(status_keys):
            raise DomainValidationError(
                "required status context_key identities must be unique"
            )
        object.__setattr__(self, "required_checks", tuple(sorted(checks)))
        object.__setattr__(self, "required_statuses", tuple(sorted(statuses)))

        if identity.version == 1:
            if self.predecessor is not None:
                raise DomainValidationError(
                    "profile version 1 must not identify a predecessor"
                )
        elif self.predecessor != ProfileIdentity(
            identity.profile_id, identity.version - 1
        ):
            raise DomainValidationError(
                "profile predecessor must be the immediately preceding version "
                "of the same logical UUID"
            )

    @property
    def identity(self) -> ProfileIdentity:
        return ProfileIdentity(self.profile_id, self.version)

    def applies_at(
        self,
        evidence_sealed_at: datetime,
        *,
        successor_effective_from: datetime | None = None,
    ) -> bool:
        """Apply the exact ``[effective_from, successor.effective_from)`` interval."""

        sealed = _utc_datetime(evidence_sealed_at, "evidence_sealed_at")
        if successor_effective_from is not None:
            successor = _utc_datetime(
                successor_effective_from, "successor_effective_from"
            )
            if successor <= self.effective_from:
                raise DomainValidationError(
                    "successor effective_from must be later than predecessor"
                )
            return self.effective_from <= sealed < successor
        return self.effective_from <= sealed

    def as_mapping(self) -> dict[str, object]:
        return {
            "schema": PREPAREDNESS_PROFILE_SCHEMA_ID,
            "digest_algorithm": DIGEST_FORMAT,
            "identity": self.identity.as_mapping(),
            "repository_id": self.repository_id,
            "required_checks": [item.as_mapping() for item in self.required_checks],
            "required_commit_statuses": [
                item.as_mapping() for item in self.required_statuses
            ],
            "review_policy": {
                "block_on_current_head_changes_requested": (
                    self.block_on_changes_requested
                )
            },
            "acquisition_configuration_digest": dict(
                self.acquisition_configuration_digest.as_mapping()
            ),
            "freshness_window_seconds": PREPAREDNESS_FRESHNESS_SECONDS,
            "effective_from": _timestamp_text(self.effective_from),
            "predecessor": (
                None if self.predecessor is None else self.predecessor.as_mapping()
            ),
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> PreparednessProfile:
        """Parse one exact persisted v1 payload without implicit profile lookup."""

        _exact_keys(
            value,
            {
                "schema",
                "digest_algorithm",
                "identity",
                "repository_id",
                "required_checks",
                "required_commit_statuses",
                "review_policy",
                "acquisition_configuration_digest",
                "freshness_window_seconds",
                "effective_from",
                "predecessor",
            },
            "preparedness profile",
        )
        if value["schema"] != PREPAREDNESS_PROFILE_SCHEMA_ID:
            raise DomainValidationError("preparedness profile schema is not v1")
        if value["digest_algorithm"] != DIGEST_FORMAT:
            raise DomainValidationError(
                f"preparedness profile digest_algorithm must be {DIGEST_FORMAT}"
            )
        if value["freshness_window_seconds"] != PREPAREDNESS_FRESHNESS_SECONDS:
            raise DomainValidationError(
                "preparedness profile freshness window must be 600 seconds"
            )

        identity = _mapping(value["identity"], "profile identity")
        _exact_keys(identity, {"profile_id", "version"}, "profile identity")
        profile_id = _uuid(identity["profile_id"], "profile_id")
        version = _positive_integer(identity["version"], "profile version")

        checks_value = _sequence(value["required_checks"], "required_checks")
        checks: list[RequiredCheck] = []
        for item in checks_value:
            check = _mapping(item, "required check")
            _exact_keys(check, {"producer_app_id", "check_name"}, "required check")
            checks.append(
                RequiredCheck(
                    producer_app_id=_positive_integer(
                        check["producer_app_id"], "producer_app_id"
                    ),
                    check_name=_nonempty_text(check["check_name"], "check_name"),
                )
            )

        statuses_value = _sequence(
            value["required_commit_statuses"], "required_commit_statuses"
        )
        statuses: list[RequiredStatus] = []
        for item in statuses_value:
            status = _mapping(item, "required status")
            _exact_keys(status, {"context", "context_key"}, "required status")
            statuses.append(
                RequiredStatus(
                    context=_nonempty_text(status["context"], "status context"),
                    context_key=_nonempty_text(
                        status["context_key"], "status context_key"
                    ),
                )
            )

        review_policy = _mapping(value["review_policy"], "review_policy")
        _exact_keys(
            review_policy,
            {"block_on_current_head_changes_requested"},
            "review_policy",
        )
        blocking = review_policy["block_on_current_head_changes_requested"]
        if not isinstance(blocking, bool):
            raise DomainValidationError(
                "block_on_current_head_changes_requested must be boolean"
            )

        digest_value = _mapping(
            value["acquisition_configuration_digest"],
            "acquisition_configuration_digest",
        )
        _exact_keys(
            digest_value,
            {"format", "value"},
            "acquisition_configuration_digest",
        )
        digest = Digest(
            format=_nonempty_text(digest_value["format"], "digest format"),
            value=_nonempty_text(digest_value["value"], "digest value"),
        )

        effective_from = _timestamp_from_text(value["effective_from"], "effective_from")
        predecessor_value = value["predecessor"]
        predecessor: ProfileIdentity | None
        if predecessor_value is None:
            predecessor = None
        else:
            predecessor_mapping = _mapping(predecessor_value, "predecessor")
            _exact_keys(
                predecessor_mapping,
                {"profile_id", "version"},
                "predecessor",
            )
            predecessor = ProfileIdentity(
                profile_id=_uuid(
                    predecessor_mapping["profile_id"], "predecessor profile_id"
                ),
                version=_positive_integer(
                    predecessor_mapping["version"], "predecessor version"
                ),
            )

        repository_id = _positive_integer(value["repository_id"], "repository_id")
        return cls(
            profile_id=profile_id,
            version=version,
            repository_id=repository_id,
            required_checks=tuple(checks),
            required_statuses=tuple(statuses),
            block_on_changes_requested=blocking,
            acquisition_configuration_digest=digest,
            effective_from=effective_from,
            predecessor=predecessor,
        )


def validate_profile_successor(
    predecessor: PreparednessProfile,
    successor: PreparednessProfile,
) -> None:
    """Validate one exact linear profile succession edge."""

    if successor.predecessor != predecessor.identity:
        raise DomainValidationError("successor does not identify the exact predecessor")
    if successor.effective_from <= predecessor.effective_from:
        raise DomainValidationError(
            "successor effective_from must be later than predecessor"
        )
    if successor.repository_id != predecessor.repository_id:
        raise DomainValidationError("profile repository identity cannot change")


def preparedness_assessment_id(payload_digest: Digest) -> str:
    """Derive a UUID after JCS hashing the ID-free assessment payload."""

    if not isinstance(payload_digest, Digest):
        raise DomainValidationError("assessment payload digest must be a Digest")
    return str(
        uuid5(
            PREPAREDNESS_IDENTITY_NAMESPACE,
            f"assessment:{payload_digest.format}:{payload_digest.value}",
        )
    )


@dataclass(frozen=True, slots=True)
class PreparednessEvidence:
    """Decision-relevant material from one sealed coherent analysis view."""

    expected_identity: PullRequestIdentity
    observed_identity: PullRequestIdentity
    analysis_view_id: str
    analysis_view_digest: Digest
    evidence_sealed_at: datetime
    acquisition_configuration_digest: Digest
    pull_request_state: str
    draft: bool
    complete: bool
    stable: bool
    checks: tuple[CheckRunEvidence, ...] = ()
    statuses: tuple[CommitStatusEvidence, ...] = ()
    reviews: tuple[ReviewEvidence, ...] = ()
    uncertainty_reasons: tuple[PreparednessReasonCode, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.expected_identity, PullRequestIdentity):
            raise DomainValidationError(
                "expected_identity must be a PullRequestIdentity"
            )
        if not isinstance(self.observed_identity, PullRequestIdentity):
            raise DomainValidationError(
                "observed_identity must be a PullRequestIdentity"
            )
        _nonempty_text(self.analysis_view_id, "analysis_view_id")
        if not isinstance(self.analysis_view_digest, Digest):
            raise DomainValidationError("analysis_view_digest must be a Digest")
        _utc_datetime(self.evidence_sealed_at, "evidence_sealed_at")
        if not isinstance(self.acquisition_configuration_digest, Digest):
            raise DomainValidationError(
                "acquisition_configuration_digest must be a Digest"
            )
        _nonempty_text(self.pull_request_state, "pull_request_state")
        for field, value in (
            ("draft", self.draft),
            ("complete", self.complete),
            ("stable", self.stable),
        ):
            if not isinstance(value, bool):
                raise DomainValidationError(f"{field} must be boolean")

        checks = _typed_tuple(self.checks, CheckRunEvidence, "checks")
        statuses = _typed_tuple(self.statuses, CommitStatusEvidence, "statuses")
        reviews = _typed_tuple(self.reviews, ReviewEvidence, "reviews")
        reasons: list[PreparednessReasonCode] = []
        for reason in self.uncertainty_reasons:
            try:
                converted = PreparednessReasonCode(reason)
            except ValueError as exc:
                raise DomainValidationError(
                    "uncertainty_reasons contains an unknown reason"
                ) from exc
            if converted not in _INDETERMINATE_REASONS:
                raise DomainValidationError(
                    "uncertainty_reasons may contain only evidence uncertainty"
                )
            reasons.append(converted)
        object.__setattr__(self, "checks", checks)
        object.__setattr__(self, "statuses", statuses)
        object.__setattr__(self, "reviews", reviews)
        object.__setattr__(self, "uncertainty_reasons", _ordered_reasons(reasons))


@dataclass(frozen=True, slots=True)
class PreparednessAssessment:
    """Exact deterministic PreparednessAssessment v1 value."""

    identity: PullRequestIdentity
    profile: ProfileIdentity
    analysis_view_id: str
    analysis_view_digest: Digest
    evidence_sealed_at: datetime
    evaluated_at: datetime
    freshness: FreshnessResult
    verdict: PreparednessVerdict
    reason_codes: tuple[PreparednessReasonCode, ...]
    evidence_summary: CanonicalValue

    def __post_init__(self) -> None:
        if not isinstance(self.identity, PullRequestIdentity):
            raise DomainValidationError("identity must be a PullRequestIdentity")
        if not isinstance(self.profile, ProfileIdentity):
            raise DomainValidationError("profile must be an explicit ProfileIdentity")
        _nonempty_text(self.analysis_view_id, "analysis_view_id")
        if not isinstance(self.analysis_view_digest, Digest):
            raise DomainValidationError("analysis_view_digest must be a Digest")
        _utc_datetime(self.evidence_sealed_at, "evidence_sealed_at")
        _utc_datetime(self.evaluated_at, "evaluated_at")
        if not isinstance(self.freshness, FreshnessResult):
            raise DomainValidationError("freshness must be a FreshnessResult")
        if not isinstance(self.verdict, PreparednessVerdict):
            raise DomainValidationError("verdict must be a PreparednessVerdict")
        reasons = _ordered_reasons(self.reason_codes)
        object.__setattr__(self, "reason_codes", reasons)
        object.__setattr__(
            self, "evidence_summary", freeze_canonical_value(self.evidence_summary)
        )
        if self.verdict is PreparednessVerdict.READY_FOR_HUMAN_REVIEW and reasons:
            raise DomainValidationError("READY assessment cannot contain reason codes")
        if self.verdict is PreparednessVerdict.INDETERMINATE and (
            not reasons
            or any(reason not in _INDETERMINATE_REASONS for reason in reasons)
        ):
            raise DomainValidationError(
                "INDETERMINATE assessment requires evidence-uncertainty reasons"
            )
        if self.verdict is PreparednessVerdict.NOT_READY and (
            not reasons or any(reason in _INDETERMINATE_REASONS for reason in reasons)
        ):
            raise DomainValidationError(
                "NOT_READY assessment requires only deterministic blocker reasons"
            )

    def as_mapping(self) -> dict[str, object]:
        return {
            "schema": PREPAREDNESS_ASSESSMENT_SCHEMA_ID,
            "digest_algorithm": DIGEST_FORMAT,
            "identity": {
                **self.identity.as_mapping(),
                "profile": self.profile.as_mapping(),
                "analysis_view": {
                    "analysis_view_id": self.analysis_view_id,
                    "digest": dict(self.analysis_view_digest.as_mapping()),
                },
            },
            "evidence_sealed_at": _timestamp_text(self.evidence_sealed_at),
            "evaluated_at": _timestamp_text(self.evaluated_at),
            "freshness": self.freshness.value,
            "verdict": self.verdict.value,
            "reason_codes": [reason.value for reason in self.reason_codes],
            "evidence_summary": to_json_compatible(self.evidence_summary),
        }


def evaluate_freshness(
    evidence_sealed_at: datetime,
    evaluated_at: datetime,
) -> FreshnessResult:
    """Classify freshness from the seal clock, inclusive at exactly 600 seconds."""

    sealed = _utc_datetime(evidence_sealed_at, "evidence_sealed_at")
    evaluated = _utc_datetime(evaluated_at, "evaluated_at")
    age = evaluated - sealed
    if age < timedelta(0):
        return FreshnessResult.CLOCK_ANOMALY
    if age <= timedelta(seconds=PREPAREDNESS_FRESHNESS_SECONDS):
        return FreshnessResult.FRESH
    return FreshnessResult.STALE


def assess_preparedness(
    profile: PreparednessProfile,
    evidence: PreparednessEvidence,
    evaluated_at: datetime,
    *,
    successor_effective_from: datetime | None = None,
) -> PreparednessAssessment:
    """Evaluate one explicit profile against one sealed coherent evidence view."""

    if not isinstance(profile, PreparednessProfile):
        raise DomainValidationError("profile must be an explicit PreparednessProfile")
    if not isinstance(evidence, PreparednessEvidence):
        raise DomainValidationError("evidence must be PreparednessEvidence")
    evaluated = _utc_datetime(evaluated_at, "evaluated_at")
    freshness = evaluate_freshness(evidence.evidence_sealed_at, evaluated)

    check_summary, check_blockers, check_ambiguous = _reduce_checks(
        profile.required_checks,
        evidence.checks,
        evidence.observed_identity.head_sha,
    )
    status_summary, status_blockers, status_ambiguous = _reduce_statuses(
        profile.required_statuses,
        evidence.statuses,
        evidence.observed_identity.head_sha,
    )
    review_summary, review_blocked, review_ambiguous = _reduce_reviews(
        evidence.reviews,
        evidence.observed_identity.head_sha,
    )

    identity_matches = evidence.expected_identity == evidence.observed_identity
    configuration_matches = (
        profile.acquisition_configuration_digest
        == evidence.acquisition_configuration_digest
    )
    profile_repository_matches = (
        profile.repository_id
        == evidence.expected_identity.repository_id
        == evidence.observed_identity.repository_id
    )
    applicable = profile.applies_at(
        evidence.evidence_sealed_at,
        successor_effective_from=successor_effective_from,
    )

    uncertainty = set(evidence.uncertainty_reasons)
    if not evidence.complete:
        uncertainty.add(PreparednessReasonCode.EVIDENCE_INCOMPLETE)
    if not evidence.stable:
        uncertainty.add(PreparednessReasonCode.EVIDENCE_UNSTABLE)
    if freshness is FreshnessResult.STALE:
        uncertainty.add(PreparednessReasonCode.EVIDENCE_STALE)
    elif freshness is FreshnessResult.CLOCK_ANOMALY:
        uncertainty.add(PreparednessReasonCode.EVIDENCE_CLOCK_ANOMALY)
    if not identity_matches:
        uncertainty.add(PreparednessReasonCode.EVIDENCE_IDENTITY_MISMATCH)
    if not configuration_matches:
        uncertainty.add(PreparednessReasonCode.ACQUISITION_CONFIGURATION_MISMATCH)
    if not profile_repository_matches:
        uncertainty.add(PreparednessReasonCode.PROFILE_REPOSITORY_MISMATCH)
    if not applicable:
        uncertainty.add(PreparednessReasonCode.PROFILE_NOT_APPLICABLE)
    if evidence.pull_request_state not in {"open", "closed"}:
        uncertainty.add(PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE)
    if check_ambiguous:
        uncertainty.add(PreparednessReasonCode.CHECK_AMBIGUITY)
    if status_ambiguous:
        uncertainty.add(PreparednessReasonCode.STATUS_AMBIGUITY)
    if review_ambiguous:
        uncertainty.add(PreparednessReasonCode.REVIEW_AMBIGUITY)

    blockers = set(check_blockers) | set(status_blockers)
    if evidence.pull_request_state == "closed":
        blockers.add(PreparednessReasonCode.PR_CLOSED)
    if evidence.draft:
        blockers.add(PreparednessReasonCode.PR_DRAFT)
    if profile.block_on_changes_requested and review_blocked:
        blockers.add(PreparednessReasonCode.CURRENT_HEAD_CHANGES_REQUESTED)

    if uncertainty:
        verdict = PreparednessVerdict.INDETERMINATE
        reasons = _ordered_reasons(uncertainty)
    elif blockers:
        verdict = PreparednessVerdict.NOT_READY
        reasons = _ordered_reasons(blockers)
    else:
        verdict = PreparednessVerdict.READY_FOR_HUMAN_REVIEW
        reasons = ()

    summary = {
        "evidence_complete": evidence.complete,
        "evidence_stable": evidence.stable,
        "expected_identity": evidence.expected_identity.as_mapping(),
        "observed_identity": evidence.observed_identity.as_mapping(),
        "identity_matches": identity_matches,
        "acquisition_configuration_matches": configuration_matches,
        "profile_repository_matches": profile_repository_matches,
        "profile_applicable": applicable,
        "input_counts": {
            "check_runs": len(evidence.checks),
            "commit_statuses": len(evidence.statuses),
            "reviews": len(evidence.reviews),
        },
        "required_checks": check_summary,
        "required_commit_statuses": status_summary,
        "current_head_review_opinions": review_summary,
        "review_blocking_policy": profile.block_on_changes_requested,
    }
    return PreparednessAssessment(
        identity=evidence.observed_identity,
        profile=profile.identity,
        analysis_view_id=evidence.analysis_view_id,
        analysis_view_digest=evidence.analysis_view_digest,
        evidence_sealed_at=evidence.evidence_sealed_at,
        evaluated_at=evaluated,
        freshness=freshness,
        verdict=verdict,
        reason_codes=reasons,
        evidence_summary=freeze_canonical_value(summary),
    )


def _reduce_checks(
    required: Sequence[RequiredCheck],
    checks: Sequence[CheckRunEvidence],
    head_sha: str,
) -> tuple[list[dict[str, object]], set[PreparednessReasonCode], bool]:
    unique: dict[int, CheckRunEvidence] = {}
    ambiguous = False
    for check in checks:
        previous = unique.get(check.check_run_id)
        if previous is not None and previous != check:
            ambiguous = True
        else:
            unique[check.check_run_id] = check
        if check.head_sha != head_sha:
            ambiguous = True

    by_identity: dict[RequiredCheck, list[CheckRunEvidence]] = {}
    for check in unique.values():
        by_identity.setdefault(check.identity, []).append(check)

    summary: list[dict[str, object]] = []
    blockers: set[PreparednessReasonCode] = set()
    for identity in required:
        generations = by_identity.get(identity, [])
        item = identity.as_mapping()
        if not generations:
            blockers.add(PreparednessReasonCode.REQUIRED_CHECK_MISSING)
            item["outcome"] = PreparednessReasonCode.REQUIRED_CHECK_MISSING.value
            summary.append(item)
            continue
        if len(generations) > 1 and any(
            generation.started_at is None for generation in generations
        ):
            ambiguous = True
            item["outcome"] = PreparednessReasonCode.CHECK_AMBIGUITY.value
            summary.append(item)
            continue
        selected = max(
            generations,
            key=lambda generation: (
                generation.started_at or datetime.min.replace(tzinfo=UTC),
                generation.check_run_id,
            ),
        )
        item.update(
            {
                "selected_check_run_id": selected.check_run_id,
                "status": selected.status,
                "conclusion": selected.conclusion,
            }
        )
        if selected.status in {"queued", "in_progress"}:
            if selected.conclusion is not None or selected.completed_at is not None:
                ambiguous = True
                item["outcome"] = PreparednessReasonCode.CHECK_AMBIGUITY.value
            else:
                blockers.add(PreparednessReasonCode.REQUIRED_CHECK_PENDING)
                item["outcome"] = PreparednessReasonCode.REQUIRED_CHECK_PENDING.value
        elif selected.status == "completed":
            if selected.conclusion in ACCEPTED_CHECK_CONCLUSIONS:
                item["outcome"] = "SATISFIED"
            elif selected.conclusion in _KNOWN_UNSUCCESSFUL_CHECK_CONCLUSIONS:
                blockers.add(PreparednessReasonCode.REQUIRED_CHECK_UNSUCCESSFUL)
                item["outcome"] = (
                    PreparednessReasonCode.REQUIRED_CHECK_UNSUCCESSFUL.value
                )
            else:
                ambiguous = True
                item["outcome"] = PreparednessReasonCode.CHECK_AMBIGUITY.value
        else:
            ambiguous = True
            item["outcome"] = PreparednessReasonCode.CHECK_AMBIGUITY.value
        summary.append(item)
    return summary, blockers, ambiguous


def _reduce_statuses(
    required: Sequence[RequiredStatus],
    statuses: Sequence[CommitStatusEvidence],
    head_sha: str,
) -> tuple[list[dict[str, object]], set[PreparednessReasonCode], bool]:
    unique: dict[int, CommitStatusEvidence] = {}
    ambiguous = False
    for status in statuses:
        previous = unique.get(status.status_id)
        if previous is not None and previous != status:
            ambiguous = True
        else:
            unique[status.status_id] = status
        if status.head_sha != head_sha:
            ambiguous = True

    latest: dict[str, CommitStatusEvidence] = {}
    for status in unique.values():
        current = latest.get(status.context_key)
        if current is None or (status.updated_at, status.status_id) > (
            current.updated_at,
            current.status_id,
        ):
            latest[status.context_key] = status

    summary: list[dict[str, object]] = []
    blockers: set[PreparednessReasonCode] = set()
    state_reasons = {
        "pending": PreparednessReasonCode.REQUIRED_STATUS_PENDING,
        "failure": PreparednessReasonCode.REQUIRED_STATUS_FAILURE,
        "error": PreparednessReasonCode.REQUIRED_STATUS_ERROR,
    }
    for requirement in required:
        selected = latest.get(requirement.context_key)
        item = requirement.as_mapping()
        if selected is None:
            blockers.add(PreparednessReasonCode.REQUIRED_STATUS_MISSING)
            item["outcome"] = PreparednessReasonCode.REQUIRED_STATUS_MISSING.value
        else:
            item.update(
                {
                    "selected_status_id": selected.status_id,
                    "selected_context": selected.context,
                    "state": selected.state,
                }
            )
            if selected.state == "success":
                item["outcome"] = "SATISFIED"
            elif selected.state in state_reasons:
                reason = state_reasons[selected.state]
                blockers.add(reason)
                item["outcome"] = reason.value
            else:
                ambiguous = True
                item["outcome"] = PreparednessReasonCode.STATUS_AMBIGUITY.value
        summary.append(item)
    return summary, blockers, ambiguous


def _reduce_reviews(
    reviews: Sequence[ReviewEvidence],
    head_sha: str,
) -> tuple[list[dict[str, object]], bool, bool]:
    unique: dict[int, ReviewEvidence] = {}
    ambiguous = False
    for review in reviews:
        previous = unique.get(review.review_id)
        if previous is not None and previous != review:
            ambiguous = True
        else:
            unique[review.review_id] = review

    current: dict[int, ReviewEvidence] = {}
    for review in unique.values():
        if review.commit_id is None or _SHA.fullmatch(review.commit_id) is None:
            ambiguous = True
            continue
        if review.commit_id != head_sha:
            continue
        current[review.review_id] = review

    opinion_states = {"APPROVED", "CHANGES_REQUESTED"}
    neutral_states = {"COMMENTED", "PENDING"}
    ordered_events: list[ReviewEvidence] = []
    for review in current.values():
        if review.state in opinion_states:
            if review.submitted_at is None or review.dismisses_review_id is not None:
                ambiguous = True
            else:
                ordered_events.append(review)
        elif review.state in neutral_states:
            if review.dismisses_review_id is not None:
                ambiguous = True
        elif review.state == "DISMISSED":
            if review.submitted_at is None or review.dismisses_review_id is None:
                ambiguous = True
            else:
                ordered_events.append(review)
        else:
            ambiguous = True

    active: dict[int, ReviewEvidence] = {}
    opinions_by_id: dict[int, ReviewEvidence] = {}
    for review in sorted(
        ordered_events,
        key=lambda item: (cast(datetime, item.submitted_at), item.review_id),
    ):
        if review.state in opinion_states:
            active[review.reviewer_id] = review
            opinions_by_id[review.review_id] = review
        else:
            target = opinions_by_id.get(cast(int, review.dismisses_review_id))
            if target is None or target.reviewer_id != review.reviewer_id:
                ambiguous = True
            elif active.get(review.reviewer_id) == target:
                del active[review.reviewer_id]

    summary: list[dict[str, object]] = []
    blocked = False
    for reviewer_id, selected in sorted(active.items()):
        summary.append(
            {
                "reviewer_id": reviewer_id,
                "review_id": selected.review_id,
                "state": selected.state,
            }
        )
        blocked = blocked or selected.state == "CHANGES_REQUESTED"
    return summary, blocked, ambiguous


def _ordered_reasons(
    reasons: Sequence[PreparednessReasonCode] | set[PreparednessReasonCode],
) -> tuple[PreparednessReasonCode, ...]:
    converted: set[PreparednessReasonCode] = set()
    for reason in reasons:
        try:
            converted.add(PreparednessReasonCode(reason))
        except ValueError as exc:
            raise DomainValidationError("unknown preparedness reason code") from exc
    return tuple(sorted(converted, key=_REASON_RANK.__getitem__))


def _typed_tuple[ValueT](
    values: Sequence[ValueT],
    expected: type[ValueT],
    field: str,
) -> tuple[ValueT, ...]:
    result = tuple(values)
    if not all(isinstance(value, expected) for value in result):
        raise DomainValidationError(f"{field} contains an invalid value")
    return result


def _positive_integer(value: object, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > MAX_SAFE_INTEGER
    ):
        raise DomainValidationError(f"{field} must be a positive JCS-safe integer")
    return value


def _nonempty_text(value: object, field: str) -> str:
    if not isinstance(value, str) or value == "":
        raise DomainValidationError(f"{field} must be a non-empty string")
    freeze_canonical_value(value)
    return value


def _sha(value: object, field: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise DomainValidationError(
            f"{field} must be a 40-character lowercase hexadecimal SHA"
        )
    return value


def _utc_datetime(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise DomainValidationError(f"{field} must be a timezone-aware UTC datetime")
    if value.utcoffset() != timedelta(0):
        raise DomainValidationError(f"{field} must use UTC")
    return value


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _timestamp_from_text(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise DomainValidationError(f"{field} must be a UTC timestamp string")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise DomainValidationError(
            f"{field} must use YYYY-MM-DDTHH:MM:SS.ffffffZ"
        ) from exc
    if _timestamp_text(parsed) != value:
        raise DomainValidationError(f"{field} must use YYYY-MM-DDTHH:MM:SS.ffffffZ")
    return parsed


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise DomainValidationError(f"{field} must be a string-keyed mapping")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, (list, tuple)):
        raise DomainValidationError(f"{field} must be an array")
    return value


def _exact_keys(
    value: Mapping[str, object],
    expected: set[str],
    field: str,
) -> None:
    actual = set(value)
    if actual != expected:
        raise DomainValidationError(
            f"{field} keys differ: missing={sorted(expected - actual)}, "
            f"additional={sorted(actual - expected)}"
        )


def _uuid(value: object, field: str) -> UUID:
    if not isinstance(value, str):
        raise DomainValidationError(f"{field} must be a canonical UUID string")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise DomainValidationError(f"{field} must be a canonical UUID string") from exc
    if str(parsed) != value:
        raise DomainValidationError(f"{field} must be a canonical UUID string")
    return parsed
