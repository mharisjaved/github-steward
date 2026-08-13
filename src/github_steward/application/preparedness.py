"""Bounded recorded/fake A/pass-1/B/pass-2/C coherent acquisition."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final, NoReturn, cast
from urllib.parse import urlsplit
from uuid import UUID, uuid5

from github_steward.domain.acquisition import (
    COHERENT_ATTEMPTS,
    MAX_CHECK_RUNS,
    MAX_CHECK_SUITES,
    MAX_COMMITS,
    MAX_FILES,
    MAX_PAGES,
    MAX_RESPONSE_BYTES,
    PER_PAGE,
    SEMANTIC_FACETS,
    AcquisitionError,
    AcquisitionOutcome,
    CoherentAnalysisView,
    CommitEvidence,
    EvidenceNormalizationError,
    FileEvidence,
    NormalizedCheckRun,
    NormalizedCommitStatus,
    NormalizedReview,
    PullRequestAnchor,
    RepositoryTarget,
    RequestedReviewerAmbiguityError,
    RequestedReviewers,
    RequestedTeam,
    RequestedUser,
    SourceOrderRelation,
    compare_source_order,
    github_work_subject,
    normalize_check_runs,
    normalize_commit_statuses,
    normalize_reviews,
)
from github_steward.domain.canonical import (
    CanonicalEnvelope,
    CanonicalValue,
    Digest,
)
from github_steward.domain.errors import CanonicalizationError
from github_steward.domain.preparedness import (
    PREPAREDNESS_ASSESSMENT_SCHEMA_ID,
    PREPAREDNESS_PROFILE_SCHEMA_ID,
    CheckRunEvidence,
    CommitStatusEvidence,
    PreparednessAssessment,
    PreparednessEvidence,
    PreparednessProfile,
    PreparednessReasonCode,
    ProfileIdentity,
    ProfileReference,
    PullRequestIdentity,
    ReviewEvidence,
    assess_preparedness,
    preparedness_assessment_id,
)
from github_steward.domain.processing import require_utc_datetime
from github_steward.ports.clock import Clock
from github_steward.ports.github import (
    CoherentAcquisitionFailure,
    CoherentAcquisitionPort,
    CoherentAcquisitionResult,
    EvidenceFacet,
    RecordedFacet,
    RecordedGitHubEvidencePort,
    RecordedGitHubResponse,
)
from github_steward.ports.persistence import (
    AnalysisViewId,
    AnalysisViewRecord,
    CanonicalObservationRecord,
    CurrentObservationPointerRepository,
    ObservationPointer,
    ObservationVersionId,
    PointerCreateOutcome,
    PreparednessAssessmentId,
    PreparednessAssessmentRecord,
    PreparednessProfileId,
    PreparednessProfileRecord,
    ProcessingUnitOfWork,
)

type EnvelopeFactory = Callable[[object], CanonicalEnvelope]

COHERENT_VIEW_NAMESPACE: Final = UUID("6d6f75d2-aaaf-5c63-9cd1-aa0469357f40")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_FACET_ORDER: Final = tuple(EvidenceFacet)


@dataclass(frozen=True, slots=True)
class _NormalizedFacets:
    files: tuple[FileEvidence, ...]
    commits: tuple[CommitEvidence, ...]
    reviews: tuple[NormalizedReview, ...]
    requested_reviewers: RequestedReviewers
    check_suite_count: int
    check_runs: tuple[NormalizedCheckRun, ...]
    commit_statuses: tuple[NormalizedCommitStatus, ...]

    def semantic_mapping(self) -> Mapping[str, object]:
        return {
            EvidenceFacet.FILES.value: [item.as_mapping() for item in self.files],
            EvidenceFacet.COMMITS.value: [item.as_mapping() for item in self.commits],
            EvidenceFacet.REVIEWS.value: [item.as_mapping() for item in self.reviews],
            EvidenceFacet.REQUESTED_REVIEWERS.value: (
                self.requested_reviewers.as_mapping()
            ),
            EvidenceFacet.CHECK_SUITE_COUNT.value: self.check_suite_count,
            EvidenceFacet.CHECK_RUNS.value: [
                item.as_mapping() for item in self.check_runs
            ],
            EvidenceFacet.COMMIT_STATUSES.value: [
                item.as_mapping() for item in self.commit_statuses
            ],
        }


@dataclass(frozen=True, slots=True)
class _Pass:
    facets: _NormalizedFacets
    envelopes: Mapping[str, CanonicalEnvelope]
    raw_inventory: Mapping[str, tuple[str, ...]]


class CoherentRecordedAcquisitionService:
    """Acquire a view from bounded recorded responses without GitHub credentials."""

    def __init__(
        self,
        *,
        evidence: RecordedGitHubEvidencePort,
        clock: Clock,
        envelope_factory: EnvelopeFactory,
        acquisition_configuration_digest: Digest,
    ) -> None:
        self._evidence = evidence
        self._clock = clock
        self._envelope_factory = envelope_factory
        self._configuration_digest = acquisition_configuration_digest

    def acquire(self, target: RepositoryTarget) -> CoherentAcquisitionResult:
        """Retry only whole incoherent attempts and seal once after equality."""

        for attempt_number in range(1, COHERENT_ATTEMPTS + 1):
            try:
                attempted = self._attempt(target, attempt_number)
            except AcquisitionError as exc:
                raise CoherentAcquisitionFailure(
                    _reason_for_acquisition(exc.outcome), str(exc)
                ) from exc
            except RequestedReviewerAmbiguityError as exc:
                raise CoherentAcquisitionFailure(
                    PreparednessReasonCode.REQUESTED_REVIEWER_AMBIGUITY,
                    str(exc),
                ) from exc
            except EvidenceNormalizationError as exc:
                raise CoherentAcquisitionFailure(
                    PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE,
                    str(exc),
                ) from exc
            except CanonicalizationError as exc:
                raise CoherentAcquisitionFailure(
                    PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE,
                    "recorded evidence could not be canonicalized",
                ) from exc
            if attempted is not None:
                return attempted
        raise CoherentAcquisitionFailure(
            PreparednessReasonCode.EVIDENCE_UNSTABLE,
            "semantic coherence was not established in two whole attempts",
        )

    def _attempt(
        self,
        target: RepositoryTarget,
        attempt_number: int,
    ) -> CoherentAcquisitionResult | None:
        raw_inventory: dict[str, tuple[str, ...]] = {}

        response_a = self._read_anchor(target, "anchor_a", raw_inventory)
        anchor_a = _anchor(response_a.value, target)
        anchor_a_envelope = self._envelope_factory(anchor_a.as_mapping())

        pass_one = self._read_pass(target, anchor_a, "pass_1")
        raw_inventory.update(pass_one.raw_inventory)

        response_b = self._read_anchor(target, "anchor_b", raw_inventory)
        anchor_b = _anchor(response_b.value, target)
        anchor_b_envelope = self._envelope_factory(anchor_b.as_mapping())

        pass_two = self._read_pass(target, anchor_b, "pass_2")
        raw_inventory.update(pass_two.raw_inventory)

        response_c = self._read_anchor(target, "anchor_c", raw_inventory)
        anchor_c = _anchor(response_c.value, target)
        anchor_c_envelope = self._envelope_factory(anchor_c.as_mapping())

        anchor_digests = {
            anchor_a_envelope.digest.value,
            anchor_b_envelope.digest.value,
            anchor_c_envelope.digest.value,
        }
        if len(anchor_digests) != 1:
            return None
        for facet in _FACET_ORDER:
            if (
                pass_one.envelopes[facet.value].digest
                != pass_two.envelopes[facet.value].digest
            ):
                return None

        evidence_sealed_at = require_utc_datetime(
            self._clock.now(), "evidence_sealed_at"
        )
        semantic_digests = {
            "anchor": anchor_a_envelope.digest.value,
            **{
                facet.value: pass_one.envelopes[facet.value].digest.value
                for facet in _FACET_ORDER
            },
        }
        if set(semantic_digests) != set(SEMANTIC_FACETS):
            raise RuntimeError("internal semantic facet inventory was incomplete")
        identifier = _analysis_view_id(
            envelope_factory=self._envelope_factory,
            repository_id=anchor_a.repository_id,
            pull_number=anchor_a.pull_number,
            head_sha=anchor_a.head_sha,
            evidence_sealed_at=evidence_sealed_at,
            acquisition_configuration_digest=self._configuration_digest,
            raw_digest_inventory=raw_inventory,
            semantic_digest_inventory=semantic_digests,
        )
        facets = pass_one.facets
        view = CoherentAnalysisView(
            analysis_view_id=identifier,
            anchor=anchor_a,
            files=facets.files,
            commits=facets.commits,
            files_digest=pass_one.envelopes[EvidenceFacet.FILES.value].digest.value,
            commits_digest=pass_one.envelopes[EvidenceFacet.COMMITS.value].digest.value,
            requested_reviewers=facets.requested_reviewers,
            check_suite_count=facets.check_suite_count,
            check_runs=facets.check_runs,
            commit_statuses=facets.commit_statuses,
            reviews=facets.reviews,
            acquisition_configuration_digest=self._configuration_digest.value,
            evidence_sealed_at=evidence_sealed_at,
            raw_digest_inventory=raw_inventory,
            semantic_digest_inventory=semantic_digests,
        )
        return CoherentAcquisitionResult(
            view=view,
            view_envelope=self._envelope_factory(view.as_mapping()),
            attempts=attempt_number,
            facet_envelopes=pass_one.envelopes,
        )

    def _read_anchor(
        self,
        target: RepositoryTarget,
        role: str,
        inventory: dict[str, tuple[str, ...]],
    ) -> RecordedGitHubResponse:
        response = self._evidence.read_anchor(target)
        _validate_response(response)
        inventory[role] = (response.raw_sha256,)
        return response

    def _read_pass(
        self,
        target: RepositoryTarget,
        anchor: PullRequestAnchor,
        pass_role: str,
    ) -> _Pass:
        acquired: dict[EvidenceFacet, RecordedFacet] = {}
        raw_inventory: dict[str, tuple[str, ...]] = {}
        for facet in _FACET_ORDER:
            recorded = self._evidence.read_facet(
                target,
                head_sha=anchor.head_sha,
                facet=facet,
            )
            _validate_facet(recorded, facet)
            acquired[facet] = recorded
            raw_inventory[f"{pass_role}:{facet.value}"] = tuple(
                response.raw_sha256 for response in recorded.raw_responses
            )
        facets = _normalize_facets(acquired, anchor, target)
        if len(facets.files) != anchor.changed_files:
            _fail(
                PreparednessReasonCode.EVIDENCE_TOTAL_COUNT_INCONSISTENT,
                "file count did not match anchor metadata",
            )
        if len(facets.commits) != anchor.commit_count:
            _fail(
                PreparednessReasonCode.EVIDENCE_TOTAL_COUNT_INCONSISTENT,
                "commit count did not match anchor metadata",
            )
        semantic = facets.semantic_mapping()
        envelopes = {
            facet.value: self._envelope_factory(semantic[facet.value])
            for facet in _FACET_ORDER
        }
        return _Pass(facets, envelopes, raw_inventory)


def _validate_response(response: object) -> None:
    if not isinstance(response, RecordedGitHubResponse):
        _fail(
            PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE,
            "recorded response provenance had an invalid shape",
        )
    if (
        not isinstance(response.raw_sha256, str)
        or _DIGEST.fullmatch(response.raw_sha256) is None
    ):
        _fail(
            PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE,
            "recorded response raw digest was malformed",
        )
    if (
        isinstance(response.response_bytes, bool)
        or not isinstance(response.response_bytes, int)
        or not 0 <= response.response_bytes <= MAX_RESPONSE_BYTES
    ):
        _fail(
            PreparednessReasonCode.EVIDENCE_CAP_EXCEEDED,
            "recorded response exceeded the response-byte ceiling",
        )


def _analysis_view_id(
    *,
    envelope_factory: EnvelopeFactory,
    repository_id: int,
    pull_number: int,
    head_sha: str,
    evidence_sealed_at: datetime,
    acquisition_configuration_digest: Digest,
    raw_digest_inventory: Mapping[str, tuple[str, ...]],
    semantic_digest_inventory: Mapping[str, str],
) -> str:
    identity_material = {
        "repository_id": repository_id,
        "pull_number": pull_number,
        "head_sha": head_sha,
        "evidence_sealed_at": _timestamp(evidence_sealed_at),
        "acquisition_configuration_digest": dict(
            acquisition_configuration_digest.as_mapping()
        ),
        "raw_digest_inventory": {
            role: list(digests) for role, digests in raw_digest_inventory.items()
        },
        "semantic_digest_inventory": dict(semantic_digest_inventory),
    }
    material_digest = envelope_factory(identity_material).digest
    return str(
        uuid5(
            COHERENT_VIEW_NAMESPACE,
            f"{material_digest.format}:{material_digest.value}",
        )
    )


def _validate_facet(recorded: object, facet: EvidenceFacet) -> None:
    if not isinstance(recorded, RecordedFacet):
        _fail(
            PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE,
            f"{facet.value} recorded facet had an invalid shape",
        )
    if not isinstance(recorded.complete, bool):
        _fail(
            PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE,
            f"{facet.value} completeness marker was not boolean",
        )
    if not recorded.complete:
        _fail(
            PreparednessReasonCode.EVIDENCE_PAGINATION_UNCERTAIN,
            f"{facet.value} facet was not complete",
        )
    if not isinstance(recorded.raw_responses, tuple):
        _fail(
            PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE,
            f"{facet.value} raw response provenance was not a tuple",
        )
    if not 1 <= len(recorded.raw_responses) <= MAX_PAGES:
        _fail(
            PreparednessReasonCode.EVIDENCE_PAGINATION_UNCERTAIN,
            f"{facet.value} pagination was outside the bound",
        )
    for response in recorded.raw_responses:
        _validate_response(response)
    if recorded.total_count is not None and (
        isinstance(recorded.total_count, bool)
        or not isinstance(recorded.total_count, int)
        or recorded.total_count < 0
    ):
        _fail(
            PreparednessReasonCode.EVIDENCE_TOTAL_COUNT_INCONSISTENT,
            f"{facet.value} total_count was invalid",
        )


def _normalize_facets(
    acquired: Mapping[EvidenceFacet, RecordedFacet],
    anchor: PullRequestAnchor,
    target: RepositoryTarget,
) -> _NormalizedFacets:
    files = tuple(
        sorted(
            FileEvidence.from_mapping(_object(item, "file"))
            for item in _array(acquired[EvidenceFacet.FILES].value, "files")
        )
    )
    commits = tuple(
        CommitEvidence.from_mapping(_only_commit_fields(_object(item, "commit")))
        for item in _array(acquired[EvidenceFacet.COMMITS].value, "commits")
    )
    reviews = normalize_reviews(
        _review(_object(item, "review"), target)
        for item in _array(acquired[EvidenceFacet.REVIEWS].value, "reviews")
    )
    requested = _requested_reviewers(
        _object(
            acquired[EvidenceFacet.REQUESTED_REVIEWERS].value,
            "requested reviewers",
        )
    )
    suite_count = _suite_count(acquired[EvidenceFacet.CHECK_SUITE_COUNT])
    checks = normalize_check_runs(
        _check(_object(item, "check run"), anchor.head_sha)
        for item in _array(acquired[EvidenceFacet.CHECK_RUNS].value, "check runs")
    )
    statuses = normalize_commit_statuses(
        _status(_object(item, "commit status"), anchor.head_sha)
        for item in _array(
            acquired[EvidenceFacet.COMMIT_STATUSES].value, "commit statuses"
        )
    )
    _enforce_count(acquired[EvidenceFacet.FILES], len(files), MAX_FILES, "files")
    _enforce_count(
        acquired[EvidenceFacet.COMMITS], len(commits), MAX_COMMITS, "commits"
    )
    _enforce_count(
        acquired[EvidenceFacet.CHECK_RUNS],
        len(checks),
        MAX_CHECK_RUNS,
        "check runs",
    )
    _enforce_count(
        acquired[EvidenceFacet.REVIEWS],
        len(reviews),
        MAX_PAGES * PER_PAGE,
        "reviews",
    )
    _enforce_count(
        acquired[EvidenceFacet.COMMIT_STATUSES],
        len(statuses),
        MAX_PAGES * PER_PAGE,
        "commit statuses",
    )
    return _NormalizedFacets(
        files,
        commits,
        reviews,
        requested,
        suite_count,
        checks,
        statuses,
    )


def _enforce_count(
    facet: RecordedFacet,
    actual: int,
    maximum: int,
    label: str,
) -> None:
    raw_item_count = len(_array(facet.value, label))
    if raw_item_count > len(facet.raw_responses) * PER_PAGE:
        _fail(
            PreparednessReasonCode.EVIDENCE_PAGINATION_UNCERTAIN,
            f"{label} item count exceeded recorded page capacity",
        )
    if actual > maximum or (
        facet.total_count is not None and facet.total_count > maximum
    ):
        _fail(
            PreparednessReasonCode.EVIDENCE_CAP_EXCEEDED,
            f"{label} exceeded its completeness ceiling",
        )
    if facet.total_count is not None and facet.total_count != actual:
        _fail(
            PreparednessReasonCode.EVIDENCE_TOTAL_COUNT_INCONSISTENT,
            f"{label} total_count did not match complete items",
        )


def _anchor(value: object, target: RepositoryTarget) -> PullRequestAnchor:
    body = _object(value, "pull request")
    base = _object(body.get("base"), "base")
    head = _object(body.get("head"), "head")
    repository = _object(base.get("repo"), "base repository")
    full_name = _text(repository.get("full_name"), "repository full_name")
    number = _positive(body.get("number"), "pull number")
    if (
        full_name.casefold() != target.full_name.casefold()
        or number != target.pull_number
    ):
        raise EvidenceNormalizationError(
            "recorded anchor route did not match the requested pull request"
        )
    draft = body.get("draft")
    if not isinstance(draft, bool):
        raise EvidenceNormalizationError("anchor draft was not boolean")
    return PullRequestAnchor(
        repository_id=_positive(repository.get("id"), "repository id"),
        pull_number=number,
        pull_request_id=_positive(body.get("id"), "pull request id"),
        head_sha=_sha(head.get("sha"), "head sha"),
        base_repository_id=_positive(repository.get("id"), "base repository id"),
        base_ref=_text(base.get("ref"), "base ref"),
        base_sha=_sha(base.get("sha"), "base sha"),
        state=_text(body.get("state"), "pull request state"),
        draft=draft,
        updated_at=_github_timestamp(body.get("updated_at"), "updated_at"),
        changed_files=_nonnegative(body.get("changed_files"), "changed_files"),
        commit_count=_nonnegative(body.get("commits"), "commits"),
    )


def _only_commit_fields(value: Mapping[str, object]) -> Mapping[str, object]:
    return {"sha": value.get("sha")}


def _requested_reviewers(value: Mapping[str, object]) -> RequestedReviewers:
    users = tuple(
        RequestedUser(
            _positive(item.get("id"), "requested user id"),
            _text(item.get("login"), "requested user login"),
        )
        for raw in _array(value.get("users"), "requested users")
        for item in [_object(raw, "requested user")]
    )
    teams = tuple(
        RequestedTeam(
            _positive(item.get("id"), "requested team id"),
            _text(item.get("slug"), "requested team slug"),
        )
        for raw in _array(value.get("teams"), "requested teams")
        for item in [_object(raw, "requested team")]
    )
    return RequestedReviewers(users, teams)


def _suite_count(recorded: RecordedFacet) -> int:
    value = recorded.value
    if isinstance(value, int) and not isinstance(value, bool):
        total = value
    else:
        total = _nonnegative(
            _object(value, "check-suite count").get("total_count"),
            "check-suite total_count",
        )
    if recorded.total_count is not None and recorded.total_count != total:
        _fail(
            PreparednessReasonCode.EVIDENCE_TOTAL_COUNT_INCONSISTENT,
            "check-suite totals disagreed",
        )
    if total > MAX_CHECK_SUITES:
        _fail(
            PreparednessReasonCode.EVIDENCE_CAP_EXCEEDED,
            "check-suite count exceeded its completeness ceiling",
        )
    return total


def _check(value: Mapping[str, object], head_sha: str) -> NormalizedCheckRun:
    app = _object(value.get("app"), "check app")
    observed_head = _sha(value.get("head_sha"), "check head_sha")
    if observed_head != head_sha:
        raise EvidenceNormalizationError("check run did not belong to exact head")
    return NormalizedCheckRun(
        check_run_id=_positive(value.get("id"), "check id"),
        head_sha=observed_head,
        producer_app_id=_positive(app.get("id"), "producer app id"),
        check_name=_text(value.get("name"), "check name"),
        status=_text(value.get("status"), "check status"),
        conclusion=_optional_text(value.get("conclusion"), "check conclusion"),
        started_at=_optional_github_timestamp(value.get("started_at"), "started_at"),
        completed_at=_optional_github_timestamp(
            value.get("completed_at"), "completed_at"
        ),
    )


def _status(value: Mapping[str, object], head_sha: str) -> NormalizedCommitStatus:
    observed_head = _sha(value.get("head_sha", value.get("sha")), "status head_sha")
    if observed_head != head_sha:
        raise EvidenceNormalizationError("commit status did not belong to exact head")
    return NormalizedCommitStatus(
        status_id=_positive(value.get("id"), "status id"),
        head_sha=observed_head,
        context=_text(value.get("context"), "status context"),
        state=_text(value.get("state"), "status state"),
        updated_at=_github_timestamp(value.get("updated_at"), "status updated_at"),
    )


def _review(value: Mapping[str, object], target: RepositoryTarget) -> NormalizedReview:
    user = _object(value.get("user"), "review user")
    pull_request_url = _text(value.get("pull_request_url"), "review pull_request_url")
    if not _canonical_pull_request_url(pull_request_url, target):
        raise EvidenceNormalizationError(
            "review pull_request_url did not match requested pull request"
        )
    dismissed = value.get("dismisses_review_id")
    return NormalizedReview(
        review_id=_positive(value.get("id"), "review id"),
        reviewer_id=_positive(user.get("id"), "reviewer id"),
        commit_id=_optional_sha(value.get("commit_id"), "review commit_id"),
        state=_text(value.get("state"), "review state"),
        submitted_at=_optional_github_timestamp(
            value.get("submitted_at"), "review submitted_at"
        ),
        dismisses_review_id=(
            None if dismissed is None else _positive(dismissed, "dismissed review id")
        ),
    )


def _canonical_pull_request_url(value: str, target: RepositoryTarget) -> bool:
    expected = (
        "https://api.github.com/repos/"
        f"{target.owner}/{target.repository}/pulls/{target.pull_number}"
    )
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    expected_parts = urlsplit(expected)
    return all(
        (
            "%" not in value,
            parsed.scheme == "https",
            parsed.netloc == "api.github.com",
            parsed.hostname == "api.github.com",
            parsed.username is None,
            parsed.password is None,
            port is None,
            parsed.path == expected_parts.path,
            "/./" not in parsed.path,
            "/../" not in parsed.path,
            parsed.query == "",
            parsed.fragment == "",
            parsed == expected_parts,
            value == expected,
        )
    )


def _reason_for_acquisition(outcome: AcquisitionOutcome) -> PreparednessReasonCode:
    return {
        AcquisitionOutcome.FORBIDDEN: PreparednessReasonCode.EVIDENCE_PERMISSION_DENIED,
        AcquisitionOutcome.RATE_LIMITED: PreparednessReasonCode.EVIDENCE_RATE_LIMITED,
        AcquisitionOutcome.UNSUPPORTED_UPSTREAM_LIMIT: (
            PreparednessReasonCode.EVIDENCE_CAP_EXCEEDED
        ),
        AcquisitionOutcome.MALFORMED_RESPONSE: (
            PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE
        ),
        AcquisitionOutcome.INCOMPLETE_ACQUISITION: (
            PreparednessReasonCode.EVIDENCE_INCOMPLETE
        ),
        AcquisitionOutcome.CONCURRENT_CHANGE: PreparednessReasonCode.EVIDENCE_UNSTABLE,
        AcquisitionOutcome.NOT_FOUND: PreparednessReasonCode.EVIDENCE_ROUTE_FAILURE,
        AcquisitionOutcome.UNPROCESSABLE: PreparednessReasonCode.EVIDENCE_ROUTE_FAILURE,
        AcquisitionOutcome.TRANSPORT_ERROR: (
            PreparednessReasonCode.EVIDENCE_TRANSPORT_UNCERTAIN
        ),
        AcquisitionOutcome.TIMEOUT: PreparednessReasonCode.EVIDENCE_TRANSPORT_UNCERTAIN,
        AcquisitionOutcome.UPSTREAM_SERVER_ERROR: (
            PreparednessReasonCode.EVIDENCE_TRANSPORT_UNCERTAIN
        ),
        AcquisitionOutcome.PERSISTENCE_FAILURE: (
            PreparednessReasonCode.EVIDENCE_COHERENCE_UNCERTAIN
        ),
        AcquisitionOutcome.ACQUIRED: PreparednessReasonCode.EVIDENCE_COHERENCE_UNCERTAIN,
    }[outcome]


def _object(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise EvidenceNormalizationError(f"{label} was not an object")
    return cast(Mapping[str, object], value)


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise EvidenceNormalizationError(f"{label} was not an array")
    return cast(list[object], value)


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or value == "":
        raise EvidenceNormalizationError(f"{label} was not non-empty text")
    return value


def _optional_text(value: object, label: str) -> str | None:
    return None if value is None else _text(value, label)


def _positive(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise EvidenceNormalizationError(f"{label} was not a positive integer")
    return value


def _nonnegative(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EvidenceNormalizationError(f"{label} was not a nonnegative integer")
    return value


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise EvidenceNormalizationError(f"{label} was not a lowercase SHA")
    return value


def _optional_sha(value: object, label: str) -> str | None:
    return None if value is None else _sha(value, label)


def _github_timestamp(value: object, label: str) -> datetime:
    text = _text(value, label)
    for pattern in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"):
        try:
            return datetime.strptime(text, pattern).replace(tzinfo=UTC)
        except ValueError:
            pass
    raise EvidenceNormalizationError(f"{label} was not a GitHub UTC timestamp")


def _optional_github_timestamp(value: object, label: str) -> datetime | None:
    return None if value is None else _github_timestamp(value, label)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _fail(reason: PreparednessReasonCode, message: str) -> NoReturn:
    raise CoherentAcquisitionFailure(reason, message)


type UnitOfWorkFactory = Callable[[], ProcessingUnitOfWork]
type ViewDecoder = Callable[[Mapping[str, object]], CoherentAnalysisView]

OBSERVATION_NAMESPACE: Final = UUID("9d63b0fc-fb8b-561c-9201-7edbb6aff2c7")
EVIDENCE_SCHEMA_ID: Final = "github-steward/github-evidence-facet/v1"
COHERENT_VIEW_SCHEMA_ID: Final = "github-steward/coherent-analysis-view/v1"


class PointerPromotionOutcome(StrEnum):
    """Complete GS-I4 current-pointer result vocabulary."""

    POINTER_ADVANCED = "POINTER_ADVANCED"
    POINTER_REPLAY_NOOP = "POINTER_REPLAY_NOOP"
    POINTER_REGRESSION_REJECTED = "POINTER_REGRESSION_REJECTED"
    POINTER_INCOMPARABLE_REJECTED = "POINTER_INCOMPARABLE_REJECTED"
    POINTER_LOST_TO_NEWER = "POINTER_LOST_TO_NEWER"
    POINTER_CONCURRENCY_UNRESOLVED = "POINTER_CONCURRENCY_UNRESOLVED"


@dataclass(frozen=True, slots=True)
class PointerPromotionResult:
    """A promotion decision and the comparisons that established it."""

    outcome: PointerPromotionOutcome
    relation: SourceOrderRelation
    compared_pointer_version: int | None
    cas_attempts: int


class CurrentPointerPromotionService:
    """Promote only proven progress, with one bounded CAS recomputation."""

    def __init__(
        self,
        *,
        pointers: CurrentObservationPointerRepository,
        decode_view: ViewDecoder,
    ) -> None:
        self._pointers = pointers
        self._decode_view = decode_view

    def promote(
        self,
        *,
        entity_kind: str,
        entity_id: str,
        observation_version_id: ObservationVersionId,
        candidate: CoherentAnalysisView,
        updated_at: datetime,
    ) -> PointerPromotionResult:
        """Apply replay/progression/rejection and bounded CAS semantics."""

        current = self._pointers.get(entity_kind=entity_kind, entity_id=entity_id)
        if current is None:
            created = self._pointers.create_if_absent(
                self._replacement(
                    entity_kind=entity_kind,
                    entity_id=entity_id,
                    observation_version_id=observation_version_id,
                    candidate=candidate,
                    pointer_version=0,
                    updated_at=updated_at,
                )
            )
            if created is PointerCreateOutcome.CREATED:
                return PointerPromotionResult(
                    PointerPromotionOutcome.POINTER_ADVANCED,
                    SourceOrderRelation.PROGRESSION,
                    None,
                    0,
                )
            current = self._require_current(entity_kind, entity_id)

        relation = compare_source_order(self._view(current), candidate)
        terminal = self._terminal(relation, current.pointer_version, cas_attempts=0)
        if terminal is not None:
            return terminal

        first_version = current.pointer_version
        if self._pointers.compare_and_swap(
            expected_version=first_version,
            replacement=self._replacement(
                entity_kind=entity_kind,
                entity_id=entity_id,
                observation_version_id=observation_version_id,
                candidate=candidate,
                pointer_version=first_version + 1,
                updated_at=updated_at,
            ),
        ):
            return PointerPromotionResult(
                PointerPromotionOutcome.POINTER_ADVANCED,
                SourceOrderRelation.PROGRESSION,
                first_version,
                1,
            )

        reloaded = self._require_current(entity_kind, entity_id)
        recomputed = compare_source_order(self._view(reloaded), candidate)
        terminal = self._terminal(
            recomputed,
            reloaded.pointer_version,
            cas_attempts=1,
            after_conflict=True,
        )
        if terminal is not None:
            return terminal

        second_version = reloaded.pointer_version
        if self._pointers.compare_and_swap(
            expected_version=second_version,
            replacement=self._replacement(
                entity_kind=entity_kind,
                entity_id=entity_id,
                observation_version_id=observation_version_id,
                candidate=candidate,
                pointer_version=second_version + 1,
                updated_at=updated_at,
            ),
        ):
            return PointerPromotionResult(
                PointerPromotionOutcome.POINTER_ADVANCED,
                SourceOrderRelation.PROGRESSION,
                second_version,
                2,
            )
        return PointerPromotionResult(
            PointerPromotionOutcome.POINTER_CONCURRENCY_UNRESOLVED,
            SourceOrderRelation.PROGRESSION,
            second_version,
            2,
        )

    def _view(self, pointer: ObservationPointer) -> CoherentAnalysisView:
        ordering = pointer.ordering_key
        if not isinstance(ordering, Mapping):
            raise ValueError("GS-I4 pointer ordering material must be an object")
        return self._decode_view(cast(Mapping[str, object], ordering))

    def _require_current(self, entity_kind: str, entity_id: str) -> ObservationPointer:
        current = self._pointers.get(entity_kind=entity_kind, entity_id=entity_id)
        if current is None:
            raise RuntimeError("current pointer disappeared during bounded promotion")
        return current

    @staticmethod
    def _terminal(
        relation: SourceOrderRelation,
        pointer_version: int,
        *,
        cas_attempts: int,
        after_conflict: bool = False,
    ) -> PointerPromotionResult | None:
        if relation is SourceOrderRelation.REPLAY:
            return PointerPromotionResult(
                PointerPromotionOutcome.POINTER_REPLAY_NOOP,
                relation,
                pointer_version,
                cas_attempts,
            )
        if relation is SourceOrderRelation.REGRESSION:
            outcome = (
                PointerPromotionOutcome.POINTER_LOST_TO_NEWER
                if after_conflict
                else PointerPromotionOutcome.POINTER_REGRESSION_REJECTED
            )
            return PointerPromotionResult(
                outcome,
                relation,
                pointer_version,
                cas_attempts,
            )
        if relation is SourceOrderRelation.INCOMPARABLE:
            return PointerPromotionResult(
                PointerPromotionOutcome.POINTER_INCOMPARABLE_REJECTED,
                relation,
                pointer_version,
                cas_attempts,
            )
        return None

    @staticmethod
    def _replacement(
        *,
        entity_kind: str,
        entity_id: str,
        observation_version_id: ObservationVersionId,
        candidate: CoherentAnalysisView,
        pointer_version: int,
        updated_at: datetime,
    ) -> ObservationPointer:
        ordering_key = cast(CanonicalValue, candidate.as_mapping())
        return ObservationPointer(
            entity_kind=entity_kind,
            entity_id=entity_id,
            observation_version_id=observation_version_id,
            ordering_key=ordering_key,
            pointer_version=pointer_version,
            updated_at=updated_at,
        )


@dataclass(frozen=True, slots=True)
class ProfileRegistrationResult:
    """The immutable exact profile identity and JCS digest persisted."""

    reference: ProfileReference

    @property
    def identity(self) -> ProfileIdentity:
        return self.reference.identity

    @property
    def digest(self) -> Digest:
        return self.reference.digest


@dataclass(frozen=True, slots=True)
class PreparednessPipelineResult:
    """One complete pipeline outcome, including fail-closed acquisition."""

    assessment: PreparednessAssessment | None
    assessment_id: str | None
    assessment_digest: Digest | None
    pointer_outcome: PointerPromotionOutcome | None
    acquisition_failure: PreparednessReasonCode | None


class DeterministicPreparednessPipeline:
    """Run recorded acquisition through immutable assessment and current pointer."""

    def __init__(
        self,
        *,
        acquisition: CoherentAcquisitionPort,
        unit_of_work_factory: UnitOfWorkFactory,
        evaluation_clock: Clock,
        envelope_factory: EnvelopeFactory,
    ) -> None:
        self._acquisition = acquisition
        self._unit_of_work_factory = unit_of_work_factory
        self._evaluation_clock = evaluation_clock
        self._envelope_factory = envelope_factory

    def register_profile(
        self, profile: PreparednessProfile
    ) -> ProfileRegistrationResult:
        """Persist one explicit root or linear successor profile version."""

        envelope = self._envelope_factory(profile.as_mapping())
        predecessor = profile.predecessor
        record = PreparednessProfileRecord(
            profile_id=PreparednessProfileId(str(profile.profile_id)),
            version=profile.version,
            repository_id=profile.repository_id,
            effective_from=profile.effective_from,
            predecessor_profile_id=(
                None
                if predecessor is None
                else PreparednessProfileId(str(predecessor.profile_id))
            ),
            predecessor_profile_version=(
                None if predecessor is None else predecessor.version
            ),
            predecessor_digest=(None if predecessor is None else predecessor.digest),
            payload=envelope.payload,
            digest=envelope.digest,
        )
        with self._unit_of_work_factory() as unit:
            unit.profiles.insert(record)
            unit.commit()
        return ProfileRegistrationResult(profile.reference(envelope.digest))

    def assess(
        self,
        *,
        target: RepositoryTarget,
        expected_identity: PullRequestIdentity,
        profile_reference: ProfileReference,
    ) -> PreparednessPipelineResult:
        """Use an exact profile; never select an implicit current version."""

        try:
            acquired = self._acquisition.acquire(target)
            self._verify_acquisition(acquired)
        except CoherentAcquisitionFailure as exc:
            return PreparednessPipelineResult(None, None, None, None, exc.reason)
        except CanonicalizationError:
            return PreparednessPipelineResult(
                None,
                None,
                None,
                None,
                PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE,
            )

        observations, view_record, pointer_observation = self._records(acquired)
        entity_id = github_work_subject(
            acquired.view.anchor.repository_id,
            acquired.view.anchor.pull_number,
        )
        with self._unit_of_work_factory() as unit:
            profile, successor_effective_from = self._load_profile(
                unit,
                profile_reference,
            )
            for observation in observations:
                unit.observations.append(observation)
            unit.views.insert(view_record)
            promotion = CurrentPointerPromotionService(
                pointers=unit.pointers,
                decode_view=CoherentAnalysisView.from_mapping,
            ).promote(
                entity_kind="github_pull_request",
                entity_id=entity_id,
                observation_version_id=pointer_observation,
                candidate=acquired.view,
                updated_at=acquired.view.evidence_sealed_at,
            )
            evidence = _preparedness_evidence(
                expected_identity=expected_identity,
                acquired=acquired,
                uncertainty_reasons=_pointer_uncertainty(promotion.outcome),
            )
            evaluated_at = require_utc_datetime(
                self._evaluation_clock.now(), "evaluated_at"
            )
            assessment = assess_preparedness(
                profile,
                evidence,
                evaluated_at,
                profile_reference=profile_reference,
                successor_effective_from=successor_effective_from,
            )
            assessment_envelope = self._envelope_factory(assessment.as_mapping())
            assessment_identifier = preparedness_assessment_id(
                assessment_envelope.digest
            )
            unit.assessments.insert(
                PreparednessAssessmentRecord(
                    assessment_id=PreparednessAssessmentId(assessment_identifier),
                    repository_id=assessment.identity.repository_id,
                    pull_number=assessment.identity.pull_number,
                    head_sha=assessment.identity.head_sha,
                    profile_id=PreparednessProfileId(str(profile.profile_id)),
                    profile_version=profile.version,
                    profile_digest=profile_reference.digest,
                    analysis_view_id=view_record.view_id,
                    analysis_view_digest=view_record.digest,
                    evidence_sealed_at=assessment.evidence_sealed_at,
                    evaluated_at=assessment.evaluated_at,
                    verdict=assessment.verdict.value,
                    payload=assessment_envelope.payload,
                    digest=assessment_envelope.digest,
                    evidence_observations=view_record.observation_versions,
                )
            )
            unit.commit()
        return PreparednessPipelineResult(
            assessment,
            assessment_identifier,
            assessment_envelope.digest,
            promotion.outcome,
            None,
        )

    def _verify_acquisition(self, acquired: CoherentAcquisitionResult) -> None:
        view = acquired.view
        semantic_payloads = {
            "anchor": view.anchor.as_mapping(),
            "files": [item.as_mapping() for item in view.files],
            "commits": [item.as_mapping() for item in view.commits],
            "reviews": [item.as_mapping() for item in view.reviews],
            "requested_reviewers": view.requested_reviewers.as_mapping(),
            "check_suite_count": view.check_suite_count,
            "check_runs": [item.as_mapping() for item in view.check_runs],
            "commit_statuses": [item.as_mapping() for item in view.commit_statuses],
        }
        calculated = {
            facet: self._envelope_factory(semantic_payloads[facet])
            for facet in SEMANTIC_FACETS
        }
        expected_facets = {
            facet: calculated[facet] for facet in SEMANTIC_FACETS if facet != "anchor"
        }
        expected_semantic_digests = {
            facet: calculated[facet].digest.value for facet in SEMANTIC_FACETS
        }
        checks = (
            1 <= acquired.attempts <= COHERENT_ATTEMPTS,
            dict(acquired.facet_envelopes) == expected_facets,
            dict(view.semantic_digest_inventory) == expected_semantic_digests,
            view.files_digest == expected_semantic_digests["files"],
            view.commits_digest == expected_semantic_digests["commits"],
            acquired.view_envelope
            == self._envelope_factory(acquired.view.as_mapping()),
        )
        if not all(checks):
            raise CoherentAcquisitionFailure(
                PreparednessReasonCode.EVIDENCE_COHERENCE_UNCERTAIN,
                "acquisition result envelopes did not bind the coherent view",
            )

    def _load_profile(
        self,
        unit: ProcessingUnitOfWork,
        reference: ProfileReference,
    ) -> tuple[PreparednessProfile, datetime | None]:
        record = unit.profiles.get(
            profile_id=PreparednessProfileId(str(reference.profile_id)),
            version=reference.version,
        )
        successor = unit.profiles.get_successor(
            profile_id=PreparednessProfileId(str(reference.profile_id)),
            version=reference.version,
        )
        if record is None:
            raise ValueError("exact preparedness profile identity was not persisted")
        calculated = self._envelope_factory(record.payload)
        if calculated.digest != record.digest:
            raise ValueError("persisted preparedness profile digest did not verify")
        if calculated.digest != reference.digest:
            raise ValueError("requested preparedness profile digest did not match")
        profile = PreparednessProfile.from_mapping(
            cast(Mapping[str, object], record.payload)
        )
        if profile.identity != reference.identity:
            raise ValueError("persisted preparedness profile identity did not match")
        return profile, None if successor is None else successor.effective_from

    def _records(
        self,
        acquired: CoherentAcquisitionResult,
    ) -> tuple[
        tuple[CanonicalObservationRecord, ...],
        AnalysisViewRecord,
        ObservationVersionId,
    ]:
        view = acquired.view
        entity_id = github_work_subject(
            view.anchor.repository_id,
            view.anchor.pull_number,
        )
        anchor_envelope = self._envelope_factory(view.anchor.as_mapping())
        facet_envelopes = {
            "anchor": anchor_envelope,
            **dict(acquired.facet_envelopes),
            "coherent_view": acquired.view_envelope,
        }
        records: list[CanonicalObservationRecord] = []
        associations: list[tuple[str, ObservationVersionId]] = []
        for role in (
            "anchor",
            "files",
            "commits",
            "reviews",
            "requested_reviewers",
            "check_suite_count",
            "check_runs",
            "commit_statuses",
            "coherent_view",
        ):
            envelope = facet_envelopes[role]
            identifier = ObservationVersionId(
                str(
                    uuid5(
                        OBSERVATION_NAMESPACE,
                        f"{view.analysis_view_id}:{role}:{envelope.digest.value}",
                    )
                )
            )
            records.append(
                CanonicalObservationRecord(
                    version_id=identifier,
                    entity_kind="github_pull_request",
                    entity_id=entity_id,
                    schema_id=(
                        COHERENT_VIEW_SCHEMA_ID
                        if role == "coherent_view"
                        else EVIDENCE_SCHEMA_ID
                    ),
                    schema_version=1,
                    observed_at=view.evidence_sealed_at,
                    payload=envelope.payload,
                    digest=envelope.digest,
                )
            )
            associations.append((role, identifier))
        view_record = AnalysisViewRecord(
            view_id=AnalysisViewId(view.analysis_view_id),
            schema_id=COHERENT_VIEW_SCHEMA_ID,
            schema_version=1,
            payload=acquired.view_envelope.payload,
            digest=acquired.view_envelope.digest,
            observation_versions=tuple(associations),
        )
        return tuple(records), view_record, dict(associations)["coherent_view"]


def _preparedness_evidence(
    *,
    expected_identity: PullRequestIdentity,
    acquired: CoherentAcquisitionResult,
    uncertainty_reasons: tuple[PreparednessReasonCode, ...] = (),
) -> PreparednessEvidence:
    view = acquired.view
    observed = PullRequestIdentity(
        repository_id=view.anchor.repository_id,
        pull_request_id=view.anchor.pull_request_id,
        pull_number=view.anchor.pull_number,
        head_sha=view.anchor.head_sha,
        base_repository_id=view.anchor.base_repository_id,
        base_ref=view.anchor.base_ref,
        base_sha=view.anchor.base_sha,
    )
    return PreparednessEvidence(
        expected_identity=expected_identity,
        observed_identity=observed,
        analysis_view_id=view.analysis_view_id,
        analysis_view_digest=acquired.view_envelope.digest,
        evidence_sealed_at=view.evidence_sealed_at,
        acquisition_configuration_digest=Digest(
            value=view.acquisition_configuration_digest
        ),
        pull_request_state=view.anchor.state,
        draft=view.anchor.draft,
        complete=True,
        stable=True,
        checks=tuple(
            CheckRunEvidence(
                check_run_id=item.check_run_id,
                head_sha=item.head_sha,
                producer_app_id=item.producer_app_id,
                check_name=item.check_name,
                status=item.status,
                conclusion=item.conclusion,
                started_at=item.started_at,
                completed_at=item.completed_at,
            )
            for item in view.check_runs
        ),
        statuses=tuple(
            CommitStatusEvidence(
                status_id=item.status_id,
                head_sha=item.head_sha,
                context=item.context,
                state=item.state,
                updated_at=item.updated_at,
            )
            for item in view.commit_statuses
        ),
        reviews=tuple(
            ReviewEvidence(
                review_id=item.review_id,
                reviewer_id=item.reviewer_id,
                commit_id=item.commit_id,
                state=item.state,
                submitted_at=item.submitted_at,
                dismisses_review_id=item.dismisses_review_id,
            )
            for item in view.reviews
        ),
        uncertainty_reasons=uncertainty_reasons,
    )


def _pointer_uncertainty(
    outcome: PointerPromotionOutcome,
) -> tuple[PreparednessReasonCode, ...]:
    if outcome in {
        PointerPromotionOutcome.POINTER_REGRESSION_REJECTED,
        PointerPromotionOutcome.POINTER_INCOMPARABLE_REJECTED,
        PointerPromotionOutcome.POINTER_LOST_TO_NEWER,
    }:
        return (PreparednessReasonCode.EVIDENCE_COHERENCE_UNCERTAIN,)
    if outcome is PointerPromotionOutcome.POINTER_CONCURRENCY_UNRESOLVED:
        return (PreparednessReasonCode.EVIDENCE_UNSTABLE,)
    return ()


assert PREPAREDNESS_PROFILE_SCHEMA_ID == "github-steward/preparedness-profile/v1"
assert PREPAREDNESS_ASSESSMENT_SCHEMA_ID == (
    "github-steward/preparedness-assessment/v1"
)
