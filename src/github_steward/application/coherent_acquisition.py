"""Bounded recorded/fake A/pass-1/B/pass-2/C coherent acquisition."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
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
    AcquisitionError,
    AcquisitionOutcome,
    RepositoryTarget,
)
from github_steward.domain.canonical import CanonicalEnvelope, Digest
from github_steward.domain.errors import CanonicalizationError
from github_steward.domain.github_evidence import (
    SEMANTIC_FACETS,
    CoherentAnalysisView,
    CommitEvidence,
    EvidenceNormalizationError,
    FileEvidence,
    NormalizedCheckRun,
    NormalizedCommitStatus,
    NormalizedReview,
    PullRequestAnchor,
    RequestedReviewerAmbiguityError,
    RequestedReviewers,
    RequestedTeam,
    RequestedUser,
    normalize_check_runs,
    normalize_commit_statuses,
    normalize_reviews,
)
from github_steward.domain.preparedness import PreparednessReasonCode
from github_steward.domain.processing import require_utc_datetime
from github_steward.ports.clock import Clock
from github_steward.ports.github_evidence import (
    CoherentAcquisitionFailure,
    CoherentAcquisitionResult,
    EvidenceFacet,
    RecordedFacet,
    RecordedGitHubEvidencePort,
    RecordedGitHubResponse,
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
