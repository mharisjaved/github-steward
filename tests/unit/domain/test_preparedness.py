"""Focused deterministic PreparednessProfile/Assessment v1 tests."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from typing import cast
from uuid import UUID

import pytest

from github_steward.domain.canonical import DIGEST_FORMAT, Digest
from github_steward.domain.errors import DomainValidationError
from github_steward.domain.preparedness import (
    ACCEPTED_CHECK_CONCLUSIONS,
    PREPAREDNESS_ASSESSMENT_SCHEMA_ID,
    PREPAREDNESS_FRESHNESS_SECONDS,
    PREPAREDNESS_PROFILE_SCHEMA_ID,
    CheckRunEvidence,
    CommitStatusEvidence,
    FreshnessResult,
    PreparednessAssessment,
    PreparednessEvidence,
    PreparednessProfile,
    PreparednessReasonCode,
    PreparednessVerdict,
    ProfileIdentity,
    PullRequestIdentity,
    RequiredCheck,
    RequiredStatus,
    ReviewEvidence,
    assess_preparedness,
    evaluate_freshness,
    preparedness_assessment_id,
    validate_profile_successor,
)

NOW = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
PROFILE_ID = UUID("118eea41-a31b-4a21-9f47-aae25ae86f49")
HEAD = "a" * 40
OTHER_HEAD = "b" * 40
BASE = "c" * 40
CONFIG_DIGEST = Digest("1" * 64)
VIEW_DIGEST = Digest("2" * 64)


def _identity(
    *,
    repository_id: int = 101,
    pull_request_id: int = 202,
    pull_number: int = 17,
    head_sha: str = HEAD,
    base_repository_id: int = 101,
    base_ref: str = "main",
    base_sha: str = BASE,
) -> PullRequestIdentity:
    return PullRequestIdentity(
        repository_id=repository_id,
        pull_request_id=pull_request_id,
        pull_number=pull_number,
        head_sha=head_sha,
        base_repository_id=base_repository_id,
        base_ref=base_ref,
        base_sha=base_sha,
    )


def _profile(
    *,
    required_checks: tuple[RequiredCheck, ...] = (RequiredCheck(7, "build"),),
    required_statuses: tuple[RequiredStatus, ...] = (RequiredStatus("CI"),),
    blocking: bool = True,
    effective_from: datetime = NOW - timedelta(days=1),
    digest: Digest = CONFIG_DIGEST,
    repository_id: int = 101,
    version: int = 1,
    predecessor: ProfileIdentity | None = None,
) -> PreparednessProfile:
    return PreparednessProfile(
        profile_id=PROFILE_ID,
        version=version,
        repository_id=repository_id,
        required_checks=required_checks,
        required_statuses=required_statuses,
        block_on_changes_requested=blocking,
        acquisition_configuration_digest=digest,
        effective_from=effective_from,
        predecessor=predecessor,
    )


def _check(
    *,
    check_run_id: int = 1,
    head_sha: str = HEAD,
    producer_app_id: int = 7,
    check_name: str = "build",
    status: str = "completed",
    conclusion: str | None = "success",
    started_at: datetime | None = NOW - timedelta(minutes=2),
    completed_at: datetime | None = NOW - timedelta(minutes=1),
) -> CheckRunEvidence:
    return CheckRunEvidence(
        check_run_id=check_run_id,
        head_sha=head_sha,
        producer_app_id=producer_app_id,
        check_name=check_name,
        status=status,
        conclusion=conclusion,
        started_at=started_at,
        completed_at=completed_at,
    )


def _status(
    *,
    status_id: int = 11,
    head_sha: str = HEAD,
    context: str = "ci",
    state: str = "success",
    updated_at: datetime = NOW - timedelta(minutes=1),
) -> CommitStatusEvidence:
    return CommitStatusEvidence(
        status_id=status_id,
        head_sha=head_sha,
        context=context,
        state=state,
        updated_at=updated_at,
    )


def _review(
    *,
    review_id: int = 21,
    reviewer_id: int = 31,
    commit_id: str | None = HEAD,
    state: str = "APPROVED",
    submitted_at: datetime | None = NOW - timedelta(minutes=1),
    dismisses_review_id: int | None = None,
) -> ReviewEvidence:
    return ReviewEvidence(
        review_id=review_id,
        reviewer_id=reviewer_id,
        commit_id=commit_id,
        state=state,
        submitted_at=submitted_at,
        dismisses_review_id=dismisses_review_id,
    )


def _evidence(
    *,
    expected: PullRequestIdentity | None = None,
    observed: PullRequestIdentity | None = None,
    sealed_at: datetime = NOW,
    digest: Digest = CONFIG_DIGEST,
    state: str = "open",
    draft: bool = False,
    complete: bool = True,
    stable: bool = True,
    checks: tuple[CheckRunEvidence, ...] = (_check(),),
    statuses: tuple[CommitStatusEvidence, ...] = (_status(),),
    reviews: tuple[ReviewEvidence, ...] = (),
    uncertainty: tuple[PreparednessReasonCode, ...] = (),
) -> PreparednessEvidence:
    return PreparednessEvidence(
        expected_identity=expected or _identity(),
        observed_identity=observed or _identity(),
        analysis_view_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        analysis_view_digest=VIEW_DIGEST,
        evidence_sealed_at=sealed_at,
        acquisition_configuration_digest=digest,
        pull_request_state=state,
        draft=draft,
        complete=complete,
        stable=stable,
        checks=checks,
        statuses=statuses,
        reviews=reviews,
        uncertainty_reasons=uncertainty,
    )


def _assess(
    *,
    profile: PreparednessProfile | None = None,
    evidence: PreparednessEvidence | None = None,
    evaluated_at: datetime = NOW,
    successor_effective_from: datetime | None = None,
) -> PreparednessAssessment:
    return assess_preparedness(
        profile or _profile(),
        evidence or _evidence(),
        evaluated_at,
        successor_effective_from=successor_effective_from,
    )


def _summary(assessment: PreparednessAssessment) -> dict[str, object]:
    mapping = assessment.as_mapping()
    return cast(dict[str, object], mapping["evidence_summary"])


def test_profile_exact_payload_is_deterministic_and_round_trips() -> None:
    profile = _profile(
        required_checks=(RequiredCheck(9, "lint"), RequiredCheck(7, "build")),
        required_statuses=(RequiredStatus("Straße"), RequiredStatus(" CI ")),
    )

    payload = profile.as_mapping()

    assert payload == PreparednessProfile.from_mapping(deepcopy(payload)).as_mapping()
    assert payload["schema"] == PREPAREDNESS_PROFILE_SCHEMA_ID
    assert payload["digest_algorithm"] == DIGEST_FORMAT
    assert payload["freshness_window_seconds"] == PREPAREDNESS_FRESHNESS_SECONDS
    assert payload["identity"] == {
        "profile_id": str(PROFILE_ID),
        "version": 1,
    }
    assert payload["required_checks"] == [
        {"producer_app_id": 7, "check_name": "build"},
        {"producer_app_id": 9, "check_name": "lint"},
    ]
    assert payload["required_commit_statuses"] == [
        {"context": " CI ", "context_key": " ci "},
        {"context": "Straße", "context_key": "strasse"},
    ]
    assert payload["effective_from"] == "2026-08-10T12:00:00.000000Z"
    assert payload["predecessor"] is None


def test_profile_status_identity_casefolds_without_trim_or_unicode_normalization() -> (
    None
):
    composed = RequiredStatus("é")
    decomposed = RequiredStatus("e\u0301")
    spaced = RequiredStatus(" CI ")

    assert composed.context_key == "é"
    assert decomposed.context_key == "e\u0301"
    assert composed.context_key != decomposed.context_key
    assert spaced.context == " CI "
    assert spaced.context_key == " ci "
    assert RequiredStatus("Straße").context_key == "strasse"
    _profile(required_statuses=(composed, decomposed, spaced))


def test_profile_rejects_casefold_duplicate_statuses_and_duplicate_checks() -> None:
    with pytest.raises(DomainValidationError, match="context_key identities"):
        _profile(
            required_statuses=(RequiredStatus("Straße"), RequiredStatus("STRASSE"))
        )
    with pytest.raises(DomainValidationError, match="check identities"):
        _profile(required_checks=(RequiredCheck(7, "build"), RequiredCheck(7, "build")))


def test_profile_versions_require_exact_linear_predecessor() -> None:
    predecessor = _profile()
    successor = _profile(
        version=2,
        predecessor=predecessor.identity,
        effective_from=NOW,
    )

    validate_profile_successor(predecessor, successor)
    assert successor.as_mapping()["predecessor"] == predecessor.identity.as_mapping()

    with pytest.raises(DomainValidationError, match="version 1"):
        _profile(predecessor=ProfileIdentity(PROFILE_ID, 1))
    with pytest.raises(DomainValidationError, match="immediately preceding"):
        _profile(
            version=3,
            predecessor=ProfileIdentity(PROFILE_ID, 1),
            effective_from=NOW,
        )
    with pytest.raises(DomainValidationError, match="exact predecessor"):
        other_id = UUID("228eea41-a31b-4a21-9f47-aae25ae86f49")
        validate_profile_successor(
            predecessor,
            replace(
                successor,
                profile_id=other_id,
                predecessor=ProfileIdentity(other_id, 1),
            ),
        )
    with pytest.raises(DomainValidationError, match="later than predecessor"):
        validate_profile_successor(
            predecessor,
            replace(successor, effective_from=predecessor.effective_from),
        )
    with pytest.raises(DomainValidationError, match="repository identity"):
        validate_profile_successor(predecessor, replace(successor, repository_id=999))


def test_profile_applicability_uses_half_open_sealed_time_interval() -> None:
    profile = _profile(effective_from=NOW)
    successor = NOW + timedelta(hours=1)

    assert not profile.applies_at(NOW - timedelta(microseconds=1))
    assert profile.applies_at(NOW)
    assert profile.applies_at(
        successor - timedelta(microseconds=1), successor_effective_from=successor
    )
    assert not profile.applies_at(successor, successor_effective_from=successor)
    with pytest.raises(DomainValidationError, match="later than predecessor"):
        profile.applies_at(NOW, successor_effective_from=NOW)


@pytest.mark.parametrize(
    ("age", "expected"),
    [
        (timedelta(0), FreshnessResult.FRESH),
        (timedelta(seconds=600), FreshnessResult.FRESH),
        (timedelta(seconds=600, microseconds=1), FreshnessResult.STALE),
        (timedelta(microseconds=-1), FreshnessResult.CLOCK_ANOMALY),
    ],
)
def test_freshness_uses_evidence_seal_with_inclusive_600_second_boundary(
    age: timedelta,
    expected: FreshnessResult,
) -> None:
    assert evaluate_freshness(NOW, NOW + age) is expected


def test_ready_assessment_has_exact_explicit_identity_and_schema_content() -> None:
    assessment = _assess()
    payload = assessment.as_mapping()

    assert assessment.verdict is PreparednessVerdict.READY_FOR_HUMAN_REVIEW
    assert assessment.reason_codes == ()
    assert payload["schema"] == PREPAREDNESS_ASSESSMENT_SCHEMA_ID
    assert payload["digest_algorithm"] == DIGEST_FORMAT
    identity = cast(dict[str, object], payload["identity"])
    assert identity["repository_id"] == 101
    assert identity["pull_request_id"] == 202
    assert identity["pull_number"] == 17
    assert identity["head_sha"] == HEAD
    assert identity["profile"] == _profile().identity.as_mapping()
    assert payload["evidence_sealed_at"] == "2026-08-11T12:00:00.000000Z"
    assert payload["evaluated_at"] == "2026-08-11T12:00:00.000000Z"
    assert payload["freshness"] == "FRESH"
    assert payload["reason_codes"] == []


def test_assessment_content_and_post_digest_identity_are_deterministic() -> None:
    checks = (
        _check(check_run_id=2, producer_app_id=9, check_name="lint"),
        _check(check_run_id=1),
    )
    statuses = (
        _status(status_id=12, context="lint"),
        _status(status_id=11),
    )
    reviews = (
        _review(review_id=22, reviewer_id=32),
        _review(review_id=21, reviewer_id=31),
    )
    profile = _profile(
        required_checks=(RequiredCheck(9, "lint"), RequiredCheck(7, "build")),
        required_statuses=(RequiredStatus("lint"), RequiredStatus("CI")),
    )

    first = _assess(
        profile=profile,
        evidence=_evidence(checks=checks, statuses=statuses, reviews=reviews),
    )
    second = _assess(
        profile=replace(
            profile,
            required_checks=tuple(reversed(profile.required_checks)),
            required_statuses=tuple(reversed(profile.required_statuses)),
        ),
        evidence=_evidence(
            checks=tuple(reversed(checks)),
            statuses=tuple(reversed(statuses)),
            reviews=tuple(reversed(reviews)),
        ),
    )

    assert first == second
    assert first.as_mapping() == second.as_mapping()
    assert preparedness_assessment_id(Digest("3" * 64)) == preparedness_assessment_id(
        Digest("3" * 64)
    )
    assert preparedness_assessment_id(Digest("3" * 64)) != preparedness_assessment_id(
        Digest("4" * 64)
    )


def test_uncertainty_takes_precedence_over_ordinary_blockers() -> None:
    profile = _profile(
        required_checks=(RequiredCheck(7, "missing"),),
        required_statuses=(RequiredStatus("missing"),),
    )
    assessment = _assess(
        profile=profile,
        evidence=_evidence(
            state="closed",
            draft=True,
            complete=False,
            stable=False,
            checks=(),
            statuses=(),
            reviews=(_review(state="CHANGES_REQUESTED"),),
        ),
    )

    assert assessment.verdict is PreparednessVerdict.INDETERMINATE
    assert assessment.reason_codes == (
        PreparednessReasonCode.EVIDENCE_INCOMPLETE,
        PreparednessReasonCode.EVIDENCE_UNSTABLE,
    )
    assert PreparednessReasonCode.PR_CLOSED not in assessment.reason_codes
    assert PreparednessReasonCode.REQUIRED_CHECK_MISSING not in assessment.reason_codes


@pytest.mark.parametrize(
    ("age", "reason"),
    [
        (timedelta(seconds=601), PreparednessReasonCode.EVIDENCE_STALE),
        (timedelta(seconds=-1), PreparednessReasonCode.EVIDENCE_CLOCK_ANOMALY),
    ],
)
def test_stale_and_clock_reversal_are_indeterminate(
    age: timedelta,
    reason: PreparednessReasonCode,
) -> None:
    assessment = _assess(evaluated_at=NOW + age)
    assert assessment.verdict is PreparednessVerdict.INDETERMINATE
    assert assessment.reason_codes == (reason,)


def test_profile_applicability_and_identity_configuration_mismatches_fail_closed() -> (
    None
):
    assessment = _assess(
        profile=_profile(repository_id=999, effective_from=NOW + timedelta(seconds=1)),
        evidence=_evidence(
            observed=_identity(pull_request_id=999),
            digest=Digest("9" * 64),
        ),
    )

    assert assessment.verdict is PreparednessVerdict.INDETERMINATE
    assert assessment.reason_codes == (
        PreparednessReasonCode.EVIDENCE_IDENTITY_MISMATCH,
        PreparednessReasonCode.ACQUISITION_CONFIGURATION_MISMATCH,
        PreparednessReasonCode.PROFILE_REPOSITORY_MISMATCH,
        PreparednessReasonCode.PROFILE_NOT_APPLICABLE,
    )


def test_identity_mismatch_binds_exact_expected_and_observed_identities() -> None:
    observed = _identity()
    expected_pull = _identity(pull_request_id=999)
    expected_head = _identity(head_sha=OTHER_HEAD)
    first = _assess(
        evidence=_evidence(expected=expected_pull, observed=observed),
    )
    second = _assess(
        evidence=_evidence(expected=expected_head, observed=observed),
    )

    first_summary = _summary(first)
    second_summary = _summary(second)
    assert first_summary["expected_identity"] == expected_pull.as_mapping()
    assert second_summary["expected_identity"] == expected_head.as_mapping()
    assert first_summary["observed_identity"] == observed.as_mapping()
    assert second_summary["observed_identity"] == observed.as_mapping()
    assert first.as_mapping() != second.as_mapping()


def test_successor_boundary_makes_older_profile_indeterminate() -> None:
    assessment = _assess(successor_effective_from=NOW)
    assert assessment.reason_codes == (PreparednessReasonCode.PROFILE_NOT_APPLICABLE,)


def test_unknown_pull_state_and_precise_upstream_uncertainty_fail_closed() -> None:
    assessment = _assess(
        evidence=_evidence(
            state="merged-ish",
            uncertainty=(
                PreparednessReasonCode.EVIDENCE_RATE_LIMITED,
                PreparednessReasonCode.EVIDENCE_PAGINATION_UNCERTAIN,
            ),
        )
    )
    assert assessment.verdict is PreparednessVerdict.INDETERMINATE
    assert assessment.reason_codes == (
        PreparednessReasonCode.EVIDENCE_RATE_LIMITED,
        PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE,
        PreparednessReasonCode.EVIDENCE_PAGINATION_UNCERTAIN,
    )


def test_all_deterministic_not_ready_reason_codes_are_preserved() -> None:
    profile = _profile(
        required_checks=(
            RequiredCheck(1, "missing"),
            RequiredCheck(2, "pending"),
            RequiredCheck(3, "failed"),
        ),
        required_statuses=(
            RequiredStatus("missing"),
            RequiredStatus("pending"),
            RequiredStatus("failure"),
            RequiredStatus("error"),
        ),
    )
    evidence = _evidence(
        state="closed",
        draft=True,
        checks=(
            _check(
                check_run_id=2,
                producer_app_id=2,
                check_name="pending",
                status="queued",
                conclusion=None,
                completed_at=None,
            ),
            _check(
                check_run_id=3,
                producer_app_id=3,
                check_name="failed",
                conclusion="failure",
            ),
        ),
        statuses=(
            _status(status_id=1, context="pending", state="pending"),
            _status(status_id=2, context="failure", state="failure"),
            _status(status_id=3, context="error", state="error"),
        ),
        reviews=(_review(state="CHANGES_REQUESTED"),),
    )

    assessment = _assess(profile=profile, evidence=evidence)

    assert assessment.verdict is PreparednessVerdict.NOT_READY
    assert assessment.reason_codes == (
        PreparednessReasonCode.PR_CLOSED,
        PreparednessReasonCode.PR_DRAFT,
        PreparednessReasonCode.REQUIRED_CHECK_MISSING,
        PreparednessReasonCode.REQUIRED_CHECK_PENDING,
        PreparednessReasonCode.REQUIRED_CHECK_UNSUCCESSFUL,
        PreparednessReasonCode.REQUIRED_STATUS_MISSING,
        PreparednessReasonCode.REQUIRED_STATUS_PENDING,
        PreparednessReasonCode.REQUIRED_STATUS_FAILURE,
        PreparednessReasonCode.REQUIRED_STATUS_ERROR,
        PreparednessReasonCode.CURRENT_HEAD_CHANGES_REQUESTED,
    )


@pytest.mark.parametrize("conclusion", sorted(ACCEPTED_CHECK_CONCLUSIONS))
def test_only_recognized_success_like_terminal_checks_satisfy(
    conclusion: str,
) -> None:
    assert _assess(
        evidence=_evidence(checks=(_check(conclusion=conclusion),))
    ).verdict is (PreparednessVerdict.READY_FOR_HUMAN_REVIEW)


@pytest.mark.parametrize(
    "conclusion",
    [
        "action_required",
        "cancelled",
        "failure",
        "stale",
        "startup_failure",
        "timed_out",
    ],
)
def test_recognized_unsuccessful_check_conclusions_block(conclusion: str) -> None:
    assessment = _assess(evidence=_evidence(checks=(_check(conclusion=conclusion),)))
    assert assessment.reason_codes == (
        PreparednessReasonCode.REQUIRED_CHECK_UNSUCCESSFUL,
    )


def test_check_identity_and_remote_generation_order_are_exact() -> None:
    older_failure = _check(
        check_run_id=100,
        conclusion="failure",
        started_at=NOW - timedelta(minutes=3),
    )
    newer_success = _check(
        check_run_id=1,
        conclusion="success",
        started_at=NOW - timedelta(minutes=2),
    )
    same_time_higher_id_failure = replace(
        newer_success, check_run_id=2, conclusion="failure"
    )

    assert _assess(
        evidence=_evidence(checks=(newer_success, older_failure))
    ).verdict is (PreparednessVerdict.READY_FOR_HUMAN_REVIEW)
    assert _assess(
        evidence=_evidence(checks=(newer_success, same_time_higher_id_failure))
    ).reason_codes == (PreparednessReasonCode.REQUIRED_CHECK_UNSUCCESSFUL,)
    assert _assess(
        evidence=_evidence(checks=(_check(producer_app_id=8),))
    ).reason_codes == (PreparednessReasonCode.REQUIRED_CHECK_MISSING,)


def test_unprovable_or_malformed_check_selection_is_indeterminate() -> None:
    no_time = _check(check_run_id=1, started_at=None)
    timed = _check(check_run_id=2)
    assert _assess(evidence=_evidence(checks=(no_time, timed))).reason_codes == (
        PreparednessReasonCode.CHECK_AMBIGUITY,
    )

    contradictions = (
        _check(check_run_id=3),
        _check(check_run_id=3, conclusion="failure"),
    )
    assert _assess(evidence=_evidence(checks=contradictions)).reason_codes == (
        PreparednessReasonCode.CHECK_AMBIGUITY,
    )
    assert _assess(
        evidence=_evidence(checks=(_check(head_sha=OTHER_HEAD),))
    ).reason_codes == (PreparednessReasonCode.CHECK_AMBIGUITY,)


@pytest.mark.parametrize(
    "check",
    [
        _check(status="mystery"),
        _check(conclusion="SUCCESS"),
        _check(conclusion=None),
        _check(status="queued", conclusion="success", completed_at=None),
        _check(status="in_progress", conclusion=None, completed_at=NOW),
    ],
)
def test_ambiguous_check_states_fail_closed(check: CheckRunEvidence) -> None:
    assessment = _assess(evidence=_evidence(checks=(check,)))
    assert assessment.verdict is PreparednessVerdict.INDETERMINATE
    assert assessment.reason_codes == (PreparednessReasonCode.CHECK_AMBIGUITY,)


def test_status_context_casefold_and_latest_remote_watermark_selection() -> None:
    profile = _profile(required_statuses=(RequiredStatus("Straße"),))
    older_failure = _status(
        status_id=99,
        context="STRASSE",
        state="failure",
        updated_at=NOW - timedelta(minutes=2),
    )
    newer_success = _status(
        status_id=1,
        context="strasse",
        state="success",
        updated_at=NOW - timedelta(minutes=1),
    )
    assessment = _assess(
        profile=profile,
        evidence=_evidence(statuses=(newer_success, older_failure)),
    )

    assert assessment.verdict is PreparednessVerdict.READY_FOR_HUMAN_REVIEW
    item = cast(
        list[dict[str, object]], _summary(assessment)["required_commit_statuses"]
    )[0]
    assert item["context"] == "Straße"
    assert item["context_key"] == "strasse"
    assert item["selected_context"] == "strasse"
    assert item["selected_status_id"] == 1


def test_status_id_tiebreak_and_only_exact_success_state() -> None:
    same_time = NOW - timedelta(minutes=1)
    success = _status(status_id=1, state="success", updated_at=same_time)
    failure = _status(status_id=2, state="failure", updated_at=same_time)
    assessment = _assess(evidence=_evidence(statuses=(success, failure)))
    assert assessment.reason_codes == (PreparednessReasonCode.REQUIRED_STATUS_FAILURE,)

    uppercase = _assess(evidence=_evidence(statuses=(_status(state="SUCCESS"),)))
    assert uppercase.reason_codes == (PreparednessReasonCode.STATUS_AMBIGUITY,)


def test_status_context_is_neither_trimmed_nor_unicode_normalized() -> None:
    spaced_profile = _profile(required_statuses=(RequiredStatus(" CI "),))
    assert (
        _assess(
            profile=spaced_profile,
            evidence=_evidence(statuses=(_status(context=" ci "),)),
        ).verdict
        is PreparednessVerdict.READY_FOR_HUMAN_REVIEW
    )
    assert _assess(
        profile=spaced_profile,
        evidence=_evidence(statuses=(_status(context="ci"),)),
    ).reason_codes == (PreparednessReasonCode.REQUIRED_STATUS_MISSING,)

    composed_profile = _profile(required_statuses=(RequiredStatus("é"),))
    assert _assess(
        profile=composed_profile,
        evidence=_evidence(statuses=(_status(context="e\u0301"),)),
    ).reason_codes == (PreparednessReasonCode.REQUIRED_STATUS_MISSING,)


def test_contradictory_or_wrong_head_status_evidence_is_indeterminate() -> None:
    contradictory = (
        _status(status_id=11, state="success"),
        _status(status_id=11, state="failure"),
    )
    assert _assess(evidence=_evidence(statuses=contradictory)).reason_codes == (
        PreparednessReasonCode.STATUS_AMBIGUITY,
    )
    assert _assess(
        evidence=_evidence(statuses=(_status(head_sha=OTHER_HEAD),))
    ).reason_codes == (PreparednessReasonCode.STATUS_AMBIGUITY,)


def test_review_reduction_is_current_head_only_and_neutral_activity_does_not_clear() -> (
    None
):
    changes = _review(
        review_id=1,
        state="CHANGES_REQUESTED",
        submitted_at=NOW - timedelta(minutes=4),
    )
    commented = _review(
        review_id=2,
        state="COMMENTED",
        submitted_at=NOW - timedelta(minutes=3),
    )
    pending = _review(review_id=3, state="PENDING", submitted_at=None)
    old_head_changes = _review(
        review_id=4,
        reviewer_id=99,
        commit_id=OTHER_HEAD,
        state="CHANGES_REQUESTED",
    )

    assessment = _assess(
        evidence=_evidence(reviews=(pending, old_head_changes, commented, changes))
    )
    assert assessment.reason_codes == (
        PreparednessReasonCode.CURRENT_HEAD_CHANGES_REQUESTED,
    )


def test_later_approval_replaces_current_head_changes_requested() -> None:
    changes = _review(
        review_id=1,
        state="CHANGES_REQUESTED",
        submitted_at=NOW - timedelta(minutes=2),
    )
    approval = _review(review_id=2, submitted_at=NOW - timedelta(minutes=1))

    assessment = _assess(evidence=_evidence(reviews=(approval, changes)))

    assert assessment.verdict is PreparednessVerdict.READY_FOR_HUMAN_REVIEW
    assert _summary(assessment)["current_head_review_opinions"] == [
        {"reviewer_id": 31, "review_id": 2, "state": "APPROVED"}
    ]


def test_proper_dismissal_removes_affected_active_opinion() -> None:
    changes = _review(
        review_id=1,
        state="CHANGES_REQUESTED",
        submitted_at=NOW - timedelta(minutes=2),
    )
    dismissal = _review(
        review_id=2,
        state="DISMISSED",
        submitted_at=NOW - timedelta(minutes=1),
        dismisses_review_id=1,
    )

    assessment = _assess(evidence=_evidence(reviews=(dismissal, changes)))

    assert assessment.verdict is PreparednessVerdict.READY_FOR_HUMAN_REVIEW
    assert _summary(assessment)["current_head_review_opinions"] == []


def test_dismissal_does_not_resurrect_a_superseded_opinion() -> None:
    changes = _review(
        review_id=1,
        state="CHANGES_REQUESTED",
        submitted_at=NOW - timedelta(minutes=3),
    )
    approval = _review(
        review_id=2,
        state="APPROVED",
        submitted_at=NOW - timedelta(minutes=2),
    )
    dismissal = _review(
        review_id=3,
        state="DISMISSED",
        submitted_at=NOW - timedelta(minutes=1),
        dismisses_review_id=2,
    )

    assessment = _assess(evidence=_evidence(reviews=(dismissal, changes, approval)))

    assert assessment.verdict is PreparednessVerdict.READY_FOR_HUMAN_REVIEW
    assert _summary(assessment)["current_head_review_opinions"] == []


def test_dismissing_a_superseded_opinion_keeps_the_active_replacement() -> None:
    changes = _review(
        review_id=1,
        state="CHANGES_REQUESTED",
        submitted_at=NOW - timedelta(minutes=3),
    )
    approval = _review(
        review_id=2,
        state="APPROVED",
        submitted_at=NOW - timedelta(minutes=2),
    )
    dismissal = _review(
        review_id=3,
        state="DISMISSED",
        submitted_at=NOW - timedelta(minutes=1),
        dismisses_review_id=1,
    )

    assessment = _assess(evidence=_evidence(reviews=(dismissal, changes, approval)))

    assert assessment.verdict is PreparednessVerdict.READY_FOR_HUMAN_REVIEW
    assert _summary(assessment)["current_head_review_opinions"] == [
        {"reviewer_id": 31, "review_id": 2, "state": "APPROVED"}
    ]


@pytest.mark.parametrize(
    "reviews",
    [
        (_review(commit_id=None, state="CHANGES_REQUESTED"),),
        (_review(state="MYSTERY"),),
        (_review(state="DISMISSED", dismisses_review_id=None),),
        (_review(state="DISMISSED", dismisses_review_id=999),),
        (_review(state="APPROVED", dismisses_review_id=999),),
        (
            _review(review_id=1, state="APPROVED"),
            _review(review_id=1, state="CHANGES_REQUESTED"),
        ),
    ],
)
def test_malformed_potentially_blocking_review_evidence_fails_closed(
    reviews: tuple[ReviewEvidence, ...],
) -> None:
    assessment = _assess(evidence=_evidence(reviews=reviews))
    assert assessment.verdict is PreparednessVerdict.INDETERMINATE
    assert assessment.reason_codes == (PreparednessReasonCode.REVIEW_AMBIGUITY,)


def test_review_policy_can_explicitly_disable_change_request_blocker() -> None:
    assessment = _assess(
        profile=_profile(blocking=False),
        evidence=_evidence(reviews=(_review(state="CHANGES_REQUESTED"),)),
    )
    assert assessment.verdict is PreparednessVerdict.READY_FOR_HUMAN_REVIEW


def test_profile_parser_rejects_non_exact_persisted_payloads() -> None:
    payload = _profile().as_mapping()
    invalid_values: list[dict[str, object]] = []

    additional = deepcopy(payload)
    additional["extra"] = True
    invalid_values.append(additional)
    wrong_schema = deepcopy(payload)
    wrong_schema["schema"] = "wrong"
    invalid_values.append(wrong_schema)
    wrong_algorithm = deepcopy(payload)
    wrong_algorithm["digest_algorithm"] = "sha256"
    invalid_values.append(wrong_algorithm)
    wrong_window = deepcopy(payload)
    wrong_window["freshness_window_seconds"] = 599
    invalid_values.append(wrong_window)
    wrong_time = deepcopy(payload)
    wrong_time["effective_from"] = "2026-08-10T12:00:00Z"
    invalid_values.append(wrong_time)
    wrong_identity = deepcopy(payload)
    cast(dict[str, object], wrong_identity["identity"])["profile_id"] = str(
        PROFILE_ID
    ).upper()
    invalid_values.append(wrong_identity)
    wrong_status_key = deepcopy(payload)
    cast(list[dict[str, object]], wrong_status_key["required_commit_statuses"])[0][
        "context_key"
    ] = "different"
    invalid_values.append(wrong_status_key)

    for invalid in invalid_values:
        with pytest.raises(DomainValidationError):
            PreparednessProfile.from_mapping(invalid)


def test_profile_parser_round_trips_a_successor_predecessor_reference() -> None:
    successor = _profile(
        version=2,
        predecessor=ProfileIdentity(PROFILE_ID, 1),
        effective_from=NOW,
    )
    assert PreparednessProfile.from_mapping(successor.as_mapping()) == successor


def test_profile_and_persisted_parser_validation_guards_fail_closed() -> None:
    profile = _profile()
    invalid_profiles = (
        lambda: ProfileIdentity(cast(UUID, "not-a-uuid"), 1),
        lambda: replace(profile, block_on_changes_requested=cast(bool, 1)),
        lambda: replace(
            profile,
            acquisition_configuration_digest=cast(Digest, "not-a-digest"),
        ),
        lambda: replace(
            profile,
            required_checks=cast(tuple[RequiredCheck, ...], ("not-a-check",)),
        ),
        lambda: replace(
            profile,
            required_statuses=cast(tuple[RequiredStatus, ...], ("not-a-status",)),
        ),
        lambda: replace(_status(), context_key="not-casefolded"),
    )
    for invalid in invalid_profiles:
        with pytest.raises(DomainValidationError):
            invalid()

    def invalid_payload(**replacement: object) -> dict[str, object]:
        payload = deepcopy(profile.as_mapping())
        payload.update(replacement)
        return payload

    parser_inputs = (
        invalid_payload(review_policy={"block_on_current_head_changes_requested": 1}),
        invalid_payload(identity=[]),
        invalid_payload(required_checks={}),
        invalid_payload(effective_from=1),
        invalid_payload(effective_from="2026-08-10T12:00:00.0Z"),
        invalid_payload(identity={"profile_id": 1, "version": 1}),
        invalid_payload(identity={"profile_id": "not-a-uuid", "version": 1}),
        invalid_payload(identity={1: str(PROFILE_ID), "version": 1}),
    )
    for payload in parser_inputs:
        with pytest.raises(DomainValidationError):
            PreparednessProfile.from_mapping(payload)


def test_evidence_assessment_and_evaluator_type_guards_fail_closed() -> None:
    evidence = _evidence()
    invalid_evidence: tuple[Callable[[], PreparednessEvidence], ...] = (
        lambda: replace(
            evidence,
            expected_identity=cast(PullRequestIdentity, "wrong"),
        ),
        lambda: replace(
            evidence,
            observed_identity=cast(PullRequestIdentity, "wrong"),
        ),
        lambda: replace(evidence, analysis_view_digest=cast(Digest, "wrong")),
        lambda: replace(
            evidence,
            acquisition_configuration_digest=cast(Digest, "wrong"),
        ),
        lambda: replace(evidence, draft=cast(bool, 1)),
        lambda: replace(
            evidence,
            checks=cast(tuple[CheckRunEvidence, ...], ("wrong",)),
        ),
        lambda: replace(
            evidence,
            uncertainty_reasons=cast(
                tuple[PreparednessReasonCode, ...],
                (PreparednessReasonCode.PR_DRAFT,),
            ),
        ),
        lambda: replace(
            evidence,
            uncertainty_reasons=cast(
                tuple[PreparednessReasonCode, ...],
                ("NOT_A_REASON",),
            ),
        ),
    )
    for invalid_evidence_factory in invalid_evidence:
        with pytest.raises(DomainValidationError):
            invalid_evidence_factory()

    assessment = _assess()
    invalid_assessments: tuple[Callable[[], PreparednessAssessment], ...] = (
        lambda: replace(
            assessment,
            identity=cast(PullRequestIdentity, "wrong"),
        ),
        lambda: replace(
            assessment,
            profile=cast(ProfileIdentity, "wrong"),
        ),
        lambda: replace(
            assessment,
            analysis_view_digest=cast(Digest, "wrong"),
        ),
        lambda: replace(
            assessment,
            freshness=cast(FreshnessResult, "wrong"),
        ),
        lambda: replace(
            assessment,
            verdict=cast(PreparednessVerdict, "wrong"),
        ),
        lambda: replace(
            assessment,
            reason_codes=cast(tuple[PreparednessReasonCode, ...], ("wrong",)),
        ),
    )
    for invalid_assessment_factory in invalid_assessments:
        with pytest.raises(DomainValidationError):
            invalid_assessment_factory()

    with pytest.raises(DomainValidationError, match="explicit PreparednessProfile"):
        assess_preparedness(cast(PreparednessProfile, "wrong"), evidence, NOW)
    with pytest.raises(DomainValidationError, match="must be PreparednessEvidence"):
        assess_preparedness(_profile(), cast(PreparednessEvidence, "wrong"), NOW)


def test_neutral_review_with_a_dismissal_target_is_ambiguous() -> None:
    assessment = _assess(
        evidence=_evidence(
            reviews=(
                _review(
                    state="COMMENTED",
                    dismisses_review_id=99,
                ),
            )
        )
    )
    assert assessment.reason_codes == (PreparednessReasonCode.REVIEW_AMBIGUITY,)


@pytest.mark.parametrize(
    "factory",
    [
        lambda: ProfileIdentity(PROFILE_ID, 0),
        lambda: RequiredCheck(True, "build"),
        lambda: RequiredCheck(1, ""),
        lambda: RequiredStatus(""),
        lambda: RequiredStatus("ci", "wrong"),
        lambda: _identity(repository_id=0),
        lambda: _identity(head_sha="A" * 40),
        lambda: _identity(base_ref=""),
        lambda: _status(status_id=0),
        lambda: _status(context=""),
        lambda: _status(updated_at=datetime(2026, 1, 1)),
        lambda: _check(check_run_id=0),
        lambda: _check(conclusion=""),
        lambda: _check(started_at=datetime(2026, 1, 1)),
        lambda: _review(review_id=0),
        lambda: _review(commit_id=""),
        lambda: _review(dismisses_review_id=0),
    ],
)
def test_value_objects_reject_invalid_contract_values(
    factory: Callable[[], object],
) -> None:
    with pytest.raises(DomainValidationError):
        factory()


def test_check_run_remote_timing_rejects_clock_reversal() -> None:
    assert _check(started_at=NOW, completed_at=NOW).completed_at == NOW
    with pytest.raises(DomainValidationError, match="must not precede"):
        _check(
            started_at=NOW,
            completed_at=NOW - timedelta(microseconds=1),
        )


def test_non_utc_clocks_and_invalid_assessment_id_input_are_rejected() -> None:
    non_utc = timezone(timedelta(hours=1))
    with pytest.raises(DomainValidationError, match="must use UTC"):
        evaluate_freshness(NOW.astimezone(non_utc), NOW)
    with pytest.raises(DomainValidationError, match="must be a Digest"):
        preparedness_assessment_id(cast(Digest, "not-a-digest"))


def test_assessment_constructor_enforces_verdict_reason_invariants() -> None:
    ready = _assess()
    with pytest.raises(DomainValidationError, match="READY"):
        replace(ready, reason_codes=(PreparednessReasonCode.PR_DRAFT,))
    with pytest.raises(DomainValidationError, match="INDETERMINATE"):
        replace(
            ready,
            verdict=PreparednessVerdict.INDETERMINATE,
            reason_codes=(PreparednessReasonCode.PR_DRAFT,),
        )
    with pytest.raises(DomainValidationError, match="NOT_READY"):
        replace(
            ready,
            verdict=PreparednessVerdict.NOT_READY,
            reason_codes=(PreparednessReasonCode.EVIDENCE_STALE,),
        )
