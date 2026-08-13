"""GS-I4 normalized evidence and facet-aware ordering tests."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Self, cast
from uuid import UUID

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import github_steward.application.preparedness as coherent_acquisition
import github_steward.application.preparedness as preparedness_pipeline
from github_steward.adapters.canonicalization.rfc8785 import (
    digest_payload,
    envelope_payload,
)
from github_steward.application.preparedness import (
    CoherentRecordedAcquisitionService,
    CurrentPointerPromotionService,
    DeterministicPreparednessPipeline,
    PointerPromotionOutcome,
    PointerPromotionResult,
)
from github_steward.domain.acquisition import (
    MAX_CHECK_SUITES,
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
    RequestedReviewers,
    RequestedTeam,
    RequestedUser,
    SourceOrderRelation,
    compare_source_order,
    latest_commit_statuses,
    normalize_check_runs,
    normalize_commit_statuses,
    reduce_current_head_reviews,
)
from github_steward.domain.canonical import DIGEST_FORMAT, MAX_SAFE_INTEGER, Digest
from github_steward.domain.preparedness import (
    AcquisitionConfigurationIdentity,
    PreparednessProfile,
    PreparednessReasonCode,
    PreparednessVerdict,
    ProfileIdentity,
    ProfileReference,
    PullRequestIdentity,
    RequiredCheck,
    RequiredStatus,
)
from github_steward.ports.github import (
    CoherentAcquisitionFailure,
    CoherentAcquisitionResult,
    EvidenceFacet,
    RecordedFacet,
    RecordedGitHubEvidencePort,
    RecordedGitHubResponse,
)
from github_steward.ports.persistence import (
    AnalysisViewRecord,
    CanonicalObservationRecord,
    ObservationPointer,
    ObservationVersionId,
    PointerCreateOutcome,
    PreparednessAssessmentRecord,
    PreparednessProfileId,
    PreparednessProfileRecord,
)

NOW = datetime(2026, 8, 11, 12, tzinfo=UTC)
HEAD = "a" * 40
OTHER_HEAD = "b" * 40
BASE = "c" * 40
DIGESTS = {name: f"{index + 1:x}" * 64 for index, name in enumerate(SEMANTIC_FACETS)}


def _anchor(**changes: object) -> PullRequestAnchor:
    values: dict[str, object] = {
        "repository_id": 77,
        "pull_number": 4,
        "pull_request_id": 404,
        "head_sha": HEAD,
        "base_repository_id": 77,
        "base_ref": "main",
        "base_sha": BASE,
        "state": "open",
        "draft": False,
        "updated_at": NOW,
        "changed_files": 1,
        "commit_count": 1,
    }
    values.update(changes)
    return PullRequestAnchor(**values)  # type: ignore[arg-type]


def _status(
    status_id: int = 1,
    *,
    head_sha: str = HEAD,
    context: str = "CI/Test",
    state: str = "success",
    updated_at: datetime = NOW,
) -> NormalizedCommitStatus:
    return NormalizedCommitStatus(status_id, head_sha, context, state, updated_at)


def _check(
    check_run_id: int = 1,
    *,
    head_sha: str = HEAD,
    producer_app_id: int = 9,
    check_name: str = "tests",
    status: str = "completed",
    conclusion: str | None = "success",
    started_at: datetime | None = NOW,
    completed_at: datetime | None = NOW + timedelta(minutes=1),
) -> NormalizedCheckRun:
    return NormalizedCheckRun(
        check_run_id,
        head_sha,
        producer_app_id,
        check_name,
        status,
        conclusion,
        started_at,
        completed_at,
    )


def _review(
    review_id: int,
    state: str,
    *,
    reviewer_id: int = 10,
    commit_id: str | None = HEAD,
    submitted_at: datetime | None = NOW,
    dismisses: int | None = None,
) -> NormalizedReview:
    return NormalizedReview(
        review_id,
        reviewer_id,
        commit_id,
        state,
        submitted_at,
        dismisses,
    )


def _view(**changes: object) -> CoherentAnalysisView:
    values: dict[str, object] = {
        "analysis_view_id": "11111111-1111-5111-8111-111111111111",
        "anchor": _anchor(),
        "files": (FileEvidence("d" * 40, "a.py", "modified", 1, 1, 2),),
        "commits": (CommitEvidence(HEAD),),
        "files_digest": DIGESTS["files"],
        "commits_digest": DIGESTS["commits"],
        "requested_reviewers": RequestedReviewers(),
        "check_suite_count": 1,
        "check_runs": (_check(),),
        "commit_statuses": (_status(),),
        "reviews": (),
        "acquisition_configuration_digest": "f" * 64,
        "evidence_sealed_at": NOW + timedelta(minutes=2),
        "raw_digest_inventory": {"anchor_a": ("a" * 64,)},
        "semantic_digest_inventory": DIGESTS,
    }
    values.update(changes)
    return CoherentAnalysisView(**values)  # type: ignore[arg-type]


def test_requested_reviewers_use_numeric_identity_and_sort_deterministically() -> None:
    reviewers = RequestedReviewers(
        [RequestedUser(2, "two"), RequestedUser(1, "one"), RequestedUser(1, "one")],
        [RequestedTeam(8, "ops"), RequestedTeam(7, "core")],
    )
    assert [item.user_id for item in reviewers.users] == [1, 2]
    assert [item.team_id for item in reviewers.teams] == [7, 8]
    assert RequestedReviewers.from_mapping(reviewers.as_mapping()) == reviewers


def test_coherent_view_canonicalizes_files_but_preserves_commit_sequence() -> None:
    first_file = FileEvidence("e" * 40, "z.py", "modified", 1, 0, 1)
    second_file = FileEvidence("d" * 40, "a.py", "added", 2, 0, 2)
    first_commit = CommitEvidence("e" * 40)
    second_commit = CommitEvidence("d" * 40)

    view = _view(
        files=(first_file, second_file),
        commits=(first_commit, second_commit),
    )

    assert view.files == (second_file, first_file)
    assert view.commits == (first_commit, second_commit)
    assert CoherentAnalysisView.from_mapping(view.as_mapping()) == view


@pytest.mark.parametrize(
    "values",
    [
        [RequestedUser(1, "one"), RequestedUser(1, "renamed")],
        [RequestedTeam(1, "one"), RequestedTeam(1, "renamed")],
    ],
)
def test_conflicting_duplicate_requested_reviewer_ids_fail_closed(
    values: list[RequestedUser] | list[RequestedTeam],
) -> None:
    with pytest.raises(EvidenceNormalizationError, match="conflicting duplicate"):
        if isinstance(values[0], RequestedUser):
            RequestedReviewers(values, ())
        else:
            RequestedReviewers((), values)


def test_status_context_identity_is_casefold_only_without_trim_or_normalization() -> (
    None
):
    sharp_s = _status(context="Straße")
    upper = _status(2, context="STRASSE")
    spaced = _status(3, context=" Straße ")
    composed = _status(4, context="é")
    decomposed = _status(5, context="e\u0301")
    assert sharp_s.context_key == upper.context_key == "strasse"
    assert spaced.context_key == " strasse "
    assert composed.context_key != decomposed.context_key
    assert "context" not in sharp_s.as_mapping()


@settings(derandomize=True, max_examples=100, deadline=None)
@given(
    st.text(
        alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/_-",
        min_size=1,
        max_size=50,
    )
)
def test_arbitrary_ascii_status_casing_has_one_semantic_identity(context: str) -> None:
    upper = _status(context=context.upper())
    lower = _status(context=context.lower())
    assert upper.context_key == lower.context_key
    assert upper.as_mapping() == lower.as_mapping()


def test_status_facet_digest_and_source_order_ignore_display_casing() -> None:
    upper = _status(context="CI/Test")
    lower = _status(context="ci/test")
    assert (
        envelope_payload([upper.as_mapping()]).digest
        == envelope_payload([lower.as_mapping()]).digest
    )

    current = _view(commit_statuses=(upper,))
    candidate = replace(current, commit_statuses=(lower,))
    assert compare_source_order(current, candidate) is SourceOrderRelation.REPLAY


def test_status_latest_selection_uses_updated_at_then_numeric_id() -> None:
    earlier = _status(50, updated_at=NOW)
    same_time_later_id = _status(51, state="pending", updated_at=NOW)
    newer_time = _status(2, state="failure", updated_at=NOW + timedelta(seconds=1))
    latest = latest_commit_statuses((same_time_later_id, newer_time, earlier))
    assert latest["ci/test"] == newer_time


def test_contradictory_immutable_status_identity_is_malformed() -> None:
    with pytest.raises(EvidenceNormalizationError, match="contradictory immutable"):
        normalize_commit_statuses((_status(), _status(state="failure")))

    with pytest.raises(EvidenceNormalizationError, match="invalid value"):
        normalize_commit_statuses((cast(NormalizedCommitStatus, "not-a-status"),))


def test_check_identity_and_lifecycle_validation() -> None:
    check = _check()
    assert check.required_identity == (9, "tests")
    assert normalize_check_runs((check, check)) == (check,)
    with pytest.raises(EvidenceNormalizationError, match="terminal material"):
        _check(status="queued", conclusion="success", completed_at=NOW)
    with pytest.raises(EvidenceNormalizationError, match="lacked conclusion"):
        _check(status="completed", conclusion=None)


def test_check_remote_timing_cannot_reverse_in_constructor_or_coherent_mapping() -> (
    None
):
    assert _check(started_at=NOW, completed_at=NOW).completed_at == NOW
    with pytest.raises(EvidenceNormalizationError, match="must not precede"):
        _check(
            started_at=NOW,
            completed_at=NOW - timedelta(microseconds=1),
        )

    mapping = _view().as_mapping()
    facets = cast(dict[str, object], mapping["facets"])
    checks = cast(list[dict[str, object]], facets["check_runs"])
    checks[0]["started_at"] = "2026-08-11T12:00:00.000000Z"
    checks[0]["completed_at"] = "2026-08-11T11:59:59.999999Z"
    with pytest.raises(EvidenceNormalizationError, match="must not precede"):
        CoherentAnalysisView.from_mapping(mapping)


def test_review_reduction_is_current_head_only_and_neutral_does_not_clear() -> None:
    opinions = reduce_current_head_reviews(
        (
            _review(1, "CHANGES_REQUESTED"),
            _review(2, "COMMENTED", submitted_at=NOW + timedelta(seconds=1)),
            _review(
                3,
                "APPROVED",
                reviewer_id=11,
                commit_id=OTHER_HEAD,
                submitted_at=NOW + timedelta(seconds=2),
            ),
        ),
        HEAD,
    )
    assert [(item.reviewer_id, item.state) for item in opinions] == [
        (10, "CHANGES_REQUESTED")
    ]


def test_later_approval_replaces_change_request_and_dismissal_removes_opinion() -> None:
    replaced = reduce_current_head_reviews(
        (
            _review(1, "CHANGES_REQUESTED"),
            _review(2, "APPROVED", submitted_at=NOW + timedelta(seconds=1)),
        ),
        HEAD,
    )
    assert [(item.review_id, item.state) for item in replaced] == [(2, "APPROVED")]
    dismissed = reduce_current_head_reviews(
        (
            _review(1, "CHANGES_REQUESTED"),
            _review(
                2,
                "DISMISSED",
                submitted_at=NOW + timedelta(seconds=1),
                dismisses=1,
            ),
        ),
        HEAD,
    )
    assert dismissed == ()


@pytest.mark.parametrize(
    "reviews",
    [
        (_review(1, "CHANGES_REQUESTED", commit_id=None),),
        (_review(1, "CHANGES_REQUESTED", submitted_at=None),),
        (_review(2, "DISMISSED", dismisses=None),),
        (_review(2, "DISMISSED", dismisses=99),),
    ],
)
def test_malformed_potentially_blocking_reviews_fail_closed(
    reviews: tuple[NormalizedReview, ...],
) -> None:
    with pytest.raises(EvidenceNormalizationError):
        reduce_current_head_reviews(reviews, HEAD)


def test_coherent_view_round_trip_preserves_complete_semantic_material() -> None:
    view = _view(
        requested_reviewers=RequestedReviewers(
            (RequestedUser(1, "octo"),), (RequestedTeam(2, "core"),)
        ),
        reviews=(_review(1, "APPROVED"),),
    )
    assert CoherentAnalysisView.from_mapping(view.as_mapping()) == view
    assert dict(view.semantic_digest_inventory) == DIGESTS
    assert view.as_mapping()["evidence_sealed_at"] == "2026-08-11T12:02:00.000000Z"


def test_source_order_replay_ignores_local_seal_and_raw_digest_changes() -> None:
    current = _view()
    replay = _view(
        analysis_view_id="22222222-2222-5222-8222-222222222222",
        evidence_sealed_at=NOW + timedelta(minutes=3),
        raw_digest_inventory={"different_recording": ("b" * 64,)},
    )
    assert compare_source_order(current, replay) is SourceOrderRelation.REPLAY


def test_different_head_uses_validated_anchor_timestamp_only() -> None:
    current = _view()
    progressed = _view(
        anchor=_anchor(head_sha=OTHER_HEAD, updated_at=NOW + timedelta(seconds=1)),
        commits=(CommitEvidence(OTHER_HEAD),),
    )
    regressed = _view(
        anchor=_anchor(head_sha=OTHER_HEAD, updated_at=NOW - timedelta(seconds=1)),
        commits=(CommitEvidence(OTHER_HEAD),),
    )
    same_time = _view(anchor=_anchor(head_sha=OTHER_HEAD))
    contradictory_identity = _view(
        anchor=_anchor(
            head_sha=OTHER_HEAD,
            pull_request_id=405,
            updated_at=NOW + timedelta(seconds=1),
        )
    )
    assert compare_source_order(current, progressed) is SourceOrderRelation.PROGRESSION
    assert compare_source_order(current, regressed) is SourceOrderRelation.REGRESSION
    assert compare_source_order(current, same_time) is SourceOrderRelation.INCOMPARABLE
    assert (
        compare_source_order(current, contradictory_identity)
        is SourceOrderRelation.INCOMPARABLE
    )


def test_status_watermark_progression_regression_and_disappearance() -> None:
    current = _view()
    current_status = _status()
    newer_status = _status(2, updated_at=NOW + timedelta(seconds=1))
    newer = _view(commit_statuses=(current_status, newer_status))
    older = _view(commit_statuses=(_status(2, updated_at=NOW - timedelta(seconds=1)),))
    missing = _view(commit_statuses=())
    assert compare_source_order(current, newer) is SourceOrderRelation.PROGRESSION
    assert compare_source_order(current, older) is SourceOrderRelation.REGRESSION
    assert compare_source_order(current, missing) is SourceOrderRelation.REGRESSION

    current_history = _view(
        commit_statuses=(
            _status(10, updated_at=NOW - timedelta(seconds=1)),
            current_status,
        )
    )
    assert (
        compare_source_order(
            current_history,
            _view(commit_statuses=(current_status,)),
        )
        is SourceOrderRelation.REGRESSION
    )

    mixed_removal_and_advance = _view(commit_statuses=(newer_status,))
    assert (
        compare_source_order(current, mixed_removal_and_advance)
        is SourceOrderRelation.INCOMPARABLE
    )

    older_only_addition = _view(
        commit_statuses=(
            current_status,
            _status(2, updated_at=NOW - timedelta(seconds=1)),
        )
    )
    assert (
        compare_source_order(current, older_only_addition)
        is SourceOrderRelation.INCOMPARABLE
    )


def test_check_lifecycle_and_generation_ordering() -> None:
    queued = _view(
        check_runs=(_check(status="queued", conclusion=None, completed_at=None),)
    )
    running = _view(
        check_runs=(_check(status="in_progress", conclusion=None, completed_at=None),)
    )
    completed = _view()
    assert compare_source_order(queued, running) is SourceOrderRelation.PROGRESSION
    assert compare_source_order(running, completed) is SourceOrderRelation.PROGRESSION
    assert compare_source_order(completed, running) is SourceOrderRelation.REGRESSION

    new_generation = _view(
        check_runs=(
            _check(
                2,
                started_at=NOW + timedelta(hours=1),
                completed_at=NOW + timedelta(hours=1, minutes=1),
            ),
        )
    )
    assert (
        compare_source_order(completed, new_generation)
        is SourceOrderRelation.PROGRESSION
    )


def test_same_check_run_start_time_can_appear_only_with_forward_lifecycle() -> None:
    queued_without_start = _view(
        check_runs=(
            _check(
                status="queued",
                conclusion=None,
                started_at=None,
                completed_at=None,
            ),
        )
    )
    running_with_start = _view(
        check_runs=(
            _check(
                status="in_progress",
                conclusion=None,
                started_at=NOW,
                completed_at=None,
            ),
        )
    )
    assert (
        compare_source_order(queued_without_start, running_with_start)
        is SourceOrderRelation.PROGRESSION
    )
    assert (
        compare_source_order(running_with_start, queued_without_start)
        is SourceOrderRelation.REGRESSION
    )

    queued_with_late_start = _view(
        check_runs=(
            _check(
                status="queued",
                conclusion=None,
                started_at=NOW,
                completed_at=None,
            ),
        )
    )
    assert (
        compare_source_order(queued_without_start, queued_with_late_start)
        is SourceOrderRelation.INCOMPARABLE
    )

    running_without_start = _view(
        check_runs=(
            _check(
                status="in_progress",
                conclusion=None,
                started_at=None,
                completed_at=None,
            ),
        )
    )
    assert (
        compare_source_order(queued_with_late_start, running_without_start)
        is SourceOrderRelation.INCOMPARABLE
    )


def test_same_check_run_remote_start_is_stable_once_present() -> None:
    running = _view(
        check_runs=(
            _check(
                status="in_progress",
                conclusion=None,
                started_at=NOW,
                completed_at=None,
            ),
        )
    )
    completed_with_stable_start = _view(check_runs=(_check(started_at=NOW),))
    completed_with_mutated_start = _view(
        check_runs=(
            _check(
                started_at=NOW + timedelta(seconds=1),
                completed_at=NOW + timedelta(minutes=1),
            ),
        )
    )
    assert (
        compare_source_order(running, completed_with_stable_start)
        is SourceOrderRelation.PROGRESSION
    )
    assert (
        compare_source_order(running, completed_with_mutated_start)
        is SourceOrderRelation.INCOMPARABLE
    )


def test_unprovable_check_generation_order_is_incomparable() -> None:
    current = _view(
        check_runs=(
            _check(
                status="queued",
                conclusion=None,
                started_at=None,
                completed_at=None,
            ),
        )
    )
    candidate = _view(
        check_runs=(
            _check(
                2,
                status="queued",
                conclusion=None,
                started_at=None,
                completed_at=None,
            ),
        )
    )
    assert compare_source_order(current, candidate) is SourceOrderRelation.INCOMPARABLE


def test_same_head_unordered_file_or_commit_change_is_incomparable() -> None:
    current = _view()
    assert (
        compare_source_order(current, _view(files_digest="9" * 64))
        is SourceOrderRelation.INCOMPARABLE
    )
    assert (
        compare_source_order(current, _view(commits_digest="9" * 64))
        is SourceOrderRelation.INCOMPARABLE
    )


def test_requested_reviewer_change_requires_strict_anchor_advance() -> None:
    current = _view()
    reviewers = RequestedReviewers((RequestedUser(1, "octo"),), ())
    unchanged_anchor = _view(requested_reviewers=reviewers)
    advanced_anchor = _view(
        anchor=_anchor(updated_at=NOW + timedelta(seconds=1)),
        requested_reviewers=reviewers,
    )
    assert (
        compare_source_order(current, unchanged_anchor)
        is SourceOrderRelation.INCOMPARABLE
    )
    assert (
        compare_source_order(current, advanced_anchor)
        is SourceOrderRelation.PROGRESSION
    )


def test_check_suite_count_and_mixed_aggregate_relations() -> None:
    current = _view()
    assert (
        compare_source_order(current, _view(check_suite_count=2))
        is SourceOrderRelation.PROGRESSION
    )
    assert (
        compare_source_order(_view(check_suite_count=2), current)
        is SourceOrderRelation.REGRESSION
    )
    mixed = _view(
        anchor=_anchor(updated_at=NOW + timedelta(seconds=1)),
        check_suite_count=0,
    )
    assert compare_source_order(current, mixed) is SourceOrderRelation.INCOMPARABLE


@settings(derandomize=True, max_examples=100, deadline=None)
@given(st.integers(min_value=1, max_value=10_000))
def test_replay_is_reflexive_for_status_id(status_id: int) -> None:
    view = _view(commit_statuses=(_status(status_id),))
    assert compare_source_order(view, view) is SourceOrderRelation.REPLAY


def test_individual_mapping_contracts_round_trip_and_reject_derived_key_drift() -> None:
    file = FileEvidence("d" * 40, "src/a.py", "modified", 2, 1, 3)
    commit = CommitEvidence(HEAD)
    status = _status()
    queued = _check(
        status="queued", conclusion=None, started_at=None, completed_at=None
    )
    pending = _review(
        4,
        "PENDING",
        commit_id=None,
        submitted_at=None,
    )

    assert FileEvidence.from_mapping(file.as_mapping()) == file
    assert CommitEvidence.from_mapping(commit.as_mapping()) == commit
    assert NormalizedCommitStatus.from_mapping(status.as_mapping()) == status
    assert NormalizedCheckRun.from_mapping(queued.as_mapping()) == queued
    assert NormalizedReview.from_mapping(pending.as_mapping()) == pending
    assert PullRequestAnchor.from_mapping(_anchor().as_mapping()) == _anchor()

    status_mapping = status.as_mapping()
    status_mapping["context_key"] = "CI/Test"
    with pytest.raises(EvidenceNormalizationError, match=r"casefold\(\)"):
        NormalizedCommitStatus.from_mapping(status_mapping)


def test_value_constructors_reject_malformed_scalar_evidence() -> None:
    with pytest.raises(EvidenceNormalizationError, match="positive JCS-safe"):
        RequestedUser(0, "octo")
    with pytest.raises(EvidenceNormalizationError, match="positive JCS-safe"):
        RequestedTeam(cast(int, True), "core")
    with pytest.raises(EvidenceNormalizationError, match="positive JCS-safe"):
        RequestedUser(MAX_SAFE_INTEGER + 1, "octo")
    with pytest.raises(EvidenceNormalizationError, match="non-empty text"):
        RequestedUser(1, "")
    with pytest.raises(EvidenceNormalizationError, match="non-empty text"):
        RequestedTeam(1, cast(str, 7))
    with pytest.raises(EvidenceNormalizationError, match="lowercase 40-hex"):
        CommitEvidence("A" * 40)
    with pytest.raises(EvidenceNormalizationError, match="lowercase 40-hex"):
        CommitEvidence(cast(str, 7))
    with pytest.raises(EvidenceNormalizationError, match="nonnegative"):
        FileEvidence("d" * 40, "a.py", "modified", -1, 0, 0)
    with pytest.raises(EvidenceNormalizationError, match="nonnegative"):
        FileEvidence(
            "d" * 40,
            "a.py",
            "modified",
            MAX_SAFE_INTEGER + 1,
            0,
            0,
        )
    with pytest.raises(EvidenceNormalizationError, match="nonnegative"):
        FileEvidence("d" * 40, "a.py", "modified", cast(int, False), 0, 0)


def test_temporal_and_state_constructors_fail_closed() -> None:
    with pytest.raises(EvidenceNormalizationError, match="not recognized"):
        _check(status="waiting", conclusion=None, completed_at=None)
    with pytest.raises(EvidenceNormalizationError, match="not recognized"):
        _review(1, "approved")
    with pytest.raises(EvidenceNormalizationError, match="timezone-aware UTC"):
        _status(updated_at=NOW.replace(tzinfo=None))
    with pytest.raises(EvidenceNormalizationError, match="timezone-aware UTC"):
        _status(updated_at=NOW.astimezone(timezone(timedelta(hours=1))))
    with pytest.raises(EvidenceNormalizationError, match="timezone-aware UTC"):
        _status(updated_at=cast(datetime, "not-a-clock"))
    with pytest.raises(EvidenceNormalizationError, match="boolean"):
        _anchor(draft=0)

    anchor_mapping = _anchor().as_mapping()
    anchor_mapping["draft"] = 0
    with pytest.raises(EvidenceNormalizationError, match="boolean"):
        PullRequestAnchor.from_mapping(anchor_mapping)


def test_from_mapping_rejects_noncanonical_shapes_and_timestamps() -> None:
    with pytest.raises(EvidenceNormalizationError, match="keys were not exact"):
        CommitEvidence.from_mapping({"sha": HEAD, "extra": True})
    with pytest.raises(EvidenceNormalizationError, match="fixed UTC timestamp"):
        NormalizedCommitStatus.from_mapping(
            {
                **_status().as_mapping(),
                "updated_at": "2026-08-11T12:00:00Z",
            }
        )
    with pytest.raises(EvidenceNormalizationError, match="non-empty text"):
        NormalizedCheckRun.from_mapping(
            {
                **_check().as_mapping(),
                "conclusion": "",
            }
        )
    with pytest.raises(EvidenceNormalizationError, match="lowercase 40-hex"):
        NormalizedReview.from_mapping(
            {
                **_review(1, "APPROVED").as_mapping(),
                "commit_id": "bad",
            }
        )


def test_coherent_view_constructor_rejects_invalid_typed_material() -> None:
    with pytest.raises(EvidenceNormalizationError, match="anchor must"):
        _view(anchor=cast(PullRequestAnchor, object()))
    with pytest.raises(EvidenceNormalizationError, match="files contained"):
        _view(files=(cast(FileEvidence, object()),))
    with pytest.raises(EvidenceNormalizationError, match="commits contained"):
        _view(commits=(cast(CommitEvidence, object()),))
    with pytest.raises(EvidenceNormalizationError, match="requested_reviewers"):
        _view(requested_reviewers=cast(RequestedReviewers, object()))
    with pytest.raises(EvidenceNormalizationError, match="digest_algorithm"):
        _view(digest_algorithm="sha256")
    with pytest.raises(EvidenceNormalizationError, match="raw digest inventory"):
        _view(raw_digest_inventory={"anchor_a": ()})
    with pytest.raises(EvidenceNormalizationError, match="role was duplicated"):
        _view(
            raw_digest_inventory=(
                ("anchor_a", ("a" * 64,)),
                ("anchor_a", ("b" * 64,)),
            )
        )
    with pytest.raises(EvidenceNormalizationError, match="every required facet"):
        _view(semantic_digest_inventory={"anchor": "a" * 64})
    with pytest.raises(EvidenceNormalizationError, match="lowercase SHA-256"):
        _view(files_digest="bad")
    with pytest.raises(EvidenceNormalizationError, match="timezone-aware UTC"):
        _view(evidence_sealed_at=NOW.replace(tzinfo=None))
    with pytest.raises(EvidenceNormalizationError, match="nonnegative"):
        _view(check_suite_count=-1)
    with pytest.raises(EvidenceNormalizationError, match="non-empty text"):
        _view(analysis_view_id="")


def test_coherent_view_from_mapping_rejects_schema_and_container_drift() -> None:
    wrong_schema = _view().as_mapping()
    wrong_schema["schema"] = "github-steward/coherent-analysis-view/v2"
    with pytest.raises(EvidenceNormalizationError, match="schema was not v1"):
        CoherentAnalysisView.from_mapping(wrong_schema)

    missing_key = _view().as_mapping()
    del missing_key["schema"]
    with pytest.raises(EvidenceNormalizationError, match="keys were not exact"):
        CoherentAnalysisView.from_mapping(missing_key)

    bad_facets = _view().as_mapping()
    bad_facets["facets"] = []
    with pytest.raises(EvidenceNormalizationError, match="facets must be an object"):
        CoherentAnalysisView.from_mapping(bad_facets)

    bad_files = _view().as_mapping()
    facets = cast(dict[str, object], bad_files["facets"])
    facets["files"] = "not-an-array"
    with pytest.raises(EvidenceNormalizationError, match="files must be an array"):
        CoherentAnalysisView.from_mapping(bad_files)

    bad_item = _view().as_mapping()
    facets = cast(dict[str, object], bad_item["facets"])
    facets["commits"] = [7]
    with pytest.raises(EvidenceNormalizationError, match="commit must be an object"):
        CoherentAnalysisView.from_mapping(bad_item)

    bad_raw = _view().as_mapping()
    bad_raw["raw_digest_inventory"] = {1: ["a" * 64]}
    with pytest.raises(EvidenceNormalizationError, match="must be an object"):
        CoherentAnalysisView.from_mapping(bad_raw)


def test_source_order_rejects_subject_and_same_head_anchor_ambiguity() -> None:
    current = _view()
    assert (
        compare_source_order(current, _view(anchor=_anchor(repository_id=78)))
        is SourceOrderRelation.INCOMPARABLE
    )
    assert (
        compare_source_order(current, _view(anchor=_anchor(pull_number=5)))
        is SourceOrderRelation.INCOMPARABLE
    )
    assert (
        compare_source_order(current, _view(anchor=_anchor(pull_request_id=405)))
        is SourceOrderRelation.INCOMPARABLE
    )
    assert (
        compare_source_order(
            current,
            _view(anchor=_anchor(updated_at=NOW - timedelta(seconds=1))),
        )
        is SourceOrderRelation.REGRESSION
    )
    assert (
        compare_source_order(current, _view(anchor=_anchor(draft=True)))
        is SourceOrderRelation.INCOMPARABLE
    )


def test_status_facet_new_context_and_cross_view_contradiction() -> None:
    current = _view()
    added = _view(commit_statuses=(_status(), _status(2, context="lint")))
    contradiction = _view(commit_statuses=(_status(state="failure"),))
    assert compare_source_order(current, added) is SourceOrderRelation.PROGRESSION
    assert (
        compare_source_order(current, contradiction) is SourceOrderRelation.INCOMPARABLE
    )

    hidden_current = _view(
        commit_statuses=(
            _status(1, state="failure", updated_at=NOW - timedelta(seconds=1)),
            _status(2),
        )
    )
    hidden_contradiction = _view(
        commit_statuses=(
            _status(1, state="success", updated_at=NOW - timedelta(seconds=1)),
            _status(2),
        )
    )
    assert (
        compare_source_order(hidden_current, hidden_contradiction)
        is SourceOrderRelation.INCOMPARABLE
    )


def test_check_facet_identity_addition_disappearance_and_contradiction() -> None:
    current = _view()
    added = _view(check_runs=(_check(), _check(2, check_name="lint")))
    missing = _view(check_runs=())
    changed_identity = _view(check_runs=(_check(producer_app_id=10),))
    changed_head = _view(check_runs=(_check(head_sha=OTHER_HEAD),))
    changed_start = _view(check_runs=(_check(started_at=NOW + timedelta(seconds=1)),))
    changed_conclusion = _view(check_runs=(_check(conclusion="neutral"),))
    assert compare_source_order(current, added) is SourceOrderRelation.PROGRESSION
    assert compare_source_order(current, missing) is SourceOrderRelation.REGRESSION
    for candidate in (
        changed_identity,
        changed_head,
        changed_start,
        changed_conclusion,
    ):
        assert (
            compare_source_order(current, candidate) is SourceOrderRelation.INCOMPARABLE
        )


def test_multiple_unorderable_check_generations_are_incomparable() -> None:
    unorderable = (
        _check(
            1,
            status="queued",
            conclusion=None,
            started_at=None,
            completed_at=None,
        ),
        _check(
            2,
            status="queued",
            conclusion=None,
            started_at=None,
            completed_at=None,
        ),
    )
    assert (
        compare_source_order(_view(check_runs=unorderable), _view(check_runs=()))
        is SourceOrderRelation.INCOMPARABLE
    )
    assert (
        compare_source_order(_view(check_runs=()), _view(check_runs=unorderable))
        is SourceOrderRelation.INCOMPARABLE
    )


def test_check_generation_remote_order_and_numeric_tie_break_regress() -> None:
    later = _view(
        check_runs=(
            _check(
                2,
                started_at=NOW + timedelta(minutes=1),
                completed_at=NOW + timedelta(minutes=2),
            ),
        )
    )
    earlier = _view(check_runs=(_check(1),))
    assert compare_source_order(later, earlier) is SourceOrderRelation.REGRESSION

    higher_id = _view(check_runs=(_check(2),))
    assert compare_source_order(higher_id, earlier) is SourceOrderRelation.REGRESSION

    complete_history = _view(
        check_runs=(
            _check(1),
            _check(
                2,
                started_at=NOW + timedelta(minutes=1),
                completed_at=NOW + timedelta(minutes=2),
            ),
        )
    )
    assert (
        compare_source_order(complete_history, complete_history)
        is SourceOrderRelation.REPLAY
    )


def test_review_reduction_rejects_conflicting_event_roles() -> None:
    with pytest.raises(EvidenceNormalizationError, match="also dismissed"):
        reduce_current_head_reviews(
            (_review(1, "APPROVED", dismisses=9),),
            HEAD,
        )
    with pytest.raises(EvidenceNormalizationError, match="neutral review"):
        reduce_current_head_reviews(
            (_review(1, "PENDING", dismisses=9),),
            HEAD,
        )
    with pytest.raises(EvidenceNormalizationError, match="ambiguous"):
        reduce_current_head_reviews(
            (
                _review(1, "APPROVED", reviewer_id=10),
                _review(
                    2,
                    "DISMISSED",
                    reviewer_id=11,
                    dismisses=1,
                    submitted_at=NOW + timedelta(seconds=1),
                ),
            ),
            HEAD,
        )

    still_active = reduce_current_head_reviews(
        (
            _review(1, "CHANGES_REQUESTED"),
            _review(2, "APPROVED", submitted_at=NOW + timedelta(seconds=1)),
            _review(
                3,
                "DISMISSED",
                dismisses=1,
                submitted_at=NOW + timedelta(seconds=2),
            ),
        ),
        HEAD,
    )
    assert [(item.review_id, item.state) for item in still_active] == [(2, "APPROVED")]


def test_review_facet_history_progression_regression_and_ambiguity() -> None:
    first = _review(1, "CHANGES_REQUESTED")
    current = _view(reviews=(first,))
    appended = _view(
        reviews=(
            first,
            _review(2, "APPROVED", submitted_at=NOW + timedelta(seconds=1)),
        )
    )
    disappeared = _view(reviews=())
    replaced = _view(
        reviews=(_review(2, "APPROVED", submitted_at=NOW + timedelta(seconds=1)),)
    )
    contradicted = _view(reviews=(_review(1, "APPROVED"),))
    older_append = _view(
        reviews=(
            first,
            _review(2, "COMMENTED", submitted_at=NOW - timedelta(seconds=1)),
        )
    )
    assert compare_source_order(current, appended) is SourceOrderRelation.PROGRESSION
    assert compare_source_order(current, disappeared) is SourceOrderRelation.REGRESSION
    assert compare_source_order(current, replaced) is SourceOrderRelation.INCOMPARABLE
    assert (
        compare_source_order(current, contradicted) is SourceOrderRelation.INCOMPARABLE
    )
    assert (
        compare_source_order(current, older_append) is SourceOrderRelation.INCOMPARABLE
    )


def test_review_facet_unorderable_or_malformed_append_is_incomparable() -> None:
    missing_commit = _view(reviews=(_review(1, "APPROVED", commit_id=None),))
    assert compare_source_order(missing_commit, missing_commit) is (
        SourceOrderRelation.INCOMPARABLE
    )

    assert (
        compare_source_order(
            _view(reviews=()),
            _view(reviews=(_review(1, "PENDING", submitted_at=None),)),
        )
        is SourceOrderRelation.INCOMPARABLE
    )

    unorderable = _view(reviews=(_review(1, "CHANGES_REQUESTED", submitted_at=None),))
    assert compare_source_order(unorderable, unorderable) is (
        SourceOrderRelation.INCOMPARABLE
    )
    first = _review(1, "APPROVED")
    malformed = _review(
        2,
        "DISMISSED",
        dismisses=99,
        submitted_at=NOW + timedelta(seconds=1),
    )
    assert (
        compare_source_order(
            _view(reviews=(first,)),
            _view(reviews=(first, malformed)),
        )
        is SourceOrderRelation.INCOMPARABLE
    )


def test_requested_reviewer_routing_rename_preserves_numeric_source_identity() -> None:
    current = _view(
        requested_reviewers=RequestedReviewers(
            (RequestedUser(1, "old-login"),),
            (RequestedTeam(2, "old-slug"),),
        )
    )
    renamed = _view(
        requested_reviewers=RequestedReviewers(
            (RequestedUser(1, "new-login"),),
            (RequestedTeam(2, "new-slug"),),
        )
    )
    assert compare_source_order(current, renamed) is SourceOrderRelation.REPLAY


def test_duplicate_check_and_review_identities_fail_closed() -> None:
    with pytest.raises(EvidenceNormalizationError, match="contradictory immutable"):
        normalize_check_runs(
            (_check(), _check(status="in_progress", conclusion=None, completed_at=None))
        )
    with pytest.raises(EvidenceNormalizationError, match="contradictory immutable"):
        _view(reviews=(_review(1, "APPROVED"), _review(1, "COMMENTED")))


def test_digest_format_constant_is_the_only_view_algorithm() -> None:
    assert _view().digest_algorithm == DIGEST_FORMAT


PIPELINE_NOW = datetime(2026, 8, 11, 12, tzinfo=UTC)
PIPELINE_TARGET = RepositoryTarget("Harry5174", "github-steward", 4)
PIPELINE_PROFILE_ID = UUID("11111111-1111-5111-8111-111111111111")
PIPELINE_CONFIGURATION = digest_payload({"api_version": "2026-03-10", "per_page": 100})


class PipelineFakeClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


class PipelinePointerAwareClock:
    def __init__(self, state: PipelineState) -> None:
        self._state = state
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        assert self._state.pointer is not None
        return PIPELINE_NOW


def _pipeline_view(
    *,
    suite_count: int = 1,
    filename: str = "a.py",
    analysis_view_id: str = "22222222-2222-5222-8222-222222222222",
) -> CoherentAnalysisView:
    anchor = PullRequestAnchor(
        77,
        4,
        404,
        "a" * 40,
        77,
        "main",
        "b" * 40,
        "open",
        False,
        PIPELINE_NOW,
        1,
        1,
    )
    files = (FileEvidence("c" * 40, filename, "modified", 1, 0, 1),)
    commits = (CommitEvidence("a" * 40),)
    requested_reviewers = RequestedReviewers()
    check_runs = (
        NormalizedCheckRun(
            1,
            "a" * 40,
            9,
            "tests",
            "completed",
            "success",
            PIPELINE_NOW,
            PIPELINE_NOW,
        ),
    )
    commit_statuses = (
        NormalizedCommitStatus(1, "a" * 40, "CI/Test", "success", PIPELINE_NOW),
    )
    semantic_payloads = {
        "anchor": anchor.as_mapping(),
        "files": [item.as_mapping() for item in files],
        "commits": [item.as_mapping() for item in commits],
        "reviews": [],
        "requested_reviewers": requested_reviewers.as_mapping(),
        "check_suite_count": suite_count,
        "check_runs": [item.as_mapping() for item in check_runs],
        "commit_statuses": [item.as_mapping() for item in commit_statuses],
    }
    semantic_digests = {
        facet: envelope_payload(semantic_payloads[facet]).digest.value
        for facet in SEMANTIC_FACETS
    }
    return CoherentAnalysisView(
        analysis_view_id=analysis_view_id,
        anchor=anchor,
        files=files,
        commits=commits,
        files_digest=semantic_digests["files"],
        commits_digest=semantic_digests["commits"],
        requested_reviewers=requested_reviewers,
        check_suite_count=suite_count,
        check_runs=check_runs,
        commit_statuses=commit_statuses,
        reviews=(),
        acquisition_configuration_digest=PIPELINE_CONFIGURATION.value,
        evidence_sealed_at=PIPELINE_NOW,
        raw_digest_inventory={"recorded": ("e" * 64,)},
        semantic_digest_inventory=semantic_digests,
    )


def _pipeline_acquired(
    view: CoherentAnalysisView | None = None,
) -> CoherentAcquisitionResult:
    selected = view or _pipeline_view()
    facets = {
        "files": envelope_payload([item.as_mapping() for item in selected.files]),
        "commits": envelope_payload([item.as_mapping() for item in selected.commits]),
        "reviews": envelope_payload([]),
        "requested_reviewers": envelope_payload(
            selected.requested_reviewers.as_mapping()
        ),
        "check_suite_count": envelope_payload(selected.check_suite_count),
        "check_runs": envelope_payload(
            [item.as_mapping() for item in selected.check_runs]
        ),
        "commit_statuses": envelope_payload(
            [item.as_mapping() for item in selected.commit_statuses]
        ),
    }
    return CoherentAcquisitionResult(
        selected,
        envelope_payload(selected.as_mapping()),
        1,
        facets,
    )


def _pipeline_corrupted_acquisition(kind: str) -> CoherentAcquisitionResult:
    acquired = _pipeline_acquired()
    if kind == "attempts":
        return replace(acquired, attempts=3)
    if kind == "facet":
        facets = dict(acquired.facet_envelopes)
        facets["files"] = envelope_payload({"wrong": True})
        return replace(acquired, facet_envelopes=facets)
    if kind == "view_envelope":
        return replace(
            acquired,
            view_envelope=envelope_payload({"wrong": True}),
        )
    mapping = acquired.view.as_mapping()
    if kind == "semantic_inventory":
        mapping["semantic_digest_inventory"] = {
            **dict(acquired.view.semantic_digest_inventory),
            "anchor": "0" * 64,
        }
    elif kind == "files_digest":
        mapping["files_digest"] = "0" * 64
    else:
        assert kind == "commits_digest"
        mapping["commits_digest"] = "0" * 64
    return _pipeline_acquired(CoherentAnalysisView.from_mapping(mapping))


class PipelineFakeAcquisition:
    def __init__(
        self,
        acquired: CoherentAcquisitionResult | None = None,
        failure: PreparednessReasonCode | None = None,
    ) -> None:
        self.acquired = acquired or _pipeline_acquired()
        self.failure = failure

    def acquire(self, target: RepositoryTarget) -> CoherentAcquisitionResult:
        assert target == PIPELINE_TARGET
        if self.failure is not None:
            raise CoherentAcquisitionFailure(self.failure, "recorded failure")
        return self.acquired


class PipelineState:
    def __init__(self) -> None:
        self.profiles: dict[tuple[str, int], PreparednessProfileRecord] = {}
        self.profile_gets: list[tuple[str, int]] = []
        self.observations: list[CanonicalObservationRecord] = []
        self.views: list[AnalysisViewRecord] = []
        self.assessments: list[PreparednessAssessmentRecord] = []
        self.pointer: ObservationPointer | None = None
        self.cas_failures = 0
        self.commits = 0


class PipelineProfiles:
    def __init__(self, state: PipelineState) -> None:
        self.state = state

    def insert(self, record: PreparednessProfileRecord) -> None:
        self.state.profiles[(str(record.profile_id), record.version)] = record

    def get(
        self, *, profile_id: PreparednessProfileId, version: int
    ) -> PreparednessProfileRecord | None:
        self.state.profile_gets.append((str(profile_id), version))
        return self.state.profiles.get((str(profile_id), version))

    def get_successor(
        self, *, profile_id: PreparednessProfileId, version: int
    ) -> PreparednessProfileRecord | None:
        for record in self.state.profiles.values():
            if (
                str(record.predecessor_profile_id) == str(profile_id)
                and record.predecessor_profile_version == version
            ):
                return record
        return None


class PipelinePointers:
    def __init__(self, state: PipelineState) -> None:
        self.state = state

    def get(self, *, entity_kind: str, entity_id: str) -> ObservationPointer | None:
        assert (entity_kind, entity_id) == ("github_pull_request", "77:4")
        return self.state.pointer

    def create_if_absent(self, pointer: ObservationPointer) -> PointerCreateOutcome:
        if self.state.pointer is None:
            self.state.pointer = pointer
            return PointerCreateOutcome.CREATED
        return PointerCreateOutcome.CONFLICT

    def compare_and_swap(
        self,
        *,
        expected_version: int,
        replacement: ObservationPointer,
    ) -> bool:
        if self.state.cas_failures and self.state.pointer is not None:
            self.state.cas_failures -= 1
            self.state.pointer = replace(
                self.state.pointer,
                pointer_version=self.state.pointer.pointer_version + 1,
            )
            return False
        if (
            self.state.pointer is not None
            and self.state.pointer.pointer_version == expected_version
        ):
            self.state.pointer = replacement
            return True
        return False


class PipelineFakeUnit:
    def __init__(self, state: PipelineState) -> None:
        self.state = state
        self.profiles = PipelineProfiles(state)
        self.pointers = PipelinePointers(state)
        self.observations = SimpleNamespace(append=state.observations.append)
        self.views = SimpleNamespace(insert=state.views.append)
        self.assessments = SimpleNamespace(insert=state.assessments.append)
        self.inbox = SimpleNamespace()
        self.work = SimpleNamespace()
        self.audits = SimpleNamespace()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def commit(self) -> None:
        self.state.commits += 1

    def rollback(self) -> None:
        return None


def _pipeline_profile() -> PreparednessProfile:
    return PreparednessProfile(
        profile_id=PIPELINE_PROFILE_ID,
        version=1,
        repository_id=77,
        required_checks=(RequiredCheck(9, "tests"),),
        required_statuses=(RequiredStatus("ci/test"),),
        accepted_check_conclusions=("success",),
        block_on_current_head_changes_requested=True,
        acquisition_configuration=AcquisitionConfigurationIdentity(
            1, PIPELINE_CONFIGURATION
        ),
        effective_from=PIPELINE_NOW,
    )


def _pipeline_expected() -> PullRequestIdentity:
    return PullRequestIdentity(77, 404, 4, "a" * 40, 77, "main", "b" * 40)


def _pipeline_pointer(
    view: CoherentAnalysisView, version: int = 0
) -> ObservationPointer:
    return ObservationPointer(
        entity_kind="github_pull_request",
        entity_id="77:4",
        observation_version_id=ObservationVersionId(
            "33333333-3333-5333-8333-333333333333"
        ),
        ordering_key=view.as_mapping(),
        pointer_version=version,
        updated_at=PIPELINE_NOW,
    )


def _pipeline_service(
    state: PipelineState,
    acquisition: PipelineFakeAcquisition | None = None,
) -> DeterministicPreparednessPipeline:
    return DeterministicPreparednessPipeline(
        acquisition=acquisition or PipelineFakeAcquisition(),
        unit_of_work_factory=lambda: PipelineFakeUnit(state),
        evaluation_clock=PipelineFakeClock(PIPELINE_NOW),
        envelope_factory=envelope_payload,
    )


def test_profile_registration_then_complete_ready_persistence_and_pointer() -> None:
    state = PipelineState()
    pipeline = _pipeline_service(state)
    registered = pipeline.register_profile(_pipeline_profile())
    assert registered.identity == ProfileIdentity(PIPELINE_PROFILE_ID, 1)
    assert (
        registered.digest == envelope_payload(_pipeline_profile().as_mapping()).digest
    )

    result = pipeline.assess(
        target=PIPELINE_TARGET,
        expected_identity=_pipeline_expected(),
        profile_reference=registered.reference,
    )
    assert result.assessment is not None
    assert result.assessment.verdict is PreparednessVerdict.READY_FOR_HUMAN_REVIEW
    assert result.pointer_outcome is PointerPromotionOutcome.POINTER_ADVANCED
    assert result.acquisition_failure is None
    assert result.assessment_id is not None
    assert result.assessment_digest is not None
    assert state.profile_gets == [(str(PIPELINE_PROFILE_ID), 1)]
    assert len(state.observations) == 9
    assert len(state.views) == 1
    assert len(state.views[0].observation_versions) == 9
    assert len(state.assessments) == 1
    assert len(state.assessments[0].evidence_observations) == 9
    assert state.pointer is not None and state.pointer.pointer_version == 0


def test_evaluation_time_is_read_only_after_pointer_work() -> None:
    state = PipelineState()
    clock = PipelinePointerAwareClock(state)
    pipeline = DeterministicPreparednessPipeline(
        acquisition=PipelineFakeAcquisition(),
        unit_of_work_factory=lambda: PipelineFakeUnit(state),
        evaluation_clock=clock,
        envelope_factory=envelope_payload,
    )
    identity = pipeline.register_profile(_pipeline_profile()).reference

    result = pipeline.assess(
        target=PIPELINE_TARGET,
        expected_identity=_pipeline_expected(),
        profile_reference=identity,
    )

    assert result.assessment is not None
    assert clock.calls == 1


def test_equivalent_inputs_produce_exact_same_assessment_identity_and_content() -> None:
    results = []
    for _ in range(2):
        state = PipelineState()
        pipeline = _pipeline_service(state)
        identity = pipeline.register_profile(_pipeline_profile()).reference
        results.append(
            pipeline.assess(
                target=PIPELINE_TARGET,
                expected_identity=_pipeline_expected(),
                profile_reference=identity,
            )
        )
    assert results[0].assessment_id == results[1].assessment_id
    assert results[0].assessment_digest == results[1].assessment_digest
    assert results[0].assessment == results[1].assessment


def test_exact_replay_is_a_pointer_noop_without_version_increment() -> None:
    state = PipelineState()
    pipeline = _pipeline_service(state)
    identity = pipeline.register_profile(_pipeline_profile()).reference

    first = pipeline.assess(
        target=PIPELINE_TARGET,
        expected_identity=_pipeline_expected(),
        profile_reference=identity,
    )
    second = pipeline.assess(
        target=PIPELINE_TARGET,
        expected_identity=_pipeline_expected(),
        profile_reference=identity,
    )

    assert first.pointer_outcome is PointerPromotionOutcome.POINTER_ADVANCED
    assert second.pointer_outcome is PointerPromotionOutcome.POINTER_REPLAY_NOOP
    assert first.assessment_id == second.assessment_id
    assert state.pointer is not None and state.pointer.pointer_version == 0


def test_acquisition_uncertainty_does_not_persist_or_promote() -> None:
    state = PipelineState()
    pipeline = _pipeline_service(
        state,
        PipelineFakeAcquisition(failure=PreparednessReasonCode.EVIDENCE_UNSTABLE),
    )
    identity = pipeline.register_profile(_pipeline_profile()).reference
    result = pipeline.assess(
        target=PIPELINE_TARGET,
        expected_identity=_pipeline_expected(),
        profile_reference=identity,
    )
    assert result.assessment is None
    assert result.acquisition_failure is PreparednessReasonCode.EVIDENCE_UNSTABLE
    assert state.observations == []
    assert state.views == []
    assert state.assessments == []
    assert state.pointer is None


COHERENT_NOW = datetime(2026, 8, 11, 12, 30, tzinfo=UTC)
COHERENT_TARGET = RepositoryTarget("Harry5174", "github-steward", 4)
COHERENT_HEAD = "a" * 40
COHERENT_BASE = "b" * 40


class CoherentFakeClock:
    def __init__(self, value: datetime) -> None:
        self.value = value
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        return self.value


def _coherent_response(
    value: object, label: str, *, size: int = 100
) -> RecordedGitHubResponse:
    return RecordedGitHubResponse(
        value,
        hashlib.sha256(label.encode()).hexdigest(),
        size,
    )


def _coherent_anchor(
    *,
    head_sha: str = COHERENT_HEAD,
    updated_at: str = "2026-08-11T12:00:00Z",
    draft: bool = False,
) -> dict[str, object]:
    return {
        "id": 404,
        "number": 4,
        "state": "open",
        "draft": draft,
        "updated_at": updated_at,
        "changed_files": 1,
        "commits": 1,
        "head": {"sha": head_sha},
        "base": {
            "ref": "main",
            "sha": COHERENT_BASE,
            "repo": {"id": 77, "full_name": "Harry5174/github-steward"},
        },
    }


def _coherent_facet_value(
    facet: EvidenceFacet, *, status_state: str = "success"
) -> object:
    if facet is EvidenceFacet.FILES:
        return [
            {
                "sha": "c" * 40,
                "filename": "src/a.py",
                "status": "modified",
                "additions": 2,
                "deletions": 1,
                "changes": 3,
            }
        ]
    if facet is EvidenceFacet.COMMITS:
        return [{"sha": COHERENT_HEAD, "ignored_display_field": "safe"}]
    if facet is EvidenceFacet.REVIEWS:
        return [
            {
                "id": 1,
                "user": {"id": 9, "login": "reviewer"},
                "commit_id": COHERENT_HEAD,
                "state": "APPROVED",
                "submitted_at": "2026-08-11T11:59:00Z",
                "pull_request_url": (
                    "https://api.github.com/repos/Harry5174/github-steward/pulls/4"
                ),
            }
        ]
    if facet is EvidenceFacet.REQUESTED_REVIEWERS:
        return {
            "users": [{"id": 8, "login": "octo"}],
            "teams": [{"id": 7, "slug": "core"}],
        }
    if facet is EvidenceFacet.CHECK_SUITE_COUNT:
        return {"total_count": 1}
    if facet is EvidenceFacet.CHECK_RUNS:
        return [
            {
                "id": 12,
                "head_sha": COHERENT_HEAD,
                "app": {"id": 99},
                "name": "tests",
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-08-11T11:57:00Z",
                "completed_at": "2026-08-11T11:58:00Z",
            }
        ]
    return [
        {
            "id": 15,
            "sha": COHERENT_HEAD,
            "context": "CI/Test",
            "state": status_state,
            "updated_at": "2026-08-11T11:58:00Z",
        }
    ]


def _coherent_total(facet: EvidenceFacet) -> int | None:
    return {
        EvidenceFacet.FILES: 1,
        EvidenceFacet.COMMITS: 1,
        EvidenceFacet.REVIEWS: 1,
        EvidenceFacet.REQUESTED_REVIEWERS: None,
        EvidenceFacet.CHECK_SUITE_COUNT: 1,
        EvidenceFacet.CHECK_RUNS: 1,
        EvidenceFacet.COMMIT_STATUSES: 1,
    }[facet]


def _coherent_recorded_facet(
    facet: EvidenceFacet,
    *,
    status_state: str = "success",
    complete: bool = True,
    total: int | None = None,
    response_size: int = 100,
    label: str | None = None,
) -> RecordedFacet:
    value = _coherent_facet_value(facet, status_state=status_state)
    return RecordedFacet(
        value,
        (_coherent_response(value, label or facet.value, size=response_size),),
        _coherent_total(facet) if total is None else total,
        complete,
    )


class CoherentFakeEvidence:
    def __init__(
        self,
        anchors: list[dict[str, object]],
        facets: dict[EvidenceFacet, list[RecordedFacet]],
    ) -> None:
        self.anchors = list(anchors)
        self.facets = {key: list(values) for key, values in facets.items()}
        self.calls: list[str] = []

    def read_anchor(self, target: RepositoryTarget) -> RecordedGitHubResponse:
        assert target == COHERENT_TARGET
        self.calls.append("anchor")
        if not self.anchors:
            raise AssertionError("partial failed attempt was reused")
        return _coherent_response(self.anchors.pop(0), f"anchor-{len(self.calls)}")

    def read_facet(
        self,
        target: RepositoryTarget,
        *,
        head_sha: str,
        facet: EvidenceFacet,
    ) -> RecordedFacet:
        assert target == COHERENT_TARGET
        assert head_sha == COHERENT_HEAD
        self.calls.append(facet.value)
        values = self.facets[facet]
        if not values:
            raise AssertionError("partial failed attempt was reused")
        return values.pop(0)


def _coherent_fake(
    *,
    anchors: list[dict[str, object]] | None = None,
    overrides: dict[EvidenceFacet, list[RecordedFacet]] | None = None,
    passes: int = 2,
) -> CoherentFakeEvidence:
    facets = {
        facet: [
            _coherent_recorded_facet(facet, label=f"{facet.value}-{index}")
            for index in range(passes)
        ]
        for facet in EvidenceFacet
    }
    facets.update(overrides or {})
    return CoherentFakeEvidence(
        anchors or [_coherent_anchor(), _coherent_anchor(), _coherent_anchor()], facets
    )


def _coherent_service(
    fake: RecordedGitHubEvidencePort,
    clock: CoherentFakeClock,
    *,
    configuration_digest: Digest | None = None,
) -> CoherentRecordedAcquisitionService:
    return CoherentRecordedAcquisitionService(
        evidence=fake,
        clock=clock,
        envelope_factory=envelope_payload,
        acquisition_configuration_digest=(
            configuration_digest
            or digest_payload(
                {"api_version": "2026-03-10", "per_page": 100, "attempts": 2}
            )
        ),
    )


class CoherentFailingEvidence:
    def __init__(self, outcome: AcquisitionOutcome) -> None:
        self.outcome = outcome
        self.anchor_calls = 0

    def read_anchor(self, target: RepositoryTarget) -> RecordedGitHubResponse:
        assert target == COHERENT_TARGET
        self.anchor_calls += 1
        raise AcquisitionError(self.outcome, f"classified {self.outcome.value}")

    def read_facet(
        self,
        target: RepositoryTarget,
        *,
        head_sha: str,
        facet: EvidenceFacet,
    ) -> RecordedFacet:
        raise AssertionError(
            f"facet read after anchor failure: {target} {head_sha} {facet}"
        )


def test_exact_a_pass1_b_pass2_c_sequence_and_one_time_seal() -> None:
    fake = _coherent_fake()
    clock = CoherentFakeClock(COHERENT_NOW)
    result = _coherent_service(fake, clock).acquire(COHERENT_TARGET)
    pass_calls = [facet.value for facet in EvidenceFacet]
    assert fake.calls == ["anchor", *pass_calls, "anchor", *pass_calls, "anchor"]
    assert result.attempts == 1
    assert result.view.evidence_sealed_at == COHERENT_NOW
    assert clock.calls == 1
    assert dict(result.view.semantic_digest_inventory).keys() == {
        "anchor",
        *pass_calls,
    }
    assert len(result.view.raw_digest_inventory) == 17
    assert (
        result.view_envelope.digest == envelope_payload(result.view.as_mapping()).digest
    )


def test_facet_mismatch_retries_whole_attempt_without_partial_reuse() -> None:
    status_values = [
        _coherent_recorded_facet(EvidenceFacet.COMMIT_STATUSES, status_state="success"),
        _coherent_recorded_facet(EvidenceFacet.COMMIT_STATUSES, status_state="pending"),
        _coherent_recorded_facet(EvidenceFacet.COMMIT_STATUSES, status_state="success"),
        _coherent_recorded_facet(EvidenceFacet.COMMIT_STATUSES, status_state="success"),
    ]
    fake = _coherent_fake(
        anchors=[_coherent_anchor() for _ in range(6)],
        overrides={EvidenceFacet.COMMIT_STATUSES: status_values},
        passes=4,
    )
    clock = CoherentFakeClock(COHERENT_NOW)
    result = _coherent_service(fake, clock).acquire(COHERENT_TARGET)
    assert result.attempts == 2
    assert fake.calls.count("anchor") == 6
    assert all(fake.calls.count(facet.value) == 4 for facet in EvidenceFacet)
    assert clock.calls == 1


def test_semantically_equal_status_passes_ignore_acquisition_order() -> None:
    first = cast(list[object], _coherent_facet_value(EvidenceFacet.COMMIT_STATUSES))
    second_status = {
        "id": 16,
        "sha": COHERENT_HEAD,
        "context": "lint",
        "state": "success",
        "updated_at": "2026-08-11T11:59:00Z",
    }
    forward = [*first, second_status]
    reverse = list(reversed(forward))
    fake = _coherent_fake(
        overrides={
            EvidenceFacet.COMMIT_STATUSES: [
                RecordedFacet(
                    forward, (_coherent_response(forward, "forward"),), 2, True
                ),
                RecordedFacet(
                    reverse, (_coherent_response(reverse, "reverse"),), 2, True
                ),
            ]
        }
    )

    result = _coherent_service(fake, CoherentFakeClock(COHERENT_NOW)).acquire(
        COHERENT_TARGET
    )

    assert [item.context_key for item in result.view.commit_statuses] == [
        "ci/test",
        "lint",
    ]


def test_coherent_status_passes_ignore_display_casing() -> None:
    upper = cast(
        list[dict[str, object]],
        deepcopy(_coherent_facet_value(EvidenceFacet.COMMIT_STATUSES)),
    )
    lower = deepcopy(upper)
    lower[0]["context"] = "ci/test"
    fake = _coherent_fake(
        overrides={
            EvidenceFacet.COMMIT_STATUSES: [
                RecordedFacet(
                    upper,
                    (_coherent_response(upper, "status-upper"),),
                    1,
                    True,
                ),
                RecordedFacet(
                    lower,
                    (_coherent_response(lower, "status-lower"),),
                    1,
                    True,
                ),
            ]
        }
    )

    result = _coherent_service(fake, CoherentFakeClock(COHERENT_NOW)).acquire(
        COHERENT_TARGET
    )

    assert result.attempts == 1
    assert result.view.commit_statuses[0].context_key == "ci/test"
    assert result.facet_envelopes[EvidenceFacet.COMMIT_STATUSES.value].digest == (
        envelope_payload([result.view.commit_statuses[0].as_mapping()]).digest
    )


def test_semantically_equal_file_passes_ignore_acquisition_order() -> None:
    first = cast(list[object], _coherent_facet_value(EvidenceFacet.FILES))
    second_file = {
        "sha": "d" * 40,
        "filename": "src/b.py",
        "status": "added",
        "additions": 4,
        "deletions": 0,
        "changes": 4,
    }
    forward = [*first, second_file]
    reverse = list(reversed(forward))
    anchors = []
    for _ in range(3):
        anchor = _coherent_anchor()
        anchor["changed_files"] = 2
        anchors.append(anchor)
    fake = _coherent_fake(
        anchors=anchors,
        overrides={
            EvidenceFacet.FILES: [
                RecordedFacet(
                    forward, (_coherent_response(forward, "files-forward"),), 2, True
                ),
                RecordedFacet(
                    reverse, (_coherent_response(reverse, "files-reverse"),), 2, True
                ),
            ]
        },
    )

    result = _coherent_service(fake, CoherentFakeClock(COHERENT_NOW)).acquire(
        COHERENT_TARGET
    )

    assert [item.filename for item in result.view.files] == ["src/a.py", "src/b.py"]


def test_two_incoherent_whole_attempts_fail_unstable_without_sealing() -> None:
    status_values = [
        _coherent_recorded_facet(
            EvidenceFacet.COMMIT_STATUSES,
            status_state="success" if index % 2 == 0 else "pending",
        )
        for index in range(4)
    ]
    fake = _coherent_fake(
        anchors=[_coherent_anchor() for _ in range(6)],
        overrides={EvidenceFacet.COMMIT_STATUSES: status_values},
        passes=4,
    )
    clock = CoherentFakeClock(COHERENT_NOW)
    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _coherent_service(fake, clock).acquire(COHERENT_TARGET)
    assert raised.value.reason is PreparednessReasonCode.EVIDENCE_UNSTABLE
    assert fake.calls.count("anchor") == 6
    assert clock.calls == 0


def test_anchor_a_b_c_mismatch_retries_and_uses_new_attempt_only() -> None:
    changed = _coherent_anchor(draft=True)
    fake = _coherent_fake(
        anchors=[
            _coherent_anchor(),
            changed,
            changed,
            _coherent_anchor(),
            _coherent_anchor(),
            _coherent_anchor(),
        ],
        passes=4,
    )
    result = _coherent_service(fake, CoherentFakeClock(COHERENT_NOW)).acquire(
        COHERENT_TARGET
    )
    assert result.attempts == 2
    assert not result.view.anchor.draft


@pytest.mark.parametrize(
    ("facet", "recorded", "reason"),
    [
        (
            EvidenceFacet.FILES,
            _coherent_recorded_facet(EvidenceFacet.FILES, complete=False),
            PreparednessReasonCode.EVIDENCE_PAGINATION_UNCERTAIN,
        ),
        (
            EvidenceFacet.FILES,
            _coherent_recorded_facet(EvidenceFacet.FILES, total=2),
            PreparednessReasonCode.EVIDENCE_TOTAL_COUNT_INCONSISTENT,
        ),
        (
            EvidenceFacet.FILES,
            _coherent_recorded_facet(
                EvidenceFacet.FILES, response_size=MAX_RESPONSE_BYTES + 1
            ),
            PreparednessReasonCode.EVIDENCE_CAP_EXCEEDED,
        ),
        (
            EvidenceFacet.REVIEWS,
            RecordedFacet(
                [],
                (_coherent_response([], "reviews-total"),),
                1,
                True,
            ),
            PreparednessReasonCode.EVIDENCE_TOTAL_COUNT_INCONSISTENT,
        ),
        (
            EvidenceFacet.COMMIT_STATUSES,
            RecordedFacet(
                [],
                (_coherent_response([], "statuses-total"),),
                1,
                True,
            ),
            PreparednessReasonCode.EVIDENCE_TOTAL_COUNT_INCONSISTENT,
        ),
    ],
)
def test_precise_incomplete_count_and_response_cap_failures(
    facet: EvidenceFacet,
    recorded: RecordedFacet,
    reason: PreparednessReasonCode,
) -> None:
    fake = _coherent_fake(overrides={facet: [recorded]})
    clock = CoherentFakeClock(COHERENT_NOW)
    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _coherent_service(fake, clock).acquire(COHERENT_TARGET)
    assert raised.value.reason is reason
    assert clock.calls == 0


def test_seal_time_is_digest_bearing_view_material() -> None:
    first = _coherent_service(
        _coherent_fake(), CoherentFakeClock(COHERENT_NOW)
    ).acquire(COHERENT_TARGET)
    second = _coherent_service(
        _coherent_fake(), CoherentFakeClock(COHERENT_NOW + timedelta(microseconds=1))
    ).acquire(COHERENT_TARGET)
    assert first.view.analysis_view_id != second.view.analysis_view_id
    assert first.view_envelope.digest != second.view_envelope.digest


def test_view_identity_binds_configuration_and_raw_provenance() -> None:
    baseline = _coherent_service(
        _coherent_fake(), CoherentFakeClock(COHERENT_NOW)
    ).acquire(COHERENT_TARGET)
    changed_configuration = _coherent_service(
        _coherent_fake(),
        CoherentFakeClock(COHERENT_NOW),
        configuration_digest=digest_payload({"configuration": "different"}),
    ).acquire(COHERENT_TARGET)
    changed_raw = _coherent_service(
        _coherent_fake(
            overrides={
                EvidenceFacet.FILES: [
                    _coherent_recorded_facet(
                        EvidenceFacet.FILES, label="changed-raw-1"
                    ),
                    _coherent_recorded_facet(
                        EvidenceFacet.FILES, label="changed-raw-2"
                    ),
                ]
            }
        ),
        CoherentFakeClock(COHERENT_NOW),
    ).acquire(COHERENT_TARGET)

    assert (
        len(
            {
                baseline.view.analysis_view_id,
                changed_configuration.view.analysis_view_id,
                changed_raw.view.analysis_view_id,
            }
        )
        == 3
    )


def test_view_identity_material_is_independent_of_mapping_order() -> None:
    raw_items = (
        ("anchor_a", ("a" * 64,)),
        ("pass_1:files", ("b" * 64, "c" * 64)),
    )
    semantic_items = (
        ("anchor", "d" * 64),
        ("files", "e" * 64),
    )

    def identifier(raw: dict[str, tuple[str, ...]], semantic: dict[str, str]) -> str:
        return coherent_acquisition._analysis_view_id(
            envelope_factory=envelope_payload,
            repository_id=77,
            pull_number=4,
            head_sha=COHERENT_HEAD,
            evidence_sealed_at=COHERENT_NOW,
            acquisition_configuration_digest=digest_payload(
                {"api_version": "2026-03-10"}
            ),
            raw_digest_inventory=raw,
            semantic_digest_inventory=semantic,
        )

    forward = identifier(dict(raw_items), dict(semantic_items))
    reversed_mappings = identifier(
        dict(reversed(raw_items)), dict(reversed(semantic_items))
    )

    assert forward == reversed_mappings


def test_malformed_duplicate_requested_reviewer_identity_fails_closed() -> None:
    value = {
        "users": [{"id": 8, "login": "first"}, {"id": 8, "login": "second"}],
        "teams": [],
    }
    recorded = RecordedFacet(
        value, (_coherent_response(value, "requested"),), None, True
    )
    fake = _coherent_fake(overrides={EvidenceFacet.REQUESTED_REVIEWERS: [recorded]})
    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _coherent_service(fake, CoherentFakeClock(COHERENT_NOW)).acquire(
            COHERENT_TARGET
        )
    assert raised.value.reason is PreparednessReasonCode.REQUESTED_REVIEWER_AMBIGUITY


def test_anchor_count_mismatch_is_precise_uncertainty() -> None:
    fake = _coherent_fake(
        anchors=[_coherent_anchor(), _coherent_anchor(), _coherent_anchor()]
    )
    fake.anchors[0]["changed_files"] = 2
    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _coherent_service(fake, CoherentFakeClock(COHERENT_NOW)).acquire(
            COHERENT_TARGET
        )
    assert (
        raised.value.reason is PreparednessReasonCode.EVIDENCE_TOTAL_COUNT_INCONSISTENT
    )


@pytest.mark.parametrize(
    ("outcome", "reason"),
    [
        (
            AcquisitionOutcome.FORBIDDEN,
            PreparednessReasonCode.EVIDENCE_PERMISSION_DENIED,
        ),
        (AcquisitionOutcome.RATE_LIMITED, PreparednessReasonCode.EVIDENCE_RATE_LIMITED),
        (
            AcquisitionOutcome.UNSUPPORTED_UPSTREAM_LIMIT,
            PreparednessReasonCode.EVIDENCE_CAP_EXCEEDED,
        ),
        (
            AcquisitionOutcome.MALFORMED_RESPONSE,
            PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE,
        ),
        (
            AcquisitionOutcome.INCOMPLETE_ACQUISITION,
            PreparednessReasonCode.EVIDENCE_INCOMPLETE,
        ),
        (
            AcquisitionOutcome.CONCURRENT_CHANGE,
            PreparednessReasonCode.EVIDENCE_UNSTABLE,
        ),
        (AcquisitionOutcome.NOT_FOUND, PreparednessReasonCode.EVIDENCE_ROUTE_FAILURE),
        (
            AcquisitionOutcome.UNPROCESSABLE,
            PreparednessReasonCode.EVIDENCE_ROUTE_FAILURE,
        ),
        (
            AcquisitionOutcome.TRANSPORT_ERROR,
            PreparednessReasonCode.EVIDENCE_TRANSPORT_UNCERTAIN,
        ),
        (
            AcquisitionOutcome.TIMEOUT,
            PreparednessReasonCode.EVIDENCE_TRANSPORT_UNCERTAIN,
        ),
        (
            AcquisitionOutcome.UPSTREAM_SERVER_ERROR,
            PreparednessReasonCode.EVIDENCE_TRANSPORT_UNCERTAIN,
        ),
        (
            AcquisitionOutcome.PERSISTENCE_FAILURE,
            PreparednessReasonCode.EVIDENCE_COHERENCE_UNCERTAIN,
        ),
        (
            AcquisitionOutcome.ACQUIRED,
            PreparednessReasonCode.EVIDENCE_COHERENCE_UNCERTAIN,
        ),
    ],
)
def test_classified_acquisition_failures_do_not_retry_or_seal(
    outcome: AcquisitionOutcome,
    reason: PreparednessReasonCode,
) -> None:
    evidence = CoherentFailingEvidence(outcome)
    clock = CoherentFakeClock(COHERENT_NOW)

    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _coherent_service(evidence, clock).acquire(COHERENT_TARGET)

    assert raised.value.reason is reason
    assert evidence.anchor_calls == 1
    assert clock.calls == 0


def test_internal_semantic_inventory_guard_prevents_sealing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _coherent_fake()
    clock = CoherentFakeClock(COHERENT_NOW)
    monkeypatch.setattr(
        coherent_acquisition,
        "SEMANTIC_FACETS",
        tuple(facet.value for facet in EvidenceFacet),
    )

    with pytest.raises(RuntimeError, match="semantic facet inventory"):
        _coherent_service(fake, clock).acquire(COHERENT_TARGET)

    assert clock.calls == 1
    assert fake.calls.count("anchor") == 3


def test_anchor_commit_count_mismatch_is_precise_uncertainty() -> None:
    anchor = _coherent_anchor()
    anchor["commits"] = 2
    fake = _coherent_fake(anchors=[anchor, _coherent_anchor(), _coherent_anchor()])

    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _coherent_service(fake, CoherentFakeClock(COHERENT_NOW)).acquire(
            COHERENT_TARGET
        )

    assert (
        raised.value.reason is PreparednessReasonCode.EVIDENCE_TOTAL_COUNT_INCONSISTENT
    )


def test_exact_response_byte_ceiling_is_accepted() -> None:
    facets = [
        _coherent_recorded_facet(EvidenceFacet.FILES, response_size=MAX_RESPONSE_BYTES),
        _coherent_recorded_facet(EvidenceFacet.FILES, response_size=MAX_RESPONSE_BYTES),
    ]
    result = _coherent_service(
        _coherent_fake(overrides={EvidenceFacet.FILES: facets}),
        CoherentFakeClock(COHERENT_NOW),
    ).acquire(COHERENT_TARGET)
    assert result.attempts == 1


@pytest.mark.parametrize(
    ("raw_responses", "reason"),
    [
        (
            (
                RecordedGitHubResponse(
                    _coherent_facet_value(EvidenceFacet.FILES),
                    "malformed",
                    100,
                ),
            ),
            PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE,
        ),
        (
            (
                RecordedGitHubResponse(
                    _coherent_facet_value(EvidenceFacet.FILES),
                    cast(str, 7),
                    100,
                ),
            ),
            PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE,
        ),
        (
            (cast(RecordedGitHubResponse, object()),),
            PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE,
        ),
        (
            (
                RecordedGitHubResponse(
                    _coherent_facet_value(EvidenceFacet.FILES),
                    hashlib.sha256(b"bool-size").hexdigest(),
                    cast(int, True),
                ),
            ),
            PreparednessReasonCode.EVIDENCE_CAP_EXCEEDED,
        ),
        (
            (
                RecordedGitHubResponse(
                    _coherent_facet_value(EvidenceFacet.FILES),
                    hashlib.sha256(b"negative-size").hexdigest(),
                    -1,
                ),
            ),
            PreparednessReasonCode.EVIDENCE_CAP_EXCEEDED,
        ),
        ((), PreparednessReasonCode.EVIDENCE_PAGINATION_UNCERTAIN),
        (
            tuple(
                _coherent_response(
                    _coherent_facet_value(EvidenceFacet.FILES), f"page-{page}"
                )
                for page in range(MAX_PAGES + 1)
            ),
            PreparednessReasonCode.EVIDENCE_PAGINATION_UNCERTAIN,
        ),
    ],
)
def test_raw_response_and_pagination_safety_boundaries_fail_closed(
    raw_responses: tuple[RecordedGitHubResponse, ...],
    reason: PreparednessReasonCode,
) -> None:
    value = _coherent_facet_value(EvidenceFacet.FILES)
    recorded = RecordedFacet(value, raw_responses, 1, True)
    fake = _coherent_fake(overrides={EvidenceFacet.FILES: [recorded]})

    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _coherent_service(fake, CoherentFakeClock(COHERENT_NOW)).acquire(
            COHERENT_TARGET
        )

    assert raised.value.reason is reason


@pytest.mark.parametrize("invalid_total", [True, -1, 1.5, "1"])
def test_invalid_remote_total_count_fails_closed(invalid_total: object) -> None:
    value = _coherent_facet_value(EvidenceFacet.FILES)
    recorded = RecordedFacet(
        value,
        (_coherent_response(value, "invalid-total"),),
        cast(int, invalid_total),
        True,
    )

    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _coherent_service(
            _coherent_fake(overrides={EvidenceFacet.FILES: [recorded]}),
            CoherentFakeClock(COHERENT_NOW),
        ).acquire(COHERENT_TARGET)

    assert (
        raised.value.reason is PreparednessReasonCode.EVIDENCE_TOTAL_COUNT_INCONSISTENT
    )


@pytest.mark.parametrize(
    "recorded",
    [
        cast(RecordedFacet, object()),
        RecordedFacet(
            _coherent_facet_value(EvidenceFacet.FILES),
            cast(tuple[RecordedGitHubResponse, ...], []),
            1,
            True,
        ),
        RecordedFacet(
            _coherent_facet_value(EvidenceFacet.FILES),
            (
                _coherent_response(
                    _coherent_facet_value(EvidenceFacet.FILES), "bad-complete"
                ),
            ),
            1,
            cast(bool, 1),
        ),
    ],
)
def test_malformed_recorded_facet_shapes_fail_closed(recorded: RecordedFacet) -> None:
    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _coherent_service(
            _coherent_fake(overrides={EvidenceFacet.FILES: [recorded]}),
            CoherentFakeClock(COHERENT_NOW),
        ).acquire(COHERENT_TARGET)

    assert raised.value.reason is PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE


def test_list_facet_cannot_exceed_recorded_page_capacity() -> None:
    item = cast(list[dict[str, object]], _coherent_facet_value(EvidenceFacet.FILES))[0]
    value = [deepcopy(item) for _ in range(PER_PAGE + 1)]
    recorded = RecordedFacet(
        value,
        (_coherent_response(value, "overfull-page"),),
        len(value),
        True,
    )

    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _coherent_service(
            _coherent_fake(overrides={EvidenceFacet.FILES: [recorded]}),
            CoherentFakeClock(COHERENT_NOW),
        ).acquire(COHERENT_TARGET)

    assert raised.value.reason is PreparednessReasonCode.EVIDENCE_PAGINATION_UNCERTAIN


def test_page_capacity_uses_raw_items_before_identity_deduplication() -> None:
    item = cast(
        list[dict[str, object]],
        _coherent_facet_value(EvidenceFacet.COMMIT_STATUSES),
    )[0]
    value = [deepcopy(item) for _ in range(PER_PAGE + 1)]
    recorded = RecordedFacet(
        value,
        (_coherent_response(value, "overfull-duplicate-status-page"),),
        1,
        True,
    )

    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _coherent_service(
            _coherent_fake(overrides={EvidenceFacet.COMMIT_STATUSES: [recorded]}),
            CoherentFakeClock(COHERENT_NOW),
        ).acquire(COHERENT_TARGET)

    assert raised.value.reason is PreparednessReasonCode.EVIDENCE_PAGINATION_UNCERTAIN


def test_facet_completeness_ceiling_fails_before_count_mismatch() -> None:
    recorded = _coherent_recorded_facet(EvidenceFacet.FILES, total=MAX_FILES + 1)
    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _coherent_service(
            _coherent_fake(overrides={EvidenceFacet.FILES: [recorded]}),
            CoherentFakeClock(COHERENT_NOW),
        ).acquire(COHERENT_TARGET)
    assert raised.value.reason is PreparednessReasonCode.EVIDENCE_CAP_EXCEEDED


def test_integer_check_suite_count_normalizes_and_seals() -> None:
    response = _coherent_response(1, "integer-suite-count")
    recorded = RecordedFacet(1, (response,), 1, True)
    fake = _coherent_fake(
        overrides={EvidenceFacet.CHECK_SUITE_COUNT: [recorded, recorded]}
    )
    result = _coherent_service(fake, CoherentFakeClock(COHERENT_NOW)).acquire(
        COHERENT_TARGET
    )
    assert result.view.check_suite_count == 1


@pytest.mark.parametrize(
    ("value", "total", "reason"),
    [
        (
            {"total_count": 1},
            2,
            PreparednessReasonCode.EVIDENCE_TOTAL_COUNT_INCONSISTENT,
        ),
        (
            {"total_count": MAX_CHECK_SUITES + 1},
            MAX_CHECK_SUITES + 1,
            PreparednessReasonCode.EVIDENCE_CAP_EXCEEDED,
        ),
    ],
)
def test_check_suite_count_safety_failures_are_precise(
    value: object,
    total: int,
    reason: PreparednessReasonCode,
) -> None:
    recorded = RecordedFacet(
        value, (_coherent_response(value, "suite-invalid"),), total, True
    )
    fake = _coherent_fake(overrides={EvidenceFacet.CHECK_SUITE_COUNT: [recorded]})
    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _coherent_service(fake, CoherentFakeClock(COHERENT_NOW)).acquire(
            COHERENT_TARGET
        )
    assert raised.value.reason is reason


@pytest.mark.parametrize(
    "facet", [EvidenceFacet.CHECK_RUNS, EvidenceFacet.COMMIT_STATUSES]
)
def test_exact_head_facet_mismatch_fails_closed(facet: EvidenceFacet) -> None:
    value = deepcopy(_coherent_facet_value(facet))
    item = cast(list[dict[str, object]], value)[0]
    if facet is EvidenceFacet.CHECK_RUNS:
        item["head_sha"] = "d" * 40
    else:
        item["sha"] = "d" * 40
    recorded = RecordedFacet(value, (_coherent_response(value, "wrong-head"),), 1, True)

    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _coherent_service(
            _coherent_fake(overrides={facet: [recorded]}),
            CoherentFakeClock(COHERENT_NOW),
        ).acquire(COHERENT_TARGET)

    assert raised.value.reason is PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE


@pytest.mark.parametrize(
    "route",
    [
        None,
        "https://api.github.com/repos/Harry5174/github-steward/pulls/5",
        "https://api.github.com/repos/Harry5174/github-steward/pulls/4?x=1",
        "https://api.github.com/repos/harry5174/github-steward/pulls/4",
        "https://[malformed",
    ],
)
def test_review_route_must_exactly_match_the_acquisition_target(
    route: str | None,
) -> None:
    value = deepcopy(_coherent_facet_value(EvidenceFacet.REVIEWS))
    review = cast(list[dict[str, object]], value)[0]
    if route is None:
        review.pop("pull_request_url")
    else:
        review["pull_request_url"] = route
    recorded = RecordedFacet(
        value, (_coherent_response(value, "wrong-review-route"),), 1, True
    )

    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _coherent_service(
            _coherent_fake(overrides={EvidenceFacet.REVIEWS: [recorded]}),
            CoherentFakeClock(COHERENT_NOW),
        ).acquire(COHERENT_TARGET)

    assert raised.value.reason is PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE


def test_uncanonicalizable_evidence_text_maps_to_malformed_response() -> None:
    value = deepcopy(_coherent_facet_value(EvidenceFacet.COMMIT_STATUSES))
    cast(list[dict[str, object]], value)[0]["context"] = "\ud800"
    recorded = RecordedFacet(
        value,
        (_coherent_response(value, "uncanonicalizable-status"),),
        1,
        True,
    )

    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _coherent_service(
            _coherent_fake(overrides={EvidenceFacet.COMMIT_STATUSES: [recorded]}),
            CoherentFakeClock(COHERENT_NOW),
        ).acquire(COHERENT_TARGET)

    assert raised.value.reason is PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE


def test_fractional_github_timestamps_are_normalized() -> None:
    anchor = _coherent_anchor(updated_at="2026-08-11T12:00:00.123456Z")
    result = _coherent_service(
        _coherent_fake(anchors=[anchor, deepcopy(anchor), deepcopy(anchor)]),
        CoherentFakeClock(COHERENT_NOW),
    ).acquire(COHERENT_TARGET)
    assert result.view.anchor.updated_at.microsecond == 123456


def test_anchor_route_and_malformed_scalar_safety_fail_closed() -> None:
    wrong_route = _coherent_anchor()
    cast(dict[str, object], cast(dict[str, object], wrong_route["base"])["repo"])[
        "full_name"
    ] = "someone/else"
    wrong_number = _coherent_anchor()
    wrong_number["number"] = 5
    bad_draft = _coherent_anchor()
    bad_draft["draft"] = "false"
    bad_identifier = _coherent_anchor()
    bad_identifier["id"] = 0
    bad_count = _coherent_anchor()
    bad_count["changed_files"] = -1
    bad_sha = _coherent_anchor()
    cast(dict[str, object], bad_sha["head"])["sha"] = "A" * 40
    bad_time = _coherent_anchor(updated_at="not-a-timestamp")
    empty_name = _coherent_anchor()
    cast(dict[str, object], cast(dict[str, object], empty_name["base"])["repo"])[
        "full_name"
    ] = ""

    values: tuple[object, ...] = (
        [],
        wrong_route,
        wrong_number,
        bad_draft,
        bad_identifier,
        bad_count,
        bad_sha,
        bad_time,
        empty_name,
    )
    for value in values:
        fake = _coherent_fake(anchors=cast(list[dict[str, object]], [value]))
        with pytest.raises(CoherentAcquisitionFailure) as raised:
            _coherent_service(fake, CoherentFakeClock(COHERENT_NOW)).acquire(
                COHERENT_TARGET
            )
        assert raised.value.reason is PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE


@pytest.mark.parametrize(
    "value",
    [
        {},
        [[]],
    ],
)
def test_malformed_file_collection_shapes_fail_closed(value: object) -> None:
    recorded = RecordedFacet(value, (_coherent_response(value, "bad-files"),), 1, True)
    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _coherent_service(
            _coherent_fake(overrides={EvidenceFacet.FILES: [recorded]}),
            CoherentFakeClock(COHERENT_NOW),
        ).acquire(COHERENT_TARGET)
    assert raised.value.reason is PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE


POINTER_NOW = datetime(2026, 8, 11, 12, tzinfo=UTC)
POINTER_OBSERVATION = ObservationVersionId("11111111-1111-5111-8111-111111111111")


def _pointer_view(
    *,
    suite_count: int = 1,
    files_digest: str = "2" * 64,
    sealed_at: datetime = POINTER_NOW,
) -> CoherentAnalysisView:
    return CoherentAnalysisView(
        analysis_view_id=f"view-{suite_count}-{files_digest[0]}-{sealed_at.microsecond}",
        anchor=PullRequestAnchor(
            77,
            4,
            404,
            "a" * 40,
            77,
            "main",
            "b" * 40,
            "open",
            False,
            POINTER_NOW,
            1,
            1,
        ),
        files=(FileEvidence("c" * 40, "a.py", "modified", 1, 0, 1),),
        commits=(CommitEvidence("a" * 40),),
        files_digest=files_digest,
        commits_digest="3" * 64,
        requested_reviewers=RequestedReviewers(),
        check_suite_count=suite_count,
        check_runs=(),
        commit_statuses=(),
        reviews=(),
        acquisition_configuration_digest="f" * 64,
        evidence_sealed_at=sealed_at,
        raw_digest_inventory={"recorded": ("e" * 64,)},
        semantic_digest_inventory={
            facet: f"{index + 1:x}" * 64 for index, facet in enumerate(SEMANTIC_FACETS)
        },
    )


def _pointer_record(view: CoherentAnalysisView, version: int) -> ObservationPointer:
    return ObservationPointer(
        entity_kind="github_pull_request",
        entity_id="77:4",
        observation_version_id=POINTER_OBSERVATION,
        ordering_key=view.as_mapping(),
        pointer_version=version,
        updated_at=POINTER_NOW,
    )


class PointerFakePointers:
    def __init__(
        self,
        current: ObservationPointer | None,
        *,
        cas_script: list[tuple[bool, ObservationPointer | None]] | None = None,
        create_conflict: ObservationPointer | None = None,
    ) -> None:
        self.current = current
        self.cas_script = list(cas_script or [])
        self.create_conflict = create_conflict
        self.get_calls = 0
        self.create_calls = 0
        self.cas_calls: list[int] = []

    def get(self, *, entity_kind: str, entity_id: str) -> ObservationPointer | None:
        assert (entity_kind, entity_id) == ("github_pull_request", "77:4")
        self.get_calls += 1
        return self.current

    def create_if_absent(self, pointer: ObservationPointer) -> PointerCreateOutcome:
        self.create_calls += 1
        if self.current is None and self.create_conflict is None:
            self.current = pointer
            return PointerCreateOutcome.CREATED
        if self.create_conflict is not None:
            self.current = self.create_conflict
        return PointerCreateOutcome.CONFLICT

    def compare_and_swap(
        self,
        *,
        expected_version: int,
        replacement: ObservationPointer,
    ) -> bool:
        self.cas_calls.append(expected_version)
        if self.cas_script:
            success, concurrent = self.cas_script.pop(0)
            if success:
                self.current = replacement
            elif concurrent is not None:
                self.current = concurrent
            return success
        if (
            self.current is not None
            and self.current.pointer_version == expected_version
        ):
            self.current = replacement
            return True
        return False


class PointerCreateConflictWithoutCurrent(PointerFakePointers):
    """Model a losing create race whose winner then disappears."""

    def create_if_absent(self, pointer: ObservationPointer) -> PointerCreateOutcome:
        self.create_calls += 1
        return PointerCreateOutcome.CONFLICT


def _pointer_promote(
    fake: PointerFakePointers, candidate: CoherentAnalysisView
) -> PointerPromotionResult:
    service = CurrentPointerPromotionService(
        pointers=fake,
        decode_view=CoherentAnalysisView.from_mapping,
    )
    return service.promote(
        entity_kind="github_pull_request",
        entity_id="77:4",
        observation_version_id=POINTER_OBSERVATION,
        candidate=candidate,
        updated_at=POINTER_NOW,
    )


def test_absent_pointer_is_created_as_advanced() -> None:
    fake = PointerFakePointers(None)
    result = _pointer_promote(fake, _pointer_view())
    assert result.outcome is PointerPromotionOutcome.POINTER_ADVANCED
    assert result.cas_attempts == 0
    assert fake.create_calls == 1
    assert fake.cas_calls == []
    assert fake.current is not None and fake.current.pointer_version == 0


def test_replay_is_noop_without_cas_or_version_increment() -> None:
    current = _pointer_record(_pointer_view(), 7)
    fake = PointerFakePointers(current)
    replay = _pointer_view(sealed_at=POINTER_NOW + timedelta(microseconds=1))
    result = _pointer_promote(fake, replay)
    assert result.outcome is PointerPromotionOutcome.POINTER_REPLAY_NOOP
    assert result.relation is SourceOrderRelation.REPLAY
    assert fake.cas_calls == []
    assert fake.current == current


def test_casing_only_status_replay_does_not_increment_pointer() -> None:
    upper = NormalizedCommitStatus(
        1,
        "a" * 40,
        "CI/Test",
        "success",
        POINTER_NOW,
    )
    lower = replace(upper, context="ci/test")
    current_view = replace(_pointer_view(), commit_statuses=(upper,))
    candidate_view = replace(current_view, commit_statuses=(lower,))
    current = _pointer_record(current_view, 9)
    fake = PointerFakePointers(current)

    result = _pointer_promote(fake, candidate_view)

    assert result.outcome is PointerPromotionOutcome.POINTER_REPLAY_NOOP
    assert fake.cas_calls == []
    assert fake.current == current


def test_progression_uses_exact_loaded_version_for_cas() -> None:
    fake = PointerFakePointers(_pointer_record(_pointer_view(suite_count=1), 3))
    result = _pointer_promote(fake, _pointer_view(suite_count=2))
    assert result.outcome is PointerPromotionOutcome.POINTER_ADVANCED
    assert result.cas_attempts == 1
    assert fake.cas_calls == [3]
    assert fake.current is not None and fake.current.pointer_version == 4


def test_regression_and_incomparable_never_cas() -> None:
    regression = PointerFakePointers(_pointer_record(_pointer_view(suite_count=2), 4))
    regressed = _pointer_promote(regression, _pointer_view(suite_count=1))
    assert regressed.outcome is PointerPromotionOutcome.POINTER_REGRESSION_REJECTED
    assert regression.cas_calls == []

    incomparable = PointerFakePointers(_pointer_record(_pointer_view(), 4))
    ambiguous = _pointer_promote(incomparable, _pointer_view(files_digest="9" * 64))
    assert ambiguous.outcome is PointerPromotionOutcome.POINTER_INCOMPARABLE_REJECTED
    assert incomparable.cas_calls == []


def test_first_cas_failure_reloads_and_recomputes_replay() -> None:
    current = _pointer_record(_pointer_view(suite_count=1), 0)
    concurrent_equivalent = _pointer_record(_pointer_view(suite_count=2), 1)
    fake = PointerFakePointers(
        current,
        cas_script=[(False, concurrent_equivalent)],
    )
    result = _pointer_promote(fake, _pointer_view(suite_count=2))
    assert result.outcome is PointerPromotionOutcome.POINTER_REPLAY_NOOP
    assert result.cas_attempts == 1
    assert fake.cas_calls == [0]
    assert fake.get_calls == 2


def test_first_cas_failure_lost_to_clearly_newer_pointer() -> None:
    current = _pointer_record(_pointer_view(suite_count=1), 0)
    concurrent_newer = _pointer_record(_pointer_view(suite_count=3), 1)
    fake = PointerFakePointers(current, cas_script=[(False, concurrent_newer)])
    result = _pointer_promote(fake, _pointer_view(suite_count=2))
    assert result.outcome is PointerPromotionOutcome.POINTER_LOST_TO_NEWER
    assert result.relation is SourceOrderRelation.REGRESSION
    assert fake.cas_calls == [0]


def test_still_progression_permits_exactly_one_second_cas() -> None:
    current = _pointer_record(_pointer_view(suite_count=1), 0)
    same_semantics_new_version = _pointer_record(_pointer_view(suite_count=1), 1)
    fake = PointerFakePointers(
        current,
        cas_script=[(False, same_semantics_new_version), (True, None)],
    )
    result = _pointer_promote(fake, _pointer_view(suite_count=2))
    assert result.outcome is PointerPromotionOutcome.POINTER_ADVANCED
    assert result.cas_attempts == 2
    assert fake.cas_calls == [0, 1]
    assert fake.current is not None and fake.current.pointer_version == 2


def test_second_cas_failure_remains_unresolved() -> None:
    current = _pointer_record(_pointer_view(suite_count=1), 0)
    version_one = _pointer_record(_pointer_view(suite_count=1), 1)
    version_two = _pointer_record(_pointer_view(suite_count=1), 2)
    fake = PointerFakePointers(
        current,
        cas_script=[(False, version_one), (False, version_two)],
    )
    result = _pointer_promote(fake, _pointer_view(suite_count=2))
    assert result.outcome is PointerPromotionOutcome.POINTER_CONCURRENCY_UNRESOLVED
    assert result.cas_attempts == 2
    assert fake.cas_calls == [0, 1]


def test_create_race_reloads_and_compares_without_overwrite() -> None:
    concurrent = _pointer_record(_pointer_view(), 0)
    fake = PointerFakePointers(None, create_conflict=concurrent)
    result = _pointer_promote(
        fake, _pointer_view(sealed_at=POINTER_NOW + timedelta(seconds=1))
    )
    assert result.outcome is PointerPromotionOutcome.POINTER_REPLAY_NOOP
    assert fake.create_calls == 1
    assert fake.cas_calls == []


def test_malformed_non_object_pointer_ordering_fails_closed() -> None:
    malformed = ObservationPointer(
        entity_kind="github_pull_request",
        entity_id="77:4",
        observation_version_id=POINTER_OBSERVATION,
        ordering_key="not-an-object",
        pointer_version=0,
        updated_at=POINTER_NOW,
    )

    with pytest.raises(
        ValueError,
        match="pointer ordering material must be an object",
    ):
        _pointer_promote(PointerFakePointers(malformed), _pointer_view())


def test_create_conflict_without_reloadable_current_fails_closed() -> None:
    fake = PointerCreateConflictWithoutCurrent(None)

    with pytest.raises(
        RuntimeError,
        match="current pointer disappeared during bounded promotion",
    ):
        _pointer_promote(fake, _pointer_view())

    assert fake.get_calls == 2
    assert fake.create_calls == 1
    assert fake.cas_calls == []


def test_uncanonicalizable_acquisition_material_maps_to_malformed_response() -> None:
    state = PipelineState()
    safe = _pipeline_acquired()
    malformed_file = replace(safe.view.files[0], filename="\ud800")
    malformed_view = replace(safe.view, files=(malformed_file,))
    malformed = replace(safe, view=malformed_view)
    pipeline = _pipeline_service(state, PipelineFakeAcquisition(malformed))
    identity = pipeline.register_profile(_pipeline_profile()).reference

    result = pipeline.assess(
        target=PIPELINE_TARGET,
        expected_identity=_pipeline_expected(),
        profile_reference=identity,
    )

    assert result.assessment is None
    assert (
        result.acquisition_failure is PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE
    )
    assert state.observations == []
    assert state.views == []
    assert state.assessments == []
    assert state.pointer is None


@pytest.mark.parametrize(
    "kind",
    [
        "attempts",
        "facet",
        "semantic_inventory",
        "files_digest",
        "commits_digest",
        "view_envelope",
    ],
)
def test_acquisition_result_must_bind_every_persisted_envelope(kind: str) -> None:
    state = PipelineState()
    pipeline = _pipeline_service(
        state, PipelineFakeAcquisition(_pipeline_corrupted_acquisition(kind))
    )
    identity = pipeline.register_profile(_pipeline_profile()).reference

    result = pipeline.assess(
        target=PIPELINE_TARGET,
        expected_identity=_pipeline_expected(),
        profile_reference=identity,
    )

    assert result.assessment is None
    assert (
        result.acquisition_failure
        is PreparednessReasonCode.EVIDENCE_COHERENCE_UNCERTAIN
    )
    assert state.observations == []
    assert state.views == []
    assert state.assessments == []
    assert state.pointer is None


def test_incomparable_source_order_forces_indeterminate_assessment() -> None:
    state = PipelineState()
    state.pointer = _pipeline_pointer(_pipeline_view())
    candidate = _pipeline_view(
        filename="different.py",
        analysis_view_id="44444444-4444-5444-8444-444444444444",
    )
    pipeline = _pipeline_service(
        state, PipelineFakeAcquisition(_pipeline_acquired(candidate))
    )
    identity = pipeline.register_profile(_pipeline_profile()).reference

    result = pipeline.assess(
        target=PIPELINE_TARGET,
        expected_identity=_pipeline_expected(),
        profile_reference=identity,
    )

    assert result.assessment is not None
    assert result.assessment.verdict is PreparednessVerdict.INDETERMINATE
    assert result.assessment.reason_codes == (
        PreparednessReasonCode.EVIDENCE_COHERENCE_UNCERTAIN,
    )
    assert (
        result.pointer_outcome is PointerPromotionOutcome.POINTER_INCOMPARABLE_REJECTED
    )
    assert state.pointer.pointer_version == 0


def test_regressed_source_order_forces_indeterminate_assessment() -> None:
    state = PipelineState()
    state.pointer = _pipeline_pointer(_pipeline_view(suite_count=2))
    candidate = _pipeline_view(
        suite_count=1,
        analysis_view_id="66666666-6666-5666-8666-666666666666",
    )
    pipeline = _pipeline_service(
        state, PipelineFakeAcquisition(_pipeline_acquired(candidate))
    )
    identity = pipeline.register_profile(_pipeline_profile()).reference

    result = pipeline.assess(
        target=PIPELINE_TARGET,
        expected_identity=_pipeline_expected(),
        profile_reference=identity,
    )

    assert result.assessment is not None
    assert result.assessment.verdict is PreparednessVerdict.INDETERMINATE
    assert result.assessment.reason_codes == (
        PreparednessReasonCode.EVIDENCE_COHERENCE_UNCERTAIN,
    )
    assert result.pointer_outcome is PointerPromotionOutcome.POINTER_REGRESSION_REJECTED
    assert state.pointer.pointer_version == 0


@pytest.mark.parametrize(
    "outcome",
    [
        PointerPromotionOutcome.POINTER_REGRESSION_REJECTED,
        PointerPromotionOutcome.POINTER_LOST_TO_NEWER,
    ],
)
def test_stale_relative_pointer_outcomes_map_to_coherence_uncertainty(
    outcome: PointerPromotionOutcome,
) -> None:
    assert preparedness_pipeline._pointer_uncertainty(outcome) == (
        PreparednessReasonCode.EVIDENCE_COHERENCE_UNCERTAIN,
    )


def test_unresolved_second_cas_forces_indeterminate_assessment() -> None:
    state = PipelineState()
    state.pointer = _pipeline_pointer(_pipeline_view(suite_count=1))
    state.cas_failures = 2
    candidate = _pipeline_view(
        suite_count=2,
        analysis_view_id="55555555-5555-5555-8555-555555555555",
    )
    pipeline = _pipeline_service(
        state, PipelineFakeAcquisition(_pipeline_acquired(candidate))
    )
    identity = pipeline.register_profile(_pipeline_profile()).reference

    result = pipeline.assess(
        target=PIPELINE_TARGET,
        expected_identity=_pipeline_expected(),
        profile_reference=identity,
    )

    assert result.assessment is not None
    assert result.assessment.verdict is PreparednessVerdict.INDETERMINATE
    assert result.assessment.reason_codes == (PreparednessReasonCode.EVIDENCE_UNSTABLE,)
    assert (
        result.pointer_outcome is PointerPromotionOutcome.POINTER_CONCURRENCY_UNRESOLVED
    )


def test_profile_must_be_loaded_by_exact_explicit_identity() -> None:
    state = PipelineState()
    pipeline = _pipeline_service(state)
    try:
        pipeline.assess(
            target=PIPELINE_TARGET,
            expected_identity=_pipeline_expected(),
            profile_reference=ProfileReference(
                PIPELINE_PROFILE_ID,
                1,
                Digest("9" * 64),
            ),
        )
    except ValueError as exc:
        assert "exact preparedness profile" in str(exc)
    else:
        raise AssertionError("missing exact profile did not fail closed")


def test_persisted_profile_digest_mismatch_fails_closed_before_acquisition() -> None:
    state = PipelineState()
    pipeline = _pipeline_service(state)
    identity = pipeline.register_profile(_pipeline_profile()).reference
    key = (str(identity.profile_id), identity.version)
    state.profiles[key] = replace(
        state.profiles[key],
        digest=digest_payload({"corrupted": True}),
    )

    with pytest.raises(
        ValueError,
        match="persisted preparedness profile digest did not verify",
    ):
        pipeline.assess(
            target=PIPELINE_TARGET,
            expected_identity=_pipeline_expected(),
            profile_reference=identity,
        )

    assert state.observations == []
    assert state.views == []
    assert state.assessments == []
    assert state.pointer is None


def test_wrong_requested_profile_digest_fails_closed_before_persistence() -> None:
    state = PipelineState()
    pipeline = _pipeline_service(state)
    registered = pipeline.register_profile(_pipeline_profile()).reference
    wrong_reference = replace(registered, digest=Digest("8" * 64))

    with pytest.raises(
        ValueError,
        match="requested preparedness profile digest did not match",
    ):
        pipeline.assess(
            target=PIPELINE_TARGET,
            expected_identity=_pipeline_expected(),
            profile_reference=wrong_reference,
        )

    assert state.assessments == []
    assert state.pointer is None


def test_persisted_profile_identity_mismatch_fails_closed_before_acquisition() -> None:
    state = PipelineState()
    pipeline = _pipeline_service(state)
    registered = pipeline.register_profile(_pipeline_profile()).reference
    original_key = (str(registered.profile_id), registered.version)
    requested = ProfileReference(
        registered.profile_id,
        registered.version + 1,
        registered.digest,
    )
    state.profiles[(str(requested.profile_id), requested.version)] = replace(
        state.profiles.pop(original_key),
        version=requested.version,
    )

    with pytest.raises(
        ValueError,
        match="persisted preparedness profile identity did not match",
    ):
        pipeline.assess(
            target=PIPELINE_TARGET,
            expected_identity=_pipeline_expected(),
            profile_reference=requested,
        )

    assert state.observations == []
    assert state.views == []
    assert state.assessments == []
    assert state.pointer is None
