"""GS-I4 normalized evidence and facet-aware ordering tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from typing import cast

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from github_steward.domain.canonical import DIGEST_FORMAT, MAX_SAFE_INTEGER
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
    assert sharp_s.as_mapping()["context"] == "Straße"


def test_status_latest_selection_uses_updated_at_then_numeric_id() -> None:
    earlier = _status(50, updated_at=NOW)
    same_time_later_id = _status(51, state="pending", updated_at=NOW)
    newer_time = _status(2, state="failure", updated_at=NOW + timedelta(seconds=1))
    latest = latest_commit_statuses((same_time_later_id, newer_time, earlier))
    assert latest["ci/test"] == newer_time


def test_contradictory_immutable_status_identity_is_malformed() -> None:
    with pytest.raises(EvidenceNormalizationError, match="contradictory immutable"):
        normalize_commit_statuses((_status(), _status(state="failure")))


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
