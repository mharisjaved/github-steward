"""Bounded GS-I4 current-pointer promotion tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from github_steward.application.preparedness_pipeline import (
    CurrentPointerPromotionService,
    PointerPromotionOutcome,
    PointerPromotionResult,
)
from github_steward.domain.github_evidence import (
    SEMANTIC_FACETS,
    CoherentAnalysisView,
    CommitEvidence,
    FileEvidence,
    PullRequestAnchor,
    RequestedReviewers,
    SourceOrderRelation,
)
from github_steward.ports.persistence import (
    ObservationPointer,
    ObservationVersionId,
    PointerCreateOutcome,
)

NOW = datetime(2026, 8, 11, 12, tzinfo=UTC)
OBSERVATION = ObservationVersionId("11111111-1111-5111-8111-111111111111")


def _view(
    *,
    suite_count: int = 1,
    files_digest: str = "2" * 64,
    sealed_at: datetime = NOW,
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
            NOW,
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


def _pointer(view: CoherentAnalysisView, version: int) -> ObservationPointer:
    return ObservationPointer(
        entity_kind="github_pull_request",
        entity_id="77:4",
        observation_version_id=OBSERVATION,
        ordering_key=view.as_mapping(),
        pointer_version=version,
        updated_at=NOW,
    )


class FakePointers:
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


class CreateConflictWithoutCurrentPointers(FakePointers):
    """Model a losing create race whose winner then disappears."""

    def create_if_absent(self, pointer: ObservationPointer) -> PointerCreateOutcome:
        self.create_calls += 1
        return PointerCreateOutcome.CONFLICT


def _promote(
    fake: FakePointers, candidate: CoherentAnalysisView
) -> PointerPromotionResult:
    service = CurrentPointerPromotionService(
        pointers=fake,
        decode_view=CoherentAnalysisView.from_mapping,
    )
    return service.promote(
        entity_kind="github_pull_request",
        entity_id="77:4",
        observation_version_id=OBSERVATION,
        candidate=candidate,
        updated_at=NOW,
    )


def test_absent_pointer_is_created_as_advanced() -> None:
    fake = FakePointers(None)
    result = _promote(fake, _view())
    assert result.outcome is PointerPromotionOutcome.POINTER_ADVANCED
    assert result.cas_attempts == 0
    assert fake.create_calls == 1
    assert fake.cas_calls == []
    assert fake.current is not None and fake.current.pointer_version == 0


def test_replay_is_noop_without_cas_or_version_increment() -> None:
    current = _pointer(_view(), 7)
    fake = FakePointers(current)
    replay = _view(sealed_at=NOW + timedelta(microseconds=1))
    result = _promote(fake, replay)
    assert result.outcome is PointerPromotionOutcome.POINTER_REPLAY_NOOP
    assert result.relation is SourceOrderRelation.REPLAY
    assert fake.cas_calls == []
    assert fake.current == current


def test_progression_uses_exact_loaded_version_for_cas() -> None:
    fake = FakePointers(_pointer(_view(suite_count=1), 3))
    result = _promote(fake, _view(suite_count=2))
    assert result.outcome is PointerPromotionOutcome.POINTER_ADVANCED
    assert result.cas_attempts == 1
    assert fake.cas_calls == [3]
    assert fake.current is not None and fake.current.pointer_version == 4


def test_regression_and_incomparable_never_cas() -> None:
    regression = FakePointers(_pointer(_view(suite_count=2), 4))
    regressed = _promote(regression, _view(suite_count=1))
    assert regressed.outcome is PointerPromotionOutcome.POINTER_REGRESSION_REJECTED
    assert regression.cas_calls == []

    incomparable = FakePointers(_pointer(_view(), 4))
    ambiguous = _promote(incomparable, _view(files_digest="9" * 64))
    assert ambiguous.outcome is PointerPromotionOutcome.POINTER_INCOMPARABLE_REJECTED
    assert incomparable.cas_calls == []


def test_first_cas_failure_reloads_and_recomputes_replay() -> None:
    current = _pointer(_view(suite_count=1), 0)
    concurrent_equivalent = _pointer(_view(suite_count=2), 1)
    fake = FakePointers(
        current,
        cas_script=[(False, concurrent_equivalent)],
    )
    result = _promote(fake, _view(suite_count=2))
    assert result.outcome is PointerPromotionOutcome.POINTER_REPLAY_NOOP
    assert result.cas_attempts == 1
    assert fake.cas_calls == [0]
    assert fake.get_calls == 2


def test_first_cas_failure_lost_to_clearly_newer_pointer() -> None:
    current = _pointer(_view(suite_count=1), 0)
    concurrent_newer = _pointer(_view(suite_count=3), 1)
    fake = FakePointers(current, cas_script=[(False, concurrent_newer)])
    result = _promote(fake, _view(suite_count=2))
    assert result.outcome is PointerPromotionOutcome.POINTER_LOST_TO_NEWER
    assert result.relation is SourceOrderRelation.REGRESSION
    assert fake.cas_calls == [0]


def test_still_progression_permits_exactly_one_second_cas() -> None:
    current = _pointer(_view(suite_count=1), 0)
    same_semantics_new_version = _pointer(_view(suite_count=1), 1)
    fake = FakePointers(
        current,
        cas_script=[(False, same_semantics_new_version), (True, None)],
    )
    result = _promote(fake, _view(suite_count=2))
    assert result.outcome is PointerPromotionOutcome.POINTER_ADVANCED
    assert result.cas_attempts == 2
    assert fake.cas_calls == [0, 1]
    assert fake.current is not None and fake.current.pointer_version == 2


def test_second_cas_failure_remains_unresolved() -> None:
    current = _pointer(_view(suite_count=1), 0)
    version_one = _pointer(_view(suite_count=1), 1)
    version_two = _pointer(_view(suite_count=1), 2)
    fake = FakePointers(
        current,
        cas_script=[(False, version_one), (False, version_two)],
    )
    result = _promote(fake, _view(suite_count=2))
    assert result.outcome is PointerPromotionOutcome.POINTER_CONCURRENCY_UNRESOLVED
    assert result.cas_attempts == 2
    assert fake.cas_calls == [0, 1]


def test_create_race_reloads_and_compares_without_overwrite() -> None:
    concurrent = _pointer(_view(), 0)
    fake = FakePointers(None, create_conflict=concurrent)
    result = _promote(fake, _view(sealed_at=NOW + timedelta(seconds=1)))
    assert result.outcome is PointerPromotionOutcome.POINTER_REPLAY_NOOP
    assert fake.create_calls == 1
    assert fake.cas_calls == []


def test_malformed_non_object_pointer_ordering_fails_closed() -> None:
    malformed = ObservationPointer(
        entity_kind="github_pull_request",
        entity_id="77:4",
        observation_version_id=OBSERVATION,
        ordering_key="not-an-object",
        pointer_version=0,
        updated_at=NOW,
    )

    with pytest.raises(
        ValueError,
        match="pointer ordering material must be an object",
    ):
        _promote(FakePointers(malformed), _view())


def test_create_conflict_without_reloadable_current_fails_closed() -> None:
    fake = CreateConflictWithoutCurrentPointers(None)

    with pytest.raises(
        RuntimeError,
        match="current pointer disappeared during bounded promotion",
    ):
        _promote(fake, _view())

    assert fake.get_calls == 2
    assert fake.create_calls == 1
    assert fake.cas_calls == []
