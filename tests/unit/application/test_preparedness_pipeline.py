"""End-to-end deterministic GS-I4 application pipeline tests with fakes."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Self
from uuid import UUID

import pytest

import github_steward.application.preparedness_pipeline as preparedness_pipeline
from github_steward.adapters.canonicalization.rfc8785 import (
    digest_payload,
    envelope_payload,
)
from github_steward.application.preparedness_pipeline import (
    DeterministicPreparednessPipeline,
    PointerPromotionOutcome,
)
from github_steward.domain.acquisition import RepositoryTarget
from github_steward.domain.github_evidence import (
    SEMANTIC_FACETS,
    CoherentAnalysisView,
    CommitEvidence,
    FileEvidence,
    NormalizedCheckRun,
    NormalizedCommitStatus,
    PullRequestAnchor,
    RequestedReviewers,
)
from github_steward.domain.preparedness import (
    PreparednessProfile,
    PreparednessReasonCode,
    PreparednessVerdict,
    ProfileIdentity,
    PullRequestIdentity,
    RequiredCheck,
    RequiredStatus,
)
from github_steward.ports.github_evidence import (
    CoherentAcquisitionFailure,
    CoherentAcquisitionResult,
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
TARGET = RepositoryTarget("Harry5174", "github-steward", 4)
PROFILE_ID = UUID("11111111-1111-5111-8111-111111111111")
CONFIGURATION = digest_payload({"api_version": "2026-03-10", "per_page": 100})


class FakeClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


class PointerAwareClock:
    def __init__(self, state: State) -> None:
        self._state = state
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        assert self._state.pointer is not None
        return NOW


def _view(
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
        NOW,
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
            NOW,
            NOW,
        ),
    )
    commit_statuses = (NormalizedCommitStatus(1, "a" * 40, "CI/Test", "success", NOW),)
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
        acquisition_configuration_digest=CONFIGURATION.value,
        evidence_sealed_at=NOW,
        raw_digest_inventory={"recorded": ("e" * 64,)},
        semantic_digest_inventory=semantic_digests,
    )


def _acquired(view: CoherentAnalysisView | None = None) -> CoherentAcquisitionResult:
    selected = view or _view()
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


def _corrupted_acquisition(kind: str) -> CoherentAcquisitionResult:
    acquired = _acquired()
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
    return _acquired(CoherentAnalysisView.from_mapping(mapping))


class FakeAcquisition:
    def __init__(
        self,
        acquired: CoherentAcquisitionResult | None = None,
        failure: PreparednessReasonCode | None = None,
    ) -> None:
        self.acquired = acquired or _acquired()
        self.failure = failure

    def acquire(self, target: RepositoryTarget) -> CoherentAcquisitionResult:
        assert target == TARGET
        if self.failure is not None:
            raise CoherentAcquisitionFailure(self.failure, "recorded failure")
        return self.acquired


class State:
    def __init__(self) -> None:
        self.profiles: dict[tuple[str, int], PreparednessProfileRecord] = {}
        self.profile_gets: list[tuple[str, int]] = []
        self.observations: list[CanonicalObservationRecord] = []
        self.views: list[AnalysisViewRecord] = []
        self.assessments: list[PreparednessAssessmentRecord] = []
        self.pointer: ObservationPointer | None = None
        self.cas_failures = 0
        self.commits = 0


class Profiles:
    def __init__(self, state: State) -> None:
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


class Pointers:
    def __init__(self, state: State) -> None:
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


class FakeUnit:
    def __init__(self, state: State) -> None:
        self.state = state
        self.profiles = Profiles(state)
        self.pointers = Pointers(state)
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


def _profile() -> PreparednessProfile:
    return PreparednessProfile(
        profile_id=PROFILE_ID,
        version=1,
        repository_id=77,
        required_checks=(RequiredCheck(9, "tests"),),
        required_statuses=(RequiredStatus("ci/test"),),
        block_on_changes_requested=True,
        acquisition_configuration_digest=CONFIGURATION,
        effective_from=NOW,
    )


def _expected() -> PullRequestIdentity:
    return PullRequestIdentity(77, 404, 4, "a" * 40, 77, "main", "b" * 40)


def _pointer(view: CoherentAnalysisView, version: int = 0) -> ObservationPointer:
    return ObservationPointer(
        entity_kind="github_pull_request",
        entity_id="77:4",
        observation_version_id=ObservationVersionId(
            "33333333-3333-5333-8333-333333333333"
        ),
        ordering_key=view.as_mapping(),
        pointer_version=version,
        updated_at=NOW,
    )


def _pipeline(
    state: State,
    acquisition: FakeAcquisition | None = None,
) -> DeterministicPreparednessPipeline:
    return DeterministicPreparednessPipeline(
        acquisition=acquisition or FakeAcquisition(),
        unit_of_work_factory=lambda: FakeUnit(state),
        evaluation_clock=FakeClock(NOW),
        envelope_factory=envelope_payload,
    )


def test_profile_registration_then_complete_ready_persistence_and_pointer() -> None:
    state = State()
    pipeline = _pipeline(state)
    registered = pipeline.register_profile(_profile())
    assert registered.identity == ProfileIdentity(PROFILE_ID, 1)
    assert registered.digest == envelope_payload(_profile().as_mapping()).digest

    result = pipeline.assess(
        target=TARGET,
        expected_identity=_expected(),
        profile_identity=registered.identity,
    )
    assert result.assessment is not None
    assert result.assessment.verdict is PreparednessVerdict.READY_FOR_HUMAN_REVIEW
    assert result.pointer_outcome is PointerPromotionOutcome.POINTER_ADVANCED
    assert result.acquisition_failure is None
    assert result.assessment_id is not None
    assert result.assessment_digest is not None
    assert state.profile_gets == [(str(PROFILE_ID), 1)]
    assert len(state.observations) == 9
    assert len(state.views) == 1
    assert len(state.views[0].observation_versions) == 9
    assert len(state.assessments) == 1
    assert len(state.assessments[0].evidence_observations) == 9
    assert state.pointer is not None and state.pointer.pointer_version == 0


def test_evaluation_time_is_read_only_after_pointer_work() -> None:
    state = State()
    clock = PointerAwareClock(state)
    pipeline = DeterministicPreparednessPipeline(
        acquisition=FakeAcquisition(),
        unit_of_work_factory=lambda: FakeUnit(state),
        evaluation_clock=clock,
        envelope_factory=envelope_payload,
    )
    identity = pipeline.register_profile(_profile()).identity

    result = pipeline.assess(
        target=TARGET,
        expected_identity=_expected(),
        profile_identity=identity,
    )

    assert result.assessment is not None
    assert clock.calls == 1


def test_equivalent_inputs_produce_exact_same_assessment_identity_and_content() -> None:
    results = []
    for _ in range(2):
        state = State()
        pipeline = _pipeline(state)
        identity = pipeline.register_profile(_profile()).identity
        results.append(
            pipeline.assess(
                target=TARGET,
                expected_identity=_expected(),
                profile_identity=identity,
            )
        )
    assert results[0].assessment_id == results[1].assessment_id
    assert results[0].assessment_digest == results[1].assessment_digest
    assert results[0].assessment == results[1].assessment


def test_exact_replay_is_a_pointer_noop_without_version_increment() -> None:
    state = State()
    pipeline = _pipeline(state)
    identity = pipeline.register_profile(_profile()).identity

    first = pipeline.assess(
        target=TARGET,
        expected_identity=_expected(),
        profile_identity=identity,
    )
    second = pipeline.assess(
        target=TARGET,
        expected_identity=_expected(),
        profile_identity=identity,
    )

    assert first.pointer_outcome is PointerPromotionOutcome.POINTER_ADVANCED
    assert second.pointer_outcome is PointerPromotionOutcome.POINTER_REPLAY_NOOP
    assert first.assessment_id == second.assessment_id
    assert state.pointer is not None and state.pointer.pointer_version == 0


def test_acquisition_uncertainty_does_not_persist_or_promote() -> None:
    state = State()
    pipeline = _pipeline(
        state,
        FakeAcquisition(failure=PreparednessReasonCode.EVIDENCE_UNSTABLE),
    )
    identity = pipeline.register_profile(_profile()).identity
    result = pipeline.assess(
        target=TARGET,
        expected_identity=_expected(),
        profile_identity=identity,
    )
    assert result.assessment is None
    assert result.acquisition_failure is PreparednessReasonCode.EVIDENCE_UNSTABLE
    assert state.observations == []
    assert state.views == []
    assert state.assessments == []
    assert state.pointer is None


def test_uncanonicalizable_acquisition_material_maps_to_malformed_response() -> None:
    state = State()
    safe = _acquired()
    malformed_file = replace(safe.view.files[0], filename="\ud800")
    malformed_view = replace(safe.view, files=(malformed_file,))
    malformed = replace(safe, view=malformed_view)
    pipeline = _pipeline(state, FakeAcquisition(malformed))
    identity = pipeline.register_profile(_profile()).identity

    result = pipeline.assess(
        target=TARGET,
        expected_identity=_expected(),
        profile_identity=identity,
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
    state = State()
    pipeline = _pipeline(state, FakeAcquisition(_corrupted_acquisition(kind)))
    identity = pipeline.register_profile(_profile()).identity

    result = pipeline.assess(
        target=TARGET,
        expected_identity=_expected(),
        profile_identity=identity,
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
    state = State()
    state.pointer = _pointer(_view())
    candidate = _view(
        filename="different.py",
        analysis_view_id="44444444-4444-5444-8444-444444444444",
    )
    pipeline = _pipeline(state, FakeAcquisition(_acquired(candidate)))
    identity = pipeline.register_profile(_profile()).identity

    result = pipeline.assess(
        target=TARGET,
        expected_identity=_expected(),
        profile_identity=identity,
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
    state = State()
    state.pointer = _pointer(_view(suite_count=2))
    candidate = _view(
        suite_count=1,
        analysis_view_id="66666666-6666-5666-8666-666666666666",
    )
    pipeline = _pipeline(state, FakeAcquisition(_acquired(candidate)))
    identity = pipeline.register_profile(_profile()).identity

    result = pipeline.assess(
        target=TARGET,
        expected_identity=_expected(),
        profile_identity=identity,
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
    state = State()
    state.pointer = _pointer(_view(suite_count=1))
    state.cas_failures = 2
    candidate = _view(
        suite_count=2,
        analysis_view_id="55555555-5555-5555-8555-555555555555",
    )
    pipeline = _pipeline(state, FakeAcquisition(_acquired(candidate)))
    identity = pipeline.register_profile(_profile()).identity

    result = pipeline.assess(
        target=TARGET,
        expected_identity=_expected(),
        profile_identity=identity,
    )

    assert result.assessment is not None
    assert result.assessment.verdict is PreparednessVerdict.INDETERMINATE
    assert result.assessment.reason_codes == (PreparednessReasonCode.EVIDENCE_UNSTABLE,)
    assert (
        result.pointer_outcome is PointerPromotionOutcome.POINTER_CONCURRENCY_UNRESOLVED
    )


def test_profile_must_be_loaded_by_exact_explicit_identity() -> None:
    state = State()
    pipeline = _pipeline(state)
    try:
        pipeline.assess(
            target=TARGET,
            expected_identity=_expected(),
            profile_identity=ProfileIdentity(PROFILE_ID, 1),
        )
    except ValueError as exc:
        assert "exact preparedness profile" in str(exc)
    else:
        raise AssertionError("missing exact profile did not fail closed")


def test_persisted_profile_digest_mismatch_fails_closed_before_acquisition() -> None:
    state = State()
    pipeline = _pipeline(state)
    identity = pipeline.register_profile(_profile()).identity
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
            target=TARGET,
            expected_identity=_expected(),
            profile_identity=identity,
        )

    assert state.observations == []
    assert state.views == []
    assert state.assessments == []
    assert state.pointer is None


def test_persisted_profile_identity_mismatch_fails_closed_before_acquisition() -> None:
    state = State()
    pipeline = _pipeline(state)
    registered = pipeline.register_profile(_profile()).identity
    original_key = (str(registered.profile_id), registered.version)
    requested = ProfileIdentity(registered.profile_id, registered.version + 1)
    state.profiles[(str(requested.profile_id), requested.version)] = replace(
        state.profiles.pop(original_key),
        version=requested.version,
    )

    with pytest.raises(
        ValueError,
        match="persisted preparedness profile identity did not match",
    ):
        pipeline.assess(
            target=TARGET,
            expected_identity=_expected(),
            profile_identity=requested,
        )

    assert state.observations == []
    assert state.views == []
    assert state.assessments == []
    assert state.pointer is None
