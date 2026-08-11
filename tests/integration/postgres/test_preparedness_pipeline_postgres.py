"""Real-PostgreSQL preparedness-pipeline boundary regressions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.engine import Engine

from github_steward.adapters.canonicalization.rfc8785 import (
    digest_payload,
    envelope_payload,
)
from github_steward.adapters.postgres.metadata import (
    analysis_view,
    analysis_view_observation,
    canonical_observation,
    current_observation_pointer,
    preparedness_assessment,
    preparedness_assessment_evidence,
)
from github_steward.adapters.postgres.unit_of_work import PostgresUnitOfWork
from github_steward.application.preparedness_pipeline import (
    DeterministicPreparednessPipeline,
    PointerPromotionOutcome,
)
from github_steward.domain.acquisition import RepositoryTarget
from github_steward.domain.github_evidence import (
    SEMANTIC_FACETS,
    CoherentAnalysisView,
    PullRequestAnchor,
    RequestedReviewers,
)
from github_steward.domain.preparedness import (
    PreparednessProfile,
    PreparednessReasonCode,
    PreparednessVerdict,
    ProfileIdentity,
    PullRequestIdentity,
)
from github_steward.ports.github_evidence import CoherentAcquisitionResult

ROOT_EFFECTIVE_AT = datetime(2026, 8, 11, 13, tzinfo=UTC)
SUCCESSOR_EFFECTIVE_AT = ROOT_EFFECTIVE_AT + timedelta(seconds=1)
BOUNDARY_PROFILE_ID = UUID("00000000-0000-5000-8000-000000000094")
BOUNDARY_VIEW_ID = "00000000-0000-5000-8000-000000000095"
BOUNDARY_REPOSITORY_ID = 5192
BOUNDARY_PULL_NUMBER = 92
BOUNDARY_PULL_REQUEST_ID = 9_192
BOUNDARY_TARGET = RepositoryTarget(
    "recorded-owner",
    "recorded-repository",
    BOUNDARY_PULL_NUMBER,
)
REPLAY_PROFILE_ID = UUID("00000000-0000-5000-8000-000000000096")
REPLAY_VIEW_ID = "00000000-0000-5000-8000-000000000097"
REPLAY_REPOSITORY_ID = 5193
REPLAY_PULL_NUMBER = 93
REPLAY_PULL_REQUEST_ID = 9_193
REPLAY_TARGET = RepositoryTarget(
    "replay-owner",
    "replay-repository",
    REPLAY_PULL_NUMBER,
)
REPLAY_SEALED_AT = ROOT_EFFECTIVE_AT + timedelta(seconds=2)
CONFIGURATION = digest_payload({"api_version": "2026-03-10", "per_page": 100})


class FixedClock:
    def __init__(self, value: datetime) -> None:
        self._value = value

    def now(self) -> datetime:
        return self._value


class FixedAcquisition:
    def __init__(
        self,
        target: RepositoryTarget,
        result: CoherentAcquisitionResult,
    ) -> None:
        self._target = target
        self._result = result

    def acquire(self, target: RepositoryTarget) -> CoherentAcquisitionResult:
        assert target == self._target
        return self._result


def _acquisition(
    *,
    repository_id: int,
    pull_number: int,
    pull_request_id: int,
    view_id: str,
    evidence_sealed_at: datetime,
) -> CoherentAcquisitionResult:
    anchor = PullRequestAnchor(
        repository_id=repository_id,
        pull_number=pull_number,
        pull_request_id=pull_request_id,
        head_sha="a" * 40,
        base_repository_id=repository_id,
        base_ref="main",
        base_sha="b" * 40,
        state="open",
        draft=False,
        updated_at=evidence_sealed_at,
        changed_files=0,
        commit_count=0,
    )
    requested_reviewers = RequestedReviewers()
    facet_payloads: dict[str, object] = {
        "files": [],
        "commits": [],
        "reviews": [],
        "requested_reviewers": requested_reviewers.as_mapping(),
        "check_suite_count": 0,
        "check_runs": [],
        "commit_statuses": [],
    }
    facet_envelopes = {
        role: envelope_payload(payload) for role, payload in facet_payloads.items()
    }
    semantic_payloads = {"anchor": anchor.as_mapping(), **facet_payloads}
    semantic_digests = {
        role: envelope_payload(semantic_payloads[role]).digest.value
        for role in SEMANTIC_FACETS
    }
    view = CoherentAnalysisView(
        analysis_view_id=view_id,
        anchor=anchor,
        files=(),
        commits=(),
        files_digest=semantic_digests["files"],
        commits_digest=semantic_digests["commits"],
        requested_reviewers=requested_reviewers,
        check_suite_count=0,
        check_runs=(),
        commit_statuses=(),
        reviews=(),
        acquisition_configuration_digest=CONFIGURATION.value,
        evidence_sealed_at=evidence_sealed_at,
        raw_digest_inventory={"recorded": ("c" * 64,)},
        semantic_digest_inventory=semantic_digests,
    )
    return CoherentAcquisitionResult(
        view=view,
        view_envelope=envelope_payload(view.as_mapping()),
        attempts=1,
        facet_envelopes=facet_envelopes,
    )


def _profile(
    *,
    profile_id: UUID,
    repository_id: int,
    version: int,
    effective_from: datetime,
) -> PreparednessProfile:
    return PreparednessProfile(
        profile_id=profile_id,
        version=version,
        repository_id=repository_id,
        required_checks=(),
        required_statuses=(),
        block_on_changes_requested=True,
        acquisition_configuration_digest=CONFIGURATION,
        effective_from=effective_from,
        predecessor=None if version == 1 else ProfileIdentity(profile_id, version - 1),
    )


def _expected_identity(
    repository_id: int,
    pull_number: int,
    pull_request_id: int,
) -> PullRequestIdentity:
    return PullRequestIdentity(
        repository_id=repository_id,
        pull_request_id=pull_request_id,
        pull_number=pull_number,
        head_sha="a" * 40,
        base_repository_id=repository_id,
        base_ref="main",
        base_sha="b" * 40,
    )


def test_explicit_predecessor_at_successor_boundary_persists_indeterminate(
    postgres_engine: Engine,
) -> None:
    pipeline = DeterministicPreparednessPipeline(
        acquisition=FixedAcquisition(
            BOUNDARY_TARGET,
            _acquisition(
                repository_id=BOUNDARY_REPOSITORY_ID,
                pull_number=BOUNDARY_PULL_NUMBER,
                pull_request_id=BOUNDARY_PULL_REQUEST_ID,
                view_id=BOUNDARY_VIEW_ID,
                evidence_sealed_at=SUCCESSOR_EFFECTIVE_AT,
            ),
        ),
        unit_of_work_factory=lambda: PostgresUnitOfWork(postgres_engine),
        evaluation_clock=FixedClock(SUCCESSOR_EFFECTIVE_AT),
        envelope_factory=envelope_payload,
    )
    predecessor = pipeline.register_profile(
        _profile(
            profile_id=BOUNDARY_PROFILE_ID,
            repository_id=BOUNDARY_REPOSITORY_ID,
            version=1,
            effective_from=ROOT_EFFECTIVE_AT,
        )
    ).identity
    pipeline.register_profile(
        _profile(
            profile_id=BOUNDARY_PROFILE_ID,
            repository_id=BOUNDARY_REPOSITORY_ID,
            version=2,
            effective_from=SUCCESSOR_EFFECTIVE_AT,
        )
    )

    result = pipeline.assess(
        target=BOUNDARY_TARGET,
        expected_identity=_expected_identity(
            BOUNDARY_REPOSITORY_ID,
            BOUNDARY_PULL_NUMBER,
            BOUNDARY_PULL_REQUEST_ID,
        ),
        profile_identity=predecessor,
    )

    assert result.assessment is not None
    assert result.assessment.verdict is PreparednessVerdict.INDETERMINATE
    assert result.assessment.reason_codes == (
        PreparednessReasonCode.PROFILE_NOT_APPLICABLE,
    )
    assert result.assessment_id is not None
    with postgres_engine.connect() as connection:
        persisted = (
            connection.execute(
                sa.select(
                    preparedness_assessment.c.verdict,
                    preparedness_assessment.c.canonical_payload,
                ).where(preparedness_assessment.c.assessment_id == result.assessment_id)
            )
            .mappings()
            .one()
        )
    assert persisted["verdict"] == PreparednessVerdict.INDETERMINATE.value
    assert persisted["canonical_payload"]["reason_codes"] == [
        PreparednessReasonCode.PROFILE_NOT_APPLICABLE.value
    ]


def test_exact_pipeline_replay_is_idempotent_and_does_not_increment_pointer(
    postgres_engine: Engine,
) -> None:
    acquired = _acquisition(
        repository_id=REPLAY_REPOSITORY_ID,
        pull_number=REPLAY_PULL_NUMBER,
        pull_request_id=REPLAY_PULL_REQUEST_ID,
        view_id=REPLAY_VIEW_ID,
        evidence_sealed_at=REPLAY_SEALED_AT,
    )
    pipeline = DeterministicPreparednessPipeline(
        acquisition=FixedAcquisition(REPLAY_TARGET, acquired),
        unit_of_work_factory=lambda: PostgresUnitOfWork(postgres_engine),
        evaluation_clock=FixedClock(REPLAY_SEALED_AT),
        envelope_factory=envelope_payload,
    )
    profile = pipeline.register_profile(
        _profile(
            profile_id=REPLAY_PROFILE_ID,
            repository_id=REPLAY_REPOSITORY_ID,
            version=1,
            effective_from=ROOT_EFFECTIVE_AT,
        )
    ).identity
    expected = _expected_identity(
        REPLAY_REPOSITORY_ID,
        REPLAY_PULL_NUMBER,
        REPLAY_PULL_REQUEST_ID,
    )

    first = pipeline.assess(
        target=REPLAY_TARGET,
        expected_identity=expected,
        profile_identity=profile,
    )
    second = pipeline.assess(
        target=REPLAY_TARGET,
        expected_identity=expected,
        profile_identity=profile,
    )

    assert first.pointer_outcome is PointerPromotionOutcome.POINTER_ADVANCED
    assert second.pointer_outcome is PointerPromotionOutcome.POINTER_REPLAY_NOOP
    assert first.assessment_id == second.assessment_id
    assert first.assessment_id is not None
    entity_id = f"{REPLAY_REPOSITORY_ID}:{REPLAY_PULL_NUMBER}"
    with postgres_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(canonical_observation)
                .where(
                    canonical_observation.c.entity_kind == "github_pull_request",
                    canonical_observation.c.entity_id == entity_id,
                )
            )
            == 9
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(analysis_view)
                .where(analysis_view.c.analysis_view_id == REPLAY_VIEW_ID)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(analysis_view_observation)
                .where(analysis_view_observation.c.analysis_view_id == REPLAY_VIEW_ID)
            )
            == 9
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(preparedness_assessment)
                .where(preparedness_assessment.c.assessment_id == first.assessment_id)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(preparedness_assessment_evidence)
                .where(
                    preparedness_assessment_evidence.c.assessment_id
                    == first.assessment_id
                )
            )
            == 9
        )
        assert (
            connection.scalar(
                sa.select(current_observation_pointer.c.pointer_version).where(
                    current_observation_pointer.c.entity_kind == "github_pull_request",
                    current_observation_pointer.c.entity_id == entity_id,
                )
            )
            == 0
        )
