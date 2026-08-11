"""Deterministic GS-I4 profile registration, assessment, and persistence."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Final, cast
from uuid import UUID, uuid5

from github_steward.domain.acquisition import COHERENT_ATTEMPTS, RepositoryTarget
from github_steward.domain.canonical import CanonicalEnvelope, CanonicalValue, Digest
from github_steward.domain.errors import CanonicalizationError
from github_steward.domain.github_evidence import (
    SEMANTIC_FACETS,
    CoherentAnalysisView,
    SourceOrderRelation,
    compare_source_order,
)
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
    PullRequestIdentity,
    ReviewEvidence,
    assess_preparedness,
    preparedness_assessment_id,
)
from github_steward.domain.processing import github_work_subject, require_utc_datetime
from github_steward.ports.clock import Clock
from github_steward.ports.github_evidence import (
    CoherentAcquisitionFailure,
    CoherentAcquisitionPort,
    CoherentAcquisitionResult,
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

    identity: ProfileIdentity
    digest: Digest


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
            payload=envelope.payload,
            digest=envelope.digest,
        )
        with self._unit_of_work_factory() as unit:
            unit.profiles.insert(record)
            unit.commit()
        return ProfileRegistrationResult(profile.identity, envelope.digest)

    def assess(
        self,
        *,
        target: RepositoryTarget,
        expected_identity: PullRequestIdentity,
        profile_identity: ProfileIdentity,
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
                profile_identity,
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
                    analysis_view_id=view_record.view_id,
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
        identity: ProfileIdentity,
    ) -> tuple[PreparednessProfile, datetime | None]:
        record = unit.profiles.get(
            profile_id=PreparednessProfileId(str(identity.profile_id)),
            version=identity.version,
        )
        successor = unit.profiles.get_successor(
            profile_id=PreparednessProfileId(str(identity.profile_id)),
            version=identity.version,
        )
        if record is None:
            raise ValueError("exact preparedness profile identity was not persisted")
        calculated = self._envelope_factory(record.payload)
        if calculated.digest != record.digest:
            raise ValueError("persisted preparedness profile digest did not verify")
        profile = PreparednessProfile.from_mapping(
            cast(Mapping[str, object], record.payload)
        )
        if profile.identity != identity:
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
