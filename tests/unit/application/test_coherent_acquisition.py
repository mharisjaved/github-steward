"""Offline bounded coherent-acquisition orchestration tests."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

import github_steward.application.coherent_acquisition as coherent_acquisition
from github_steward.adapters.canonicalization.rfc8785 import (
    digest_payload,
    envelope_payload,
)
from github_steward.application.coherent_acquisition import (
    CoherentRecordedAcquisitionService,
)
from github_steward.domain.acquisition import (
    MAX_CHECK_SUITES,
    MAX_FILES,
    MAX_PAGES,
    MAX_RESPONSE_BYTES,
    PER_PAGE,
    AcquisitionError,
    AcquisitionOutcome,
    RepositoryTarget,
)
from github_steward.domain.canonical import Digest
from github_steward.domain.preparedness import PreparednessReasonCode
from github_steward.ports.github_evidence import (
    CoherentAcquisitionFailure,
    EvidenceFacet,
    RecordedFacet,
    RecordedGitHubEvidencePort,
    RecordedGitHubResponse,
)

NOW = datetime(2026, 8, 11, 12, 30, tzinfo=UTC)
TARGET = RepositoryTarget("Harry5174", "github-steward", 4)
HEAD = "a" * 40
BASE = "b" * 40


class FakeClock:
    def __init__(self, value: datetime) -> None:
        self.value = value
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        return self.value


def _response(value: object, label: str, *, size: int = 100) -> RecordedGitHubResponse:
    return RecordedGitHubResponse(
        value,
        hashlib.sha256(label.encode()).hexdigest(),
        size,
    )


def _anchor(
    *,
    head_sha: str = HEAD,
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
            "sha": BASE,
            "repo": {"id": 77, "full_name": "Harry5174/github-steward"},
        },
    }


def _facet_value(facet: EvidenceFacet, *, status_state: str = "success") -> object:
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
        return [{"sha": HEAD, "ignored_display_field": "safe"}]
    if facet is EvidenceFacet.REVIEWS:
        return [
            {
                "id": 1,
                "user": {"id": 9, "login": "reviewer"},
                "commit_id": HEAD,
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
                "head_sha": HEAD,
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
            "sha": HEAD,
            "context": "CI/Test",
            "state": status_state,
            "updated_at": "2026-08-11T11:58:00Z",
        }
    ]


def _total(facet: EvidenceFacet) -> int | None:
    return {
        EvidenceFacet.FILES: 1,
        EvidenceFacet.COMMITS: 1,
        EvidenceFacet.REVIEWS: 1,
        EvidenceFacet.REQUESTED_REVIEWERS: None,
        EvidenceFacet.CHECK_SUITE_COUNT: 1,
        EvidenceFacet.CHECK_RUNS: 1,
        EvidenceFacet.COMMIT_STATUSES: 1,
    }[facet]


def _recorded_facet(
    facet: EvidenceFacet,
    *,
    status_state: str = "success",
    complete: bool = True,
    total: int | None = None,
    response_size: int = 100,
    label: str | None = None,
) -> RecordedFacet:
    value = _facet_value(facet, status_state=status_state)
    return RecordedFacet(
        value,
        (_response(value, label or facet.value, size=response_size),),
        _total(facet) if total is None else total,
        complete,
    )


class FakeEvidence:
    def __init__(
        self,
        anchors: list[dict[str, object]],
        facets: dict[EvidenceFacet, list[RecordedFacet]],
    ) -> None:
        self.anchors = list(anchors)
        self.facets = {key: list(values) for key, values in facets.items()}
        self.calls: list[str] = []

    def read_anchor(self, target: RepositoryTarget) -> RecordedGitHubResponse:
        assert target == TARGET
        self.calls.append("anchor")
        if not self.anchors:
            raise AssertionError("partial failed attempt was reused")
        return _response(self.anchors.pop(0), f"anchor-{len(self.calls)}")

    def read_facet(
        self,
        target: RepositoryTarget,
        *,
        head_sha: str,
        facet: EvidenceFacet,
    ) -> RecordedFacet:
        assert target == TARGET
        assert head_sha == HEAD
        self.calls.append(facet.value)
        values = self.facets[facet]
        if not values:
            raise AssertionError("partial failed attempt was reused")
        return values.pop(0)


def _fake(
    *,
    anchors: list[dict[str, object]] | None = None,
    overrides: dict[EvidenceFacet, list[RecordedFacet]] | None = None,
    passes: int = 2,
) -> FakeEvidence:
    facets = {
        facet: [
            _recorded_facet(facet, label=f"{facet.value}-{index}")
            for index in range(passes)
        ]
        for facet in EvidenceFacet
    }
    facets.update(overrides or {})
    return FakeEvidence(anchors or [_anchor(), _anchor(), _anchor()], facets)


def _service(
    fake: RecordedGitHubEvidencePort,
    clock: FakeClock,
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


class FailingEvidence:
    def __init__(self, outcome: AcquisitionOutcome) -> None:
        self.outcome = outcome
        self.anchor_calls = 0

    def read_anchor(self, target: RepositoryTarget) -> RecordedGitHubResponse:
        assert target == TARGET
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
    fake = _fake()
    clock = FakeClock(NOW)
    result = _service(fake, clock).acquire(TARGET)
    pass_calls = [facet.value for facet in EvidenceFacet]
    assert fake.calls == ["anchor", *pass_calls, "anchor", *pass_calls, "anchor"]
    assert result.attempts == 1
    assert result.view.evidence_sealed_at == NOW
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
        _recorded_facet(EvidenceFacet.COMMIT_STATUSES, status_state="success"),
        _recorded_facet(EvidenceFacet.COMMIT_STATUSES, status_state="pending"),
        _recorded_facet(EvidenceFacet.COMMIT_STATUSES, status_state="success"),
        _recorded_facet(EvidenceFacet.COMMIT_STATUSES, status_state="success"),
    ]
    fake = _fake(
        anchors=[_anchor() for _ in range(6)],
        overrides={EvidenceFacet.COMMIT_STATUSES: status_values},
        passes=4,
    )
    clock = FakeClock(NOW)
    result = _service(fake, clock).acquire(TARGET)
    assert result.attempts == 2
    assert fake.calls.count("anchor") == 6
    assert all(fake.calls.count(facet.value) == 4 for facet in EvidenceFacet)
    assert clock.calls == 1


def test_semantically_equal_status_passes_ignore_acquisition_order() -> None:
    first = cast(list[object], _facet_value(EvidenceFacet.COMMIT_STATUSES))
    second_status = {
        "id": 16,
        "sha": HEAD,
        "context": "lint",
        "state": "success",
        "updated_at": "2026-08-11T11:59:00Z",
    }
    forward = [*first, second_status]
    reverse = list(reversed(forward))
    fake = _fake(
        overrides={
            EvidenceFacet.COMMIT_STATUSES: [
                RecordedFacet(forward, (_response(forward, "forward"),), 2, True),
                RecordedFacet(reverse, (_response(reverse, "reverse"),), 2, True),
            ]
        }
    )

    result = _service(fake, FakeClock(NOW)).acquire(TARGET)

    assert [item.context_key for item in result.view.commit_statuses] == [
        "ci/test",
        "lint",
    ]


def test_semantically_equal_file_passes_ignore_acquisition_order() -> None:
    first = cast(list[object], _facet_value(EvidenceFacet.FILES))
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
        anchor = _anchor()
        anchor["changed_files"] = 2
        anchors.append(anchor)
    fake = _fake(
        anchors=anchors,
        overrides={
            EvidenceFacet.FILES: [
                RecordedFacet(forward, (_response(forward, "files-forward"),), 2, True),
                RecordedFacet(reverse, (_response(reverse, "files-reverse"),), 2, True),
            ]
        },
    )

    result = _service(fake, FakeClock(NOW)).acquire(TARGET)

    assert [item.filename for item in result.view.files] == ["src/a.py", "src/b.py"]


def test_two_incoherent_whole_attempts_fail_unstable_without_sealing() -> None:
    status_values = [
        _recorded_facet(
            EvidenceFacet.COMMIT_STATUSES,
            status_state="success" if index % 2 == 0 else "pending",
        )
        for index in range(4)
    ]
    fake = _fake(
        anchors=[_anchor() for _ in range(6)],
        overrides={EvidenceFacet.COMMIT_STATUSES: status_values},
        passes=4,
    )
    clock = FakeClock(NOW)
    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _service(fake, clock).acquire(TARGET)
    assert raised.value.reason is PreparednessReasonCode.EVIDENCE_UNSTABLE
    assert fake.calls.count("anchor") == 6
    assert clock.calls == 0


def test_anchor_a_b_c_mismatch_retries_and_uses_new_attempt_only() -> None:
    changed = _anchor(draft=True)
    fake = _fake(
        anchors=[_anchor(), changed, changed, _anchor(), _anchor(), _anchor()],
        passes=4,
    )
    result = _service(fake, FakeClock(NOW)).acquire(TARGET)
    assert result.attempts == 2
    assert not result.view.anchor.draft


@pytest.mark.parametrize(
    ("facet", "recorded", "reason"),
    [
        (
            EvidenceFacet.FILES,
            _recorded_facet(EvidenceFacet.FILES, complete=False),
            PreparednessReasonCode.EVIDENCE_PAGINATION_UNCERTAIN,
        ),
        (
            EvidenceFacet.FILES,
            _recorded_facet(EvidenceFacet.FILES, total=2),
            PreparednessReasonCode.EVIDENCE_TOTAL_COUNT_INCONSISTENT,
        ),
        (
            EvidenceFacet.FILES,
            _recorded_facet(EvidenceFacet.FILES, response_size=MAX_RESPONSE_BYTES + 1),
            PreparednessReasonCode.EVIDENCE_CAP_EXCEEDED,
        ),
        (
            EvidenceFacet.REVIEWS,
            RecordedFacet(
                [],
                (_response([], "reviews-total"),),
                1,
                True,
            ),
            PreparednessReasonCode.EVIDENCE_TOTAL_COUNT_INCONSISTENT,
        ),
        (
            EvidenceFacet.COMMIT_STATUSES,
            RecordedFacet(
                [],
                (_response([], "statuses-total"),),
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
    fake = _fake(overrides={facet: [recorded]})
    clock = FakeClock(NOW)
    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _service(fake, clock).acquire(TARGET)
    assert raised.value.reason is reason
    assert clock.calls == 0


def test_seal_time_is_digest_bearing_view_material() -> None:
    first = _service(_fake(), FakeClock(NOW)).acquire(TARGET)
    second = _service(_fake(), FakeClock(NOW + timedelta(microseconds=1))).acquire(
        TARGET
    )
    assert first.view.analysis_view_id != second.view.analysis_view_id
    assert first.view_envelope.digest != second.view_envelope.digest


def test_view_identity_binds_configuration_and_raw_provenance() -> None:
    baseline = _service(_fake(), FakeClock(NOW)).acquire(TARGET)
    changed_configuration = _service(
        _fake(),
        FakeClock(NOW),
        configuration_digest=digest_payload({"configuration": "different"}),
    ).acquire(TARGET)
    changed_raw = _service(
        _fake(
            overrides={
                EvidenceFacet.FILES: [
                    _recorded_facet(EvidenceFacet.FILES, label="changed-raw-1"),
                    _recorded_facet(EvidenceFacet.FILES, label="changed-raw-2"),
                ]
            }
        ),
        FakeClock(NOW),
    ).acquire(TARGET)

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
            head_sha=HEAD,
            evidence_sealed_at=NOW,
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
    recorded = RecordedFacet(value, (_response(value, "requested"),), None, True)
    fake = _fake(overrides={EvidenceFacet.REQUESTED_REVIEWERS: [recorded]})
    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _service(fake, FakeClock(NOW)).acquire(TARGET)
    assert raised.value.reason is PreparednessReasonCode.REQUESTED_REVIEWER_AMBIGUITY


def test_anchor_count_mismatch_is_precise_uncertainty() -> None:
    fake = _fake(anchors=[_anchor(), _anchor(), _anchor()])
    fake.anchors[0]["changed_files"] = 2
    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _service(fake, FakeClock(NOW)).acquire(TARGET)
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
    evidence = FailingEvidence(outcome)
    clock = FakeClock(NOW)

    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _service(evidence, clock).acquire(TARGET)

    assert raised.value.reason is reason
    assert evidence.anchor_calls == 1
    assert clock.calls == 0


def test_internal_semantic_inventory_guard_prevents_sealing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _fake()
    clock = FakeClock(NOW)
    monkeypatch.setattr(
        coherent_acquisition,
        "SEMANTIC_FACETS",
        tuple(facet.value for facet in EvidenceFacet),
    )

    with pytest.raises(RuntimeError, match="semantic facet inventory"):
        _service(fake, clock).acquire(TARGET)

    assert clock.calls == 1
    assert fake.calls.count("anchor") == 3


def test_anchor_commit_count_mismatch_is_precise_uncertainty() -> None:
    anchor = _anchor()
    anchor["commits"] = 2
    fake = _fake(anchors=[anchor, _anchor(), _anchor()])

    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _service(fake, FakeClock(NOW)).acquire(TARGET)

    assert (
        raised.value.reason is PreparednessReasonCode.EVIDENCE_TOTAL_COUNT_INCONSISTENT
    )


def test_exact_response_byte_ceiling_is_accepted() -> None:
    facets = [
        _recorded_facet(EvidenceFacet.FILES, response_size=MAX_RESPONSE_BYTES),
        _recorded_facet(EvidenceFacet.FILES, response_size=MAX_RESPONSE_BYTES),
    ]
    result = _service(
        _fake(overrides={EvidenceFacet.FILES: facets}),
        FakeClock(NOW),
    ).acquire(TARGET)
    assert result.attempts == 1


@pytest.mark.parametrize(
    ("raw_responses", "reason"),
    [
        (
            (
                RecordedGitHubResponse(
                    _facet_value(EvidenceFacet.FILES),
                    "malformed",
                    100,
                ),
            ),
            PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE,
        ),
        (
            (
                RecordedGitHubResponse(
                    _facet_value(EvidenceFacet.FILES),
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
                    _facet_value(EvidenceFacet.FILES),
                    hashlib.sha256(b"bool-size").hexdigest(),
                    cast(int, True),
                ),
            ),
            PreparednessReasonCode.EVIDENCE_CAP_EXCEEDED,
        ),
        (
            (
                RecordedGitHubResponse(
                    _facet_value(EvidenceFacet.FILES),
                    hashlib.sha256(b"negative-size").hexdigest(),
                    -1,
                ),
            ),
            PreparednessReasonCode.EVIDENCE_CAP_EXCEEDED,
        ),
        ((), PreparednessReasonCode.EVIDENCE_PAGINATION_UNCERTAIN),
        (
            tuple(
                _response(_facet_value(EvidenceFacet.FILES), f"page-{page}")
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
    value = _facet_value(EvidenceFacet.FILES)
    recorded = RecordedFacet(value, raw_responses, 1, True)
    fake = _fake(overrides={EvidenceFacet.FILES: [recorded]})

    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _service(fake, FakeClock(NOW)).acquire(TARGET)

    assert raised.value.reason is reason


@pytest.mark.parametrize("invalid_total", [True, -1, 1.5, "1"])
def test_invalid_remote_total_count_fails_closed(invalid_total: object) -> None:
    value = _facet_value(EvidenceFacet.FILES)
    recorded = RecordedFacet(
        value,
        (_response(value, "invalid-total"),),
        cast(int, invalid_total),
        True,
    )

    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _service(
            _fake(overrides={EvidenceFacet.FILES: [recorded]}),
            FakeClock(NOW),
        ).acquire(TARGET)

    assert (
        raised.value.reason is PreparednessReasonCode.EVIDENCE_TOTAL_COUNT_INCONSISTENT
    )


@pytest.mark.parametrize(
    "recorded",
    [
        cast(RecordedFacet, object()),
        RecordedFacet(
            _facet_value(EvidenceFacet.FILES),
            cast(tuple[RecordedGitHubResponse, ...], []),
            1,
            True,
        ),
        RecordedFacet(
            _facet_value(EvidenceFacet.FILES),
            (_response(_facet_value(EvidenceFacet.FILES), "bad-complete"),),
            1,
            cast(bool, 1),
        ),
    ],
)
def test_malformed_recorded_facet_shapes_fail_closed(recorded: RecordedFacet) -> None:
    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _service(
            _fake(overrides={EvidenceFacet.FILES: [recorded]}),
            FakeClock(NOW),
        ).acquire(TARGET)

    assert raised.value.reason is PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE


def test_list_facet_cannot_exceed_recorded_page_capacity() -> None:
    item = cast(list[dict[str, object]], _facet_value(EvidenceFacet.FILES))[0]
    value = [deepcopy(item) for _ in range(PER_PAGE + 1)]
    recorded = RecordedFacet(
        value,
        (_response(value, "overfull-page"),),
        len(value),
        True,
    )

    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _service(
            _fake(overrides={EvidenceFacet.FILES: [recorded]}),
            FakeClock(NOW),
        ).acquire(TARGET)

    assert raised.value.reason is PreparednessReasonCode.EVIDENCE_PAGINATION_UNCERTAIN


def test_page_capacity_uses_raw_items_before_identity_deduplication() -> None:
    item = cast(
        list[dict[str, object]],
        _facet_value(EvidenceFacet.COMMIT_STATUSES),
    )[0]
    value = [deepcopy(item) for _ in range(PER_PAGE + 1)]
    recorded = RecordedFacet(
        value,
        (_response(value, "overfull-duplicate-status-page"),),
        1,
        True,
    )

    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _service(
            _fake(overrides={EvidenceFacet.COMMIT_STATUSES: [recorded]}),
            FakeClock(NOW),
        ).acquire(TARGET)

    assert raised.value.reason is PreparednessReasonCode.EVIDENCE_PAGINATION_UNCERTAIN


def test_facet_completeness_ceiling_fails_before_count_mismatch() -> None:
    recorded = _recorded_facet(EvidenceFacet.FILES, total=MAX_FILES + 1)
    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _service(
            _fake(overrides={EvidenceFacet.FILES: [recorded]}),
            FakeClock(NOW),
        ).acquire(TARGET)
    assert raised.value.reason is PreparednessReasonCode.EVIDENCE_CAP_EXCEEDED


def test_integer_check_suite_count_normalizes_and_seals() -> None:
    response = _response(1, "integer-suite-count")
    recorded = RecordedFacet(1, (response,), 1, True)
    fake = _fake(overrides={EvidenceFacet.CHECK_SUITE_COUNT: [recorded, recorded]})
    result = _service(fake, FakeClock(NOW)).acquire(TARGET)
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
    recorded = RecordedFacet(value, (_response(value, "suite-invalid"),), total, True)
    fake = _fake(overrides={EvidenceFacet.CHECK_SUITE_COUNT: [recorded]})
    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _service(fake, FakeClock(NOW)).acquire(TARGET)
    assert raised.value.reason is reason


@pytest.mark.parametrize(
    "facet", [EvidenceFacet.CHECK_RUNS, EvidenceFacet.COMMIT_STATUSES]
)
def test_exact_head_facet_mismatch_fails_closed(facet: EvidenceFacet) -> None:
    value = deepcopy(_facet_value(facet))
    item = cast(list[dict[str, object]], value)[0]
    if facet is EvidenceFacet.CHECK_RUNS:
        item["head_sha"] = "d" * 40
    else:
        item["sha"] = "d" * 40
    recorded = RecordedFacet(value, (_response(value, "wrong-head"),), 1, True)

    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _service(_fake(overrides={facet: [recorded]}), FakeClock(NOW)).acquire(TARGET)

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
    value = deepcopy(_facet_value(EvidenceFacet.REVIEWS))
    review = cast(list[dict[str, object]], value)[0]
    if route is None:
        review.pop("pull_request_url")
    else:
        review["pull_request_url"] = route
    recorded = RecordedFacet(value, (_response(value, "wrong-review-route"),), 1, True)

    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _service(
            _fake(overrides={EvidenceFacet.REVIEWS: [recorded]}),
            FakeClock(NOW),
        ).acquire(TARGET)

    assert raised.value.reason is PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE


def test_uncanonicalizable_evidence_text_maps_to_malformed_response() -> None:
    value = deepcopy(_facet_value(EvidenceFacet.COMMIT_STATUSES))
    cast(list[dict[str, object]], value)[0]["context"] = "\ud800"
    recorded = RecordedFacet(
        value,
        (_response(value, "uncanonicalizable-status"),),
        1,
        True,
    )

    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _service(
            _fake(overrides={EvidenceFacet.COMMIT_STATUSES: [recorded]}),
            FakeClock(NOW),
        ).acquire(TARGET)

    assert raised.value.reason is PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE


def test_fractional_github_timestamps_are_normalized() -> None:
    anchor = _anchor(updated_at="2026-08-11T12:00:00.123456Z")
    result = _service(
        _fake(anchors=[anchor, deepcopy(anchor), deepcopy(anchor)]),
        FakeClock(NOW),
    ).acquire(TARGET)
    assert result.view.anchor.updated_at.microsecond == 123456


def test_anchor_route_and_malformed_scalar_safety_fail_closed() -> None:
    wrong_route = _anchor()
    cast(dict[str, object], cast(dict[str, object], wrong_route["base"])["repo"])[
        "full_name"
    ] = "someone/else"
    wrong_number = _anchor()
    wrong_number["number"] = 5
    bad_draft = _anchor()
    bad_draft["draft"] = "false"
    bad_identifier = _anchor()
    bad_identifier["id"] = 0
    bad_count = _anchor()
    bad_count["changed_files"] = -1
    bad_sha = _anchor()
    cast(dict[str, object], bad_sha["head"])["sha"] = "A" * 40
    bad_time = _anchor(updated_at="not-a-timestamp")
    empty_name = _anchor()
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
        fake = _fake(anchors=cast(list[dict[str, object]], [value]))
        with pytest.raises(CoherentAcquisitionFailure) as raised:
            _service(fake, FakeClock(NOW)).acquire(TARGET)
        assert raised.value.reason is PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE


@pytest.mark.parametrize(
    "value",
    [
        {},
        [[]],
    ],
)
def test_malformed_file_collection_shapes_fail_closed(value: object) -> None:
    recorded = RecordedFacet(value, (_response(value, "bad-files"),), 1, True)
    with pytest.raises(CoherentAcquisitionFailure) as raised:
        _service(
            _fake(overrides={EvidenceFacet.FILES: [recorded]}),
            FakeClock(NOW),
        ).acquire(TARGET)
    assert raised.value.reason is PreparednessReasonCode.EVIDENCE_MALFORMED_RESPONSE
