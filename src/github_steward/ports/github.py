"""Project-owned port for public GitHub reads."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from github_steward.domain.acquisition import CoherentAnalysisView, RepositoryTarget
from github_steward.domain.canonical import CanonicalEnvelope
from github_steward.domain.preparedness import PreparednessReasonCode
from github_steward.ports.persistence import DeliveryIngressResult


@dataclass(frozen=True, slots=True)
class GitHubResponse:
    """Validated JSON response plus authoritative raw-body provenance."""

    value: object
    raw_sha256: str
    next_url: str | None
    path: str


@dataclass(frozen=True, slots=True)
class RequestAudit:
    """Credential-free request fact suitable for evidence."""

    method: str
    host: str
    path: str
    classification: str
    scheme: str = "https"
    port_classification: str = "default_https"
    query: tuple[tuple[str, str], ...] = ()
    application_headers: tuple[str, ...] = ()
    credentials_absent: bool = True
    raw_response_sha256: str | None = None
    raw_target: str = ""
    endpoint_kind: str = ""
    semantic_identity: tuple[tuple[str, str], ...] = ()
    current_page: int = 1
    next_page: int | None = None


class GitHubReadPort(Protocol):
    """Only the operation required by GS-I3; no mutation surface exists."""

    @property
    def audit(self) -> tuple[RequestAudit, ...]: ...

    def get(self, path_or_url: str) -> GitHubResponse: ...


class DecodedMappingIntake(Protocol):
    """Existing GS-I2 decoded-mapping durable intake shape."""

    def receive(
        self, *, provider_delivery_id: str, mapping: Mapping[str, object]
    ) -> DeliveryIngressResult: ...


class EvidenceFacet(StrEnum):
    """The complete, fixed GS-I4 coherent-acquisition facet inventory."""

    FILES = "files"
    COMMITS = "commits"
    REVIEWS = "reviews"
    REQUESTED_REVIEWERS = "requested_reviewers"
    CHECK_SUITE_COUNT = "check_suite_count"
    CHECK_RUNS = "check_runs"
    COMMIT_STATUSES = "commit_statuses"


@dataclass(frozen=True, slots=True)
class RecordedGitHubResponse:
    """One already-recorded response and its bounded provenance."""

    value: object
    raw_sha256: str
    response_bytes: int


@dataclass(frozen=True, slots=True)
class RecordedFacet:
    """One complete recorded facet, independent of pagination boundaries."""

    value: object
    raw_responses: tuple[RecordedGitHubResponse, ...]
    total_count: int | None = None
    complete: bool = True


class RecordedGitHubEvidencePort(Protocol):
    """Read-only recorded/fake evidence; no live client or mutation surface."""

    def read_anchor(self, target: RepositoryTarget) -> RecordedGitHubResponse:
        """Return one pull-request anchor read."""

    def read_facet(
        self,
        target: RepositoryTarget,
        *,
        head_sha: str,
        facet: EvidenceFacet,
    ) -> RecordedFacet:
        """Return one complete exact-head facet acquisition."""


class CoherentAcquisitionFailure(RuntimeError):
    """A precise fail-closed acquisition outcome safe for assessment reporting."""

    def __init__(self, reason: PreparednessReasonCode, message: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class CoherentAcquisitionResult:
    """One sealed coherent analysis view plus deterministic digest evidence."""

    view: CoherentAnalysisView
    view_envelope: CanonicalEnvelope
    attempts: int
    facet_envelopes: Mapping[str, CanonicalEnvelope]


class CoherentAcquisitionPort(Protocol):
    """Application-facing bounded coherent-acquisition result."""

    def acquire(self, target: RepositoryTarget) -> CoherentAcquisitionResult:
        """Return one coherent view or raise CoherentAcquisitionFailure."""
