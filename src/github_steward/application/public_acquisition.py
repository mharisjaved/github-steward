"""Two-pass public pull-request acquisition into the existing durable intake."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import NoReturn, cast

from github_steward.domain.acquisition import (
    API_VERSION,
    MAX_CHECK_RUNS,
    MAX_CHECK_SUITES,
    MAX_COMMITS,
    MAX_FILES,
    MAX_PAGES,
    SNAPSHOT_SCHEMA_ID,
    AcquisitionError,
    AcquisitionOutcome,
    RepositoryTarget,
    poll_delivery_identity,
    require_sha,
)
from github_steward.domain.canonical import CanonicalEnvelope
from github_steward.ports.github import (
    DecodedMappingIntake,
    GitHubReadPort,
    GitHubResponse,
    RequestAudit,
)

type EnvelopeFactory = Callable[[object], CanonicalEnvelope]


@dataclass(frozen=True, slots=True)
class AcquisitionResult:
    """Concise acquisition and durable-intake result."""

    outcome: AcquisitionOutcome
    repository: str
    pull_number: int
    head_sha: str
    snapshot_digest: str
    delivery_identity: str
    pagination: Mapping[str, int]
    durable_intake: str
    audit: tuple[RequestAudit, ...]

    def as_mapping(self) -> dict[str, object]:
        return {
            "outcome": self.outcome.value,
            "repository": self.repository,
            "pull_request_number": self.pull_number,
            "head_sha": self.head_sha,
            "snapshot_digest": self.snapshot_digest,
            "delivery_identity": self.delivery_identity,
            "pagination": dict(self.pagination),
            "completeness": "COMPLETE",
            "durable_intake": self.durable_intake,
        }


@dataclass(frozen=True, slots=True)
class _Anchor:
    repo_id: int
    repo_full_name: str
    pull_id: int
    number: int
    state: str
    draft: bool
    head_sha: str
    base_sha: str
    updated_at: str
    changed_files: int
    commits: int


@dataclass(frozen=True, slots=True)
class _Attempt:
    anchor: _Anchor
    snapshot: Mapping[str, object]
    counts: Mapping[str, int]


class PublicPullRequestAcquisitionService:
    """Acquire one complete, stable public PR and durably classify it."""

    def __init__(
        self,
        *,
        github: GitHubReadPort,
        receipt: DecodedMappingIntake,
        envelope_factory: EnvelopeFactory,
    ) -> None:
        self._github = github
        self._receipt = receipt
        self._envelope_factory = envelope_factory

    def acquire(self, target: RepositoryTarget) -> AcquisitionResult:
        stable: _Attempt | None = None
        for _ in range(2):
            attempted, same = self._attempt(target)
            if same:
                stable = attempted
                break
        if stable is None:
            raise AcquisitionError(
                AcquisitionOutcome.CONCURRENT_CHANGE,
                "pull request changed during both bounded acquisition attempts",
            )

        envelope = self._envelope_factory(stable.snapshot)
        digest = envelope.digest.value
        identity = poll_delivery_identity(
            stable.anchor.repo_id,
            stable.anchor.number,
            digest,
        )
        observed, sequence = _observation_time(stable.anchor.updated_at)
        observation = {
            "schema_id": SNAPSHOT_SCHEMA_ID,
            "schema_version": 1,
            "snapshot": envelope.as_mapping()["payload"],
            "snapshot_digest": dict(envelope.digest.as_mapping()),
        }
        try:
            durable = self._receipt.receive(
                provider_delivery_id=identity,
                mapping={
                    "entity_kind": "github_pull_request_snapshot",
                    "entity_id": f"{stable.anchor.repo_id}:{stable.anchor.number}",
                    "observed_at": observed,
                    "sequence": sequence,
                    "expected_pointer_version": None,
                    "observation": observation,
                },
            )
        except Exception as exc:
            raise AcquisitionError(
                AcquisitionOutcome.PERSISTENCE_FAILURE,
                "durable intake transaction failed",
            ) from exc
        return AcquisitionResult(
            outcome=AcquisitionOutcome.ACQUIRED,
            repository=stable.anchor.repo_full_name,
            pull_number=stable.anchor.number,
            head_sha=stable.anchor.head_sha,
            snapshot_digest=digest,
            delivery_identity=identity,
            pagination=stable.counts,
            durable_intake=durable.outcome.value,
            audit=self._github.audit,
        )

    def _attempt(self, target: RepositoryTarget) -> tuple[_Attempt, bool]:
        base = f"/repos/{target.owner}/{target.repository}"
        primary_path = f"{base}/pulls/{target.pull_number}"
        first_response = self._github.get(primary_path)
        first = _anchor(first_response.value, target)
        if first.changed_files > MAX_FILES:
            _unsupported("files", MAX_FILES)
        if first.commits > MAX_COMMITS:
            _unsupported("commits", MAX_COMMITS)

        files, file_pages = self._list_pages(
            f"{primary_path}/files?per_page=100", "files", MAX_FILES
        )
        commits, commit_pages = self._list_pages(
            f"{primary_path}/commits?per_page=100", "commits", MAX_COMMITS
        )
        reviews, review_pages = self._list_pages(
            f"{primary_path}/reviews?per_page=100", "reviews", None
        )
        check_suite_total, check_suite_response = self._check_suite_count(
            f"{base}/commits/{first.head_sha}/check-suites"
        )
        checks, check_pages, check_total = self._check_pages(
            f"{base}/commits/{first.head_sha}/check-runs?filter=latest&per_page=100"
        )
        if len(files) != first.changed_files:
            _incomplete("files count did not match pull-request metadata")
        if len(commits) != first.commits:
            _incomplete("commits count did not match pull-request metadata")
        if len(checks) != check_total:
            _incomplete("check-run total_count did not match pagination")
        _validate_collection_relationships(
            files=files,
            commits=commits,
            reviews=reviews,
            checks=checks,
            target=target,
            head_sha=first.head_sha,
        )

        second_response = self._github.get(primary_path)
        second = _anchor(second_response.value, target)
        responses = [
            _provenance("pull_request:first", first_response),
            *file_pages,
            *commit_pages,
            *review_pages,
            check_suite_response,
            *check_pages,
            _provenance("pull_request:second", second_response),
        ]
        counts = {
            "files": len(files),
            "commits": len(commits),
            "reviews": len(reviews),
            "check_suites": check_suite_total,
            "check_runs": len(checks),
            "responses": len(responses),
        }
        snapshot: Mapping[str, object] = {
            "schema_id": SNAPSHOT_SCHEMA_ID,
            "schema_version": 1,
            "source": {
                "provider": "github",
                "api_origin": "https://api.github.com",
                "api_version": API_VERSION,
                "authentication": "anonymous",
            },
            "repository": {
                "id": first.repo_id,
                "full_name": first.repo_full_name,
            },
            "pull_request": first_response.value,
            "identity": {
                "id": first.pull_id,
                "number": first.number,
                "head_sha": first.head_sha,
                "base_sha": first.base_sha,
            },
            "collections": {
                "files": files,
                "commits": commits,
                "reviews": reviews,
                "check_runs": checks,
            },
            "completeness": {"status": "COMPLETE", "counts": counts},
            "raw_responses": responses,
        }
        return _Attempt(first, snapshot, counts), first == second

    def _list_pages(
        self,
        path: str,
        name: str,
        maximum: int | None,
    ) -> tuple[list[object], list[Mapping[str, str]]]:
        items: list[object] = []
        provenance: list[Mapping[str, str]] = []
        seen: set[str] = set()
        current: str | None = path
        while current is not None:
            if current in seen or len(provenance) >= MAX_PAGES:
                _incomplete(f"{name} pagination was cyclic or exceeded page bound")
            seen.add(current)
            response = self._github.get(current)
            page = _list(response.value, name)
            items.extend(page)
            provenance.append(_provenance(name, response))
            if maximum is not None and len(items) > maximum:
                _unsupported(name, maximum)
            current = response.next_url
        return items, provenance

    def _check_suite_count(self, path: str) -> tuple[int, Mapping[str, str]]:
        response = self._github.get(path)
        body = _mapping(response.value, "check-suite response")
        total = _integer(body, "total_count", minimum=0)
        _list(body.get("check_suites"), "check_suites")
        if total > MAX_CHECK_SUITES:
            _unsupported("check_suites", MAX_CHECK_SUITES)
        return total, _provenance("check_suites", response)

    def _check_pages(
        self, path: str
    ) -> tuple[list[object], list[Mapping[str, str]], int]:
        items: list[object] = []
        provenance: list[Mapping[str, str]] = []
        total: int | None = None
        seen: set[str] = set()
        current: str | None = path
        while current is not None:
            if current in seen or len(provenance) >= MAX_PAGES:
                _incomplete("check-run pagination was cyclic or exceeded page bound")
            seen.add(current)
            response = self._github.get(current)
            body = _mapping(response.value, "check-run response")
            page_total = _integer(body, "total_count", minimum=0)
            if page_total > MAX_CHECK_RUNS:
                _unsupported("check_runs", MAX_CHECK_RUNS)
            if total is not None and page_total != total:
                _incomplete("check-run total_count changed between pages")
            total = page_total
            items.extend(_list(body.get("check_runs"), "check_runs"))
            if len(items) > MAX_CHECK_RUNS:
                _unsupported("check_runs", MAX_CHECK_RUNS)
            provenance.append(_provenance("check_runs", response))
            current = response.next_url
        return items, provenance, total or 0


def _anchor(value: object, target: RepositoryTarget) -> _Anchor:
    body = _mapping(value, "pull-request response")
    base = _mapping(body.get("base"), "base")
    head = _mapping(body.get("head"), "head")
    repository = _mapping(base.get("repo"), "base.repo")
    repo_id = _integer(repository, "id", minimum=1)
    full_name = _string(repository, "full_name")
    number = _integer(body, "number", minimum=1)
    if (
        full_name.casefold() != target.full_name.casefold()
        or number != target.pull_number
    ):
        raise AcquisitionError(
            AcquisitionOutcome.MALFORMED_RESPONSE,
            "GitHub response identity did not match requested pull request",
        )
    draft = body.get("draft")
    if not isinstance(draft, bool):
        _malformed("draft must be a boolean")
    updated_at = _string(body, "updated_at")
    _observation_time(updated_at)
    return _Anchor(
        repo_id=repo_id,
        repo_full_name=full_name,
        pull_id=_integer(body, "id", minimum=1),
        number=number,
        state=_string(body, "state"),
        draft=draft,
        head_sha=require_sha(head.get("sha"), "head.sha"),
        base_sha=require_sha(base.get("sha"), "base.sha"),
        updated_at=updated_at,
        changed_files=_integer(body, "changed_files", minimum=0),
        commits=_integer(body, "commits", minimum=0),
    )


def _validate_collection_relationships(
    *,
    files: list[object],
    commits: list[object],
    reviews: list[object],
    checks: list[object],
    target: RepositoryTarget,
    head_sha: str,
) -> None:
    for item in files:
        file = _mapping(item, "file item")
        require_sha(file.get("sha"), "file.sha")
        _string(file, "filename")
        _string(file, "status")
        _integer(file, "additions", minimum=0)
        _integer(file, "deletions", minimum=0)
        _integer(file, "changes", minimum=0)
    for item in commits:
        require_sha(_mapping(item, "commit item").get("sha"), "commit.sha")
    suffix = f"/repos/{target.owner}/{target.repository}/pulls/{target.pull_number}"
    for item in reviews:
        review = _mapping(item, "review item")
        _integer(review, "id", minimum=1)
        _string(review, "state")
        url = review.get("pull_request_url")
        if url is not None and (not isinstance(url, str) or not url.endswith(suffix)):
            _malformed("review pull_request_url did not match requested pull request")
        commit_id = review.get("commit_id")
        if commit_id is not None:
            require_sha(commit_id, "review.commit_id")
    for item in checks:
        check = _mapping(item, "check-run item")
        _integer(check, "id", minimum=1)
        _string(check, "name")
        _string(check, "status")
        if require_sha(check.get("head_sha"), "check_run.head_sha") != head_sha:
            _malformed("check run did not belong to the acquired head SHA")


def _observation_time(value: str) -> tuple[str, int]:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise AcquisitionError(
            AcquisitionOutcome.MALFORMED_RESPONSE,
            "updated_at must be a GitHub UTC timestamp",
        ) from exc
    return parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), int(parsed.timestamp())


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        _malformed(f"{name} must be an object")
    return cast(Mapping[str, object], value)


def _list(value: object, name: str) -> list[object]:
    if not isinstance(value, list):
        _malformed(f"{name} response must be an array")
    return cast(list[object], value)


def _string(mapping: Mapping[str, object], field: str) -> str:
    value = mapping.get(field)
    if not isinstance(value, str) or value == "":
        _malformed(f"{field} must be a non-empty string")
    return value


def _integer(mapping: Mapping[str, object], field: str, *, minimum: int) -> int:
    value = mapping.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _malformed(f"{field} must be an integer >= {minimum}")
    return value


def _provenance(kind: str, response: GitHubResponse) -> Mapping[str, str]:
    return {"kind": kind, "path": response.path, "sha256": response.raw_sha256}


def _malformed(message: str) -> NoReturn:
    raise AcquisitionError(AcquisitionOutcome.MALFORMED_RESPONSE, message)


def _incomplete(message: str) -> NoReturn:
    raise AcquisitionError(AcquisitionOutcome.INCOMPLETE_ACQUISITION, message)


def _unsupported(name: str, maximum: int) -> NoReturn:
    raise AcquisitionError(
        AcquisitionOutcome.UNSUPPORTED_UPSTREAM_LIMIT,
        f"{name} exceeds GitHub completeness limit {maximum}",
    )
