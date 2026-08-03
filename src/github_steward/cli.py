"""Small machine-readable operator interface for GitHub Steward."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence

import httpx
import sqlalchemy as sa

from github_steward.adapters.canonicalization.rfc8785 import envelope_payload
from github_steward.adapters.github.public_rest import PublicGitHubRestClient
from github_steward.adapters.postgres.unit_of_work import PostgresUnitOfWork
from github_steward.application.local_processing import SyntheticReceiptService
from github_steward.application.public_acquisition import (
    AcquisitionResult,
    PublicPullRequestAcquisitionService,
)
from github_steward.domain.acquisition import (
    AcquisitionError,
    AcquisitionOutcome,
    RepositoryTarget,
)
from github_steward.domain.errors import DomainValidationError
from github_steward.infrastructure.clock import SystemClock


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="github-steward")
    commands = parser.add_subparsers(dest="command", required=True)
    acquire = commands.add_parser("acquire-public-pr")
    acquire.add_argument("--owner", required=True)
    acquire.add_argument("--repo", required=True)
    acquire.add_argument("--pull", required=True, type=int)
    return parser


def _run(target: RepositoryTarget) -> AcquisitionResult:
    database_url = os.environ.get("GITHUB_STEWARD_DATABASE_URL")
    if not database_url:
        raise AcquisitionError(
            AcquisitionOutcome.PERSISTENCE_FAILURE,
            "GITHUB_STEWARD_DATABASE_URL is required",
        )
    timeout = httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=5.0)
    limits = httpx.Limits(max_connections=4, max_keepalive_connections=2)
    engine = sa.create_engine(database_url, pool_pre_ping=True)
    try:
        with httpx.Client(
            timeout=timeout,
            limits=limits,
            follow_redirects=False,
        ) as client:
            github = PublicGitHubRestClient(client)
            receipt = SyntheticReceiptService(
                unit_of_work_factory=lambda: PostgresUnitOfWork(engine),
                clock=SystemClock(),
                envelope_factory=envelope_payload,
            )
            service = PublicPullRequestAcquisitionService(
                github=github,
                receipt=receipt,
                envelope_factory=envelope_payload,
            )
            return service.acquire(target)
    finally:
        engine.dispose()


def main(argv: Sequence[str] | None = None) -> int:
    """Run one bounded command and emit exactly one JSON value on stdout."""

    arguments = _parser().parse_args(argv)
    try:
        target = RepositoryTarget(arguments.owner, arguments.repo, arguments.pull)
        result = _run(target)
    except (AcquisitionError, DomainValidationError) as exc:
        outcome = (
            exc.outcome.value
            if isinstance(exc, AcquisitionError)
            else AcquisitionOutcome.MALFORMED_RESPONSE.value
        )
        print(
            json.dumps(
                {
                    "outcome": outcome,
                    "repository": f"{arguments.owner}/{arguments.repo}",
                    "pull_request_number": arguments.pull,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result.as_mapping(), separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
