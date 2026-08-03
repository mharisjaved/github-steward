"""CLI stdout/stderr and configuration-secrecy contracts."""

from __future__ import annotations

import json

import pytest
import sqlalchemy as sa

from github_steward import cli
from github_steward.application.public_acquisition import AcquisitionResult
from github_steward.domain.acquisition import (
    AcquisitionError,
    AcquisitionOutcome,
    RepositoryTarget,
)


def _result() -> AcquisitionResult:
    return AcquisitionResult(
        AcquisitionOutcome.ACQUIRED,
        "Harry5174/github-steward",
        1,
        "a" * 40,
        "b" * 64,
        "github-public-pr:77:1:" + "b" * 64,
        {"files": 1, "commits": 1, "reviews": 0, "check_runs": 1},
        "CREATED",
        (),
    )


def test_cli_success_is_one_concise_stdout_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "_run", lambda _: _result())
    assert (
        cli.main(
            [
                "acquire-public-pr",
                "--owner",
                "Harry5174",
                "--repo",
                "github-steward",
                "--pull",
                "1",
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert output["outcome"] == "ACQUIRED"
    assert output["completeness"] == "COMPLETE"
    assert captured.err == ""
    assert captured.out.count("\n") == 1


def test_cli_failure_has_safe_json_and_stderr(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(_: object) -> AcquisitionResult:
        raise AcquisitionError(AcquisitionOutcome.NOT_FOUND, "public PR not found")

    monkeypatch.setattr(cli, "_run", fail)
    assert (
        cli.main(["acquire-public-pr", "--owner", "o", "--repo", "r", "--pull", "1"])
        == 1
    )
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "outcome": "NOT_FOUND",
        "pull_request_number": 1,
        "repository": "o/r",
    }
    assert captured.err == "public PR not found\n"


def test_cli_rejects_bad_target_without_running(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "_run", lambda _: pytest.fail("must not run"))
    assert (
        cli.main(
            ["acquire-public-pr", "--owner", "bad/name", "--repo", "r", "--pull", "1"]
        )
        == 1
    )
    captured = capsys.readouterr()
    assert json.loads(captured.out)["outcome"] == "MALFORMED_RESPONSE"


def test_run_requires_database_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_STEWARD_DATABASE_URL", raising=False)
    with pytest.raises(AcquisitionError) as raised:
        cli._run(RepositoryTarget("o", "r", 1))
    assert raised.value.outcome is AcquisitionOutcome.PERSISTENCE_FAILURE


def test_run_composes_bounded_client_and_disposes_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_STEWARD_DATABASE_URL", "postgresql+psycopg://local")

    class Engine:
        disposed = False

        def dispose(self) -> None:
            self.disposed = True

    class Client:
        entered = False
        exited = False

        def __enter__(self) -> Client:
            self.entered = True
            return self

        def __exit__(self, *args: object) -> None:
            self.exited = True
            return None

    engine = Engine()
    client = Client()
    monkeypatch.setattr(sa, "create_engine", lambda *args, **kwargs: engine)
    monkeypatch.setattr(cli, "PublicGitHubRestClient", lambda: client)
    monkeypatch.setattr(cli, "SyntheticReceiptService", lambda **kwargs: object())

    class Service:
        def __init__(self, **kwargs: object) -> None:
            assert kwargs["github"] is client

        def acquire(self, target: RepositoryTarget) -> AcquisitionResult:
            assert target.full_name == "o/r"
            return _result()

    monkeypatch.setattr(cli, "PublicPullRequestAcquisitionService", Service)
    assert cli._run(RepositoryTarget("o", "r", 1)) == _result()
    assert client.entered
    assert client.exited
    assert engine.disposed
