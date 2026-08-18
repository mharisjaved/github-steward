"""Defensive branches in the PostgreSQL GitHub authorization adapter."""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Self, cast
from uuid import UUID

import pytest
from sqlalchemy.engine import Connection

from github_steward.adapters.postgres import github_authorization as adapter_module
from github_steward.adapters.postgres.github_authorization import (
    PostgresGitHubAuthorizationRepository,
)

NOW = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
OBSERVATION_ID = UUID("00000000-0000-0000-0000-000000000551")


class _Result:
    def __init__(self, row: Mapping[str, object] | None) -> None:
        self._row = row

    def mappings(self) -> Self:
        return self

    def one_or_none(self) -> Mapping[str, object] | None:
        return self._row


class _Connection:
    def __init__(self, *rows: Mapping[str, object] | None) -> None:
        self._rows = deque(rows)

    def execute(self, _statement: object) -> _Result:
        return _Result(self._rows.popleft())


def _repository(
    *rows: Mapping[str, object] | None,
) -> PostgresGitHubAuthorizationRepository:
    return PostgresGitHubAuthorizationRepository(cast(Connection, _Connection(*rows)))


def _observation_row() -> dict[str, object]:
    return {
        "observation_id": OBSERVATION_ID,
        "installation_id": 71,
        "app_id": 61,
        "account_id": 81,
        "account_type": "Organization",
        "repository_selection": "selected",
        "permission_metadata": "read",
        "permission_pull_requests": "read",
        "permission_checks": "read",
        "permission_statuses": "read",
        "suspended": False,
        "suspended_at": None,
        "observed_at": NOW,
        "source_digest": "a" * 64,
    }


def _authorization_row(**changes: object) -> dict[str, object]:
    values: dict[str, object] = {
        "repository_id": 91,
        "authorization_version": 1,
        "installation_id": 71,
        "installation_observation_id": OBSERVATION_ID,
        "route_owner": "octo",
        "route_repository": "repo",
        "installation_account_id": 81,
        "repository_selected": True,
        "route_verified": True,
        "granted_metadata": "read",
        "granted_pull_requests": "read",
        "granted_checks": "read",
        "granted_statuses": "read",
        "capability": "AUTHORIZED_READ",
        "write_enabled": False,
        "updated_at": NOW,
    }
    values.update(changes)
    return values


def test_missing_current_authorization_and_observation_return_none() -> None:
    assert _repository(None).get_repository_authorization(91) is None
    assert _repository(None).get_installation_observation(str(OBSERVATION_ID)) is None


def test_missing_referenced_observation_fails_closed() -> None:
    with pytest.raises(RuntimeError, match="lost"):
        _repository(_authorization_row(), None).get_repository_authorization(91)


def test_invalid_or_write_enabled_persisted_capability_fails_closed() -> None:
    with pytest.raises(RuntimeError, match="capability is invalid"):
        _repository(
            _authorization_row(capability="INVALID"),
            _observation_row(),
        ).get_repository_authorization(91)
    with pytest.raises(RuntimeError, match="enabled writes"):
        _repository(
            _authorization_row(write_enabled=True),
            _observation_row(),
        ).get_repository_authorization(91)


def test_invalid_persisted_permission_fails_closed() -> None:
    with pytest.raises(RuntimeError, match="permission"):
        adapter_module._permissions(
            metadata="read",
            pull_requests="write",
            checks="read",
            statuses="read",
        )


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"entity_kind": "other", "entity_id": "1:1"},
        {"entity_kind": "github_pull_request", "entity_id": 1},
        {"entity_kind": "github_pull_request", "entity_id": "1:1:1"},
        {"entity_kind": "github_pull_request", "entity_id": "é:1"},
        {"entity_kind": "github_pull_request", "entity_id": "1:é"},
        {"entity_kind": "github_pull_request", "entity_id": "x:1"},
        {"entity_kind": "github_pull_request", "entity_id": "1:x"},
        {"entity_kind": "github_pull_request", "entity_id": "0:1"},
        {"entity_kind": "github_pull_request", "entity_id": "1:0"},
        {
            "entity_kind": "github_pull_request",
            "entity_id": f"{1 << 63}:1",
        },
    ],
)
def test_invalid_work_subject_shapes_fail_closed(payload: object) -> None:
    with pytest.raises(ValueError):
        adapter_module._work_subject(payload)


@pytest.mark.parametrize(
    "value",
    [
        1,
        "bad",
        "AAAAAAAA-0000-0000-0000-000000000551",
    ],
)
def test_adapter_uuid_requires_canonical_string(value: object) -> None:
    with pytest.raises(ValueError, match="canonical UUID"):
        adapter_module._canonical_uuid(value, "identifier")


@pytest.mark.parametrize("value", [True, object(), 0, 1 << 63])
def test_adapter_bigint_rejects_invalid_values(value: object) -> None:
    with pytest.raises(ValueError, match="bigint"):
        adapter_module._positive_bigint(value, "identifier")


def test_database_scalar_guards_reject_wrong_types() -> None:
    with pytest.raises(RuntimeError, match="boolean"):
        adapter_module._database_bool(1, "flag")
    with pytest.raises(RuntimeError, match="integer"):
        adapter_module._database_int(True, "identifier")
    with pytest.raises(RuntimeError, match="integer"):
        adapter_module._database_int("1", "identifier")
    with pytest.raises(RuntimeError, match="timestamp"):
        adapter_module._database_datetime("now", "observed_at")
    with pytest.raises(RuntimeError, match="timestamp"):
        adapter_module._database_datetime(
            NOW.replace(tzinfo=None),
            "observed_at",
        )
    assert adapter_module._database_optional_datetime(None, "suspended_at") is None
    assert adapter_module._database_optional_datetime(NOW, "suspended_at") == NOW


def test_public_reads_reject_invalid_numeric_or_uuid_identity() -> None:
    repository = _repository()
    with pytest.raises(ValueError, match="bigint"):
        repository.get_repository_authorization(True)
    with pytest.raises(ValueError, match="canonical UUID"):
        repository.get_installation_observation("not-a-uuid")
