"""PostgreSQL authorization state and trusted GitHub work-subject adapter."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import Connection

from github_steward.adapters.postgres.metadata import (
    delivery_inbox,
    installation_observation,
    repository_authorization,
    work_record,
)
from github_steward.domain.acquisition import GITHUB_REFRESH_WORK_TYPE
from github_steward.domain.github_authorization import (
    AuthorizationCapability,
    GitHubPermissionLevel,
    InstallationAccount,
    InstallationAccountType,
    InstallationObservationV1,
    RepositoryAuthorizationV1,
    RepositoryPermissions,
    RepositoryRoute,
    RepositorySelection,
)
from github_steward.ports.github_authorization import BrokerWorkIdentity

_MAX_BIGINT = (1 << 63) - 1
_GITHUB_PULL_REQUEST_ENTITY_KIND = "github_pull_request"


class PostgresGitHubAuthorizationRepository:
    """Credential-free exact reads, observation appends, and authorization CAS."""

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def get_work_identity(self, work_record_id: str) -> BrokerWorkIdentity | None:
        """Load a work identity and parse only its persisted numeric subject."""

        work_uuid = _canonical_uuid(work_record_id, "work_record_id")
        row = (
            self._connection.execute(
                sa.select(
                    work_record.c.work_record_id,
                    work_record.c.work_type,
                    delivery_inbox.c.provider,
                    delivery_inbox.c.canonical_payload,
                )
                .join(
                    delivery_inbox,
                    delivery_inbox.c.delivery_id == work_record.c.delivery_id,
                )
                .where(work_record.c.work_record_id == work_uuid)
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None
        work_type = str(row["work_type"])
        if work_type != GITHUB_REFRESH_WORK_TYPE:
            return BrokerWorkIdentity(
                work_record_id=str(row["work_record_id"]),
                provider=str(row["provider"]),
                work_type=work_type,
                repository_id=0,
                pull_number=0,
            )
        repository_id, pull_number = _work_subject(row["canonical_payload"])
        return BrokerWorkIdentity(
            work_record_id=str(row["work_record_id"]),
            provider=str(row["provider"]),
            work_type=work_type,
            repository_id=repository_id,
            pull_number=pull_number,
        )

    def get_repository_authorization(
        self,
        repository_id: int,
    ) -> RepositoryAuthorizationV1 | None:
        """Load and independently re-derive one persisted current capability."""

        checked_repository_id = _positive_bigint(repository_id, "repository_id")
        row = (
            self._connection.execute(
                sa.select(repository_authorization).where(
                    repository_authorization.c.repository_id == checked_repository_id
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None
        observation = self.get_installation_observation(
            str(row["installation_observation_id"])
        )
        if observation is None:
            raise RuntimeError(
                "repository authorization lost its installation observation"
            )
        record = RepositoryAuthorizationV1.derive(
            repository_id=int(row["repository_id"]),
            authorization_version=int(row["authorization_version"]),
            installation=observation,
            installation_id=int(row["installation_id"]),
            route=RepositoryRoute(
                owner=str(row["route_owner"]),
                repository=str(row["route_repository"]),
            ),
            installation_account_id=int(row["installation_account_id"]),
            repository_selected=_database_bool(
                row["repository_selected"], "repository_selected"
            ),
            route_verified=_database_bool(row["route_verified"], "route_verified"),
            granted_permissions=_permissions(
                metadata=row["granted_metadata"],
                pull_requests=row["granted_pull_requests"],
                checks=row["granted_checks"],
                statuses=row["granted_statuses"],
            ),
            updated_at=_database_datetime(row["updated_at"], "updated_at"),
        )
        try:
            stored_capability = AuthorizationCapability(str(row["capability"]))
        except ValueError as exc:
            raise RuntimeError(
                "persisted repository authorization capability is invalid"
            ) from exc
        if stored_capability is not record.capability:
            raise RuntimeError(
                "persisted repository authorization capability is inconsistent"
            )
        if _database_bool(row["write_enabled"], "write_enabled"):
            raise RuntimeError("persisted repository authorization enabled writes")
        return record

    def get_installation_observation(
        self,
        observation_id: str,
    ) -> InstallationObservationV1 | None:
        """Load one immutable observation by its exact canonical UUID."""

        observation_uuid = _canonical_uuid(observation_id, "observation_id")
        row = (
            self._connection.execute(
                sa.select(installation_observation).where(
                    installation_observation.c.observation_id == observation_uuid
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None
        return _installation_observation(cast(Mapping[str, object], row))

    def append_installation_observation(
        self,
        observation: InstallationObservationV1,
    ) -> None:
        """Append a strictly validated observation using a plain insert."""

        self._connection.execute(
            installation_observation.insert().values(
                observation_id=UUID(observation.observation_id),
                installation_id=observation.installation_id,
                app_id=observation.app_id,
                account_id=observation.account.account_id,
                account_type=observation.account.account_type.value,
                repository_selection=observation.repository_selection.value,
                permission_metadata=observation.permissions.metadata.value,
                permission_pull_requests=(observation.permissions.pull_requests.value),
                permission_checks=observation.permissions.checks.value,
                permission_statuses=observation.permissions.statuses.value,
                suspended=observation.suspended,
                suspended_at=observation.suspended_at,
                observed_at=observation.observed_at,
                source_digest=observation.source_digest,
            )
        )

    def compare_and_swap_repository_authorization(
        self,
        *,
        expected_authorization_version: int,
        replacement: RepositoryAuthorizationV1,
    ) -> bool:
        """Create version one or perform one guarded version increment."""

        if (
            isinstance(expected_authorization_version, bool)
            or not isinstance(expected_authorization_version, int)
            or expected_authorization_version < 0
        ):
            raise ValueError(
                "expected_authorization_version must be a nonnegative integer"
            )
        if replacement.authorization_version != expected_authorization_version + 1:
            raise ValueError("replacement authorization version must increment by one")
        values = _authorization_values(replacement)
        if expected_authorization_version == 0:
            changed = self._connection.execute(
                pg_insert(repository_authorization)
                .values(**values)
                .on_conflict_do_nothing(
                    index_elements=[repository_authorization.c.repository_id]
                )
                .returning(repository_authorization.c.repository_id)
            ).scalar_one_or_none()
        else:
            changed = self._connection.execute(
                repository_authorization.update()
                .where(
                    repository_authorization.c.repository_id
                    == replacement.repository_id,
                    repository_authorization.c.authorization_version
                    == expected_authorization_version,
                )
                .values(**values)
                .returning(repository_authorization.c.repository_id)
            ).scalar_one_or_none()
        return changed is not None


def _installation_observation(
    row: Mapping[str, object],
) -> InstallationObservationV1:
    return InstallationObservationV1(
        observation_id=str(row["observation_id"]),
        installation_id=_database_int(row["installation_id"], "installation_id"),
        app_id=_database_int(row["app_id"], "app_id"),
        account=InstallationAccount(
            account_id=_database_int(row["account_id"], "account_id"),
            account_type=InstallationAccountType(str(row["account_type"])),
        ),
        repository_selection=RepositorySelection(str(row["repository_selection"])),
        permissions=_permissions(
            metadata=row["permission_metadata"],
            pull_requests=row["permission_pull_requests"],
            checks=row["permission_checks"],
            statuses=row["permission_statuses"],
        ),
        suspended=_database_bool(row["suspended"], "suspended"),
        suspended_at=_database_optional_datetime(row["suspended_at"], "suspended_at"),
        observed_at=_database_datetime(row["observed_at"], "observed_at"),
        source_digest=str(row["source_digest"]),
    )


def _permissions(
    *,
    metadata: object,
    pull_requests: object,
    checks: object,
    statuses: object,
) -> RepositoryPermissions:
    try:
        return RepositoryPermissions(
            metadata=GitHubPermissionLevel(str(metadata)),
            pull_requests=GitHubPermissionLevel(str(pull_requests)),
            checks=GitHubPermissionLevel(str(checks)),
            statuses=GitHubPermissionLevel(str(statuses)),
        )
    except ValueError as exc:
        raise RuntimeError("persisted GitHub permission level is invalid") from exc


def _authorization_values(
    authorization: RepositoryAuthorizationV1,
) -> dict[str, object]:
    return {
        "repository_id": authorization.repository_id,
        "authorization_version": authorization.authorization_version,
        "installation_id": authorization.installation_id,
        "installation_observation_id": UUID(authorization.installation_observation_id),
        "route_owner": authorization.route.owner,
        "route_repository": authorization.route.repository,
        "installation_account_id": authorization.installation_account_id,
        "repository_selected": authorization.repository_selected,
        "route_verified": authorization.route_verified,
        "granted_metadata": authorization.granted_permissions.metadata.value,
        "granted_pull_requests": (
            authorization.granted_permissions.pull_requests.value
        ),
        "granted_checks": authorization.granted_permissions.checks.value,
        "granted_statuses": authorization.granted_permissions.statuses.value,
        "capability": authorization.capability.value,
        "write_enabled": authorization.write_enabled,
        "updated_at": authorization.updated_at,
    }


def _work_subject(value: object) -> tuple[int, int]:
    if not isinstance(value, Mapping):
        raise ValueError("stored GitHub work payload must be a mapping")
    if value.get("entity_kind") != _GITHUB_PULL_REQUEST_ENTITY_KIND:
        raise ValueError("stored GitHub work entity kind is invalid")
    subject = value.get("entity_id")
    if not isinstance(subject, str) or subject.count(":") != 1:
        raise ValueError("stored GitHub work subject is invalid")
    repository_text, pull_text = subject.split(":")
    if (
        not repository_text.isascii()
        or not pull_text.isascii()
        or not repository_text.isdecimal()
        or not pull_text.isdecimal()
        or repository_text.startswith("0")
        or pull_text.startswith("0")
    ):
        raise ValueError("stored GitHub work subject is invalid")
    repository_id = _positive_bigint(int(repository_text), "repository_id")
    pull_number = _positive_bigint(int(pull_text), "pull_number")
    return repository_id, pull_number


def _canonical_uuid(value: object, field: str) -> UUID:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a canonical UUID string")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be a canonical UUID string") from exc
    if str(parsed) != value:
        raise ValueError(f"{field} must be a canonical UUID string")
    return parsed


def _positive_bigint(value: object, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > _MAX_BIGINT
    ):
        raise ValueError(f"{field} must be a positive PostgreSQL bigint")
    return value


def _database_bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise RuntimeError(f"persisted {field} is not a boolean")
    return value


def _database_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimeError(f"persisted {field} is not an integer")
    return value


def _database_datetime(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise RuntimeError(f"persisted {field} is not a timestamp")
    return value.astimezone(UTC)


def _database_optional_datetime(value: object, field: str) -> datetime | None:
    if value is None:
        return None
    return _database_datetime(value, field)
