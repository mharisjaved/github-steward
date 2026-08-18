"""PostgreSQL authorization persistence, CAS, and trusted-work assertions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from threading import Barrier, Thread
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError, IntegrityError

from github_steward.adapters.postgres.github_authorization import (
    PostgresGitHubAuthorizationRepository,
)
from github_steward.adapters.postgres.metadata import (
    delivery_inbox,
    installation_observation,
    repository_authorization,
    work_record,
)
from github_steward.adapters.postgres.unit_of_work import PostgresUnitOfWork
from github_steward.domain.acquisition import (
    GITHUB_PROVIDER,
    GITHUB_REFRESH_WORK_TYPE,
)
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

NOW = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
READ = RepositoryPermissions(
    GitHubPermissionLevel.READ,
    GitHubPermissionLevel.READ,
    GitHubPermissionLevel.READ,
    GitHubPermissionLevel.READ,
)


def _installation(
    *,
    observation_id: UUID | None = None,
    installation_id: int = 7101,
    account_id: int = 8101,
) -> InstallationObservationV1:
    return InstallationObservationV1(
        observation_id=str(observation_id or uuid4()),
        installation_id=installation_id,
        app_id=6101,
        account=InstallationAccount(
            account_id,
            InstallationAccountType.ORGANIZATION,
        ),
        repository_selection=RepositorySelection.SELECTED,
        permissions=READ,
        suspended=False,
        suspended_at=None,
        observed_at=NOW,
        source_digest="a" * 64,
    )


def _authorization(
    installation: InstallationObservationV1,
    *,
    repository_id: int,
    version: int,
    route_repository: str = "repo",
    updated_at: datetime = NOW,
) -> RepositoryAuthorizationV1:
    return RepositoryAuthorizationV1.derive(
        repository_id=repository_id,
        authorization_version=version,
        installation=installation,
        installation_id=installation.installation_id,
        route=RepositoryRoute("octo", route_repository),
        installation_account_id=installation.account.account_id,
        repository_selected=True,
        route_verified=True,
        granted_permissions=READ,
        updated_at=updated_at,
    )


def _new_repository_id() -> int:
    return uuid4().int % 8_000_000_000 + 1_000_000_000


def test_observation_round_trip_and_create_update_cas(
    postgres_engine: Engine,
) -> None:
    installed = _installation()
    repository_id = _new_repository_id()
    first = _authorization(installed, repository_id=repository_id, version=1)
    with PostgresUnitOfWork(postgres_engine) as unit:
        unit.github_authorization.append_installation_observation(installed)
        assert (
            unit.github_authorization.get_installation_observation(
                installed.observation_id
            )
            == installed
        )
        assert unit.github_authorization.compare_and_swap_repository_authorization(
            expected_authorization_version=0,
            replacement=first,
        )
        unit.commit()

    second = _authorization(
        installed,
        repository_id=repository_id,
        version=2,
        route_repository="renamed",
        updated_at=NOW + timedelta(seconds=1),
    )
    with PostgresUnitOfWork(postgres_engine) as unit:
        assert (
            unit.github_authorization.get_repository_authorization(repository_id)
            == first
        )
        assert unit.github_authorization.compare_and_swap_repository_authorization(
            expected_authorization_version=1,
            replacement=second,
        )
        unit.commit()
    with PostgresUnitOfWork(postgres_engine) as unit:
        assert (
            unit.github_authorization.get_repository_authorization(repository_id)
            == second
        )


def test_stale_cas_is_explicit_and_does_not_overwrite(postgres_engine: Engine) -> None:
    installed = _installation()
    repository_id = _new_repository_id()
    first = _authorization(installed, repository_id=repository_id, version=1)
    with PostgresUnitOfWork(postgres_engine) as unit:
        unit.github_authorization.append_installation_observation(installed)
        assert unit.github_authorization.compare_and_swap_repository_authorization(
            expected_authorization_version=0,
            replacement=first,
        )
        unit.commit()
    competing = _authorization(
        installed,
        repository_id=repository_id,
        version=2,
        route_repository="competing",
        updated_at=NOW + timedelta(seconds=1),
    )
    winner = _authorization(
        installed,
        repository_id=repository_id,
        version=2,
        route_repository="winner",
        updated_at=NOW + timedelta(seconds=1),
    )
    with PostgresUnitOfWork(postgres_engine) as unit:
        assert unit.github_authorization.compare_and_swap_repository_authorization(
            expected_authorization_version=1,
            replacement=winner,
        )
        unit.commit()
    with PostgresUnitOfWork(postgres_engine) as unit:
        assert not unit.github_authorization.compare_and_swap_repository_authorization(
            expected_authorization_version=1,
            replacement=competing,
        )
        unit.commit()
    with PostgresUnitOfWork(postgres_engine) as unit:
        assert (
            unit.github_authorization.get_repository_authorization(repository_id)
            == winner
        )


def test_two_concurrent_cas_writers_have_one_winner(postgres_engine: Engine) -> None:
    installed = _installation()
    repository_id = _new_repository_id()
    first = _authorization(installed, repository_id=repository_id, version=1)
    with PostgresUnitOfWork(postgres_engine) as unit:
        unit.github_authorization.append_installation_observation(installed)
        assert unit.github_authorization.compare_and_swap_repository_authorization(
            expected_authorization_version=0,
            replacement=first,
        )
        unit.commit()

    barrier = Barrier(2)
    outcomes: list[bool] = []
    errors: list[BaseException] = []

    def replace(route_repository: str) -> None:
        replacement = _authorization(
            installed,
            repository_id=repository_id,
            version=2,
            route_repository=route_repository,
            updated_at=NOW + timedelta(seconds=1),
        )
        try:
            with PostgresUnitOfWork(postgres_engine) as unit:
                barrier.wait()
                changed = (
                    unit.github_authorization.compare_and_swap_repository_authorization(
                        expected_authorization_version=1,
                        replacement=replacement,
                    )
                )
                unit.commit()
            outcomes.append(changed)
        except BaseException as exc:
            errors.append(exc)

    threads = [
        Thread(target=replace, args=(route,))
        for route in ("candidate-one", "candidate-two")
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert sorted(outcomes) == [False, True]
    with PostgresUnitOfWork(postgres_engine) as unit:
        current = unit.github_authorization.get_repository_authorization(repository_id)
    assert current is not None
    assert current.authorization_version == 2
    assert current.route.repository in {"candidate-one", "candidate-two"}


def test_observation_and_authorization_roll_back_atomically(
    postgres_engine: Engine,
) -> None:
    installed = _installation()
    repository_id = _new_repository_id()
    current = _authorization(installed, repository_id=repository_id, version=1)
    with PostgresUnitOfWork(postgres_engine) as unit:
        unit.github_authorization.append_installation_observation(installed)
        assert unit.github_authorization.compare_and_swap_repository_authorization(
            expected_authorization_version=0,
            replacement=current,
        )
    with postgres_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(installation_observation)
                .where(
                    installation_observation.c.observation_id
                    == UUID(installed.observation_id)
                )
            )
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(repository_authorization)
                .where(repository_authorization.c.repository_id == repository_id)
            )
            == 0
        )


def test_database_requires_version_increment_and_forbids_delete(
    postgres_engine: Engine,
) -> None:
    installed = _installation()
    repository_id = _new_repository_id()
    current = _authorization(installed, repository_id=repository_id, version=1)
    with PostgresUnitOfWork(postgres_engine) as unit:
        unit.github_authorization.append_installation_observation(installed)
        assert unit.github_authorization.compare_and_swap_repository_authorization(
            expected_authorization_version=0,
            replacement=current,
        )
        unit.commit()
    with postgres_engine.begin() as connection:
        nested = connection.begin_nested()
        with pytest.raises(DBAPIError, match="exact version increment"):
            connection.execute(
                repository_authorization.update()
                .where(repository_authorization.c.repository_id == repository_id)
                .values(route_repository="bypass")
            )
        nested.rollback()
        nested = connection.begin_nested()
        with pytest.raises(DBAPIError, match="deletion is forbidden"):
            connection.execute(
                repository_authorization.delete().where(
                    repository_authorization.c.repository_id == repository_id
                )
            )
        nested.rollback()


def test_cas_rejects_nonincrementing_replacement(postgres_engine: Engine) -> None:
    installed = _installation()
    replacement = _authorization(
        installed,
        repository_id=_new_repository_id(),
        version=2,
    )
    with PostgresUnitOfWork(postgres_engine) as unit:
        with pytest.raises(ValueError, match="increment"):
            unit.github_authorization.compare_and_swap_repository_authorization(
                expected_authorization_version=0,
                replacement=replacement,
            )
        with pytest.raises(ValueError, match="nonnegative"):
            unit.github_authorization.compare_and_swap_repository_authorization(
                expected_authorization_version=True,
                replacement=replacement,
            )


def test_persisted_capability_is_rederived_on_read(postgres_engine: Engine) -> None:
    installed = _installation()
    repository_id = _new_repository_id()
    with postgres_engine.connect() as connection:
        transaction = connection.begin()
        try:
            connection.execute(
                installation_observation.insert().values(
                    observation_id=UUID(installed.observation_id),
                    installation_id=installed.installation_id,
                    app_id=installed.app_id,
                    account_id=installed.account.account_id,
                    account_type=installed.account.account_type.value,
                    repository_selection=installed.repository_selection.value,
                    permission_metadata="read",
                    permission_pull_requests="read",
                    permission_checks="read",
                    permission_statuses="read",
                    suspended=False,
                    observed_at=NOW,
                    source_digest=installed.source_digest,
                )
            )
            connection.execute(
                repository_authorization.insert().values(
                    repository_id=repository_id,
                    authorization_version=1,
                    installation_id=installed.installation_id,
                    installation_observation_id=UUID(installed.observation_id),
                    route_owner="octo",
                    route_repository="repo",
                    installation_account_id=installed.account.account_id,
                    repository_selected=True,
                    route_verified=True,
                    granted_metadata="read",
                    granted_pull_requests="read",
                    granted_checks="read",
                    granted_statuses="read",
                    capability=AuthorizationCapability.INSUFFICIENT_PERMISSIONS.value,
                    write_enabled=False,
                    updated_at=NOW,
                )
            )
            adapter = PostgresGitHubAuthorizationRepository(connection)
            with pytest.raises(RuntimeError, match="inconsistent"):
                adapter.get_repository_authorization(repository_id)
        finally:
            transaction.rollback()


def test_database_rejects_write_capable_permission_values(
    postgres_engine: Engine,
) -> None:
    installed = _installation()
    with pytest.raises(IntegrityError), postgres_engine.begin() as connection:
        connection.execute(
            installation_observation.insert().values(
                observation_id=UUID(installed.observation_id),
                installation_id=installed.installation_id,
                app_id=installed.app_id,
                account_id=installed.account.account_id,
                account_type=installed.account.account_type.value,
                repository_selection=installed.repository_selection.value,
                permission_metadata="read",
                permission_pull_requests="write",
                permission_checks="read",
                permission_statuses="read",
                suspended=False,
                observed_at=NOW,
                source_digest=installed.source_digest,
            )
        )


def _insert_work(
    engine: Engine,
    *,
    entity_id: str,
    provider: str = GITHUB_PROVIDER,
    work_type: str = GITHUB_REFRESH_WORK_TYPE,
) -> str:
    delivery_id = uuid4()
    work_id = uuid4()
    with engine.begin() as connection:
        connection.execute(
            delivery_inbox.insert().values(
                delivery_id=delivery_id,
                provider=provider,
                provider_delivery_id=f"broker-work-{delivery_id}",
                payload_digest="b" * 64,
                received_at=NOW,
                payload_schema_id="github-steward/github-refresh/v1",
                payload_schema_version=1,
                canonical_payload={
                    "entity_kind": "github_pull_request",
                    "entity_id": entity_id,
                },
                payload_digest_format="jcs-sha256/v1",
            )
        )
        connection.execute(
            work_record.insert().values(
                work_record_id=work_id,
                delivery_id=delivery_id,
                work_type=work_type,
                state="AVAILABLE",
                available_at=NOW,
            )
        )
    return str(work_id)


def test_work_identity_comes_only_from_persisted_numeric_subject(
    postgres_engine: Engine,
) -> None:
    work_id = _insert_work(postgres_engine, entity_id="123456:17")
    with PostgresUnitOfWork(postgres_engine) as unit:
        identity = unit.github_authorization.get_work_identity(work_id)
        assert unit.github_authorization.get_work_identity(str(uuid4())) is None
    assert identity is not None
    assert identity.work_record_id == work_id
    assert identity.provider == GITHUB_PROVIDER
    assert identity.work_type == GITHUB_REFRESH_WORK_TYPE
    assert identity.repository_id == 123456
    assert identity.pull_number == 17


@pytest.mark.parametrize("subject", ["0123:17", "123:0", "123:17:2", "route/name"])
def test_work_identity_rejects_noncanonical_or_nonnumeric_subjects(
    postgres_engine: Engine,
    subject: str,
) -> None:
    work_id = _insert_work(postgres_engine, entity_id=subject)
    with (
        PostgresUnitOfWork(postgres_engine) as unit,
        pytest.raises(ValueError, match="subject"),
    ):
        unit.github_authorization.get_work_identity(work_id)


def test_work_identity_rejects_noncanonical_caller_identifier(
    postgres_engine: Engine,
) -> None:
    with (
        PostgresUnitOfWork(postgres_engine) as unit,
        pytest.raises(ValueError, match="canonical UUID"),
    ):
        unit.github_authorization.get_work_identity("not-a-uuid")
