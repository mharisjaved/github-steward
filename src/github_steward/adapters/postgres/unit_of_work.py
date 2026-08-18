"""Explicit synchronous PostgreSQL processing unit of work."""

from __future__ import annotations

from types import TracebackType

from sqlalchemy.engine import Connection, Engine
from sqlalchemy.engine.base import RootTransaction

from github_steward.adapters.postgres.github_authorization import (
    PostgresGitHubAuthorizationRepository,
)
from github_steward.adapters.postgres.repositories import (
    FaultInjector,
    PostgresAnalysisViewRepository,
    PostgresAuditEventRepository,
    PostgresCanonicalObservationRepository,
    PostgresCurrentObservationPointerRepository,
    PostgresInboxWorkRepository,
    PostgresPreparednessAssessmentRepository,
    PostgresPreparednessProfileRepository,
    PostgresWorkRepository,
)


class PostgresUnitOfWork:
    """Own exactly one READ COMMITTED transaction and its repositories."""

    inbox: PostgresInboxWorkRepository
    work: PostgresWorkRepository
    observations: PostgresCanonicalObservationRepository
    pointers: PostgresCurrentObservationPointerRepository
    views: PostgresAnalysisViewRepository
    audits: PostgresAuditEventRepository
    profiles: PostgresPreparednessProfileRepository
    assessments: PostgresPreparednessAssessmentRepository
    github_authorization: PostgresGitHubAuthorizationRepository

    def __init__(
        self,
        engine: Engine,
        fault_injector: FaultInjector | None = None,
    ) -> None:
        self._engine = engine
        self._fault_injector = fault_injector
        self._connection: Connection | None = None
        self._transaction: RootTransaction | None = None

    def __enter__(self) -> PostgresUnitOfWork:
        if self._connection is not None:
            raise RuntimeError("unit of work cannot be entered twice")
        connection = self._engine.connect().execution_options(
            isolation_level="READ COMMITTED"
        )
        self._connection = connection
        self._transaction = connection.begin()
        self.inbox = PostgresInboxWorkRepository(connection, self._fault_injector)
        self.work = PostgresWorkRepository(connection, self._fault_injector)
        self.observations = PostgresCanonicalObservationRepository(
            connection,
            self._fault_injector,
        )
        self.pointers = PostgresCurrentObservationPointerRepository(
            connection,
            self._fault_injector,
        )
        self.views = PostgresAnalysisViewRepository(connection, self._fault_injector)
        self.audits = PostgresAuditEventRepository(connection, self._fault_injector)
        self.profiles = PostgresPreparednessProfileRepository(connection)
        self.assessments = PostgresPreparednessAssessmentRepository(connection)
        self.github_authorization = PostgresGitHubAuthorizationRepository(connection)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        transaction = self._transaction
        connection = self._connection
        try:
            if transaction is not None and transaction.is_active:
                transaction.rollback()
        finally:
            if connection is not None:
                connection.close()
            self._transaction = None
            self._connection = None
        return None

    def commit(self) -> None:
        """Commit the application-owned transaction."""

        transaction = self._require_transaction()
        transaction.commit()

    def rollback(self) -> None:
        """Roll back the application-owned transaction."""

        transaction = self._require_transaction()
        transaction.rollback()

    def _require_transaction(self) -> RootTransaction:
        transaction = self._transaction
        if transaction is None or not transaction.is_active:
            raise RuntimeError("unit of work has no active transaction")
        return transaction
