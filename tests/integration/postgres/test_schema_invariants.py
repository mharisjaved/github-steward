"""Direct PostgreSQL catalog, immutable-reference, and trigger assertions."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import DBAPIError, IntegrityError

from github_steward.adapters.canonicalization.rfc8785 import canonicalize
from github_steward.adapters.postgres.metadata import (
    APPEND_ONLY_TABLE_NAMES,
    TABLE_NAMES,
    analysis_view,
    analysis_view_observation,
    audit_event,
    canonical_observation,
)
from github_steward.domain.errors import CanonicalizationError

NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
DIGEST = "0" * 64


def _insert_observation(connection: Connection) -> UUID:
    identifier = uuid4()
    connection.execute(
        canonical_observation.insert().values(
            observation_version_id=identifier,
            entity_kind="pull_request",
            entity_id="17",
            schema_id="github.pull-request",
            schema_version=1,
            observed_at=NOW,
            canonical_payload={"id": 17},
            digest_format="jcs-sha256/v1",
            digest_value=DIGEST,
        )
    )
    return identifier


def test_direct_catalog_table_column_constraint_index_and_fk_inventory(
    postgres_engine: Engine,
) -> None:
    inspector = sa.inspect(postgres_engine)
    tables = set(inspector.get_table_names(schema="public"))
    assert tables == {*TABLE_NAMES, "alembic_version"}
    for table_name in TABLE_NAMES:
        assert inspector.get_columns(table_name)
        primary_key = inspector.get_pk_constraint(table_name)
        assert primary_key["name"]
        for unique_constraint in inspector.get_unique_constraints(table_name):
            assert unique_constraint["name"]
        for check_constraint in inspector.get_check_constraints(table_name):
            assert check_constraint["name"]
        for foreign_key in inspector.get_foreign_keys(table_name):
            assert foreign_key["name"]
        for index in inspector.get_indexes(table_name):
            assert index["name"]

    with postgres_engine.connect() as connection:
        foreign_edges = set(
            connection.execute(
                sa.text(
                    "SELECT conrelid::regclass::text, "
                    "confrelid::regclass::text, conname "
                    "FROM pg_constraint WHERE contype = 'f' "
                    "AND connamespace = 'public'::regnamespace"
                )
            ).tuples()
        )
        assert foreign_edges == {
            ("work_record", "delivery_inbox", "fk_work_record_delivery"),
            ("work_attempt", "work_record", "fk_work_attempt_work_record"),
            (
                "current_observation_pointer",
                "canonical_observation",
                "fk_current_observation_pointer_observation",
            ),
            (
                "analysis_view_observation",
                "analysis_view",
                "fk_analysis_view_observation_view",
            ),
            (
                "analysis_view_observation",
                "canonical_observation",
                "fk_analysis_view_observation_observation",
            ),
        }
        trigger_rows = set(
            connection.execute(
                sa.text(
                    "SELECT c.relname, t.tgname, p.proname "
                    "FROM pg_trigger t "
                    "JOIN pg_class c ON c.oid = t.tgrelid "
                    "JOIN pg_proc p ON p.oid = t.tgfoid "
                    "WHERE NOT t.tgisinternal "
                    "AND c.relnamespace = 'public'::regnamespace"
                )
            ).tuples()
        )
        assert trigger_rows == {
            (
                table_name,
                f"trg_{table_name}_reject_mutation",
                "gs_i1_reject_append_only_mutation",
            )
            for table_name in APPEND_ONLY_TABLE_NAMES
        }


@pytest.mark.parametrize("table_name", APPEND_ONLY_TABLE_NAMES)
@pytest.mark.parametrize("operation", ["update", "delete"])
def test_append_only_trigger_rejects_update_and_delete(
    postgres_engine: Engine,
    table_name: str,
    operation: str,
) -> None:
    with postgres_engine.begin() as connection:
        observation_id = _insert_observation(connection)
        if table_name == "analysis_view":
            identifier = uuid4()
            connection.execute(
                analysis_view.insert().values(
                    analysis_view_id=identifier,
                    schema_id="analysis",
                    schema_version=1,
                    canonical_payload={"ok": True},
                    digest_format="jcs-sha256/v1",
                    digest_value=DIGEST,
                )
            )
            key_column = "analysis_view_id"
        elif table_name == "audit_event":
            identifier = uuid4()
            connection.execute(
                audit_event.insert().values(
                    audit_event_id=identifier,
                    event_kind="OBSERVED",
                    actor_or_authority_id="system",
                    occurred_at=NOW,
                    schema_id="audit",
                    schema_version=1,
                    canonical_payload={"ok": True},
                    digest_format="jcs-sha256/v1",
                    digest_value=DIGEST,
                )
            )
            key_column = "audit_event_id"
        else:
            identifier = observation_id
            key_column = "observation_version_id"
        nested = connection.begin_nested()
        with pytest.raises(DBAPIError, match="append-only"):
            if operation == "update":
                connection.exec_driver_sql(
                    f"UPDATE {table_name} SET digest_value = digest_value "
                    f"WHERE {key_column} = %s",
                    (identifier,),
                )
            else:
                connection.exec_driver_sql(
                    f"DELETE FROM {table_name} WHERE {key_column} = %s",
                    (identifier,),
                )
        nested.rollback()


def test_analysis_view_references_immutable_versions_and_enforces_uniqueness(
    postgres_engine: Engine,
) -> None:
    with postgres_engine.begin() as connection:
        observation_id = _insert_observation(connection)
        view_id = uuid4()
        connection.execute(
            analysis_view.insert().values(
                analysis_view_id=view_id,
                schema_id="analysis",
                schema_version=1,
                canonical_payload={"facets": 1},
                digest_format="jcs-sha256/v1",
                digest_value=DIGEST,
            )
        )
        values = {
            "analysis_view_id": view_id,
            "observation_version_id": observation_id,
            "facet_role_id": "pull_request",
        }
        connection.execute(analysis_view_observation.insert().values(**values))
        nested = connection.begin_nested()
        with pytest.raises(IntegrityError):
            connection.execute(analysis_view_observation.insert().values(**values))
        nested.rollback()
        assert "current" not in {
            column.name for column in analysis_view_observation.columns
        }


def test_sqlalchemy_row_mapping_cannot_cross_canonical_boundary(
    postgres_engine: Engine,
) -> None:
    with postgres_engine.connect() as connection:
        row_mapping = (
            connection.execute(sa.select(sa.literal(1).label("value"))).mappings().one()
        )
    with pytest.raises(CanonicalizationError, match="SQLAlchemy rows"):
        canonicalize(row_mapping)
