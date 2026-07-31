"""Alembic graph and transactional round-trip evidence."""

from __future__ import annotations

import os

import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.engine import Engine

EXPECTED_TABLES = {
    "delivery_inbox",
    "work_record",
    "work_attempt",
    "canonical_observation",
    "current_observation_pointer",
    "analysis_view",
    "analysis_view_observation",
    "audit_event",
}
EXPECTED_APPEND_ONLY_TABLES = {
    "canonical_observation",
    "analysis_view",
    "analysis_view_observation",
    "audit_event",
}


def _config() -> Config:
    return Config("alembic.ini")


def _application_tables(engine: Engine) -> set[str]:
    with engine.connect() as connection:
        return set(
            connection.execute(
                sa.text(
                    "SELECT tablename FROM pg_catalog.pg_tables "
                    "WHERE schemaname = 'public' AND tablename <> 'alembic_version'"
                )
            ).scalars()
        )


def _append_only_trigger_tables(engine: Engine) -> set[str]:
    with engine.connect() as connection:
        return set(
            connection.execute(
                sa.text(
                    "SELECT c.relname FROM pg_trigger t "
                    "JOIN pg_class c ON c.oid = t.tgrelid "
                    "JOIN pg_proc p ON p.oid = t.tgfoid "
                    "WHERE NOT t.tgisinternal "
                    "AND c.relnamespace = 'public'::regnamespace "
                    "AND p.proname = 'gs_i1_reject_append_only_mutation'"
                )
            ).scalars()
        )


def test_exactly_one_root_revision_and_one_head() -> None:
    script = ScriptDirectory.from_config(_config())
    revisions = list(script.walk_revisions())
    assert len(revisions) == 1
    assert revisions[0].revision == "gs_i1_0001"
    assert revisions[0].down_revision is None
    assert script.get_heads() == ["gs_i1_0001"]


def test_transactional_downgrade_and_reupgrade(
    postgres_database_url: str,
    postgres_engine: Engine,
) -> None:
    assert os.environ["GS_TEST_DATABASE_URL"] == postgres_database_url
    assert _application_tables(postgres_engine) == EXPECTED_TABLES
    assert _append_only_trigger_tables(postgres_engine) == EXPECTED_APPEND_ONLY_TABLES
    command.downgrade(_config(), "base")
    assert _application_tables(postgres_engine) == set()
    command.upgrade(_config(), "head")
    assert _application_tables(postgres_engine) == EXPECTED_TABLES
    assert _append_only_trigger_tables(postgres_engine) == EXPECTED_APPEND_ONLY_TABLES
