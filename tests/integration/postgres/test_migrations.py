"""Alembic graph and transactional round-trip evidence."""

from __future__ import annotations

import os

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.engine import Engine

GS_I2_TABLES = {
    "delivery_inbox",
    "work_record",
    "work_attempt",
    "canonical_observation",
    "current_observation_pointer",
    "analysis_view",
    "analysis_view_observation",
    "audit_event",
}
GS_I4_TABLES = {
    "preparedness_profile",
    "preparedness_assessment",
    "preparedness_assessment_evidence",
}
EXPECTED_TABLES = GS_I2_TABLES | GS_I4_TABLES
GS_I2_APPEND_ONLY_TABLES = {
    "delivery_inbox",
    "canonical_observation",
    "analysis_view",
    "analysis_view_observation",
    "audit_event",
}
EXPECTED_APPEND_ONLY_TABLES = GS_I2_APPEND_ONLY_TABLES | GS_I4_TABLES


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


def _truncate_application_data(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "TRUNCATE TABLE " + ", ".join(sorted(EXPECTED_TABLES)) + " CASCADE"
        )


def test_exactly_three_linear_revisions_and_one_head() -> None:
    script = ScriptDirectory.from_config(_config())
    revisions = list(script.walk_revisions())
    assert len(revisions) == 3
    assert revisions[0].revision == "gs_i4_0003"
    assert revisions[0].down_revision == "gs_i2_0002"
    assert revisions[1].revision == "gs_i2_0002"
    assert revisions[1].down_revision == "gs_i1_0001"
    assert revisions[2].revision == "gs_i1_0001"
    assert revisions[2].down_revision is None
    assert script.get_heads() == ["gs_i4_0003"]


def test_transactional_downgrade_and_reupgrade(
    postgres_database_url: str,
    postgres_engine: Engine,
) -> None:
    assert os.environ["GS_TEST_DATABASE_URL"] == postgres_database_url
    assert _application_tables(postgres_engine) == EXPECTED_TABLES
    assert _append_only_trigger_tables(postgres_engine) == EXPECTED_APPEND_ONLY_TABLES
    _truncate_application_data(postgres_engine)
    command.downgrade(_config(), "gs_i2_0002")
    assert _application_tables(postgres_engine) == GS_I2_TABLES
    assert _append_only_trigger_tables(postgres_engine) == GS_I2_APPEND_ONLY_TABLES
    command.upgrade(_config(), "head")
    assert _application_tables(postgres_engine) == EXPECTED_TABLES
    assert _append_only_trigger_tables(postgres_engine) == EXPECTED_APPEND_ONLY_TABLES


def test_nonempty_inbox_migration_fails_closed_and_can_recover(
    postgres_engine: Engine,
) -> None:
    command.downgrade(_config(), "gs_i1_0001")
    with postgres_engine.begin() as connection:
        connection.execute(
            sa.text(
                "INSERT INTO delivery_inbox "
                "(delivery_id, provider, provider_delivery_id, payload_digest, "
                "received_at) VALUES "
                "('00000000-0000-0000-0000-000000000001', 'synthetic', "
                "'historical', :digest, CURRENT_TIMESTAMP)"
            ),
            {"digest": "a" * 64},
        )
    try:
        with pytest.raises(Exception, match="refuses to identify payloads"):
            command.upgrade(_config(), "head")
        with postgres_engine.begin() as connection:
            connection.execute(sa.text("DELETE FROM delivery_inbox"))
        command.upgrade(_config(), "head")
    finally:
        with postgres_engine.connect() as connection:
            revision = connection.scalar(
                sa.text("SELECT version_num FROM alembic_version")
            )
        if revision != "gs_i4_0003":
            command.upgrade(_config(), "head")


def test_offline_sql_generation_contains_all_revisions(
    postgres_database_url: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert postgres_database_url
    command.upgrade(_config(), "head", sql=True)
    output = capsys.readouterr().out
    assert "Running upgrade  -> gs_i1_0001" in output
    assert "Running upgrade gs_i1_0001 -> gs_i2_0002" in output
    assert "Running upgrade gs_i2_0002 -> gs_i4_0003" in output
