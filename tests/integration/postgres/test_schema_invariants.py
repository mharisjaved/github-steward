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
    current_observation_pointer,
    delivery_inbox,
    preparedness_assessment,
    preparedness_assessment_evidence,
    preparedness_profile,
    work_attempt,
    work_record,
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


def _insert_analysis_view(connection: Connection) -> UUID:
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
    return identifier


def _insert_delivery(connection: Connection, suffix: str = "schema") -> UUID:
    identifier = uuid4()
    connection.execute(
        delivery_inbox.insert().values(
            delivery_id=identifier,
            provider="synthetic",
            provider_delivery_id=f"{suffix}-{identifier}",
            payload_digest=DIGEST,
            received_at=NOW,
            payload_schema_id="github-steward.synthetic-delivery",
            payload_schema_version=1,
            canonical_payload={"value": suffix},
            payload_digest_format="jcs-sha256/v1",
        )
    )
    return identifier


def _insert_profile(connection: Connection) -> tuple[UUID, int]:
    identifier = uuid4()
    repository_id = uuid4().int % 9_000_000_000 + 1
    connection.execute(
        preparedness_profile.insert().values(
            profile_id=identifier,
            profile_version=1,
            repository_id=repository_id,
            effective_from=NOW,
            schema_id="github-steward/preparedness-profile/v1",
            canonical_payload={"profile_id": str(identifier), "version": 1},
            digest_format="jcs-sha256/v1",
            digest_value=DIGEST,
        )
    )
    return identifier, repository_id


def _insert_assessment(
    connection: Connection,
    observation_id: UUID,
    *,
    include_evidence: bool,
) -> tuple[UUID, UUID]:
    profile_id, repository_id = _insert_profile(connection)
    view_id = _insert_analysis_view(connection)
    connection.execute(
        analysis_view_observation.insert().values(
            analysis_view_id=view_id,
            observation_version_id=observation_id,
            facet_role_id="pull_request",
        )
    )
    assessment_id = uuid4()
    connection.execute(
        preparedness_assessment.insert().values(
            assessment_id=assessment_id,
            repository_id=repository_id,
            pull_number=17,
            head_sha="a" * 40,
            profile_id=profile_id,
            profile_version=1,
            profile_digest_format="jcs-sha256/v1",
            profile_digest_value=DIGEST,
            analysis_view_id=view_id,
            analysis_view_digest_format="jcs-sha256/v1",
            analysis_view_digest_value=DIGEST,
            evidence_sealed_at=NOW,
            evaluated_at=NOW,
            verdict="READY_FOR_HUMAN_REVIEW",
            schema_id="github-steward/preparedness-assessment/v1",
            canonical_payload={"assessment_id": str(assessment_id)},
            digest_format="jcs-sha256/v1",
            digest_value=DIGEST,
        )
    )
    if include_evidence:
        connection.execute(
            preparedness_assessment_evidence.insert().values(
                assessment_id=assessment_id,
                analysis_view_id=view_id,
                observation_version_id=observation_id,
                facet_role_id="pull_request",
            )
        )
    return assessment_id, view_id


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
                "fk_current_observation_pointer_entity_observation",
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
            (
                "preparedness_profile",
                "preparedness_profile",
                "fk_preparedness_profile_predecessor",
            ),
            (
                "preparedness_assessment",
                "preparedness_profile",
                "fk_preparedness_assessment_profile",
            ),
            (
                "preparedness_assessment",
                "analysis_view",
                "fk_preparedness_assessment_view",
            ),
            (
                "preparedness_assessment_evidence",
                "preparedness_assessment",
                "fk_preparedness_assessment_evidence_assessment",
            ),
            (
                "preparedness_assessment_evidence",
                "analysis_view_observation",
                "fk_preparedness_assessment_evidence_view_observation",
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
    assert {column["name"] for column in inspector.get_columns("delivery_inbox")} == {
        "delivery_id",
        "provider",
        "provider_delivery_id",
        "payload_digest",
        "received_at",
        "payload_schema_id",
        "payload_schema_version",
        "canonical_payload",
        "payload_digest_format",
    }
    assert {
        constraint["name"]
        for constraint in inspector.get_check_constraints("work_record")
    } >= {
        "ck_work_record_work_type_inventory",
        "ck_work_record_state_inventory",
        "ck_work_record_state_lease_consistency",
    }
    assert {
        constraint["name"]
        for constraint in inspector.get_check_constraints("delivery_inbox")
    } >= {"ck_delivery_inbox_provider_inventory"}
    assert {
        constraint["name"]
        for constraint in inspector.get_check_constraints("work_attempt")
    } >= {
        "ck_work_attempt_state_inventory",
        "ck_work_attempt_state_timestamp_consistency",
        "ck_work_attempt_number_positive",
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
        parameters: tuple[object, ...]
        if table_name == "delivery_inbox":
            identifier = _insert_delivery(connection, operation)
            predicate = "delivery_id = %s"
            parameters = (identifier,)
            assignment = "payload_digest = payload_digest"
        elif table_name == "analysis_view_observation":
            view_id = _insert_analysis_view(connection)
            connection.execute(
                analysis_view_observation.insert().values(
                    analysis_view_id=view_id,
                    observation_version_id=observation_id,
                    facet_role_id="pull_request",
                )
            )
            predicate = (
                "analysis_view_id = %s AND observation_version_id = %s "
                "AND facet_role_id = %s"
            )
            parameters = (view_id, observation_id, "pull_request")
            assignment = "facet_role_id = facet_role_id"
        elif table_name == "analysis_view":
            identifier = _insert_analysis_view(connection)
            key_column = "analysis_view_id"
            predicate = f"{key_column} = %s"
            parameters = (identifier,)
            assignment = "digest_value = digest_value"
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
            predicate = f"{key_column} = %s"
            parameters = (identifier,)
            assignment = "digest_value = digest_value"
        elif table_name == "preparedness_profile":
            identifier, _ = _insert_profile(connection)
            predicate = "profile_id = %s AND profile_version = %s"
            parameters = (identifier, 1)
            assignment = "digest_value = digest_value"
        elif table_name == "preparedness_assessment":
            identifier, _ = _insert_assessment(
                connection,
                observation_id,
                include_evidence=False,
            )
            predicate = "assessment_id = %s"
            parameters = (identifier,)
            assignment = "digest_value = digest_value"
        elif table_name == "preparedness_assessment_evidence":
            identifier, view_id = _insert_assessment(
                connection,
                observation_id,
                include_evidence=True,
            )
            predicate = (
                "assessment_id = %s AND analysis_view_id = %s "
                "AND observation_version_id = %s AND facet_role_id = %s"
            )
            parameters = (
                identifier,
                view_id,
                observation_id,
                "pull_request",
            )
            assignment = "facet_role_id = facet_role_id"
        else:
            identifier = observation_id
            key_column = "observation_version_id"
            predicate = f"{key_column} = %s"
            parameters = (identifier,)
            assignment = "digest_value = digest_value"
        nested = connection.begin_nested()
        with pytest.raises(DBAPIError, match="append-only"):
            if operation == "update":
                connection.exec_driver_sql(
                    f"UPDATE {table_name} SET {assignment} WHERE {predicate}",
                    parameters,
                )
            else:
                connection.exec_driver_sql(
                    f"DELETE FROM {table_name} WHERE {predicate}",
                    parameters,
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


def test_pointer_composite_foreign_key_rejects_cross_entity_reference(
    postgres_engine: Engine,
) -> None:
    with postgres_engine.begin() as connection:
        observation_id = _insert_observation(connection)
        with pytest.raises(IntegrityError):
            connection.execute(
                current_observation_pointer.insert().values(
                    entity_kind="pull_request",
                    entity_id="different",
                    observation_version_id=observation_id,
                    ordering_key={"sequence": "1"},
                    pointer_version=0,
                    updated_at=NOW,
                )
            )


def test_assessment_evidence_must_belong_to_exact_analysis_view(
    postgres_engine: Engine,
) -> None:
    with postgres_engine.begin() as connection:
        included_observation = _insert_observation(connection)
        assessment_id, view_id = _insert_assessment(
            connection,
            included_observation,
            include_evidence=False,
        )
        unrelated_observation = _insert_observation(connection)
        with pytest.raises(IntegrityError):
            connection.execute(
                preparedness_assessment_evidence.insert().values(
                    assessment_id=assessment_id,
                    analysis_view_id=view_id,
                    observation_version_id=unrelated_observation,
                    facet_role_id="pull_request",
                )
            )


@pytest.mark.parametrize(
    ("table", "values"),
    [
        (
            work_record,
            {
                "work_record_id": uuid4(),
                "delivery_id": uuid4(),
                "work_type": "PROCESS_SYNTHETIC_OBSERVATION",
                "state": "UNKNOWN",
                "available_at": NOW,
            },
        ),
        (
            work_attempt,
            {
                "work_attempt_id": uuid4(),
                "work_record_id": uuid4(),
                "attempt_number": 1,
                "state": "UNKNOWN",
                "started_at": NOW,
            },
        ),
    ],
)
def test_exact_state_inventories_reject_unknown_values(
    postgres_engine: Engine,
    table: sa.Table,
    values: dict[str, object],
) -> None:
    with pytest.raises(IntegrityError), postgres_engine.begin() as connection:
        connection.execute(table.insert().values(**values))


def test_sqlalchemy_row_mapping_cannot_cross_canonical_boundary(
    postgres_engine: Engine,
) -> None:
    with postgres_engine.connect() as connection:
        row_mapping = (
            connection.execute(sa.select(sa.literal(1).label("value"))).mappings().one()
        )
    with pytest.raises(CanonicalizationError, match="SQLAlchemy rows"):
        canonicalize(row_mapping)
