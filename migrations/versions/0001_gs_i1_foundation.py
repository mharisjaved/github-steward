"""Establish the bounded GS-I1 PostgreSQL foundation.

Revision ID: gs_i1_0001
Revises: None
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "gs_i1_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_UUID = postgresql.UUID(as_uuid=True)
_TIMESTAMP = postgresql.TIMESTAMP(timezone=True)
_JSONB = postgresql.JSONB()


def upgrade() -> None:
    """Create exactly the eight authorized GS-I1 tables and append-only triggers."""

    op.create_table(
        "delivery_inbox",
        sa.Column("delivery_id", _UUID, nullable=False),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("provider_delivery_id", sa.Text(), nullable=False),
        sa.Column("payload_digest", sa.Text(), nullable=False),
        sa.Column("received_at", _TIMESTAMP, nullable=False),
        sa.PrimaryKeyConstraint("delivery_id", name="pk_delivery_inbox"),
        sa.UniqueConstraint(
            "provider",
            "provider_delivery_id",
            name="uq_delivery_inbox_provider_delivery",
        ),
        sa.CheckConstraint(
            "provider <> ''",
            name="ck_delivery_inbox_provider_nonempty",
        ),
        sa.CheckConstraint(
            "provider_delivery_id <> ''",
            name="ck_delivery_inbox_provider_delivery_id_nonempty",
        ),
        sa.CheckConstraint(
            "payload_digest ~ '^[0-9a-f]{64}$'",
            name="ck_delivery_inbox_payload_digest_sha256",
        ),
    )
    op.create_table(
        "work_record",
        sa.Column("work_record_id", _UUID, nullable=False),
        sa.Column("delivery_id", _UUID, nullable=False),
        sa.Column("work_type", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("available_at", _TIMESTAMP, nullable=False),
        sa.Column("lease_owner", sa.Text(), nullable=True),
        sa.Column("lease_token", _UUID, nullable=True),
        sa.Column("lease_expires_at", _TIMESTAMP, nullable=True),
        sa.Column("version", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column(
            "created_at",
            _TIMESTAMP,
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            _TIMESTAMP,
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("work_record_id", name="pk_work_record"),
        sa.ForeignKeyConstraint(
            ["delivery_id"],
            ["delivery_inbox.delivery_id"],
            name="fk_work_record_delivery",
        ),
        sa.UniqueConstraint("delivery_id", name="uq_work_record_delivery"),
        sa.CheckConstraint(
            "work_type <> ''",
            name="ck_work_record_work_type_nonempty",
        ),
        sa.CheckConstraint("state <> ''", name="ck_work_record_state_nonempty"),
        sa.CheckConstraint(
            "version >= 0",
            name="ck_work_record_version_nonnegative",
        ),
        sa.CheckConstraint(
            "(lease_owner IS NULL AND lease_token IS NULL "
            "AND lease_expires_at IS NULL) OR "
            "(lease_owner IS NOT NULL AND lease_token IS NOT NULL "
            "AND lease_expires_at IS NOT NULL)",
            name="ck_work_record_lease_all_or_none",
        ),
    )
    op.create_index(
        "ix_work_record_available_state",
        "work_record",
        ["state", "available_at"],
        unique=False,
    )
    op.create_index(
        "ix_work_record_lease_expiry",
        "work_record",
        ["lease_expires_at"],
        unique=False,
        postgresql_where=sa.text("lease_expires_at IS NOT NULL"),
    )
    op.create_table(
        "work_attempt",
        sa.Column("work_attempt_id", _UUID, nullable=False),
        sa.Column("work_record_id", _UUID, nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("started_at", _TIMESTAMP, nullable=True),
        sa.Column("completed_at", _TIMESTAMP, nullable=True),
        sa.PrimaryKeyConstraint("work_attempt_id", name="pk_work_attempt"),
        sa.ForeignKeyConstraint(
            ["work_record_id"],
            ["work_record.work_record_id"],
            name="fk_work_attempt_work_record",
        ),
        sa.UniqueConstraint(
            "work_record_id",
            "attempt_number",
            name="uq_work_attempt_work_number",
        ),
        sa.CheckConstraint(
            "attempt_number > 0",
            name="ck_work_attempt_number_positive",
        ),
        sa.CheckConstraint("state <> ''", name="ck_work_attempt_state_nonempty"),
        sa.CheckConstraint(
            "completed_at IS NULL OR started_at IS NOT NULL",
            name="ck_work_attempt_completion_requires_start",
        ),
    )
    op.create_index(
        "ix_work_attempt_state",
        "work_attempt",
        ["state"],
        unique=False,
    )
    op.create_table(
        "canonical_observation",
        sa.Column("observation_version_id", _UUID, nullable=False),
        sa.Column("entity_kind", sa.Text(), nullable=False),
        sa.Column("entity_id", sa.Text(), nullable=False),
        sa.Column("schema_id", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("observed_at", _TIMESTAMP, nullable=False),
        sa.Column("canonical_payload", _JSONB, nullable=False),
        sa.Column("digest_format", sa.Text(), nullable=False),
        sa.Column("digest_value", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            _TIMESTAMP,
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint(
            "observation_version_id",
            name="pk_canonical_observation",
        ),
        sa.CheckConstraint(
            "entity_kind <> ''",
            name="ck_canonical_observation_entity_kind_nonempty",
        ),
        sa.CheckConstraint(
            "entity_id <> ''",
            name="ck_canonical_observation_entity_id_nonempty",
        ),
        sa.CheckConstraint(
            "schema_id <> ''",
            name="ck_canonical_observation_schema_id_nonempty",
        ),
        sa.CheckConstraint(
            "schema_version > 0",
            name="ck_canonical_observation_schema_version_positive",
        ),
        sa.CheckConstraint(
            "digest_format = 'jcs-sha256/v1'",
            name="ck_canonical_observation_digest_format",
        ),
        sa.CheckConstraint(
            "digest_value ~ '^[0-9a-f]{64}$'",
            name="ck_canonical_observation_digest_value",
        ),
    )
    op.create_index(
        "ix_canonical_observation_entity_time",
        "canonical_observation",
        ["entity_kind", "entity_id", "observed_at"],
        unique=False,
    )
    op.create_table(
        "current_observation_pointer",
        sa.Column("entity_kind", sa.Text(), nullable=False),
        sa.Column("entity_id", sa.Text(), nullable=False),
        sa.Column("observation_version_id", _UUID, nullable=False),
        sa.Column("ordering_key", _JSONB, nullable=False),
        sa.Column(
            "pointer_version",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            _TIMESTAMP,
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint(
            "entity_kind",
            "entity_id",
            name="pk_current_observation_pointer",
        ),
        sa.ForeignKeyConstraint(
            ["observation_version_id"],
            ["canonical_observation.observation_version_id"],
            name="fk_current_observation_pointer_observation",
        ),
        sa.CheckConstraint(
            "entity_kind <> ''",
            name="ck_current_observation_pointer_entity_kind_nonempty",
        ),
        sa.CheckConstraint(
            "entity_id <> ''",
            name="ck_current_observation_pointer_entity_id_nonempty",
        ),
        sa.CheckConstraint(
            "pointer_version >= 0",
            name="ck_current_observation_pointer_version_nonnegative",
        ),
    )
    op.create_index(
        "ix_current_observation_pointer_version",
        "current_observation_pointer",
        ["observation_version_id"],
        unique=False,
    )
    op.create_table(
        "analysis_view",
        sa.Column("analysis_view_id", _UUID, nullable=False),
        sa.Column("schema_id", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("canonical_payload", _JSONB, nullable=False),
        sa.Column("digest_format", sa.Text(), nullable=False),
        sa.Column("digest_value", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            _TIMESTAMP,
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("analysis_view_id", name="pk_analysis_view"),
        sa.CheckConstraint(
            "schema_id <> ''",
            name="ck_analysis_view_schema_id_nonempty",
        ),
        sa.CheckConstraint(
            "schema_version > 0",
            name="ck_analysis_view_schema_version_positive",
        ),
        sa.CheckConstraint(
            "digest_format = 'jcs-sha256/v1'",
            name="ck_analysis_view_digest_format",
        ),
        sa.CheckConstraint(
            "digest_value ~ '^[0-9a-f]{64}$'",
            name="ck_analysis_view_digest_value",
        ),
    )
    op.create_table(
        "analysis_view_observation",
        sa.Column("analysis_view_id", _UUID, nullable=False),
        sa.Column("observation_version_id", _UUID, nullable=False),
        sa.Column("facet_role_id", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint(
            "analysis_view_id",
            "observation_version_id",
            "facet_role_id",
            name="pk_analysis_view_observation",
        ),
        sa.ForeignKeyConstraint(
            ["analysis_view_id"],
            ["analysis_view.analysis_view_id"],
            name="fk_analysis_view_observation_view",
        ),
        sa.ForeignKeyConstraint(
            ["observation_version_id"],
            ["canonical_observation.observation_version_id"],
            name="fk_analysis_view_observation_observation",
        ),
        sa.CheckConstraint(
            "facet_role_id <> ''",
            name="ck_analysis_view_observation_facet_nonempty",
        ),
    )
    op.create_index(
        "ix_analysis_view_observation_version",
        "analysis_view_observation",
        ["observation_version_id"],
        unique=False,
    )
    op.create_table(
        "audit_event",
        sa.Column("audit_event_id", _UUID, nullable=False),
        sa.Column("event_kind", sa.Text(), nullable=False),
        sa.Column("actor_or_authority_id", sa.Text(), nullable=False),
        sa.Column("occurred_at", _TIMESTAMP, nullable=False),
        sa.Column("schema_id", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("canonical_payload", _JSONB, nullable=False),
        sa.Column("digest_format", sa.Text(), nullable=False),
        sa.Column("digest_value", sa.Text(), nullable=False),
        sa.Column(
            "inserted_at",
            _TIMESTAMP,
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("audit_event_id", name="pk_audit_event"),
        sa.CheckConstraint(
            "event_kind <> ''",
            name="ck_audit_event_event_kind_nonempty",
        ),
        sa.CheckConstraint(
            "actor_or_authority_id <> ''",
            name="ck_audit_event_actor_nonempty",
        ),
        sa.CheckConstraint(
            "schema_id <> ''",
            name="ck_audit_event_schema_id_nonempty",
        ),
        sa.CheckConstraint(
            "schema_version > 0",
            name="ck_audit_event_schema_version_positive",
        ),
        sa.CheckConstraint(
            "digest_format = 'jcs-sha256/v1'",
            name="ck_audit_event_digest_format",
        ),
        sa.CheckConstraint(
            "digest_value ~ '^[0-9a-f]{64}$'",
            name="ck_audit_event_digest_value",
        ),
    )
    op.create_index(
        "ix_audit_event_occurrence",
        "audit_event",
        ["occurred_at"],
        unique=False,
    )
    op.execute(
        """
        CREATE FUNCTION gs_i1_reject_append_only_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $function$
        BEGIN
            RAISE EXCEPTION '% is append-only; % is prohibited',
                TG_TABLE_NAME, TG_OP
                USING ERRCODE = '55000';
        END;
        $function$
        """
    )
    for table_name in (
        "canonical_observation",
        "analysis_view",
        "analysis_view_observation",
        "audit_event",
    ):
        op.execute(
            f"""
            CREATE TRIGGER trg_{table_name}_reject_mutation
            BEFORE UPDATE OR DELETE ON {table_name}
            FOR EACH ROW
            EXECUTE FUNCTION gs_i1_reject_append_only_mutation()
            """
        )


def downgrade() -> None:
    """Remove only the GS-I1 objects."""

    op.drop_index("ix_audit_event_occurrence", table_name="audit_event")
    op.drop_table("audit_event")
    op.drop_index(
        "ix_analysis_view_observation_version",
        table_name="analysis_view_observation",
    )
    op.drop_table("analysis_view_observation")
    op.drop_table("analysis_view")
    op.drop_index(
        "ix_current_observation_pointer_version",
        table_name="current_observation_pointer",
    )
    op.drop_table("current_observation_pointer")
    op.drop_index(
        "ix_canonical_observation_entity_time",
        table_name="canonical_observation",
    )
    op.drop_table("canonical_observation")
    op.drop_index("ix_work_attempt_state", table_name="work_attempt")
    op.drop_table("work_attempt")
    op.drop_index("ix_work_record_lease_expiry", table_name="work_record")
    op.drop_index("ix_work_record_available_state", table_name="work_record")
    op.drop_table("work_record")
    op.drop_table("delivery_inbox")
    op.execute("DROP FUNCTION gs_i1_reject_append_only_mutation()")
