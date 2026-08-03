"""Add bounded durable local processing and recovery.

Revision ID: gs_i2_0002
Revises: gs_i1_0001
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "gs_i2_0002"
down_revision: str | None = "gs_i1_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TIMESTAMP = postgresql.TIMESTAMP(timezone=True)
_JSONB = postgresql.JSONB()


def upgrade() -> None:
    """Apply the exact GS-I2 changes while retaining eight tables."""

    op.execute(
        """
        DO $block$
        BEGIN
            IF EXISTS (SELECT 1 FROM delivery_inbox LIMIT 1) THEN
                RAISE EXCEPTION
                    'GS-I2 refuses to identify payloads for existing delivery rows'
                    USING ERRCODE = '55000';
            END IF;
        END;
        $block$
        """
    )
    op.add_column(
        "delivery_inbox",
        sa.Column("payload_schema_id", sa.Text(), nullable=False),
    )
    op.add_column(
        "delivery_inbox",
        sa.Column("payload_schema_version", sa.Integer(), nullable=False),
    )
    op.add_column(
        "delivery_inbox",
        sa.Column("canonical_payload", _JSONB, nullable=False),
    )
    op.add_column(
        "delivery_inbox",
        sa.Column("payload_digest_format", sa.Text(), nullable=False),
    )
    op.create_check_constraint(
        "ck_delivery_inbox_payload_schema_id_nonempty",
        "delivery_inbox",
        "payload_schema_id <> ''",
    )
    op.create_check_constraint(
        "ck_delivery_inbox_payload_schema_version_positive",
        "delivery_inbox",
        "payload_schema_version > 0",
    )
    op.create_check_constraint(
        "ck_delivery_inbox_payload_digest_format",
        "delivery_inbox",
        "payload_digest_format = 'jcs-sha256/v1'",
    )
    op.execute(
        """
        CREATE TRIGGER trg_delivery_inbox_reject_mutation
        BEFORE UPDATE OR DELETE ON delivery_inbox
        FOR EACH ROW
        EXECUTE FUNCTION gs_i1_reject_append_only_mutation()
        """
    )

    op.drop_constraint(
        "ck_work_record_state_nonempty",
        "work_record",
        type_="check",
    )
    op.drop_constraint(
        "ck_work_record_lease_all_or_none",
        "work_record",
        type_="check",
    )
    op.create_check_constraint(
        "ck_work_record_state_inventory",
        "work_record",
        "state IN ('AVAILABLE', 'PROCESSING', 'RETRY_WAIT', 'SUCCEEDED', 'FAILED')",
    )
    op.create_check_constraint(
        "ck_work_record_state_lease_consistency",
        "work_record",
        "(state = 'PROCESSING' AND lease_owner IS NOT NULL "
        "AND lease_owner <> '' AND lease_token IS NOT NULL "
        "AND lease_expires_at IS NOT NULL) OR "
        "(state <> 'PROCESSING' AND lease_owner IS NULL "
        "AND lease_token IS NULL AND lease_expires_at IS NULL)",
    )

    op.drop_constraint(
        "ck_work_attempt_state_nonempty",
        "work_attempt",
        type_="check",
    )
    op.drop_constraint(
        "ck_work_attempt_completion_requires_start",
        "work_attempt",
        type_="check",
    )
    op.create_check_constraint(
        "ck_work_attempt_state_inventory",
        "work_attempt",
        "state IN ('STARTED', 'SUCCEEDED', 'RETRYABLE_FAILURE', "
        "'TERMINAL_FAILURE', 'ABANDONED')",
    )
    op.create_check_constraint(
        "ck_work_attempt_state_timestamp_consistency",
        "work_attempt",
        "(state = 'STARTED' AND started_at IS NOT NULL "
        "AND completed_at IS NULL) OR "
        "(state <> 'STARTED' AND started_at IS NOT NULL "
        "AND completed_at IS NOT NULL)",
    )

    op.drop_constraint(
        "fk_current_observation_pointer_observation",
        "current_observation_pointer",
        type_="foreignkey",
    )
    op.create_unique_constraint(
        "uq_canonical_observation_entity_version",
        "canonical_observation",
        ["entity_kind", "entity_id", "observation_version_id"],
    )
    op.create_foreign_key(
        "fk_current_observation_pointer_entity_observation",
        "current_observation_pointer",
        "canonical_observation",
        ["entity_kind", "entity_id", "observation_version_id"],
        ["entity_kind", "entity_id", "observation_version_id"],
    )


def downgrade() -> None:
    """Restore the accepted GS-I1 schema without changing other objects."""

    op.execute("DROP TRIGGER trg_delivery_inbox_reject_mutation ON delivery_inbox")

    op.drop_constraint(
        "fk_current_observation_pointer_entity_observation",
        "current_observation_pointer",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "fk_current_observation_pointer_observation",
        "current_observation_pointer",
        "canonical_observation",
        ["observation_version_id"],
        ["observation_version_id"],
    )
    op.drop_constraint(
        "uq_canonical_observation_entity_version",
        "canonical_observation",
        type_="unique",
    )

    op.drop_constraint(
        "ck_work_attempt_state_timestamp_consistency",
        "work_attempt",
        type_="check",
    )
    op.drop_constraint(
        "ck_work_attempt_state_inventory",
        "work_attempt",
        type_="check",
    )
    op.create_check_constraint(
        "ck_work_attempt_state_nonempty",
        "work_attempt",
        "state <> ''",
    )
    op.create_check_constraint(
        "ck_work_attempt_completion_requires_start",
        "work_attempt",
        "completed_at IS NULL OR started_at IS NOT NULL",
    )

    op.drop_constraint(
        "ck_work_record_state_lease_consistency",
        "work_record",
        type_="check",
    )
    op.drop_constraint(
        "ck_work_record_state_inventory",
        "work_record",
        type_="check",
    )
    op.create_check_constraint(
        "ck_work_record_state_nonempty",
        "work_record",
        "state <> ''",
    )
    op.create_check_constraint(
        "ck_work_record_lease_all_or_none",
        "work_record",
        "(lease_owner IS NULL AND lease_token IS NULL "
        "AND lease_expires_at IS NULL) OR "
        "(lease_owner IS NOT NULL AND lease_token IS NOT NULL "
        "AND lease_expires_at IS NOT NULL)",
    )

    op.drop_constraint(
        "ck_delivery_inbox_payload_digest_format",
        "delivery_inbox",
        type_="check",
    )
    op.drop_constraint(
        "ck_delivery_inbox_payload_schema_version_positive",
        "delivery_inbox",
        type_="check",
    )
    op.drop_constraint(
        "ck_delivery_inbox_payload_schema_id_nonempty",
        "delivery_inbox",
        type_="check",
    )
    op.drop_column("delivery_inbox", "payload_digest_format")
    op.drop_column("delivery_inbox", "canonical_payload")
    op.drop_column("delivery_inbox", "payload_schema_version")
    op.drop_column("delivery_inbox", "payload_schema_id")
