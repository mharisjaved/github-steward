"""Add verified webhook ingress and append-only security events.

Revision ID: gs_i6_0005
Revises: gs_i5_0004
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "gs_i6_0005"
down_revision: str | None = "gs_i5_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_UUID = postgresql.UUID(as_uuid=True)
_TIMESTAMP = postgresql.TIMESTAMP(timezone=True)
_JSONB = postgresql.JSONB()


def upgrade() -> None:
    """Add only persistence required by bounded GS-I6 webhook intake."""

    op.add_column(
        "delivery_inbox",
        sa.Column("raw_payload_digest", sa.Text(), nullable=True),
    )
    op.create_check_constraint(
        "ck_delivery_inbox_raw_payload_digest_sha256",
        "delivery_inbox",
        "raw_payload_digest IS NULL OR raw_payload_digest ~ '^[0-9a-f]{64}$'",
    )
    op.create_check_constraint(
        "ck_delivery_inbox_webhook_raw_digest",
        "delivery_inbox",
        "(payload_schema_id = 'github-steward.github-webhook-delivery/v1' "
        "AND payload_schema_version = 1 AND provider = 'github' "
        "AND raw_payload_digest IS NOT NULL) OR "
        "(payload_schema_id <> 'github-steward.github-webhook-delivery/v1' "
        "AND raw_payload_digest IS NULL)",
    )

    op.drop_constraint(
        "ck_work_record_work_type_inventory",
        "work_record",
        type_="check",
    )
    op.create_check_constraint(
        "ck_work_record_work_type_inventory",
        "work_record",
        "work_type IN ('PROCESS_SYNTHETIC_OBSERVATION', "
        "'REFRESH_GITHUB_PULL_REQUEST', 'REFRESH_GITHUB_REPOSITORY', "
        "'REFRESH_GITHUB_AUTHORIZATION')",
    )

    op.create_table(
        "security_event",
        sa.Column("security_event_id", _UUID, nullable=False),
        sa.Column("delivery_id", _UUID, nullable=False),
        sa.Column("event_kind", sa.Text(), nullable=False),
        sa.Column("occurred_at", _TIMESTAMP, nullable=False),
        sa.Column("schema_id", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("canonical_metadata", _JSONB, nullable=False),
        sa.Column("digest_format", sa.Text(), nullable=False),
        sa.Column("digest_value", sa.Text(), nullable=False),
        sa.Column(
            "inserted_at",
            _TIMESTAMP,
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint(
            "security_event_id",
            name="pk_security_event",
        ),
        sa.ForeignKeyConstraint(
            ["delivery_id"],
            ["delivery_inbox.delivery_id"],
            name="fk_security_event_delivery",
        ),
        sa.CheckConstraint(
            "event_kind IN ("
            "'WEBHOOK_DELIVERY_INTEGRITY_CONFLICT', "
            "'WEBHOOK_SIGNED_SCHEMA_INVALID', "
            "'WEBHOOK_SIGNED_IDENTITY_MISMATCH', "
            "'WEBHOOK_AUTHORIZATION_CONTEXT_MISMATCH', "
            "'WEBHOOK_PERMISSION_CEILING_MISMATCH')",
            name="ck_security_event_kind_inventory",
        ),
        sa.CheckConstraint(
            "schema_id = 'github-steward.security-event/v1'",
            name="ck_security_event_schema_id",
        ),
        sa.CheckConstraint(
            "schema_version = 1",
            name="ck_security_event_schema_version",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(canonical_metadata) = 'object'",
            name="ck_security_event_metadata_object",
        ),
        sa.CheckConstraint(
            "octet_length(canonical_metadata::text) <= 4096",
            name="ck_security_event_metadata_bounded",
        ),
        sa.CheckConstraint(
            "digest_format = 'jcs-sha256/v1'",
            name="ck_security_event_digest_format",
        ),
        sa.CheckConstraint(
            "digest_value ~ '^[0-9a-f]{64}$'",
            name="ck_security_event_digest_value",
        ),
    )
    op.create_index(
        "ix_security_event_delivery_occurrence",
        "security_event",
        ["delivery_id", "occurred_at"],
        unique=False,
    )
    op.execute(
        """
        CREATE TRIGGER trg_security_event_reject_mutation
        BEFORE UPDATE OR DELETE ON security_event
        FOR EACH ROW
        EXECUTE FUNCTION gs_i1_reject_append_only_mutation()
        """
    )


def downgrade() -> None:
    """Remove only GS-I6 persistence and restore GS-I5 constraints."""

    op.drop_index(
        "ix_security_event_delivery_occurrence",
        table_name="security_event",
    )
    op.drop_table("security_event")

    op.drop_constraint(
        "ck_work_record_work_type_inventory",
        "work_record",
        type_="check",
    )
    op.create_check_constraint(
        "ck_work_record_work_type_inventory",
        "work_record",
        "work_type IN ('PROCESS_SYNTHETIC_OBSERVATION', 'REFRESH_GITHUB_PULL_REQUEST')",
    )

    op.drop_constraint(
        "ck_delivery_inbox_webhook_raw_digest",
        "delivery_inbox",
        type_="check",
    )
    op.drop_constraint(
        "ck_delivery_inbox_raw_payload_digest_sha256",
        "delivery_inbox",
        type_="check",
    )
    op.drop_column("delivery_inbox", "raw_payload_digest")
