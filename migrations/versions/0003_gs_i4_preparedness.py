"""Add deterministic preparedness persistence.

Revision ID: gs_i4_0003
Revises: gs_i2_0002
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "gs_i4_0003"
down_revision: str | None = "gs_i2_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_UUID = postgresql.UUID(as_uuid=True)
_TIMESTAMP = postgresql.TIMESTAMP(timezone=True)
_JSONB = postgresql.JSONB()


def upgrade() -> None:
    """Add exactly three immutable GS-I4 persistence concepts."""

    op.drop_constraint(
        "ck_delivery_inbox_provider_nonempty",
        "delivery_inbox",
        type_="check",
    )
    op.create_check_constraint(
        "ck_delivery_inbox_provider_inventory",
        "delivery_inbox",
        "provider IN ('synthetic', 'github')",
    )
    op.drop_constraint(
        "ck_work_record_work_type_nonempty",
        "work_record",
        type_="check",
    )
    op.create_check_constraint(
        "ck_work_record_work_type_inventory",
        "work_record",
        "work_type IN ('PROCESS_SYNTHETIC_OBSERVATION', 'REFRESH_GITHUB_PULL_REQUEST')",
    )

    op.create_table(
        "preparedness_profile",
        sa.Column("profile_id", _UUID, nullable=False),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column("repository_id", sa.BigInteger(), nullable=False),
        sa.Column("effective_from", _TIMESTAMP, nullable=False),
        sa.Column("predecessor_profile_id", _UUID, nullable=True),
        sa.Column("predecessor_profile_version", sa.Integer(), nullable=True),
        sa.Column("schema_id", sa.Text(), nullable=False),
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
            "profile_id",
            "profile_version",
            name="pk_preparedness_profile",
        ),
        sa.UniqueConstraint(
            "repository_id",
            "profile_id",
            "profile_version",
            name="uq_preparedness_profile_repository_identity",
        ),
        sa.UniqueConstraint(
            "predecessor_profile_id",
            "predecessor_profile_version",
            name="uq_preparedness_profile_predecessor",
        ),
        sa.ForeignKeyConstraint(
            [
                "repository_id",
                "predecessor_profile_id",
                "predecessor_profile_version",
            ],
            [
                "preparedness_profile.repository_id",
                "preparedness_profile.profile_id",
                "preparedness_profile.profile_version",
            ],
            name="fk_preparedness_profile_predecessor",
        ),
        sa.CheckConstraint(
            "profile_version > 0",
            name="ck_preparedness_profile_version_positive",
        ),
        sa.CheckConstraint(
            "repository_id > 0",
            name="ck_preparedness_profile_repository_positive",
        ),
        sa.CheckConstraint(
            "(profile_version = 1 AND predecessor_profile_id IS NULL "
            "AND predecessor_profile_version IS NULL) OR "
            "(profile_version > 1 AND predecessor_profile_id = profile_id "
            "AND predecessor_profile_version = profile_version - 1)",
            name="ck_preparedness_profile_linear_identity",
        ),
        sa.CheckConstraint(
            "schema_id = 'github-steward/preparedness-profile/v1'",
            name="ck_preparedness_profile_schema",
        ),
        sa.CheckConstraint(
            "digest_format = 'jcs-sha256/v1'",
            name="ck_preparedness_profile_digest_format",
        ),
        sa.CheckConstraint(
            "digest_value ~ '^[0-9a-f]{64}$'",
            name="ck_preparedness_profile_digest_value",
        ),
    )
    op.create_index(
        "ix_preparedness_profile_repository_effective",
        "preparedness_profile",
        ["repository_id", "effective_from"],
        unique=False,
    )
    op.create_table(
        "preparedness_assessment",
        sa.Column("assessment_id", _UUID, nullable=False),
        sa.Column("repository_id", sa.BigInteger(), nullable=False),
        sa.Column("pull_number", sa.BigInteger(), nullable=False),
        sa.Column("head_sha", sa.Text(), nullable=False),
        sa.Column("profile_id", _UUID, nullable=False),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column("analysis_view_id", _UUID, nullable=False),
        sa.Column("evidence_sealed_at", _TIMESTAMP, nullable=False),
        sa.Column("evaluated_at", _TIMESTAMP, nullable=False),
        sa.Column("verdict", sa.Text(), nullable=False),
        sa.Column("schema_id", sa.Text(), nullable=False),
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
            "assessment_id",
            name="pk_preparedness_assessment",
        ),
        sa.UniqueConstraint(
            "assessment_id",
            "analysis_view_id",
            name="uq_preparedness_assessment_view",
        ),
        sa.ForeignKeyConstraint(
            ["repository_id", "profile_id", "profile_version"],
            [
                "preparedness_profile.repository_id",
                "preparedness_profile.profile_id",
                "preparedness_profile.profile_version",
            ],
            name="fk_preparedness_assessment_profile",
        ),
        sa.ForeignKeyConstraint(
            ["analysis_view_id"],
            ["analysis_view.analysis_view_id"],
            name="fk_preparedness_assessment_view",
        ),
        sa.CheckConstraint(
            "repository_id > 0",
            name="ck_preparedness_assessment_repository_positive",
        ),
        sa.CheckConstraint(
            "pull_number > 0",
            name="ck_preparedness_assessment_pull_positive",
        ),
        sa.CheckConstraint(
            "head_sha ~ '^[0-9a-f]{40}$'",
            name="ck_preparedness_assessment_head_sha",
        ),
        sa.CheckConstraint(
            "profile_version > 0",
            name="ck_preparedness_assessment_profile_version_positive",
        ),
        sa.CheckConstraint(
            "verdict IN ('READY_FOR_HUMAN_REVIEW', 'NOT_READY', 'INDETERMINATE')",
            name="ck_preparedness_assessment_verdict_inventory",
        ),
        sa.CheckConstraint(
            "schema_id = 'github-steward/preparedness-assessment/v1'",
            name="ck_preparedness_assessment_schema",
        ),
        sa.CheckConstraint(
            "digest_format = 'jcs-sha256/v1'",
            name="ck_preparedness_assessment_digest_format",
        ),
        sa.CheckConstraint(
            "digest_value ~ '^[0-9a-f]{64}$'",
            name="ck_preparedness_assessment_digest_value",
        ),
    )
    op.create_index(
        "ix_preparedness_assessment_subject_time",
        "preparedness_assessment",
        ["repository_id", "pull_number", "evaluated_at"],
        unique=False,
    )

    op.create_table(
        "preparedness_assessment_evidence",
        sa.Column("assessment_id", _UUID, nullable=False),
        sa.Column("analysis_view_id", _UUID, nullable=False),
        sa.Column("observation_version_id", _UUID, nullable=False),
        sa.Column("facet_role_id", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint(
            "assessment_id",
            "observation_version_id",
            "facet_role_id",
            name="pk_preparedness_assessment_evidence",
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id", "analysis_view_id"],
            [
                "preparedness_assessment.assessment_id",
                "preparedness_assessment.analysis_view_id",
            ],
            name="fk_preparedness_assessment_evidence_assessment",
        ),
        sa.ForeignKeyConstraint(
            ["analysis_view_id", "observation_version_id", "facet_role_id"],
            [
                "analysis_view_observation.analysis_view_id",
                "analysis_view_observation.observation_version_id",
                "analysis_view_observation.facet_role_id",
            ],
            name="fk_preparedness_assessment_evidence_view_observation",
        ),
        sa.CheckConstraint(
            "facet_role_id <> ''",
            name="ck_preparedness_assessment_evidence_facet_nonempty",
        ),
    )
    op.create_index(
        "ix_preparedness_assessment_evidence_observation",
        "preparedness_assessment_evidence",
        ["observation_version_id"],
        unique=False,
    )

    for table_name in (
        "preparedness_profile",
        "preparedness_assessment",
        "preparedness_assessment_evidence",
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
    """Remove only the three GS-I4 concepts and restore GS-I2 constraints."""

    op.drop_index(
        "ix_preparedness_assessment_evidence_observation",
        table_name="preparedness_assessment_evidence",
    )
    op.drop_table("preparedness_assessment_evidence")
    op.drop_index(
        "ix_preparedness_assessment_subject_time",
        table_name="preparedness_assessment",
    )
    op.drop_table("preparedness_assessment")
    op.drop_index(
        "ix_preparedness_profile_repository_effective",
        table_name="preparedness_profile",
    )
    op.drop_table("preparedness_profile")

    op.drop_constraint(
        "ck_work_record_work_type_inventory",
        "work_record",
        type_="check",
    )
    op.create_check_constraint(
        "ck_work_record_work_type_nonempty",
        "work_record",
        "work_type <> ''",
    )
    op.drop_constraint(
        "ck_delivery_inbox_provider_inventory",
        "delivery_inbox",
        type_="check",
    )
    op.create_check_constraint(
        "ck_delivery_inbox_provider_nonempty",
        "delivery_inbox",
        "provider <> ''",
    )
