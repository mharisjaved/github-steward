"""Add GitHub App installation and repository authorization state.

Revision ID: gs_i5_0004
Revises: gs_i4_0003
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "gs_i5_0004"
down_revision: str | None = "gs_i4_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_UUID = postgresql.UUID(as_uuid=True)
_TIMESTAMP = postgresql.TIMESTAMP(timezone=True)


def upgrade() -> None:
    """Add exactly the two credential-free GS-I5 authorization concepts."""

    op.create_table(
        "installation_observation",
        sa.Column("observation_id", _UUID, nullable=False),
        sa.Column("installation_id", sa.BigInteger(), nullable=False),
        sa.Column("app_id", sa.BigInteger(), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=False),
        sa.Column("account_type", sa.Text(), nullable=False),
        sa.Column("repository_selection", sa.Text(), nullable=False),
        sa.Column("permission_metadata", sa.Text(), nullable=False),
        sa.Column("permission_pull_requests", sa.Text(), nullable=False),
        sa.Column("permission_checks", sa.Text(), nullable=False),
        sa.Column("permission_statuses", sa.Text(), nullable=False),
        sa.Column("suspended", sa.Boolean(), nullable=False),
        sa.Column("suspended_at", _TIMESTAMP, nullable=True),
        sa.Column("observed_at", _TIMESTAMP, nullable=False),
        sa.Column("source_digest", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            _TIMESTAMP,
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint(
            "observation_id",
            name="pk_installation_observation",
        ),
        sa.CheckConstraint(
            "installation_id > 0",
            name="ck_installation_observation_installation_positive",
        ),
        sa.CheckConstraint(
            "app_id > 0",
            name="ck_installation_observation_app_positive",
        ),
        sa.CheckConstraint(
            "account_id > 0",
            name="ck_installation_observation_account_positive",
        ),
        sa.CheckConstraint(
            "account_type IN ('User', 'Organization')",
            name="ck_installation_observation_account_type_inventory",
        ),
        sa.CheckConstraint(
            "repository_selection IN ('all', 'selected')",
            name="ck_installation_observation_selection_inventory",
        ),
        sa.CheckConstraint(
            "permission_metadata IN ('none', 'read')",
            name="ck_installation_observation_metadata_permission",
        ),
        sa.CheckConstraint(
            "permission_pull_requests IN ('none', 'read')",
            name="ck_installation_observation_pull_requests_permission",
        ),
        sa.CheckConstraint(
            "permission_checks IN ('none', 'read')",
            name="ck_installation_observation_checks_permission",
        ),
        sa.CheckConstraint(
            "permission_statuses IN ('none', 'read')",
            name="ck_installation_observation_statuses_permission",
        ),
        sa.CheckConstraint(
            "(suspended AND suspended_at IS NOT NULL) OR "
            "(NOT suspended AND suspended_at IS NULL)",
            name="ck_installation_observation_suspension_consistency",
        ),
        sa.CheckConstraint(
            "suspended_at IS NULL OR suspended_at <= observed_at",
            name="ck_installation_observation_suspension_time",
        ),
        sa.CheckConstraint(
            "source_digest ~ '^[0-9a-f]{64}$'",
            name="ck_installation_observation_source_digest",
        ),
    )
    op.create_index(
        "ix_installation_observation_installation_time",
        "installation_observation",
        ["installation_id", "observed_at"],
        unique=False,
    )
    op.execute(
        """
        CREATE TRIGGER trg_installation_observation_reject_mutation
        BEFORE UPDATE OR DELETE ON installation_observation
        FOR EACH ROW
        EXECUTE FUNCTION gs_i1_reject_append_only_mutation()
        """
    )

    op.create_table(
        "repository_authorization",
        sa.Column("repository_id", sa.BigInteger(), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("installation_id", sa.BigInteger(), nullable=False),
        sa.Column("installation_observation_id", _UUID, nullable=False),
        sa.Column("route_owner", sa.Text(), nullable=False),
        sa.Column("route_repository", sa.Text(), nullable=False),
        sa.Column("installation_account_id", sa.BigInteger(), nullable=False),
        sa.Column("repository_selected", sa.Boolean(), nullable=False),
        sa.Column("route_verified", sa.Boolean(), nullable=False),
        sa.Column("granted_metadata", sa.Text(), nullable=False),
        sa.Column("granted_pull_requests", sa.Text(), nullable=False),
        sa.Column("granted_checks", sa.Text(), nullable=False),
        sa.Column("granted_statuses", sa.Text(), nullable=False),
        sa.Column("capability", sa.Text(), nullable=False),
        sa.Column(
            "write_enabled",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
        sa.Column("updated_at", _TIMESTAMP, nullable=False),
        sa.PrimaryKeyConstraint(
            "repository_id",
            name="pk_repository_authorization",
        ),
        sa.ForeignKeyConstraint(
            ["installation_observation_id"],
            ["installation_observation.observation_id"],
            name="fk_repository_authorization_installation_observation",
        ),
        sa.CheckConstraint(
            "repository_id > 0",
            name="ck_repository_authorization_repository_positive",
        ),
        sa.CheckConstraint(
            "authorization_version > 0",
            name="ck_repository_authorization_version_positive",
        ),
        sa.CheckConstraint(
            "installation_id > 0",
            name="ck_repository_authorization_installation_positive",
        ),
        sa.CheckConstraint(
            "installation_account_id > 0",
            name="ck_repository_authorization_account_positive",
        ),
        sa.CheckConstraint(
            "route_owner <> '' AND route_repository <> ''",
            name="ck_repository_authorization_route_nonempty",
        ),
        sa.CheckConstraint(
            "granted_metadata IN ('none', 'read')",
            name="ck_repository_authorization_metadata_permission",
        ),
        sa.CheckConstraint(
            "granted_pull_requests IN ('none', 'read')",
            name="ck_repository_authorization_pull_requests_permission",
        ),
        sa.CheckConstraint(
            "granted_checks IN ('none', 'read')",
            name="ck_repository_authorization_checks_permission",
        ),
        sa.CheckConstraint(
            "granted_statuses IN ('none', 'read')",
            name="ck_repository_authorization_statuses_permission",
        ),
        sa.CheckConstraint(
            "capability IN ('AUTHORIZED_READ', 'INSTALLATION_SUSPENDED', "
            "'REPOSITORY_NOT_SELECTED', 'INSUFFICIENT_PERMISSIONS', "
            "'ROUTE_UNVERIFIED', 'INSTALLATION_MISMATCH')",
            name="ck_repository_authorization_capability_inventory",
        ),
        sa.CheckConstraint(
            "write_enabled = false",
            name="ck_repository_authorization_write_disabled",
        ),
    )
    op.create_index(
        "ix_repository_authorization_installation",
        "repository_authorization",
        ["installation_id"],
        unique=False,
    )
    op.execute(
        """
        CREATE FUNCTION gs_i5_require_authorization_cas_version()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $function$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'repository authorization deletion is forbidden'
                    USING ERRCODE = '55000';
            END IF;
            IF NEW.repository_id <> OLD.repository_id
               OR NEW.authorization_version <> OLD.authorization_version + 1 THEN
                RAISE EXCEPTION
                    'repository authorization requires an exact version increment'
                    USING ERRCODE = '40001';
            END IF;
            RETURN NEW;
        END;
        $function$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_repository_authorization_require_cas_version
        BEFORE UPDATE OR DELETE ON repository_authorization
        FOR EACH ROW
        EXECUTE FUNCTION gs_i5_require_authorization_cas_version()
        """
    )


def downgrade() -> None:
    """Remove only the two GS-I5 authorization concepts."""

    op.drop_index(
        "ix_repository_authorization_installation",
        table_name="repository_authorization",
    )
    op.drop_table("repository_authorization")
    op.execute("DROP FUNCTION gs_i5_require_authorization_cas_version()")
    op.drop_index(
        "ix_installation_observation_installation_time",
        table_name="installation_observation",
    )
    op.drop_table("installation_observation")
