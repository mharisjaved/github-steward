"""The bounded eight-table GS-I1 PostgreSQL metadata foundation."""

from __future__ import annotations

from typing import Final

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

metadata = sa.MetaData()

_UUID = postgresql.UUID(as_uuid=True)
_TIMESTAMP = postgresql.TIMESTAMP(timezone=True)
_JSONB = postgresql.JSONB()
_NOW = sa.text("CURRENT_TIMESTAMP")

delivery_inbox = sa.Table(
    "delivery_inbox",
    metadata,
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

work_record = sa.Table(
    "work_record",
    metadata,
    sa.Column("work_record_id", _UUID, nullable=False),
    sa.Column("delivery_id", _UUID, nullable=False),
    sa.Column("work_type", sa.Text(), nullable=False),
    sa.Column("state", sa.Text(), nullable=False),
    sa.Column("available_at", _TIMESTAMP, nullable=False),
    sa.Column("lease_owner", sa.Text(), nullable=True),
    sa.Column("lease_token", _UUID, nullable=True),
    sa.Column("lease_expires_at", _TIMESTAMP, nullable=True),
    sa.Column("version", sa.Integer(), nullable=False, server_default=sa.text("0")),
    sa.Column("created_at", _TIMESTAMP, nullable=False, server_default=_NOW),
    sa.Column("updated_at", _TIMESTAMP, nullable=False, server_default=_NOW),
    sa.PrimaryKeyConstraint("work_record_id", name="pk_work_record"),
    sa.ForeignKeyConstraint(
        ["delivery_id"],
        ["delivery_inbox.delivery_id"],
        name="fk_work_record_delivery",
    ),
    sa.UniqueConstraint("delivery_id", name="uq_work_record_delivery"),
    sa.CheckConstraint("work_type <> ''", name="ck_work_record_work_type_nonempty"),
    sa.CheckConstraint("state <> ''", name="ck_work_record_state_nonempty"),
    sa.CheckConstraint("version >= 0", name="ck_work_record_version_nonnegative"),
    sa.CheckConstraint(
        "(lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL) "
        "OR (lease_owner IS NOT NULL AND lease_token IS NOT NULL "
        "AND lease_expires_at IS NOT NULL)",
        name="ck_work_record_lease_all_or_none",
    ),
)
sa.Index(
    "ix_work_record_available_state",
    work_record.c.state,
    work_record.c.available_at,
)
sa.Index(
    "ix_work_record_lease_expiry",
    work_record.c.lease_expires_at,
    postgresql_where=work_record.c.lease_expires_at.is_not(None),
)

work_attempt = sa.Table(
    "work_attempt",
    metadata,
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
sa.Index("ix_work_attempt_state", work_attempt.c.state)

canonical_observation = sa.Table(
    "canonical_observation",
    metadata,
    sa.Column("observation_version_id", _UUID, nullable=False),
    sa.Column("entity_kind", sa.Text(), nullable=False),
    sa.Column("entity_id", sa.Text(), nullable=False),
    sa.Column("schema_id", sa.Text(), nullable=False),
    sa.Column("schema_version", sa.Integer(), nullable=False),
    sa.Column("observed_at", _TIMESTAMP, nullable=False),
    sa.Column("canonical_payload", _JSONB, nullable=False),
    sa.Column("digest_format", sa.Text(), nullable=False),
    sa.Column("digest_value", sa.Text(), nullable=False),
    sa.Column("created_at", _TIMESTAMP, nullable=False, server_default=_NOW),
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
sa.Index(
    "ix_canonical_observation_entity_time",
    canonical_observation.c.entity_kind,
    canonical_observation.c.entity_id,
    canonical_observation.c.observed_at,
)

current_observation_pointer = sa.Table(
    "current_observation_pointer",
    metadata,
    sa.Column("entity_kind", sa.Text(), nullable=False),
    sa.Column("entity_id", sa.Text(), nullable=False),
    sa.Column("observation_version_id", _UUID, nullable=False),
    sa.Column("ordering_key", _JSONB, nullable=False),
    sa.Column(
        "pointer_version",
        sa.Integer(),
        nullable=False,
        server_default=sa.text("0"),
    ),
    sa.Column("updated_at", _TIMESTAMP, nullable=False, server_default=_NOW),
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
sa.Index(
    "ix_current_observation_pointer_version",
    current_observation_pointer.c.observation_version_id,
)

analysis_view = sa.Table(
    "analysis_view",
    metadata,
    sa.Column("analysis_view_id", _UUID, nullable=False),
    sa.Column("schema_id", sa.Text(), nullable=False),
    sa.Column("schema_version", sa.Integer(), nullable=False),
    sa.Column("canonical_payload", _JSONB, nullable=False),
    sa.Column("digest_format", sa.Text(), nullable=False),
    sa.Column("digest_value", sa.Text(), nullable=False),
    sa.Column("created_at", _TIMESTAMP, nullable=False, server_default=_NOW),
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

analysis_view_observation = sa.Table(
    "analysis_view_observation",
    metadata,
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
sa.Index(
    "ix_analysis_view_observation_version",
    analysis_view_observation.c.observation_version_id,
)

audit_event = sa.Table(
    "audit_event",
    metadata,
    sa.Column("audit_event_id", _UUID, nullable=False),
    sa.Column("event_kind", sa.Text(), nullable=False),
    sa.Column("actor_or_authority_id", sa.Text(), nullable=False),
    sa.Column("occurred_at", _TIMESTAMP, nullable=False),
    sa.Column("schema_id", sa.Text(), nullable=False),
    sa.Column("schema_version", sa.Integer(), nullable=False),
    sa.Column("canonical_payload", _JSONB, nullable=False),
    sa.Column("digest_format", sa.Text(), nullable=False),
    sa.Column("digest_value", sa.Text(), nullable=False),
    sa.Column("inserted_at", _TIMESTAMP, nullable=False, server_default=_NOW),
    sa.PrimaryKeyConstraint("audit_event_id", name="pk_audit_event"),
    sa.CheckConstraint(
        "event_kind <> ''",
        name="ck_audit_event_event_kind_nonempty",
    ),
    sa.CheckConstraint(
        "actor_or_authority_id <> ''",
        name="ck_audit_event_actor_nonempty",
    ),
    sa.CheckConstraint("schema_id <> ''", name="ck_audit_event_schema_id_nonempty"),
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
sa.Index("ix_audit_event_occurrence", audit_event.c.occurred_at)

TABLE_NAMES: Final = (
    "delivery_inbox",
    "work_record",
    "work_attempt",
    "canonical_observation",
    "current_observation_pointer",
    "analysis_view",
    "analysis_view_observation",
    "audit_event",
)
APPEND_ONLY_TABLE_NAMES: Final = (
    "canonical_observation",
    "analysis_view",
    "audit_event",
)

assert tuple(metadata.tables) == TABLE_NAMES
