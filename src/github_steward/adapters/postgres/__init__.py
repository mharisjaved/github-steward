"""Synchronous SQLAlchemy Core PostgreSQL metadata."""

from github_steward.adapters.postgres.metadata import (
    APPEND_ONLY_TABLE_NAMES,
    TABLE_NAMES,
    metadata,
)

__all__ = ["APPEND_ONLY_TABLE_NAMES", "TABLE_NAMES", "metadata"]
