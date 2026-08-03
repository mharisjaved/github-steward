"""Standard local UTC clock implementation."""

from __future__ import annotations

from datetime import UTC, datetime


class SystemClock:
    """Read the wall clock only behind the explicit Clock port."""

    def now(self) -> datetime:
        """Return the current timezone-aware UTC time."""

        return datetime.now(UTC)
