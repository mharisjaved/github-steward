"""Explicit time source for deterministic services."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol


class Clock(Protocol):
    """Supply the current time without implicit wall-clock access."""

    def now(self) -> datetime:
        """Return one timezone-aware UTC timestamp."""
