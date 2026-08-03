"""Shared test configuration."""

from __future__ import annotations

import pytest


@pytest.fixture
def sample_payload() -> dict[str, object]:
    """A deterministic constructed Python payload."""

    return {
        "entity": "pull_request",
        "id": 17,
        "labels": ["ready", "reviewed"],
        "optional": None,
    }
