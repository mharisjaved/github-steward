"""Domain error types."""

from __future__ import annotations


class DomainValidationError(ValueError):
    """A value violates a project-owned domain contract."""


class CanonicalizationError(DomainValidationError):
    """A value cannot cross the strict canonicalization boundary."""


class InvalidTransitionError(DomainValidationError):
    """A requested lifecycle transition is not explicitly authorized."""

    def __init__(self, lifecycle: str, source: str, target: str) -> None:
        self.lifecycle = lifecycle
        self.source = source
        self.target = target
        super().__init__(f"{lifecycle} cannot transition from {source} to {target}")


class RetryableLocalProcessingError(Exception):
    """A deterministic local-processing failure that may be retried."""


class PermanentLocalProcessingError(Exception):
    """A deterministic local-processing failure that must not be retried."""
