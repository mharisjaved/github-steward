"""Project-owned port for public GitHub reads."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from github_steward.ports.persistence import DeliveryIngressResult


@dataclass(frozen=True, slots=True)
class GitHubResponse:
    """Validated JSON response plus authoritative raw-body provenance."""

    value: object
    raw_sha256: str
    next_url: str | None
    path: str


@dataclass(frozen=True, slots=True)
class RequestAudit:
    """Credential-free request fact suitable for evidence."""

    method: str
    host: str
    path: str
    classification: str
    scheme: str = "https"
    port_classification: str = "default_https"
    query: tuple[tuple[str, str], ...] = ()
    application_headers: tuple[str, ...] = ()
    credentials_absent: bool = True
    raw_response_sha256: str | None = None
    raw_target: str = ""
    endpoint_kind: str = ""
    semantic_identity: tuple[tuple[str, str], ...] = ()
    current_page: int = 1
    next_page: int | None = None


class GitHubReadPort(Protocol):
    """Only the operation required by GS-I3; no mutation surface exists."""

    @property
    def audit(self) -> tuple[RequestAudit, ...]: ...

    def get(self, path_or_url: str) -> GitHubResponse: ...


class DecodedMappingIntake(Protocol):
    """Existing GS-I2 decoded-mapping durable intake shape."""

    def receive(
        self, *, provider_delivery_id: str, mapping: Mapping[str, object]
    ) -> DeliveryIngressResult: ...
