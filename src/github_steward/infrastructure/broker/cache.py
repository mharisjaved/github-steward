"""Process-local, authorization-versioned installation-token cache."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import RLock
from typing import Final

from github_steward.domain.processing import require_utc_datetime
from github_steward.ports.secrets import OpaqueBearerToken

CACHE_SAFETY_MARGIN: Final = timedelta(seconds=300)


@dataclass(frozen=True, slots=True)
class TokenCacheKey:
    installation_id: int
    repository_id: int
    authorization_version: int
    permissions_digest: str


@dataclass(frozen=True, slots=True)
class CachedReadToken:
    token: OpaqueBearerToken
    expires_at: datetime


class ReadTokenCache:
    """Thread-safe volatile cache; no persistence operation exists."""

    __slots__ = ("_entries", "_lock")

    def __init__(self) -> None:
        self._entries: dict[TokenCacheKey, CachedReadToken] = {}
        self._lock = RLock()

    def get(self, key: TokenCacheKey, *, now: datetime) -> CachedReadToken | None:
        checked_now = require_utc_datetime(now, "cache_now")
        with self._lock:
            cached = self._entries.get(key)
            if cached is None:
                return None
            if checked_now >= cached.expires_at - CACHE_SAFETY_MARGIN:
                self._entries.pop(key, None)
                return None
            return cached

    def put(
        self,
        key: TokenCacheKey,
        *,
        token: OpaqueBearerToken,
        expires_at: datetime,
    ) -> None:
        checked_expiry = require_utc_datetime(expires_at, "token_expires_at")
        with self._lock:
            self._entries[key] = CachedReadToken(token, checked_expiry)

    def invalidate_repository(self, repository_id: int) -> None:
        with self._lock:
            doomed = [
                key for key in self._entries if key.repository_id == repository_id
            ]
            for key in doomed:
                self._entries.pop(key, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
