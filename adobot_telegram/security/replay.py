"""Replay protection for authenticated commands."""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass


DEFAULT_MAX_AGE_SECONDS = 300


@dataclass
class ReplayGuard:
    max_age: int = DEFAULT_MAX_AGE_SECONDS

    def validate_timestamp(self, issued_at: int, now: int | None = None) -> None:
        current = int(time.time()) if now is None else now

        if issued_at > current + self.max_age:
            raise ValueError("command timestamp is in the future")

        if current - issued_at > self.max_age:
            raise ValueError("command has expired")

    @staticmethod
    def digest(command_id: str, nonce: str) -> str:
        return hashlib.sha256(
            f"{command_id}:{nonce}".encode("utf-8")
        ).hexdigest()

    @staticmethod
    def constant_time_equal(left: str, right: str) -> bool:
        return hmac.compare_digest(left, right)

class ReplayCache:
    """
    Bounded process-local replay cache.

    A previously accepted principal/command/nonce tuple cannot be accepted
    again until its entry expires. Entries are pruned by TTL and bounded by
    max_entries.
    """

    def __init__(
        self,
        *,
        max_entries: int = 4096,
        ttl_seconds: int = DEFAULT_MAX_AGE_SECONDS,
    ) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")

        from threading import RLock

        self._max_entries = max_entries
        self._ttl_seconds = ttl_seconds
        self._entries: dict[str, float] = {}
        self._lock = RLock()

    def _prune(self, now: float) -> None:
        expired = [
            key
            for key, expires_at in self._entries.items()
            if expires_at <= now
        ]

        for key in expired:
            self._entries.pop(key, None)

        overflow = len(self._entries) - self._max_entries

        if overflow > 0:
            oldest = sorted(
                self._entries.items(),
                key=lambda item: item[1],
            )[:overflow]

            for key, _ in oldest:
                self._entries.pop(key, None)

    def check_and_record(
        self,
        *,
        principal: str,
        command_id: str,
        nonce: str,
        now: float | None = None,
    ) -> bool:
        if not principal or not command_id or not nonce:
            raise ValueError(
                "principal, command_id and nonce are required"
            )

        import time

        current = time.time() if now is None else float(now)
        key = f"{principal}:{ReplayGuard.digest(command_id, nonce)}"

        with self._lock:
            self._prune(current)

            if key in self._entries:
                return False

            self._entries[key] = current + self._ttl_seconds
            self._prune(current)

            return True

    def size(self) -> int:
        with self._lock:
            return len(self._entries)
