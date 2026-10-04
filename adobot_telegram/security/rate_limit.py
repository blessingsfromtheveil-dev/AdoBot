"""Small in-process fail-closed rate limiter."""

from __future__ import annotations

import threading
import time
from collections import deque


class RateLimitExceeded(RuntimeError):
    """Raised when a principal exceeds its request allowance."""


class RateLimiter:
    def __init__(
        self,
        *,
        limit: int = 30,
        window_seconds: float = 60.0,
    ) -> None:
        if limit < 1:
            raise ValueError("limit must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self.limit = limit
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, principal: str, *, now: float | None = None) -> None:
        if not principal:
            raise RateLimitExceeded("missing rate-limit principal")

        current = time.monotonic() if now is None else now

        with self._lock:
            events = self._events.setdefault(principal, deque())

            cutoff = current - self.window_seconds
            while events and events[0] <= cutoff:
                events.popleft()

            if len(events) >= self.limit:
                raise RateLimitExceeded("rate limit exceeded")

            events.append(current)

            if len(self._events) > 4096:
                self._prune(current)

    def _prune(self, current: float) -> None:
        cutoff = current - self.window_seconds

        stale = [
            principal
            for principal, events in self._events.items()
            if not events or events[-1] <= cutoff
        ]

        for principal in stale:
            self._events.pop(principal, None)
