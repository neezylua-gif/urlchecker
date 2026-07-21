from __future__ import annotations

import asyncio
import time
from collections import deque


class UserRateLimiter:
    """In-memory sliding-window limiter with bounded key cardinality."""

    def __init__(self, limit: int, window_seconds: int, max_keys: int = 10_000) -> None:
        if limit < 1 or window_seconds < 1 or max_keys < 1:
            raise ValueError("limit, window_seconds and max_keys must be positive")
        self._limit = limit
        self._window = float(window_seconds)
        self._max_keys = max_keys
        self._events: dict[int, deque[float]] = {}
        self._lock = asyncio.Lock()
        self._checks = 0

    def _cleanup_stale(self, cutoff: float) -> None:
        stale_keys: list[int] = []
        for key, queue in self._events.items():
            while queue and queue[0] <= cutoff:
                queue.popleft()
            if not queue:
                stale_keys.append(key)
        for key in stale_keys:
            self._events.pop(key, None)

    async def check(self, key: int) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - self._window

        async with self._lock:
            events = self._events.get(key)
            if events is None:
                if len(self._events) >= self._max_keys:
                    self._cleanup_stale(cutoff)
                if len(self._events) >= self._max_keys:
                    # Fail closed for previously unseen identities instead of
                    # allowing unbounded memory growth during a botnet flood.
                    return False, max(1, int(self._window))
                events = deque()
                self._events[key] = events

            while events and events[0] <= cutoff:
                events.popleft()

            if len(events) >= self._limit:
                retry_after = max(1, int(events[0] + self._window - now) + 1)
                return False, retry_after

            events.append(now)
            self._checks += 1
            if self._checks % 200 == 0:
                self._cleanup_stale(cutoff)
            return True, 0
