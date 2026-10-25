"""Per-user sliding-window rate limiting (Spec S12).

The Telegram handler graph runs on a single asyncio event loop, and every
``allow`` call is synchronous with no awaits inside it, so no other coroutine
can interleave mid-update. That "thread of one" property is why the plain
``dict`` + ``deque`` below need no locks; if this limiter is ever shared across
threads or the check-and-record split is awaited, add a lock.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable

WINDOW_SECONDS = 60.0


class RateLimiter:
    """Allow at most ``limit_per_min`` messages per user in any rolling 60s window.

    The clock is injectable so tests (and future replay tooling) can move time
    without sleeping. Entries are pruned per user on every call, and a user with
    no retained hits loses their entry entirely, so memory stays bounded by the
    number of users active inside one window.
    """

    def __init__(
        self,
        limit_per_min: int,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if isinstance(limit_per_min, bool) or not isinstance(limit_per_min, int):
            raise ValueError("limit_per_min must be an integer")
        if limit_per_min < 1:
            raise ValueError("limit_per_min must be at least 1")
        self.limit_per_min = limit_per_min
        self.window_seconds = WINDOW_SECONDS
        self._clock = clock
        self._hits: dict[int, deque[float]] = {}

    def allow(self, user_id: int) -> bool:
        """Record one message for ``user_id`` if the window still has room.

        Uses ``time.monotonic`` semantics: only elapsed time matters, so wall
        clock changes or NTP jumps cannot extend or shrink the window.
        """
        if isinstance(user_id, bool) or not isinstance(user_id, int):
            # Same reasoning as app.security.authz: only numeric IDs get a bucket.
            return False
        now = self._clock()
        cutoff = now - self.window_seconds
        hits = self._hits.get(user_id)
        if hits is not None:
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if not hits:
                del self._hits[user_id]
                hits = None
            elif len(hits) >= self.limit_per_min:
                return False
        if hits is None:
            hits = deque()
            self._hits[user_id] = hits
        hits.append(now)
        return True
