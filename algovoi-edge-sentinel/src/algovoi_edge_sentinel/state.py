"""Runtime state for the stateful checks: rate counters and the seen-nonce cache.

This state is what makes the edge layer *runtime* (not a substrate property): it depends on a clock and
on what has been seen before. The in-memory implementations below are correct for a single process; a
multi-process deployment injects a shared backend (Redis / DSN) with the same tiny interface. The clock
is injectable so tests are deterministic.
"""
from __future__ import annotations

from collections import defaultdict, deque


class InMemoryRateLimiter:
    """Sliding-window request counter per scope id. ``hit(scope_id, now, window_s)`` records the request
    and returns the count within the trailing window."""

    def __init__(self) -> None:
        self._events: dict[str, deque] = defaultdict(deque)

    def hit(self, scope_id: str, now: float, window_s: int) -> int:
        dq = self._events[scope_id]
        dq.append(now)
        cutoff = now - window_s
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)


class InMemoryNonceCache:
    """Seen-nonce cache with TTL. ``seen_before(nonce, now, ttl_s)`` records the nonce and returns True
    iff it was already present (a replay)."""

    def __init__(self) -> None:
        self._seen: dict[str, float] = {}

    def seen_before(self, nonce: str, now: float, ttl_s: int) -> bool:
        # purge expired so the cache does not grow unbounded
        expired = [n for n, exp in self._seen.items() if exp <= now]
        for n in expired:
            del self._seen[n]
        # SECURITY (2026-08-19): atomic check-and-set. A separate ``in`` check followed by assignment has a
        # TOCTOU gap — under threading the GIL can switch between the two statements, letting two concurrent
        # requests with the SAME nonce both see "not present" and both pass (replay). ``dict.setdefault`` is
        # a single dict operation: it returns the object we passed IFF it inserted (nonce unseen), otherwise
        # the previously-stored expiry, so the identity check distinguishes the two atomically.
        marker = now + ttl_s
        return self._seen.setdefault(nonce, marker) is not marker


__all__ = ["InMemoryRateLimiter", "InMemoryNonceCache"]
