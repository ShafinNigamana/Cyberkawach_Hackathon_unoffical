"""
In-memory rate limiter with sliding window defense against DoS and brute-force.
"""

from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock
from typing import Optional

from fastapi import HTTPException, Request, status


class SlidingWindowRateLimiter:
    """
    Sliding window rate limiter tracking requests per client IP.
    """

    def __init__(self, requests_per_minute: int = 30):
        self.limit = requests_per_minute
        self.window_seconds = 60.0
        self._history: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def is_allowed(self, client_key: str) -> tuple[bool, int]:
        """
        Check if a request from client_key is allowed.

        Returns:
            (allowed: bool, retry_after_seconds: int)
        """
        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            # Purge timestamps outside the sliding window
            timestamps = self._history[client_key]
            valid_timestamps = [ts for ts in timestamps if ts > cutoff]

            if len(valid_timestamps) >= self.limit:
                # Rate limit exceeded.
                oldest = valid_timestamps[0]
                retry_after = max(1, int(oldest + self.window_seconds - now))
                self._history[client_key] = valid_timestamps
                return False, retry_after

            valid_timestamps.append(now)
            self._history[client_key] = valid_timestamps

            # Periodic cleanup of idle keys if dictionary grows large
            if len(self._history) > 10000:
                self._cleanup_idle(cutoff)

            return True, 0

    def _cleanup_idle(self, cutoff: float) -> None:
        """Purge idle keys to prevent memory leak."""
        keys_to_delete = [
            key for key, timestamps in self._history.items()
            if not timestamps or timestamps[-1] <= cutoff
        ]
        for key in keys_to_delete:
            del self._history[key]

    def reset(self) -> None:
        """Reset rate limiter state (useful in tests)."""
        with self._lock:
            self._history.clear()


# Global rate limiter instance
_global_rate_limiter = SlidingWindowRateLimiter(requests_per_minute=30)


def get_rate_limiter(rate_limit: Optional[int] = None) -> SlidingWindowRateLimiter:
    global _global_rate_limiter
    if rate_limit is not None and rate_limit != _global_rate_limiter.limit:
        _global_rate_limiter = SlidingWindowRateLimiter(requests_per_minute=rate_limit)
    return _global_rate_limiter


def check_rate_limit(request: Request) -> None:
    """
    FastAPI dependency to enforce rate limiting on specific routes.
    """
    client_ip = request.client.host if request.client else "unknown"

    # Support X-Forwarded-For if behind a reverse proxy, taking first IP
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    limiter = get_rate_limiter()
    allowed, retry_after = limiter.is_allowed(client_ip)

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Please wait {retry_after} seconds before retrying.",
            headers={"Retry-After": str(retry_after)},
        )
