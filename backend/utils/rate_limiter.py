"""
Production Sliding-Window Rate Limiter (Phase 5).

Implements distributed sliding-window rate limiting with:
- Tier 1: Anonymous users -> 15 requests/minute (keyed by client IP / subnet).
- Tier 2: Authenticated users / LEA / Analyst API keys -> 120 requests/minute (keyed by user_id/token).
- Redis atomic sorted set sliding window (ZADD, ZREMRANGEBYSCORE, ZCARD) when Redis is enabled.
- Thread-safe in-memory sliding window fallback when Redis is unconfigured or unavailable.
- Standard HTTP 429 Too Many Requests response with RFC-compliant Retry-After header.
- Protection against spoofed X-Forwarded-For headers, denial-of-wallet, and endpoint exhaustion.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import logging
from threading import Lock
import time
from typing import Optional, Tuple

from fastapi import HTTPException, Request, status

from backend.config import get_settings
from backend.utils.security_logging import safe_error_message

logger = logging.getLogger("cyber_guardian.rate_limiter")
settings = get_settings()


class SlidingWindowRateLimiter:
    """
    Hybrid sliding-window rate limiter with Redis distributed coordination
    and thread-safe in-memory fallback.
    """

    def __init__(
        self,
        default_limit: int = 30,
        anon_limit: int = 15,
        auth_limit: int = 120,
        window_seconds: float = 60.0,
    ):
        self.default_limit = default_limit
        self.anon_limit = anon_limit
        self.auth_limit = auth_limit
        self.window_seconds = window_seconds

        self._history: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()
        self._redis_client: Optional[Any] = None
        self._redis_checked = False
        self._redis_available = False

        # Rejection metric counters for Phase 6
        self.rejections_count: dict[str, int] = {"anon": 0, "auth": 0, "total": 0}

    def _get_redis(self):
        if not self._redis_checked:
            self._redis_checked = True
            if settings.redis_enabled:
                try:
                    import redis
                    client = redis.from_url(settings.redis_url, decode_responses=True, socket_timeout=1.5)
                    client.ping()
                    self._redis_client = client
                    self._redis_available = True
                    logger.info("Rate limiter connected to Redis distributed store at %s", settings.redis_url)
                except Exception as e:
                    self._redis_available = False
                    logger.warning("Redis rate limiter offline; using in-memory sliding window: %s", safe_error_message(e))
        return self._redis_client if self._redis_available else None

    def is_allowed(self, client_key: str, limit: Optional[int] = None) -> Tuple[bool, int]:
        """
        Check if a request from client_key is allowed under the sliding window limit.

        Returns:
            (allowed: bool, retry_after_seconds: int)
        """
        effective_limit = limit if limit is not None else self.default_limit
        now = time.time()
        cutoff = now - self.window_seconds

        # 1. Attempt Redis atomic sliding window
        redis_cli = self._get_redis()
        if redis_cli:
            try:
                redis_key = f"cf:rl:{client_key}"
                pipe = redis_cli.pipeline()
                pipe.zremrangebyscore(redis_key, 0, cutoff)
                pipe.zcard(redis_key)
                pipe.zrange(redis_key, 0, 0, withscores=True)
                _, count, oldest_items = pipe.execute()

                if count >= effective_limit:
                    oldest_ts = oldest_items[0][1] if oldest_items else cutoff
                    retry_after = max(1, int(oldest_ts + self.window_seconds - now))
                    return False, retry_after

                # Add current request with atomic expire
                pipe = redis_cli.pipeline()
                pipe.zadd(redis_key, {str(now): now})
                pipe.expire(redis_key, int(self.window_seconds * 2))
                pipe.execute()
                return True, 0
            except Exception as e:
                logger.debug("Redis rate limit check failed; falling back to in-memory: %s", safe_error_message(e))

        # 2. In-Memory Thread-Safe Sliding Window Fallback
        with self._lock:
            timestamps = self._history[client_key]
            valid_timestamps = [ts for ts in timestamps if ts > cutoff]

            if len(valid_timestamps) >= effective_limit:
                oldest = valid_timestamps[0]
                retry_after = max(1, int(oldest + self.window_seconds - now))
                self._history[client_key] = valid_timestamps
                return False, retry_after

            valid_timestamps.append(now)
            self._history[client_key] = valid_timestamps

            # Periodic cleanup of idle keys
            if len(self._history) > 10000:
                self._cleanup_idle(cutoff)

            return True, 0

    def _cleanup_idle(self, cutoff: float) -> None:
        """Purge idle keys from in-memory history to prevent leaks."""
        keys_to_delete = [
            k for k, ts in self._history.items() if not ts or ts[-1] <= cutoff
        ]
        for k in keys_to_delete:
            del self._history[k]

    def reset(self) -> None:
        """Reset in-memory history and counters (useful in tests)."""
        with self._lock:
            self._history.clear()
            self.rejections_count = {"anon": 0, "auth": 0, "total": 0}


# Global rate limiter singleton
rate_limiter = SlidingWindowRateLimiter(
    anon_limit=settings.rate_limit_anon_per_minute,
    auth_limit=settings.rate_limit_auth_per_minute,
)


def get_rate_limiter(
    rate_limit: Optional[int] = None,
    anon_limit: Optional[int] = None,
    auth_limit: Optional[int] = None,
) -> SlidingWindowRateLimiter:
    """Return the global rate limiter instance, optionally updating limits for test suites."""
    global rate_limiter
    if rate_limit is not None:
        rate_limiter.default_limit = rate_limit
        rate_limiter.anon_limit = rate_limit
        rate_limiter.auth_limit = rate_limit
    if anon_limit is not None:
        rate_limiter.anon_limit = anon_limit
    if auth_limit is not None:
        rate_limiter.auth_limit = auth_limit
    return rate_limiter


def get_client_identification(request: Request) -> Tuple[str, str, int]:
    """
    Extract client identity and applicable quota limit:
    - Authenticated users (Bearer token / Session) -> 120 req/min
    - Anonymous requests (Client IP) -> 15 req/min
    Hardened against:
    - Bearer token rotation evasion (unvalidated tokens never elevate quota)
    - X-Forwarded-For spoofing (only trusted proxy peer IPs can set upstream client IP)
    """
    settings = get_settings()

    # 1. Check Authorization Bearer header or X-Session-Token
    auth_header = request.headers.get("Authorization", "").strip()
    raw_token = ""
    if auth_header.lower().startswith("bearer "):
        raw_token = auth_header[7:].strip()
    elif request.headers.get("X-Session-Token"):
        raw_token = request.headers.get("X-Session-Token", "").strip()

    if raw_token:
        try:
            from backend.services.neo4j_repository import neo4j_repo
            session_data = neo4j_repo.validate_session(raw_token)
            if session_data:
                user_dict = session_data.get("user") if isinstance(session_data, dict) and "user" in session_data else session_data
                user_id = user_dict.get("user_id") if isinstance(user_dict, dict) else hashlib.sha256(raw_token.encode("utf-8")).hexdigest()[:16]
                return f"auth:{user_id}", "auth", rate_limiter.auth_limit
        except Exception:
            pass
        # Unvalidated or expired token: DO NOT elevate tier or key on unvalidated token.
        # Fall through to anonymous IP-based limiting.

    # 2. Extract Client IP with trusted proxy verification
    peer_ip = request.client.host if request.client else "unknown"
    trusted = getattr(settings, "trusted_proxy_list", ["127.0.0.1", "::1"])

    client_ip = peer_ip
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded and (peer_ip in trusted):
        first_hop = forwarded.split(",")[0].strip()
        if first_hop:
            client_ip = first_hop

    return f"anon:{client_ip}", "anon", rate_limiter.anon_limit


def check_rate_limit(request: Request) -> None:
    """
    FastAPI dependency enforcing tiered sliding-window rate limits.
    Emits HTTP 429 with Retry-After header on limit breach.
    """
    client_key, client_tier, limit = get_client_identification(request)
    allowed, retry_after = rate_limiter.is_allowed(client_key, limit=limit)

    if not allowed:
        rate_limiter.rejections_count["total"] += 1
        rate_limiter.rejections_count[client_tier] = (
            rate_limiter.rejections_count.get(client_tier, 0) + 1
        )
        logger.warning(
            "Rate limit exceeded for %s (%s tier, limit=%d/min). Retry-After: %ds",
            client_key,
            client_tier,
            limit,
            retry_after,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded: maximum {limit} requests per minute for your tier. Retry after {retry_after}s.",
            headers={"Retry-After": str(retry_after)},
        )
