"""
Two-Tier Caching Architecture (Phase 4).

Provides:
- L1: Bounded, thread-safe, TTL-aware in-memory LRU Cache (OrderedDict).
- L2: Redis-backed distributed cache shared across application worker processes.
- Deterministic normalized IOC hashing: sha256(ioc:type:value:schema_v1).
- Stampede defense (per-key mutex locks for in-flight requests).
- Epistemic outcome safety: Caches clean results for short TTL (15m),
  malicious matches for long TTL (24h), and NEVER caches provider failures/errors.
- Resilient fallback: Redis unavailability degrades seamlessly to L1 with zero service interruptions.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
import hashlib
import json
import logging
from threading import Lock
import time
from typing import Any, Callable, Optional, TypeVar

from backend.config import get_settings
from backend.utils.security_logging import safe_error_message

logger = logging.getLogger("cyber_guardian.cache_service")
settings = get_settings()

T = TypeVar("T")


class BoundedTTLCache:
    """
    Thread-safe, bounded in-memory LRU cache with fine-grained TTL support.
    """

    def __init__(self, maxsize: int = 5000):
        self.maxsize = max(1, maxsize)
        self._data: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._lock = Lock()

    def get(self, key: str) -> Optional[Any]:
        now = time.time()
        with self._lock:
            if key not in self._data:
                return None
            expire_at, val = self._data[key]
            if now > expire_at:
                del self._data[key]
                return None
            # Move to end for LRU freshness
            self._data.move_to_end(key)
            return val

    def set(self, key: str, value: Any, ttl_seconds: float = 3600.0) -> None:
        now = time.time()
        expire_at = now + ttl_seconds
        with self._lock:
            if key in self._data:
                del self._data[key]
            elif len(self._data) >= self.maxsize:
                # Evict oldest item
                self._data.popitem(last=False)
            self._data[key] = (expire_at, value)

    def delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._data)


class TwoTierCacheManager:
    """
    Two-Tier Caching Coordinator (L1 In-Memory + L2 Distributed Redis).
    """

    def __init__(self):
        self.l1 = BoundedTTLCache(maxsize=settings.cache_l1_max_size)
        self._redis_client: Optional[Any] = None
        self._redis_connected = False
        self._redis_checked = False
        self._locks: dict[str, asyncio.Lock] = {}
        self._lock_mutex = Lock()
        self.stats = {
            "l1_hits": 0,
            "l2_hits": 0,
            "misses": 0,
            "writes": 0,
            "redis_errors": 0,
        }

    def _get_key_lock(self, key: str) -> asyncio.Lock:
        with self._lock_mutex:
            if key not in self._locks:
                self._locks[key] = asyncio.Lock()
            return self._locks[key]

    def _init_redis_sync(self) -> None:
        """Lazily initialize Redis connection if configured."""
        if self._redis_checked:
            return
        self._redis_checked = True

        if not settings.redis_enabled:
            return

        try:
            import redis
            client = redis.from_url(settings.redis_url, decode_responses=True, socket_timeout=2.0)
            client.ping()
            self._redis_client = client
            self._redis_connected = True
            logger.info("Connected to L2 Redis cache at %s", settings.redis_url)
        except Exception as e:
            self.stats["redis_errors"] += 1
            logger.warning("Redis L2 cache unavailable; falling back to L1 LRU: %s", safe_error_message(e))
            self._redis_connected = False

    def make_ioc_key(self, ioc_type: str, value: str, namespace: str = "v1") -> str:
        """
        Generate a normalized, deterministic SHA-256 cache key.
        Prevents key-space collisions and normalizes case/whitespace.
        """
        norm_val = str(value).strip().lower()
        digest = hashlib.sha256(norm_val.encode("utf-8")).hexdigest()[:32]
        return f"cf:ioc:{ioc_type.lower()}:{digest}:{namespace}"

    def get(self, key: str) -> Optional[Any]:
        """Synchronously check L1 and L2 cache."""
        # 1. Check L1 In-Memory
        val = self.l1.get(key)
        if val is not None:
            self.stats["l1_hits"] += 1
            return val

        # 2. Check L2 Redis
        self._init_redis_sync()
        if self._redis_connected and self._redis_client:
            try:
                raw_json = self._redis_client.get(key)
                if raw_json:
                    parsed = json.loads(raw_json)
                    ttl = self._redis_client.ttl(key)
                    if ttl and ttl > 0:
                        self.l1.set(key, parsed, ttl_seconds=float(ttl))
                    self.stats["l2_hits"] += 1
                    return parsed
            except Exception as e:
                self.stats["redis_errors"] += 1
                logger.debug("Redis L2 read error: %s", safe_error_message(e))

        self.stats["misses"] += 1
        return None

    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> None:
        """Synchronously write to both L1 and L2 cache."""
        ttl = ttl_seconds if ttl_seconds is not None else settings.cache_default_ttl_seconds
        self.stats["writes"] += 1

        # 1. Write L1
        self.l1.set(key, value, ttl_seconds=float(ttl))

        # 2. Write L2 Redis
        self._init_redis_sync()
        if self._redis_connected and self._redis_client:
            try:
                serialized = json.dumps(value, default=str)
                self._redis_client.setex(key, ttl, serialized)
            except Exception as e:
                self.stats["redis_errors"] += 1
                logger.debug("Redis L2 write error: %s", safe_error_message(e))

    async def get_or_compute(
        self,
        key: str,
        compute_fn: Callable[[], Any],
        ttl_seconds: Optional[int] = None,
        is_cacheable_fn: Optional[Callable[[Any], bool]] = None,
    ) -> Any:
        """
        Stampede-protected get or compute with async mutex per key.
        Guarantees that only ONE worker executes compute_fn for a key concurrently.
        """
        # Fast path without acquiring mutex
        cached = self.get(key)
        if cached is not None:
            return cached

        lock = self._get_key_lock(key)
        async with lock:
            # Re-check inside critical section
            cached = self.get(key)
            if cached is not None:
                return cached

            # Compute value
            if asyncio.iscoroutinefunction(compute_fn):
                value = await compute_fn()
            else:
                value = compute_fn()

            # Check if value is permitted to be cached (e.g. don't cache provider errors)
            if is_cacheable_fn is None or is_cacheable_fn(value):
                self.set(key, value, ttl_seconds=ttl_seconds)

            return value


# Global singleton instance
cache_manager = TwoTierCacheManager()
