"""
Unit tests for Phase 4: Two-Tier Caching architecture.
"""

import asyncio
import time
import pytest

from backend.services.cache_service import BoundedTTLCache, TwoTierCacheManager
from backend.services.evidence_store import get_cached_indicator, set_cached_indicator


@pytest.fixture
def anyio_backend():
    return "asyncio"


def test_bounded_ttl_cache_eviction_and_expiry():
    cache = BoundedTTLCache(maxsize=3)

    # 1. Fill cache
    cache.set("a", 1, ttl_seconds=10.0)
    cache.set("b", 2, ttl_seconds=10.0)
    cache.set("c", 3, ttl_seconds=10.0)
    assert cache.size() == 3

    # 2. Access "a" so "b" becomes the oldest (LRU)
    assert cache.get("a") == 1

    # 3. Add "d", which should evict "b"
    cache.set("d", 4, ttl_seconds=10.0)
    assert cache.size() == 3
    assert cache.get("b") is None
    assert cache.get("a") == 1
    assert cache.get("c") == 3
    assert cache.get("d") == 4

    # 4. Expiration
    cache.set("short_lived", "temp", ttl_seconds=0.05)
    time.sleep(0.1)
    assert cache.get("short_lived") is None


def test_two_tier_cache_manager_ioc_keys():
    mgr = TwoTierCacheManager()
    k1 = mgr.make_ioc_key("phishtank", "  HTTPS://Phish-Target.xyz/Login  ")
    k2 = mgr.make_ioc_key("phishtank", "https://phish-target.xyz/login")
    assert k1 == k2
    assert "cf:ioc:phishtank:" in k1


@pytest.mark.anyio
async def test_cache_stampede_protection():
    mgr = TwoTierCacheManager()
    call_count = 0

    async def expensive_computation():
        nonlocal call_count
        call_count += 1
        await asyncio.sleep(0.05)
        return {"data": "verified"}

    key = mgr.make_ioc_key("dns", "example-stampede.com")

    # Launch 5 concurrent calls for the exact same key
    results = await asyncio.gather(
        mgr.get_or_compute(key, expensive_computation, ttl_seconds=10),
        mgr.get_or_compute(key, expensive_computation, ttl_seconds=10),
        mgr.get_or_compute(key, expensive_computation, ttl_seconds=10),
        mgr.get_or_compute(key, expensive_computation, ttl_seconds=10),
        mgr.get_or_compute(key, expensive_computation, ttl_seconds=10),
    )

    # All 5 callers get the exact same result, but expensive_computation ran only ONCE
    assert len(results) == 5
    for r in results:
        assert r == {"data": "verified"}
    assert call_count == 1


def test_evidence_store_never_caches_errors():
    test_indicator = "error-test-domain.online"

    # Attempt to cache an error result
    set_cached_indicator(
        test_indicator,
        "safebrowsing",
        {"error": "503 Service Unavailable", "intel_status": "SOURCE_ERROR"},
    )
    # Must NOT be stored in cache
    res = get_cached_indicator(test_indicator, "safebrowsing")
    assert res is None

    # Cache a valid clean match
    set_cached_indicator(
        test_indicator,
        "safebrowsing",
        {"match": False, "intel_status": "NO_KNOWN_MATCH"},
    )
    res_valid = get_cached_indicator(test_indicator, "safebrowsing")
    assert res_valid is not None
    assert res_valid["intel_status"] == "NO_KNOWN_MATCH"
