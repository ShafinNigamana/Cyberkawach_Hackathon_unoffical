"""
OpenPhish Community Feed adapter.

P0/P1 threat-intel source. Free community feed of active phishing URLs.
Maintains an in-memory TTL cache (1 hour) to avoid frequent external downloads.
Fails safe on network error, timeouts, or parsing errors.
"""

from __future__ import annotations

import asyncio
import logging
import time
from urllib.parse import urlparse

import httpx

from backend.config import get_settings
from backend.models.evidence import ThreatIntelResult, ThreatIntelStatus
from backend.utils.security_logging import safe_error_message

logger = logging.getLogger(__name__)

_OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
_CACHE_TTL_SECONDS = 3600.0  # 1 hour
_FEED_CACHE: set[str] = set()
_FEED_CACHE_TIME: float = 0.0
_FEED_LOCK = asyncio.Lock()


def _normalize_url(url: str) -> str:
    """Normalize URL for consistent lookup."""
    u = url.strip().lower()
    return u.rstrip("/")


def set_openphish_cache_for_testing(urls: list[str]) -> None:
    """Helper to populate in-memory feed cache for unit tests."""
    global _FEED_CACHE, _FEED_CACHE_TIME
    _FEED_CACHE = {_normalize_url(u) for u in urls}
    _FEED_CACHE_TIME = time.time()


def clear_openphish_cache() -> None:
    """Clear in-memory cache."""
    global _FEED_CACHE, _FEED_CACHE_TIME
    _FEED_CACHE = set()
    _FEED_CACHE_TIME = 0.0


async def _fetch_openphish_feed() -> bool:
    """
    Fetch the community feed from OpenPhish and update cache.
    Returns True if feed was updated or already fresh, False if fetch failed.
    """
    global _FEED_CACHE, _FEED_CACHE_TIME

    now = time.time()
    if _FEED_CACHE and (now - _FEED_CACHE_TIME < _CACHE_TTL_SECONDS):
        return True

    async with _FEED_LOCK:
        # Double check after acquiring lock
        if _FEED_CACHE and (now - _FEED_CACHE_TIME < _CACHE_TTL_SECONDS):
            return True

        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                resp = await client.get(
                    _OPENPHISH_FEED_URL,
                    headers={"User-Agent": "cyber-fraud-guardian/0.1.0"},
                )
                resp.raise_for_status()
                lines = resp.text.splitlines()
                urls = set()
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        urls.add(_normalize_url(line))

                _FEED_CACHE = urls
                _FEED_CACHE_TIME = time.time()
                return True
        except Exception as e:
            logger.debug("OpenPhish feed update failed: %s", safe_error_message(e))
            # If we already have stale cache, keep using it
            return bool(_FEED_CACHE)


async def check_openphish(urls: list[str]) -> list[ThreatIntelResult]:
    """
    Check URLs against OpenPhish phishing feed.
    Returns one ThreatIntelResult per URL.
    """
    settings = get_settings()
    results: list[ThreatIntelResult] = []

    if hasattr(settings, "openphish_enabled") and not settings.openphish_enabled:
        for u in urls:
            results.append(ThreatIntelResult(
                source="openphish",
                match=None,
                lookup_url=u,
                intel_status=ThreatIntelStatus.SOURCE_UNAVAILABLE,
                error="OpenPhish source disabled",
            ))
        return results

    feed_ready = await _fetch_openphish_feed()

    if not feed_ready and not _FEED_CACHE:
        # Feed failed and no cache available
        for u in urls:
            results.append(ThreatIntelResult(
                source="openphish",
                match=None,
                lookup_url=u,
                intel_status=ThreatIntelStatus.SOURCE_ERROR,
                error="OpenPhish feed unavailable",
            ))
        return results

    for raw_url in urls:
        norm_url = _normalize_url(raw_url)
        # Also check without query string
        parsed = urlparse(norm_url)
        clean_no_query = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")

        is_match = (norm_url in _FEED_CACHE) or (clean_no_query in _FEED_CACHE)

        if is_match:
            results.append(ThreatIntelResult(
                source="openphish",
                match=True,
                lookup_url=raw_url,
                intel_status=ThreatIntelStatus.KNOWN_MALICIOUS,
                details="Active phishing URL confirmed in OpenPhish community feed",
            ))
        else:
            results.append(ThreatIntelResult(
                source="openphish",
                match=False,
                lookup_url=raw_url,
                intel_status=ThreatIntelStatus.NO_KNOWN_MATCH,
                details="No known match in OpenPhish community feed",
            ))

    return results
