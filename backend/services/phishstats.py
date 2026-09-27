"""
PhishStats Threat Intelligence API adapter.

P0/P1 threat-intel provider.
Queries verified phishing records from PhishStats REST API (https://api.phishstats.info).
Authentication: X-API-Key: ${PHISHSTATS_API_KEY}
Normalizes URL, domain, IP, ASN, ISP, country, score, and dates into ThreatIntelResult.
Hardened against secret leakage, rate-limiting (429), timeouts, and malformed responses.
"""

from __future__ import annotations

import logging
import time
from threading import Lock
from typing import Any, Optional
from urllib.parse import quote

import httpx

from backend.config import get_settings
from backend.models.evidence import ThreatIntelResult, ThreatIntelStatus
from backend.utils.security_logging import safe_error_message

logger = logging.getLogger(__name__)

_PHISHSTATS_BASE_URL = "https://api.phishstats.info/api/phishing"
_DEFAULT_TIMEOUT = 15.0
_DEFAULT_TTL_SECONDS = 3600  # 1 hour

# In-memory TTL cache for lookups: url -> (timestamp, ThreatIntelResult)
_CACHE: dict[str, tuple[float, ThreatIntelResult]] = {}
_CACHE_LOCK = Lock()


def clear_phishstats_cache() -> None:
    """Clear in-memory PhishStats cache (used in testing)."""
    with _CACHE_LOCK:
        _CACHE.clear()


def set_phishstats_cache_for_testing(url: str, result: ThreatIntelResult) -> None:
    """Set an in-memory cache entry for testing without network requests."""
    with _CACHE_LOCK:
        _CACHE[url] = (time.time(), result)


def _get_cached_result(url: str) -> Optional[ThreatIntelResult]:
    now = time.time()
    with _CACHE_LOCK:
        if url in _CACHE:
            cached_time, cached_res = _CACHE[url]
            if now - cached_time < _DEFAULT_TTL_SECONDS:
                return cached_res
    return None


def _set_cached_result(url: str, res: ThreatIntelResult) -> None:
    with _CACHE_LOCK:
        _CACHE[url] = (time.time(), res)


def _normalize_phishstats_record(record: dict[str, Any], lookup_url: str) -> ThreatIntelResult:
    """
    Safely extract and normalize PhishStats fields.
    Every field is optional and validated against malformed data.
    """
    raw_score = record.get("score")
    try:
        score = float(raw_score) if raw_score is not None else 0.0
    except (ValueError, TypeError):
        score = 0.0

    ip = str(record.get("ip") or "").strip()
    asn = str(record.get("asn") or "").strip()
    isp = str(record.get("isp") or "").strip()
    country = str(record.get("countryname") or record.get("countrycode") or "").strip()
    obs_date = str(record.get("date") or "").strip()
    update_date = str(record.get("date_update") or "").strip()
    host = str(record.get("host") or "").strip()
    ssl_issuer = str(record.get("ssl_issuer") or "").strip()
    matched_url = str(record.get("url") or lookup_url).strip()

    # PhishStats cataloged entry is considered malicious if score >= 2.0 (scores range 0 to 10)
    is_phish = score >= 2.0 or bool(record.get("id"))

    summary_parts = [f"PhishStats Score: {score:.1f}/10"]
    if country:
        summary_parts.append(f"Country: {country}")
    if asn:
        summary_parts.append(f"ASN: {asn}")
    if ip:
        summary_parts.append(f"IP: {ip}")

    details = " | ".join(summary_parts)

    return ThreatIntelResult(
        source="phishstats",
        match=is_phish,
        lookup_url=lookup_url,
        intel_status=ThreatIntelStatus.KNOWN_MALICIOUS if is_phish else ThreatIntelStatus.NO_KNOWN_MATCH,
        details=details,
        error=None,
    )


async def check_phishstats(urls: list[str] | str) -> list[ThreatIntelResult]:
    """
    Query PhishStats API for a batch of URLs.
    Never throws an exception — always returns ThreatIntelResult with explicit status.
    Protects against secret leakage in headers, logs, and error messages.
    """
    if isinstance(urls, str):
        urls = [urls]

    settings = get_settings()
    results: list[ThreatIntelResult] = []

    api_key = (settings.phishstats_api_key or "").strip() if hasattr(settings, "phishstats_api_key") else ""

    headers: dict[str, str] = {
        "User-Agent": "cyber-fraud-guardian/1.0",
        "Accept": "application/json",
    }
    if api_key:
        headers["X-API-Key"] = api_key

    async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
        for url in urls:
            clean_url = str(url).strip()
            if not clean_url:
                continue

            # 1. Check in-memory TTL cache
            cached = _get_cached_result(clean_url)
            if cached:
                results.append(cached)
                continue

            # 2. Check if API key is not configured and anonymous lookup is disabled
            if not api_key:
                res = ThreatIntelResult(
                    source="phishstats",
                    match=None,
                    lookup_url=clean_url,
                    intel_status=ThreatIntelStatus.SOURCE_UNAVAILABLE,
                    error="API key not configured",
                )
                _set_cached_result(clean_url, res)
                results.append(res)
                continue

            # 3. Query API with safe filter and limit size to 1 for fast retrieval
            try:
                query_url = f"{_PHISHSTATS_BASE_URL}?_where=(url,eq,{clean_url})&_size=1"
                resp = await client.get(query_url, headers=headers)

                if resp.status_code == 429:
                    logger.warning("PhishStats rate limit exceeded (HTTP 429)")
                    res = ThreatIntelResult(
                        source="phishstats",
                        match=None,
                        lookup_url=clean_url,
                        intel_status=ThreatIntelStatus.SOURCE_ERROR,
                        error="Rate limit reached (HTTP 429)",
                    )
                elif resp.status_code in (401, 403):
                    logger.warning("PhishStats authentication failed (HTTP %s)", resp.status_code)
                    res = ThreatIntelResult(
                        source="phishstats",
                        match=None,
                        lookup_url=clean_url,
                        intel_status=ThreatIntelStatus.SOURCE_ERROR,
                        error="Invalid API key",
                    )
                elif resp.status_code != 200:
                    res = ThreatIntelResult(
                        source="phishstats",
                        match=None,
                        lookup_url=clean_url,
                        intel_status=ThreatIntelStatus.SOURCE_ERROR,
                        error=f"HTTP {resp.status_code} from service",
                    )
                else:
                    data = resp.json()
                    # If exact lookup has no results, try trailing slash fallback
                    if (not isinstance(data, list) or len(data) == 0):
                        alt_url = clean_url + "/" if not clean_url.endswith("/") else clean_url.rstrip("/")
                        alt_query_url = f"{_PHISHSTATS_BASE_URL}?_where=(url,eq,{alt_url})&_size=1"
                        alt_resp = await client.get(alt_query_url, headers=headers)
                        if alt_resp.status_code == 200:
                            alt_data = alt_resp.json()
                            if isinstance(alt_data, list) and len(alt_data) > 0:
                                data = alt_data

                    if isinstance(data, list) and len(data) > 0:
                        first_record = data[0]
                        if isinstance(first_record, dict):
                            res = _normalize_phishstats_record(first_record, clean_url)
                        else:
                            res = ThreatIntelResult(
                                source="phishstats",
                                match=False,
                                lookup_url=clean_url,
                                intel_status=ThreatIntelStatus.NO_KNOWN_MATCH,
                                details="No known match in PhishStats database",
                            )
                    else:
                        res = ThreatIntelResult(
                            source="phishstats",
                            match=False,
                            lookup_url=clean_url,
                            intel_status=ThreatIntelStatus.NO_KNOWN_MATCH,
                            details="No known match in PhishStats database",
                        )

            except httpx.TimeoutException:
                res = ThreatIntelResult(
                    source="phishstats",
                    match=None,
                    lookup_url=clean_url,
                    intel_status=ThreatIntelStatus.SOURCE_ERROR,
                    error="Request timed out",
                )
            except Exception as e:
                res = ThreatIntelResult(
                    source="phishstats",
                    match=None,
                    lookup_url=clean_url,
                    intel_status=ThreatIntelStatus.SOURCE_ERROR,
                    error=safe_error_message(e),
                )

            _set_cached_result(clean_url, res)
            results.append(res)

    return results
