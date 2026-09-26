"""
PhishTank API adapter.

P0 threat-intel source. Free, requires registration for API key.
Checks URLs against PhishTank's verified phishing database.
Hardened against secret leakage in error messages.
"""

from __future__ import annotations

import httpx

from backend.config import get_settings
from backend.models.evidence import ThreatIntelResult
from backend.utils.security_logging import safe_error_message

_PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"


async def check_phishtank(urls: list[str]) -> list[ThreatIntelResult]:
    """
    Query PhishTank for each URL. Returns one ThreatIntelResult per URL.
    If API key is not configured, returns results with error field set.
    """
    settings = get_settings()
    results = []

    if not settings.phishtank_api_key:
        for url in urls:
            results.append(ThreatIntelResult(
                source="phishtank",
                match=None,
                lookup_url=url,
                error="API key not configured",
            ))
        return results

    async with httpx.AsyncClient(timeout=10.0) as client:
        for url in urls:
            try:
                resp = await client.post(
                    _PHISHTANK_URL,
                    data={
                        "url": url,
                        "format": "json",
                        "app_key": settings.phishtank_api_key,
                    },
                    headers={"User-Agent": "phishtank/cyber-fraud-guardian"},
                )
                resp.raise_for_status()
                data = resp.json()

                result_data = data.get("results", {})
                in_database = result_data.get("in_database", False)
                is_phish = result_data.get("valid", False) if in_database else False

                results.append(ThreatIntelResult(
                    source="phishtank",
                    match=is_phish,
                    lookup_url=url,
                    details=(
                        f"Verified phish (ID: {result_data.get('phish_id', 'N/A')})"
                        if is_phish
                        else "Not in PhishTank database" if not in_database
                        else "In database but not verified as phish"
                    ),
                ))

            except httpx.TimeoutException:
                results.append(ThreatIntelResult(
                    source="phishtank",
                    match=None,
                    lookup_url=url,
                    error="Request timed out",
                ))
            except Exception as e:
                results.append(ThreatIntelResult(
                    source="phishtank",
                    match=None,
                    lookup_url=url,
                    error=safe_error_message(e),
                ))

    return results
