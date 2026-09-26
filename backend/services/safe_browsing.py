"""
Google Safe Browsing Lookup API v4 adapter.

P0 threat-intel source. Free for non-commercial use.
Returns whether a URL appears in Google's phishing/malware/social engineering lists.
"""

from __future__ import annotations

from backend.config import get_settings
from backend.models.evidence import ThreatIntelResult

import httpx

_SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


async def check_safe_browsing(urls: list[str]) -> list[ThreatIntelResult]:
    """
    Query Google Safe Browsing Lookup API for a list of URLs.
    Returns one ThreatIntelResult per URL checked.
    If API key is not configured, returns results with error field set.
    """
    settings = get_settings()
    results = []

    if not settings.safe_browsing_api_key:
        for url in urls:
            results.append(ThreatIntelResult(
                source="safe_browsing",
                match=None,
                lookup_url=url,
                error="API key not configured",
            ))
        return results

    body = {
        "client": {
            "clientId": "cyber-fraud-guardian",
            "clientVersion": "0.1.0",
        },
        "threatInfo": {
            "threatTypes": _THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url} for url in urls],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                _SAFE_BROWSING_URL,
                params={"key": settings.safe_browsing_api_key},
                json=body,
            )
            resp.raise_for_status()
            data = resp.json()

        # Build a set of matched URLs
        matched_urls: set[str] = set()
        threat_details: dict[str, list[str]] = {}
        for match in data.get("matches", []):
            matched_url = match.get("threat", {}).get("url", "")
            matched_urls.add(matched_url)
            threat_details.setdefault(matched_url, []).append(match.get("threatType", "UNKNOWN"))

        for url in urls:
            is_match = url in matched_urls
            results.append(ThreatIntelResult(
                source="safe_browsing",
                match=is_match,
                lookup_url=url,
                details=f"Threat types: {', '.join(threat_details.get(url, []))}" if is_match else "No threats found",
            ))

    except httpx.TimeoutException:
        for url in urls:
            results.append(ThreatIntelResult(
                source="safe_browsing",
                match=None,
                lookup_url=url,
                error="Request timed out",
            ))
    except Exception as e:
        for url in urls:
            results.append(ThreatIntelResult(
                source="safe_browsing",
                match=None,
                lookup_url=url,
                error=str(e),
            ))

    return results
