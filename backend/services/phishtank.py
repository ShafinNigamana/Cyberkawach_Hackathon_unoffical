"""
PhishTank API adapter.

P0 threat-intel source. Free, requires registration for API key.
Checks URLs against PhishTank's verified phishing database.
Hardened against secret leakage in error messages.
"""

from __future__ import annotations

import httpx
from urllib.parse import urlparse

from backend.config import get_settings
from backend.models.evidence import ThreatIntelResult, ThreatIntelStatus
from backend.utils.security_logging import safe_error_message

_PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"


def _get_url_variants(raw_url: str) -> list[str]:
    """Generate canonical URL variants (trailing slash, schemes) to maximize matching against PhishTank."""
    cleaned = raw_url.strip()
    if not cleaned:
        return []
    variants = [cleaned]
    parsed = urlparse(cleaned)
    if not parsed.scheme:
        variants = [f"https://{cleaned}", f"http://{cleaned}"]
        parsed = urlparse(variants[0])

    if parsed.netloc:
        base = f"{parsed.scheme}://{parsed.netloc}"
        if parsed.path in ("", "/"):
            variants.extend([f"{base}/", base])
            alt_scheme = "http" if parsed.scheme == "https" else "https"
            variants.extend([f"{alt_scheme}://{parsed.netloc}/", f"{alt_scheme}://{parsed.netloc}"])
        else:
            if cleaned.endswith("/"):
                variants.append(cleaned.rstrip("/"))
            else:
                variants.append(f"{cleaned}/")

    seen = set()
    unique = []
    for v in variants:
        if v not in seen:
            seen.add(v)
            unique.append(v)
    return unique


async def check_phishtank(urls: list[str]) -> list[ThreatIntelResult]:
    """
    Query PhishTank for each URL. Returns one ThreatIntelResult per URL.
    Generates URL variants to ensure URLs with or without trailing slash/protocol
    are accurately identified against PhishTank's database.
    If API key is not configured, returns results with error field set and SOURCE_UNAVAILABLE.
    """
    settings = get_settings()
    results = []

    if not settings.phishtank_api_key:
        for url in urls:
            results.append(ThreatIntelResult(
                source="phishtank",
                match=None,
                lookup_url=url,
                intel_status=ThreatIntelStatus.SOURCE_UNAVAILABLE,
                error="API key not configured",
            ))
        return results

    async with httpx.AsyncClient(timeout=10.0) as client:
        for url in urls:
            variants = _get_url_variants(url)
            best_result = None

            for candidate in variants:
                try:
                    resp = await client.post(
                        _PHISHTANK_URL,
                        data={
                            "url": candidate,
                            "format": "json",
                            "app_key": settings.phishtank_api_key,
                        },
                        headers={"User-Agent": "phishtank/cyber-fraud-guardian"},
                    )
                    resp.raise_for_status()
                    data = resp.json()

                    result_data = data.get("results", {})
                    in_database = result_data.get("in_database", False)
                    verified = result_data.get("verified", False)
                    valid = result_data.get("valid", False)
                    phish_id = result_data.get("phish_id")

                    if in_database:
                        # If explicitly verified as NOT a phish by community votes
                        if verified is True and valid is False:
                            best_result = ThreatIntelResult(
                                source="phishtank",
                                match=False,
                                lookup_url=url,
                                intel_status=ThreatIntelStatus.NO_KNOWN_MATCH,
                                details=f"Community verified as not phishing in PhishTank (ID: {phish_id})",
                            )
                        else:
                            # It IS an active/cataloged phish in PhishTank database
                            details = (
                                f"Verified phish in PhishTank database (ID: {phish_id})"
                                if valid
                                else f"Cataloged phishing lure in PhishTank database (ID: {phish_id}, active submission)"
                            )
                            best_result = ThreatIntelResult(
                                source="phishtank",
                                match=True,
                                lookup_url=url,
                                intel_status=ThreatIntelStatus.KNOWN_MALICIOUS,
                                details=details,
                            )
                            # Once we find a confirmed or cataloged threat, no need to check further variants
                            break
                    else:
                        if best_result is None:
                            best_result = ThreatIntelResult(
                                source="phishtank",
                                match=False,
                                lookup_url=url,
                                intel_status=ThreatIntelStatus.NO_KNOWN_MATCH,
                                details="No known match in PhishTank database",
                            )

                except httpx.TimeoutException:
                    if best_result is None:
                        best_result = ThreatIntelResult(
                            source="phishtank",
                            match=None,
                            lookup_url=url,
                            intel_status=ThreatIntelStatus.SOURCE_ERROR,
                            error="Request timed out",
                        )
                except Exception as e:
                    if best_result is None:
                        best_result = ThreatIntelResult(
                            source="phishtank",
                            match=None,
                            lookup_url=url,
                            intel_status=ThreatIntelStatus.SOURCE_ERROR,
                            error=safe_error_message(e),
                        )

            results.append(best_result or ThreatIntelResult(
                source="phishtank",
                match=False,
                lookup_url=url,
                intel_status=ThreatIntelStatus.NO_KNOWN_MATCH,
                details="No known match in PhishTank database",
            ))

    return results

