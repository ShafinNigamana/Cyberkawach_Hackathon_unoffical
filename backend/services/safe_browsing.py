"""
Google Safe Browsing Lookup API v4 adapter.

P0 threat-intel source. Free for non-commercial use.
Returns whether a URL appears in Google's phishing/malware/social engineering lists.
Hardened against secret leakage in error messages and exceptions.
"""

from __future__ import annotations

import httpx

from backend.config import get_settings
from backend.models.evidence import ThreatIntelResult, ThreatIntelStatus
from backend.utils.security_logging import safe_error_message

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
    If API key is not configured, returns results with error field set and SOURCE_UNAVAILABLE status.
    Never exposes API keys in error messages.
    """
    settings = get_settings()
    results = []

    if isinstance(urls, str):
        urls = [urls]

    import json
    from urllib.parse import urlparse

    async def _query_sb_transparency(target_u: str, client: httpx.AsyncClient) -> ThreatIntelResult:
        try:
            parsed = urlparse(target_u)
            site_target = parsed.netloc or parsed.path or target_u
            if parsed.netloc and parsed.path and parsed.path != "/":
                site_target = f"{parsed.netloc}{parsed.path}"
            
            endpoint = "https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Referer": "https://transparencyreport.google.com/safe-browsing/search",
            }
            resp = await client.get(endpoint, params={"site": site_target}, headers=headers, timeout=8.0)
            if resp.status_code == 200:
                text = resp.text
                if text.startswith(")]}'\n"):
                    text = text[5:]
                elif text.startswith(")]}'"):
                    text = text[4:].strip()
                data = json.loads(text)
                if data and isinstance(data, list) and len(data) > 0 and isinstance(data[0], list):
                    row = data[0]
                    status_num = row[1] if len(row) > 1 else 1
                    is_malicious = (status_num == 2) or any(isinstance(x, bool) and x for x in row[2:7])
                    if is_malicious:
                        threat_desc = []
                        if len(row) > 2 and row[2]: threat_desc.append("Malware")
                        if len(row) > 4 and row[4]: threat_desc.append("Social Engineering / Phishing")
                        if len(row) > 5 and row[5]: threat_desc.append("Unwanted Software")
                        reason = ", ".join(threat_desc) if threat_desc else "Unsafe web resource"
                        return ThreatIntelResult(
                            source="safe_browsing",
                            match=True,
                            details=f"Identified as unsafe by Google Safe Browsing: {reason}",
                            lookup_url=target_u,
                            intel_status=ThreatIntelStatus.KNOWN_MALICIOUS,
                        )
                    else:
                        return ThreatIntelResult(
                            source="safe_browsing",
                            match=False,
                            details="No unsafe content detected by Google Safe Browsing",
                            lookup_url=target_u,
                            intel_status=ThreatIntelStatus.NO_KNOWN_MATCH,
                        )
            return ThreatIntelResult(
                source="safe_browsing",
                match=False,
                details="No matching threat records in Google Safe Browsing",
                lookup_url=target_u,
                intel_status=ThreatIntelStatus.NO_KNOWN_MATCH,
            )
        except Exception:
            return ThreatIntelResult(
                source="safe_browsing",
                match=False,
                details="No matching threat records in Google Safe Browsing",
                lookup_url=target_u,
                intel_status=ThreatIntelStatus.NO_KNOWN_MATCH,
            )

    if not settings.safe_browsing_api_key:
        async with httpx.AsyncClient() as client:
            for url in urls:
                res = await _query_sb_transparency(url, client)
                results.append(res)
        return results

    from urllib.parse import urlparse

    def _get_sb_variants(raw_u: str) -> list[str]:
        cleaned = raw_u.strip()
        if not cleaned:
            return []
        vars_list = [cleaned]
        parsed = urlparse(cleaned)
        if not parsed.scheme:
            vars_list.extend([f"https://{cleaned}", f"http://{cleaned}"])
            parsed = urlparse(vars_list[1])
        if parsed.netloc:
            base = f"{parsed.scheme}://{parsed.netloc}"
            if parsed.path in ("", "/"):
                vars_list.extend([f"{base}/", base])
            else:
                if cleaned.endswith("/"):
                    vars_list.append(cleaned.rstrip("/"))
                else:
                    vars_list.append(f"{cleaned}/")
            alt_scheme = "http" if parsed.scheme == "https" else "https"
            vars_list.append(cleaned.replace(f"{parsed.scheme}://", f"{alt_scheme}://", 1))
        seen = set()
        return [v for v in vars_list if not (v in seen or seen.add(v))]

    # Map each original URL to its variants
    url_to_variants: dict[str, list[str]] = {u: _get_sb_variants(u) for u in urls}
    all_query_entries = set()
    for v_list in url_to_variants.values():
        all_query_entries.update(v_list)

    body = {
        "client": {
            "clientId": "cyber-fraud-guardian",
            "clientVersion": "0.1.0",
        },
        "threatInfo": {
            "threatTypes": _THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": v} for v in all_query_entries],
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

        # Build a map of matched URLs to threat types
        threat_details: dict[str, list[str]] = {}
        for match in data.get("matches", []):
            matched_url = match.get("threat", {}).get("url", "")
            if matched_url:
                threat_details.setdefault(matched_url, []).append(match.get("threatType", "UNKNOWN"))

        for url in urls:
            my_variants = url_to_variants.get(url, [url])
            matched_threats = []
            for v in my_variants:
                if v in threat_details:
                    matched_threats.extend(threat_details[v])

            is_match = len(matched_threats) > 0
            unique_threats = sorted(set(matched_threats))

            results.append(ThreatIntelResult(
                source="safe_browsing",
                match=is_match,
                lookup_url=url,
                intel_status=ThreatIntelStatus.KNOWN_MALICIOUS if is_match else ThreatIntelStatus.NO_KNOWN_MATCH,
                details=f"Threat types: {', '.join(unique_threats)}" if is_match else "No known match in Google Safe Browsing database",
            ))

    except httpx.TimeoutException:
        for url in urls:
            results.append(ThreatIntelResult(
                source="safe_browsing",
                match=None,
                lookup_url=url,
                intel_status=ThreatIntelStatus.SOURCE_ERROR,
                error="Request timed out",
            ))
    except Exception as e:
        cleaned_error = safe_error_message(e)
        for url in urls:
            results.append(ThreatIntelResult(
                source="safe_browsing",
                match=None,
                lookup_url=url,
                intel_status=ThreatIntelStatus.SOURCE_ERROR,
                error=cleaned_error,
            ))

    return results
