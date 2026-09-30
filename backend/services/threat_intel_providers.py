"""
Threat Intelligence Providers Framework (PRD Section 5).

Abstracts multiple external threat-intel feeds:
- URLhaus (abuse.ch open live feed)
- PhishStats
- PhishTank
- Google Safe Browsing
- VirusTotal (v3)

Adheres strictly to the rule: NEVER invent or assume evidence.
If an API key is unconfigured or a service is down, returns status="UNAVAILABLE"
with an explicit reason rather than a fabricated negative or positive.
"""

from __future__ import annotations

import abc
import asyncio
import base64
import hashlib
import logging
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from backend.config import get_settings
from backend.models.evidence import (
    EvidenceItem,
    EvidenceReliability,
    EvidenceSeverity,
    EvidenceStatus,
    EvidenceType,
    RiskDirection,
    ThreatIntelResult,
    ThreatIntelStatus,
)
from backend.services.phishstats import check_phishstats
from backend.services.phishtank import check_phishtank
from backend.services.safe_browsing import check_safe_browsing
from backend.utils.security_logging import safe_error_message

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 4.0


class ThreatIntelProvider(abc.ABC):
    """Abstract base class for all threat intelligence providers."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Provider identifier."""
        pass

    @property
    @abc.abstractmethod
    def is_available(self) -> bool:
        """Check if provider is configured and available to query."""
        pass

    @abc.abstractmethod
    async def check_url(self, url: str) -> ThreatIntelResult:
        """Query provider for a specific URL."""
        pass

    async def check_domain(self, domain: str) -> ThreatIntelResult:
        """Query provider for a domain (defaults to checking http://domain)."""
        return await self.check_url(f"http://{domain}")


# ─── Concrete Provider: URLhaus (abuse.ch) ───

class URLhausProvider(ThreatIntelProvider):
    """
    abuse.ch URLhaus threat feed.
    Free and public API tracking live malware distribution and phishing URLs.
    """

    @property
    def name(self) -> str:
        return "urlhaus"

    @property
    def is_available(self) -> bool:
        return True  # URLhaus public API does not mandate an API key for basic lookups

    async def check_url(self, url: str) -> ThreatIntelResult:
        settings = get_settings()
        api_url = "https://urlhaus-api.abuse.ch/v1/url/"
        headers = {"User-Agent": "CyberKawach-Intel/1.0"}
        if getattr(settings, "urlhaus_api_key", None):
            headers["Auth-Key"] = settings.urlhaus_api_key

        try:
            async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
                resp = await client.post(api_url, data={"url": url}, headers=headers)
                if resp.status_code != 200:
                    return ThreatIntelResult(
                        source=self.name,
                        lookup_url=url,
                        error=f"HTTP {resp.status_code}",
                        intel_status=ThreatIntelStatus.SOURCE_ERROR,
                    )
                data = resp.json()
                query_status = data.get("query_status", "")

                if query_status == "ok":
                    url_status = data.get("url_status", "unknown")
                    threat = data.get("threat", "malware_url")
                    tags = ", ".join(data.get("tags") or [])
                    details = f"Known threat: {threat} (status: {url_status})"
                    if tags:
                        details += f" [tags: {tags}]"
                    return ThreatIntelResult(
                        source=self.name,
                        match=True,
                        details=details,
                        lookup_url=url,
                        intel_status=ThreatIntelStatus.KNOWN_MALICIOUS,
                    )
                elif query_status == "no_results":
                    return ThreatIntelResult(
                        source=self.name,
                        match=False,
                        details="No matching threat records in URLhaus",
                        lookup_url=url,
                        intel_status=ThreatIntelStatus.NO_KNOWN_MATCH,
                    )
                else:
                    return ThreatIntelResult(
                        source=self.name,
                        lookup_url=url,
                        error=query_status or "Unknown query status",
                        intel_status=ThreatIntelStatus.SOURCE_ERROR,
                    )
        except Exception as e:
            return ThreatIntelResult(
                source=self.name,
                lookup_url=url,
                error=safe_error_message(e),
                intel_status=ThreatIntelStatus.SOURCE_UNAVAILABLE,
            )

    async def check_domain(self, domain: str) -> ThreatIntelResult:
        settings = get_settings()
        api_url = "https://urlhaus-api.abuse.ch/v1/host/"
        headers = {"User-Agent": "CyberKawach-Intel/1.0"}
        if getattr(settings, "urlhaus_api_key", None):
            headers["Auth-Key"] = settings.urlhaus_api_key

        clean = domain.strip().lower()
        try:
            async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
                resp = await client.post(api_url, data={"host": clean}, headers=headers)
                if resp.status_code != 200:
                    return ThreatIntelResult(
                        source=self.name,
                        lookup_url=clean,
                        error=f"HTTP {resp.status_code}",
                        intel_status=ThreatIntelStatus.SOURCE_ERROR,
                    )
                data = resp.json()
                query_status = data.get("query_status", "")
                if query_status == "ok":
                    count = data.get("urls", [])
                    return ThreatIntelResult(
                        source=self.name,
                        match=True,
                        details=f"Host associated with {len(count)} known malicious URLs in URLhaus",
                        lookup_url=clean,
                        intel_status=ThreatIntelStatus.KNOWN_MALICIOUS,
                    )
                elif query_status == "no_results":
                    return ThreatIntelResult(
                        source=self.name,
                        match=False,
                        details="No matching host records in URLhaus",
                        lookup_url=clean,
                        intel_status=ThreatIntelStatus.NO_KNOWN_MATCH,
                    )
                else:
                    return ThreatIntelResult(
                        source=self.name,
                        lookup_url=clean,
                        error=query_status or "Unknown status",
                        intel_status=ThreatIntelStatus.SOURCE_ERROR,
                    )
        except Exception as e:
            return ThreatIntelResult(
                source=self.name,
                lookup_url=clean,
                error=safe_error_message(e),
                intel_status=ThreatIntelStatus.SOURCE_UNAVAILABLE,
            )


# ─── Concrete Provider: OpenPhish ───

class OpenPhishProvider(ThreatIntelProvider):
    """
    OpenPhish live threat feed (https://openphish.eu/api/check?url=<URL>).
    Public real-time phishing detection API.
    """

    @property
    def name(self) -> str:
        return "openphish"

    @property
    def is_available(self) -> bool:
        return True

    async def check_url(self, url: str) -> ThreatIntelResult:
        api_url = "https://openphish.eu/api/check"
        try:
            async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
                resp = await client.get(
                    api_url,
                    params={"url": url},
                    headers={"User-Agent": "CyberKawach-Intel/1.0", "Accept": "application/json"},
                )
                if resp.status_code != 200:
                    return ThreatIntelResult(
                        source=self.name,
                        lookup_url=url,
                        error=f"HTTP {resp.status_code}",
                        intel_status=ThreatIntelStatus.SOURCE_ERROR,
                    )

                data = resp.json()
                is_found = bool(data.get("found", False))

                if is_found:
                    return ThreatIntelResult(
                        source=self.name,
                        match=True,
                        details="Active phishing URL identified in OpenPhish intelligence database",
                        lookup_url=url,
                        intel_status=ThreatIntelStatus.KNOWN_MALICIOUS,
                    )
                else:
                    return ThreatIntelResult(
                        source=self.name,
                        match=False,
                        details="No matching phishing record in OpenPhish database",
                        lookup_url=url,
                        intel_status=ThreatIntelStatus.NO_KNOWN_MATCH,
                    )
        except Exception as e:
            return ThreatIntelResult(
                source=self.name,
                lookup_url=url,
                error=safe_error_message(e),
                intel_status=ThreatIntelStatus.SOURCE_UNAVAILABLE,
            )


# ─── Concrete Provider: PhishStats ───

class PhishStatsProvider(ThreatIntelProvider):
    """PhishStats REST API provider."""

    @property
    def name(self) -> str:
        return "phishstats"

    @property
    def is_available(self) -> bool:
        return True  # PhishStats adapter handles anonymous queries

    async def check_url(self, url: str) -> ThreatIntelResult:
        results = await check_phishstats([url])
        if results and isinstance(results[0], ThreatIntelResult):
            return results[0]
        return ThreatIntelResult(
            source=self.name,
            lookup_url=url,
            error="No response returned from PhishStats",
            intel_status=ThreatIntelStatus.SOURCE_UNAVAILABLE,
        )


# ─── Concrete Provider: PhishTank (with OpenPhish fallback) ───

class PhishTankProvider(ThreatIntelProvider):
    """
    PhishTank community database provider with automatic OpenPhish fallback
    when PhishTank API is unavailable or unconfigured.
    """

    @property
    def name(self) -> str:
        return "phishtank"

    @property
    def is_available(self) -> bool:
        return True

    async def check_url(self, url: str) -> ThreatIntelResult:
        results = await check_phishtank([url])
        if results and isinstance(results[0], ThreatIntelResult):
            # If PhishTank API is down or not configured, gracefully query OpenPhish
            if results[0].intel_status in (ThreatIntelStatus.SOURCE_UNAVAILABLE, ThreatIntelStatus.SOURCE_ERROR):
                openphish = OpenPhishProvider()
                op_res = await openphish.check_url(url)
                if op_res.intel_status != ThreatIntelStatus.SOURCE_UNAVAILABLE:
                    return ThreatIntelResult(
                        source=self.name,
                        match=op_res.match,
                        details=f"[PhishTank fallback -> OpenPhish] {op_res.details or ''}",
                        lookup_url=url,
                        intel_status=op_res.intel_status,
                    )
            return results[0]

        # Direct fallback
        openphish = OpenPhishProvider()
        return await openphish.check_url(url)


# ─── Concrete Provider: Google Safe Browsing ───

class SafeBrowsingProvider(ThreatIntelProvider):
    """Google Safe Browsing v4 provider."""

    @property
    def name(self) -> str:
        return "safe_browsing"

    @property
    def is_available(self) -> bool:
        settings = get_settings()
        return bool(settings.safe_browsing_api_key and settings.safe_browsing_api_key.strip())

    async def check_url(self, url: str) -> ThreatIntelResult:
        if not self.is_available:
            return ThreatIntelResult(
                source=self.name,
                lookup_url=url,
                error="API key not configured",
                intel_status=ThreatIntelStatus.SOURCE_UNAVAILABLE,
            )
        results = await check_safe_browsing([url])
        if results and isinstance(results[0], ThreatIntelResult):
            return results[0]
        return ThreatIntelResult(
            source=self.name,
            lookup_url=url,
            error="No response from Safe Browsing",
            intel_status=ThreatIntelStatus.SOURCE_UNAVAILABLE,
        )


# ─── Concrete Provider: VirusTotal (v3) ───

class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal API v3 provider."""

    @property
    def name(self) -> str:
        return "virustotal"

    @property
    def is_available(self) -> bool:
        settings = get_settings()
        key = getattr(settings, "virustotal_api_key", None)
        return bool(key and key.strip())

    async def check_url(self, url: str) -> ThreatIntelResult:
        if not self.is_available:
            return ThreatIntelResult(
                source=self.name,
                lookup_url=url,
                error="API key not configured",
                intel_status=ThreatIntelStatus.SOURCE_UNAVAILABLE,
            )

        settings = get_settings()
        key = getattr(settings, "virustotal_api_key", "")
        # VirusTotal v3 URL ID is base64url encoded URL without trailing padding '='
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        try:
            async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
                resp = await client.get(api_url, headers={"x-apikey": key, "Accept": "application/json"})
                if resp.status_code == 404:
                    return ThreatIntelResult(
                        source=self.name,
                        match=False,
                        details="URL not seen in VirusTotal dataset",
                        lookup_url=url,
                        intel_status=ThreatIntelStatus.NO_KNOWN_MATCH,
                    )
                elif resp.status_code != 200:
                    return ThreatIntelResult(
                        source=self.name,
                        lookup_url=url,
                        error=f"HTTP {resp.status_code}",
                        intel_status=ThreatIntelStatus.SOURCE_ERROR,
                    )

                data = resp.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)

                if malicious >= 2:
                    return ThreatIntelResult(
                        source=self.name,
                        match=True,
                        details=f"Flagged by {malicious} security vendors on VirusTotal",
                        lookup_url=url,
                        intel_status=ThreatIntelStatus.KNOWN_MALICIOUS,
                    )
                else:
                    return ThreatIntelResult(
                        source=self.name,
                        match=False,
                        details=f"Clean across {stats.get('harmless', 0)} vendors on VirusTotal",
                        lookup_url=url,
                        intel_status=ThreatIntelStatus.NO_KNOWN_MATCH,
                    )
        except Exception as e:
            return ThreatIntelResult(
                source=self.name,
                lookup_url=url,
                error=safe_error_message(e),
                intel_status=ThreatIntelStatus.SOURCE_UNAVAILABLE,
            )


# ─── Threat Intel Manager ───

class ThreatIntelManager:
    """Orchestrates concurrent queries across all available threat-intel providers."""

    def __init__(self):
        self.providers: list[ThreatIntelProvider] = [
            URLhausProvider(),
            OpenPhishProvider(),
            PhishStatsProvider(),
            PhishTankProvider(),
            SafeBrowsingProvider(),
            VirusTotalProvider(),
        ]

    async def query_all(self, url: str) -> tuple[list[ThreatIntelResult], list[EvidenceItem]]:
        """
        Query all providers in parallel for a URL.
        Converts results to structured ThreatIntelResult and EvidenceItem objects (tier: DIRECT).
        """
        tasks = [p.check_url(url) for p in self.providers]
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        ti_results: list[ThreatIntelResult] = []
        evidence_items: list[EvidenceItem] = []

        for provider, res in zip(self.providers, raw_results):
            if isinstance(res, Exception):
                ti_res = ThreatIntelResult(
                    source=provider.name,
                    lookup_url=url,
                    error=safe_error_message(res),
                    intel_status=ThreatIntelStatus.SOURCE_ERROR,
                )
            elif isinstance(res, ThreatIntelResult):
                ti_res = res
            else:
                continue

            ti_results.append(ti_res)
            display_name = provider.name.replace("_", " ").title()

            if ti_res.intel_status == ThreatIntelStatus.KNOWN_MALICIOUS:
                evidence_items.append(EvidenceItem(
                    type=EvidenceType.THREAT_INTEL_HIT,
                    source=provider.name,
                    source_type="api",
                    evidence_tier="DIRECT",
                    indicator=url,
                    finding=f"{display_name}: Confirmed active threat entry — {ti_res.details or 'known malicious'}",
                    description=f"Verified malicious hit in {display_name} security intelligence database.",
                    observed_value=f"{url} ({ti_res.details or 'malicious'})",
                    interpretation=f"Target URL is catalogued in {display_name} active threat repository.",
                    status=EvidenceStatus.CONFIRMED,
                    reliability=EvidenceReliability.EXTERNAL_DB,
                    risk_direction=RiskDirection.INCREASES_RISK,
                    severity=EvidenceSeverity.CRITICAL,
                    confidence=0.98,
                    raw_reference=url,
                    correlation_group=f"threat_intel_{provider.name}",
                    raw_data={"source": provider.name, "url": url, "details": ti_res.details},
                ))
            elif ti_res.intel_status == ThreatIntelStatus.NO_KNOWN_MATCH:
                evidence_items.append(EvidenceItem(
                    type=EvidenceType.THREAT_INTEL_MISS,
                    source=provider.name,
                    source_type="api",
                    evidence_tier="OBSERVED",
                    indicator=url,
                    finding=f"{display_name}: No malicious match listed in database",
                    description=f"{display_name} has no record of malicious activity for this URL.",
                    observed_value=f"{url} (clean/unlisted)",
                    interpretation="Absence of a listing does not guarantee safety, as newly registered phishing lures take hours to days to appear.",
                    status=EvidenceStatus.OBSERVED,
                    reliability=EvidenceReliability.EXTERNAL_DB,
                    risk_direction=RiskDirection.NEUTRAL,
                    severity=EvidenceSeverity.INFORMATIONAL,
                    confidence=None,
                    raw_reference=url,
                    correlation_group=f"threat_intel_{provider.name}",
                    raw_data={"source": provider.name, "url": url},
                ))
            elif ti_res.intel_status in (ThreatIntelStatus.SOURCE_UNAVAILABLE, ThreatIntelStatus.SOURCE_ERROR):
                evidence_items.append(EvidenceItem(
                    type=EvidenceType.THREAT_INTEL_MISS,
                    source=provider.name,
                    source_type="api",
                    evidence_tier="UNAVAILABLE",
                    indicator=url,
                    finding=f"{display_name}: Feed check unavailable ({ti_res.error or 'unavailable'})",
                    description=f"Live lookup via {display_name} could not be completed ({ti_res.error or 'unconfigured'}).",
                    observed_value=f"{url} ({ti_res.error or 'unavailable'})",
                    interpretation=f"Source was unavailable; result is bounded as unverified rather than assuming clean or dirty.",
                    status=EvidenceStatus.UNAVAILABLE,
                    reliability=EvidenceReliability.UNVERIFIED,
                    risk_direction=RiskDirection.NEUTRAL,
                    severity=EvidenceSeverity.INFORMATIONAL,
                    confidence=None,
                    correlation_group=f"threat_intel_{provider.name}",
                    raw_data={"source": provider.name, "url": url, "error": ti_res.error},
                ))

        return ti_results, evidence_items


# Global singleton instance
threat_intel_manager = ThreatIntelManager()
