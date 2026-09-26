"""
Threat intelligence orchestrator — queries all configured P0 sources.

TI-01: Orchestrates Safe Browsing + PhishTank (P0).
Each result is stored as an individual ThreatIntelResult with source attribution.
"""

from __future__ import annotations

import asyncio

from backend.models.evidence import (
    EvidenceItem,
    EvidenceType,
    IncidentEvidence,
)
from backend.services.safe_browsing import check_safe_browsing
from backend.services.phishtank import check_phishtank


async def query_threat_intel(evidence: IncidentEvidence) -> IncidentEvidence:
    """
    Query all P0 threat-intel sources for URLs in the evidence.
    Runs Safe Browsing and PhishTank in parallel.
    Each result appears as its own sourced evidence item — never collapsed.
    """
    if not evidence.urls:
        return evidence

    urls = [u.url for u in evidence.urls]

    # Run P0 sources in parallel
    sb_results, pt_results = await asyncio.gather(
        check_safe_browsing(urls),
        check_phishtank(urls),
        return_exceptions=True,
    )

    # Process Safe Browsing results
    if isinstance(sb_results, Exception):
        evidence.errors.append(f"safe_browsing: {str(sb_results)}")
    else:
        for result in sb_results:
            evidence.threat_intel.append(result)
            if result.match is True:
                evidence.evidence.append(EvidenceItem(
                    type=EvidenceType.THREAT_INTEL_HIT,
                    source="safe_browsing",
                    description=f"Google Safe Browsing: URL flagged — {result.details or 'match found'}",
                    confidence=0.9,
                    raw_data={
                        "source": "safe_browsing",
                        "url": result.lookup_url,
                        "details": result.details,
                    },
                ))
            elif result.match is False:
                evidence.evidence.append(EvidenceItem(
                    type=EvidenceType.THREAT_INTEL_MISS,
                    source="safe_browsing",
                    description=f"Google Safe Browsing: URL not flagged",
                    confidence=0.7,
                    raw_data={
                        "source": "safe_browsing",
                        "url": result.lookup_url,
                    },
                ))
            # match=None (error) — already captured in result.error

    # Process PhishTank results
    if isinstance(pt_results, Exception):
        evidence.errors.append(f"phishtank: {str(pt_results)}")
    else:
        for result in pt_results:
            evidence.threat_intel.append(result)
            if result.match is True:
                evidence.evidence.append(EvidenceItem(
                    type=EvidenceType.THREAT_INTEL_HIT,
                    source="phishtank",
                    description=f"PhishTank: URL confirmed as phishing — {result.details or 'verified phish'}",
                    confidence=0.95,
                    raw_data={
                        "source": "phishtank",
                        "url": result.lookup_url,
                        "details": result.details,
                    },
                ))
            elif result.match is False:
                evidence.evidence.append(EvidenceItem(
                    type=EvidenceType.THREAT_INTEL_MISS,
                    source="phishtank",
                    description=f"PhishTank: URL not in phishing database",
                    confidence=0.6,
                    raw_data={
                        "source": "phishtank",
                        "url": result.lookup_url,
                    },
                ))

    return evidence
