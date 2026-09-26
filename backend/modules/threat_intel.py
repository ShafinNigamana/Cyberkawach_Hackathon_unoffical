"""
Threat intelligence orchestrator — queries all configured P0 sources.

TI-01: Orchestrates Safe Browsing + PhishTank (P0).
Each result is stored as an individual ThreatIntelResult with source attribution.
"""

from __future__ import annotations

import asyncio

from backend.models.evidence import (
    EvidenceItem,
    EvidenceReliability,
    EvidenceSeverity,
    EvidenceStatus,
    EvidenceType,
    IncidentEvidence,
    RiskDirection,
    ThreatIntelResult,
    ThreatIntelStatus,
)
from backend.services.safe_browsing import check_safe_browsing
from backend.services.phishtank import check_phishtank
from backend.services.phishstats import check_phishstats


async def query_threat_intel(evidence: IncidentEvidence) -> IncidentEvidence:
    """
    Query all configured threat-intel sources for URLs in the evidence.
    Runs Safe Browsing, PhishTank, and PhishStats in parallel.
    Each result appears as its own sourced evidence item with explicit epistemic status.
    """
    if not evidence.urls:
        return evidence

    urls = [u.url for u in evidence.urls]

    # Run sources in parallel
    results_list = await asyncio.gather(
        check_safe_browsing(urls),
        check_phishtank(urls),
        check_phishstats(urls),
        return_exceptions=True,
    )

    source_names = ["safe_browsing", "phishtank", "phishstats"]

    for src_name, batch_result in zip(source_names, results_list):
        if isinstance(batch_result, Exception):
            evidence.errors.append(f"{src_name}: {str(batch_result)}")
            continue

        for result in batch_result:
            if not isinstance(result, ThreatIntelResult):
                continue

            evidence.threat_intel.append(result)

            display_source = result.source.replace("_", " ").title()

            if result.intel_status == ThreatIntelStatus.KNOWN_MALICIOUS:
                evidence.evidence.append(EvidenceItem(
                    type=EvidenceType.THREAT_INTEL_HIT,
                    source=result.source,
                    description=f"{display_source}: URL confirmed malicious — {result.details or 'known threat match'}",
                    confidence=0.95,
                    status=EvidenceStatus.CONFIRMED,
                    reliability=EvidenceReliability.EXTERNAL_DB,
                    severity=EvidenceSeverity.CRITICAL,
                    risk_direction=RiskDirection.INCREASES_RISK,
                    observed_value=f"{result.lookup_url} (match: {result.details or 'confirmed phish'})",
                    interpretation=f"URL actively catalogued as malicious in {display_source} threat intelligence feed",
                    correlation_group=f"threat_intel_{result.source}",
                    raw_data={
                        "source": result.source,
                        "url": result.lookup_url,
                        "details": result.details,
                        "intel_status": result.intel_status.value,
                    },
                ))
            elif result.intel_status == ThreatIntelStatus.NO_KNOWN_MATCH:
                evidence.evidence.append(EvidenceItem(
                    type=EvidenceType.THREAT_INTEL_MISS,
                    source=result.source,
                    description=f"{display_source}: URL has no known match in feed",
                    confidence=None,
                    status=EvidenceStatus.OBSERVED,
                    reliability=EvidenceReliability.EXTERNAL_DB,
                    severity=EvidenceSeverity.INFORMATIONAL,
                    risk_direction=RiskDirection.NEUTRAL,
                    observed_value=f"{result.lookup_url} (no match)",
                    interpretation=(
                        f"URL is not currently listed in {display_source}; "
                        "absence of a match does not guarantee the URL is safe"
                    ),
                    correlation_group=f"threat_intel_{result.source}",
                    raw_data={
                        "source": result.source,
                        "url": result.lookup_url,
                        "intel_status": result.intel_status.value,
                    },
                ))
            elif result.intel_status in (ThreatIntelStatus.SOURCE_UNAVAILABLE, ThreatIntelStatus.SOURCE_ERROR):
                # Informational record that source was not available
                evidence.evidence.append(EvidenceItem(
                    type=EvidenceType.THREAT_INTEL_MISS,
                    source=result.source,
                    description=f"{display_source}: Source lookup unavailable ({result.error or 'unavailable'})",
                    confidence=None,
                    status=EvidenceStatus.UNAVAILABLE,
                    reliability=EvidenceReliability.UNVERIFIED,
                    severity=EvidenceSeverity.INFORMATIONAL,
                    risk_direction=RiskDirection.NEUTRAL,
                    observed_value=f"{result.lookup_url} ({result.error or 'unavailable'})",
                    interpretation=f"{display_source} was unavailable; could not verify URL against this feed",
                    correlation_group=f"threat_intel_{result.source}",
                    raw_data={
                        "source": result.source,
                        "url": result.lookup_url,
                        "intel_status": result.intel_status.value,
                        "error": result.error,
                    },
                ))

    return evidence
