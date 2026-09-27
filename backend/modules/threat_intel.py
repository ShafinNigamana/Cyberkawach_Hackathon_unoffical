"""
Threat intelligence orchestrator — queries all configured P0 sources.

TI-01: Orchestrates Safe Browsing + PhishTank + PhishStats (P0).
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
from backend.services.threat_intel_providers import threat_intel_manager


async def query_threat_intel(evidence: IncidentEvidence) -> IncidentEvidence:
    """
    Query all configured threat-intel sources for URLs in the evidence.
    Runs URLhaus, PhishTank, PhishStats, Safe Browsing, and VirusTotal in parallel.
    Each result appears as its own sourced evidence item with explicit epistemic status.
    """
    if not evidence.urls:
        return evidence

    urls = [u.url for u in evidence.urls]

    for target_url in urls:
        try:
            ti_results, ev_items = await threat_intel_manager.query_all(target_url)
            for res in ti_results:
                evidence.threat_intel.append(res)
            for item in ev_items:
                evidence.evidence.append(item)
        except Exception as e:
            evidence.errors.append(f"threat_intel_manager: {str(e)}")

    return evidence
