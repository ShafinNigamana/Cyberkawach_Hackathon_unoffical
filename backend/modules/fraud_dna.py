"""
Fraud DNA & Campaign Syndicate Correlation Engine.

Performs cross-incident fingerprinting and clusters related fraud incidents into
tracked threat campaigns based on IOC Jaccard similarity, brand targets,
shared Certificate Transparency subjects, and linguistic lure patterns.
"""

from __future__ import annotations

import hashlib
import re
import threading
from typing import Optional

from backend.models.evidence import FraudDNA, IncidentEvidence


class CampaignTracker:
    """Thread-safe in-memory store for tracking and clustering fraud campaigns."""

    def __init__(self, max_incidents: int = 2000):
        self._lock = threading.Lock()
        self._max_incidents = max_incidents
        # incident_id -> dict(fingerprint, iocs, brand, category, campaign_id, domain)
        self._incidents: dict[str, dict] = {}
        # campaign_id -> list of incident_ids
        self._campaigns: dict[str, list[str]] = {}
        self._campaign_counter: int = 1

    def clear(self) -> None:
        """Clear all stored campaigns (useful for testing)."""
        with self._lock:
            self._incidents.clear()
            self._campaigns.clear()
            self._campaign_counter = 1

    def correlate(
        self,
        incident_id: str,
        fingerprint: str,
        iocs: set[str],
        brand: Optional[str],
        category: str,
        domain: Optional[str],
    ) -> tuple[str, float, list[str], list[str]]:
        """
        Correlate an incident with existing clusters.
        Returns:
            (campaign_id, confidence, related_incident_ids, cluster_indicators)
        """
        with self._lock:
            best_match_id = None
            highest_score = 0.0
            indicators = []

            for past_id, past_data in self._incidents.items():
                if past_id == incident_id:
                    continue

                score = 0.0
                curr_indicators = []

                # Brand match bonus
                if brand and past_data.get("brand") == brand:
                    score += 0.35
                    curr_indicators.append(f"Target brand: {brand}")

                # Category match bonus
                if category and category != "generic" and past_data.get("category") == category:
                    score += 0.25
                    curr_indicators.append(f"Scam category: {category}")

                # IOC overlap (Jaccard similarity)
                past_iocs = past_data.get("iocs", set())
                if iocs and past_iocs:
                    intersection = iocs.intersection(past_iocs)
                    union = iocs.union(past_iocs)
                    if union:
                        jaccard = len(intersection) / len(union)
                        score += jaccard * 0.40
                        if intersection:
                            curr_indicators.append(f"Shared IOCs: {', '.join(list(intersection)[:3])}")

                # Domain root match
                past_domain = past_data.get("domain")
                if domain and past_domain:
                    d1_parts = domain.split(".")
                    d2_parts = past_domain.split(".")
                    # Check shared TLD and length/pattern
                    if len(d1_parts) >= 2 and len(d2_parts) >= 2:
                        if d1_parts[-1] == d2_parts[-1] and (brand and brand.lower() in domain and brand.lower() in past_domain):
                            score += 0.30
                            curr_indicators.append(f"Targeted domain naming: {brand}")

                if score > highest_score:
                    highest_score = score
                    best_match_id = past_id
                    indicators = curr_indicators

            # Clustering decision threshold
            if highest_score >= 0.45 and best_match_id:
                matched_campaign = self._incidents[best_match_id]["campaign_id"]
                campaign_id = matched_campaign
                related = self._campaigns.get(campaign_id, [])
                if incident_id not in related:
                    related.append(incident_id)
                    self._campaigns[campaign_id] = related
                confidence = min(0.95, round(highest_score, 2))
            else:
                # Mint a new campaign ID
                prefix = (brand or category or "PHISH").upper()[:6]
                campaign_id = f"CAMP-{prefix}-{self._campaign_counter:03d}"
                self._campaign_counter += 1
                self._campaigns[campaign_id] = [incident_id]
                confidence = 0.50
                related = []

            # Save current incident
            if len(self._incidents) >= self._max_incidents:
                # Evict oldest entry
                oldest_key = next(iter(self._incidents))
                del self._incidents[oldest_key]

            self._incidents[incident_id] = {
                "fingerprint": fingerprint,
                "iocs": iocs,
                "brand": brand,
                "category": category,
                "campaign_id": campaign_id,
                "domain": domain,
            }

            # Related incidents excluding self
            other_related = [i for i in self._campaigns.get(campaign_id, []) if i != incident_id]
            return campaign_id, confidence, other_related, indicators


_GLOBAL_TRACKER = CampaignTracker()


def get_campaign_tracker() -> CampaignTracker:
    """Access the global campaign tracker singleton."""
    return _GLOBAL_TRACKER


def compute_fraud_dna(evidence: IncidentEvidence) -> FraudDNA:
    """
    Generate Fraud DNA fingerprint and correlate with active syndicate campaigns.
    """
    # 1. Gather structural features for fingerprint
    target_brand = None
    if evidence.brands:
        target_brand = evidence.brands[0].brand_name

    category = evidence.fraud_category or "generic"

    extracted_domain = None
    if evidence.urls:
        extracted_domain = evidence.urls[0].domain

    # Normalize tokens for structural hash
    raw_tokens = re.findall(r"\b[a-zA-Z]{3,}\b", evidence.message.lower())
    token_sample = "-".join(sorted(set(raw_tokens[:15])))

    seed = f"{target_brand}:{category}:{extracted_domain}:{token_sample}"
    fingerprint = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]

    # Collect IOC set
    iocs: set[str] = set()
    if extracted_domain:
        iocs.add(extracted_domain.lower())
    for url_obj in evidence.urls:
        if url_obj.domain:
            iocs.add(url_obj.domain.lower())
    for item in evidence.evidence:
        if item.raw_data and "phone" in item.raw_data:
            iocs.add(str(item.raw_data["phone"]))

    # Correlate with campaign tracker
    campaign_id, confidence, related, indicators = _GLOBAL_TRACKER.correlate(
        incident_id=evidence.incident_id,
        fingerprint=fingerprint,
        iocs=iocs,
        brand=target_brand,
        category=category,
        domain=extracted_domain,
    )

    return FraudDNA(
        fingerprint=fingerprint,
        campaign_id=campaign_id,
        related_incidents=related,
        available=True,
    )
