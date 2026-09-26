"""
Evidence fusion — combines all upstream signals into a single risk score.

FUS-01: Weighted fusion with provenance tracking.
Every contributing factor is recorded so the score is explainable.
"""

from __future__ import annotations

from backend.models.evidence import (
    EvidenceType,
    IncidentEvidence,
    RiskAssessment,
    RiskLevel,
)


# ─── Signal weights for fusion ───

_WEIGHTS = {
    EvidenceType.THREAT_INTEL_HIT: 0.30,
    EvidenceType.BRAND_MISMATCH: 0.20,
    EvidenceType.RULE_MATCH: 0.15,
    EvidenceType.PATTERN_MATCH: 0.12,
    EvidenceType.URL_ANALYSIS: 0.10,
    EvidenceType.IOC_EXTRACTED: 0.05,
    EvidenceType.THREAT_INTEL_MISS: -0.05,  # Negative — reduces score slightly
    EvidenceType.LAYA_SIGNAL: 0.15,
    EvidenceType.REDIRECT_CHAIN: 0.08,
    EvidenceType.DOMAIN_AGE: 0.10,
    EvidenceType.CAMPAIGN_LINK: 0.10,
}

# ─── Risk level thresholds ───

_THRESHOLDS = {
    RiskLevel.CRITICAL: 0.85,
    RiskLevel.HIGH: 0.65,
    RiskLevel.MEDIUM: 0.40,
    RiskLevel.LOW: 0.15,
}


def _score_to_level(score: float) -> RiskLevel:
    """Convert numeric score to risk level."""
    if score >= _THRESHOLDS[RiskLevel.CRITICAL]:
        return RiskLevel.CRITICAL
    elif score >= _THRESHOLDS[RiskLevel.HIGH]:
        return RiskLevel.HIGH
    elif score >= _THRESHOLDS[RiskLevel.MEDIUM]:
        return RiskLevel.MEDIUM
    elif score >= _THRESHOLDS[RiskLevel.LOW]:
        return RiskLevel.LOW
    else:
        return RiskLevel.UNKNOWN


def fuse_evidence(evidence: IncidentEvidence) -> IncidentEvidence:
    """
    Fuse all evidence items into a single risk score with provenance.
    Uses weighted summation clamped to [0, 1].
    """
    if not evidence.evidence:
        evidence.risk = RiskAssessment(
            level=RiskLevel.UNKNOWN,
            score=0.0,
            calibrated=False,
            contributing_factors=["No evidence items to evaluate"],
        )
        return evidence

    total_score = 0.0
    contributing_factors = []

    # Group evidence by type and compute weighted contribution
    type_contributions: dict[str, float] = {}

    for item in evidence.evidence:
        weight = _WEIGHTS.get(item.type, 0.05)
        contribution = weight * item.confidence
        total_score += contribution

        type_key = item.type.value
        type_contributions[type_key] = type_contributions.get(type_key, 0.0) + contribution

        if contribution > 0.05:  # Only track significant contributors
            contributing_factors.append(
                f"{item.source}: {item.description[:80]} (+{contribution:.2f})"
            )

    # Clamp to [0, 1]
    final_score = max(0.0, min(1.0, total_score))

    # Boost: multiple threat-intel hits from different sources = high confidence
    ti_hit_count = sum(
        1 for item in evidence.evidence
        if item.type == EvidenceType.THREAT_INTEL_HIT
    )
    if ti_hit_count >= 2:
        final_score = min(1.0, final_score + 0.15)
        contributing_factors.append(f"Multiple threat-intel hits ({ti_hit_count} sources) — score boosted")

    # Boost: brand mismatch + credential request = strong phishing signal
    has_brand_mismatch = any(
        item.type == EvidenceType.BRAND_MISMATCH for item in evidence.evidence
    )
    has_credential_request = any(
        'credential_request' in (item.raw_data or {}).get('credential_signals', [{}])[0].get('type', '')
        if item.raw_data and 'credential_signals' in item.raw_data
        else 'credential_request' in item.description
        for item in evidence.evidence
    )
    if has_brand_mismatch and has_credential_request:
        final_score = min(1.0, final_score + 0.10)
        contributing_factors.append("Brand mismatch + credential request = strong phishing signal")

    evidence.risk = RiskAssessment(
        level=_score_to_level(final_score),
        score=round(final_score, 3),
        calibrated=False,  # True only after Phase 4 calibration
        contributing_factors=contributing_factors,
    )

    return evidence
