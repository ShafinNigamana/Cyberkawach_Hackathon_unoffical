"""
Evidence fusion — combines all upstream signals into a calibrated risk assessment.

Phase 4 Accuracy Refinement:
- Two-Tier Architecture:
  * Tier 1: Ground truth / authoritative deterministic overrides (confirmed threat intel, spoofed brand + credential demand).
  * Tier 2: Corroborated probabilistic aggregation with correlation dampening.
- Evidentiary Sufficiency:
  * Distinguishes "Insufficient evidence" (UNKNOWN) from "Low concern".
- Contradictory Signal Resolution:
  * Official brand domains dampen generic keyword alarms.
- Epistemic Negative Bounding:
  * Explicitly records what the system cannot conclude.
"""

from __future__ import annotations

from backend.models.evidence import (
    EvidenceSeverity,
    EvidenceStatus,
    EvidenceType,
    IncidentEvidence,
    RiskAssessment,
    RiskDirection,
    RiskLevel,
    UserCategory,
)
from backend.modules.brand_check import is_official_brand_domain


# ─── Signal weights for fusion (Tier 2) ───

_WEIGHTS = {
    EvidenceType.THREAT_INTEL_HIT: 0.30,
    EvidenceType.BRAND_MISMATCH: 0.20,
    EvidenceType.RULE_MATCH: 0.22,
    EvidenceType.PATTERN_MATCH: 0.15,
    EvidenceType.URL_ANALYSIS: 0.10,
    EvidenceType.IOC_EXTRACTED: 0.05,
    EvidenceType.THREAT_INTEL_MISS: 0.0,  # Neutral — absence of match never reduces risk score
    EvidenceType.LAYA_SIGNAL: 0.15,
    EvidenceType.ML_SIGNAL: 0.12,
    EvidenceType.REDIRECT_CHAIN: 0.08,
    EvidenceType.DOMAIN_AGE: 0.12,
    EvidenceType.CAMPAIGN_LINK: 0.10,
    EvidenceType.DNS_RECORD: 0.08,
    EvidenceType.TLS_CERTIFICATE: 0.12,
    EvidenceType.HTTP_REDIRECT: 0.10,
    EvidenceType.WEBSITE_BEHAVIOR: 0.22,
    EvidenceType.SENDER_ANALYSIS: 0.18,
}

# ─── Risk level thresholds ───

_THRESHOLDS = {
    RiskLevel.CRITICAL: 0.85,
    RiskLevel.HIGH: 0.60,
    RiskLevel.MEDIUM: 0.30,
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
    else:
        return RiskLevel.LOW


def fuse_evidence(evidence: IncidentEvidence) -> IncidentEvidence:
    """
    Two-Tier Risk Fusion Engine:
    1. Evaluates Tier 1 hard authoritative overrides.
    2. If no hard override, computes Tier 2 dampened weighted sum.
    3. Resolves contradictory signals (e.g. verified official domains).
    4. Computes evidentiary sufficiency, uncertainty reasons, and negative bounds.
    """
    contributing_factors: list[str] = []
    uncertainty_reasons: list[str] = []
    what_cannot_be_concluded: list[str] = []

    # ─────────────────────────────────────────────────────────────
    # Tier 1: Authoritative Deterministic Overrides
    # ─────────────────────────────────────────────────────────────

    # 1. Confirmed Threat Intel Hit
    confirmed_ti_hits = [
        item for item in evidence.evidence
        if item.type == EvidenceType.THREAT_INTEL_HIT
        and getattr(item, "status", None) == EvidenceStatus.CONFIRMED
    ]

    # 2. Strong Brand Impersonation + Credential/Financial/Metadata Demand
    has_strong_brand_mismatch = any(
        item.type == EvidenceType.BRAND_MISMATCH
        and (item.confidence or 0.0) >= 0.70
        for item in evidence.evidence
    )
    has_credential_request = any(
        'credential_request' in (item.raw_data or {}).get('credential_signals', [{}])[0].get('type', '')
        if item.raw_data and 'credential_signals' in item.raw_data
        else 'credential_request' in item.description.lower()
        for item in evidence.evidence
    )
    has_financial_demand = any(
        'financial' in item.description.lower() or 'fee' in item.description.lower()
        for item in evidence.evidence
    )
    has_cloud_metadata = any(
        (item.raw_data or {}).get("signal") == "cloud_metadata_ip"
        for item in evidence.evidence
    )

    if confirmed_ti_hits:
        hit_src = confirmed_ti_hits[0].source.replace("_", " ").title()
        contributing_factors.append(
            f"[AUTHORITATIVE OVERRIDE] Confirmed threat database hit ({hit_src}): {confirmed_ti_hits[0].description[:80]}"
        )
        what_cannot_be_concluded.append(
            "System cannot determine whether credentials or financial assets were actually compromised on the user device."
        )

        evidence.risk = RiskAssessment(
            level=RiskLevel.CRITICAL,
            category=UserCategory.CONFIRMED_HIGH_RISK,
            score=0.98,
            calibrated=True,
            evidence_sufficiency="SUFFICIENT",
            uncertainty_reasons=[],
            what_cannot_be_concluded=what_cannot_be_concluded,
            contributing_factors=contributing_factors,
        )
        return evidence

    if has_strong_brand_mismatch and (has_credential_request or has_financial_demand or has_cloud_metadata):
        contributing_factors.append(
            "[AUTHORITATIVE OVERRIDE] Verified brand impersonation combined with sensitive credential/financial demand"
        )
        what_cannot_be_concluded.append(
            "System cannot determine whether credentials or financial assets were actually compromised on the user device."
        )

        evidence.risk = RiskAssessment(
            level=RiskLevel.CRITICAL,
            category=UserCategory.HIGH_RISK,
            score=0.88,
            calibrated=True,
            evidence_sufficiency="SUFFICIENT",
            uncertainty_reasons=["Domain is not yet listed in external threat databases (likely newly registered)."],
            what_cannot_be_concluded=what_cannot_be_concluded,
            contributing_factors=contributing_factors,
        )
        return evidence

    # 3. Credential Harvesting / Cross-Domain Form Exfiltration Observed on Site
    has_cred_exfiltration = any(
        item.type == EvidenceType.WEBSITE_BEHAVIOR
        and item.severity == EvidenceSeverity.CRITICAL
        and item.status == EvidenceStatus.CONFIRMED
        for item in evidence.evidence
    )
    if has_cred_exfiltration:
        contributing_factors.append(
            "[AUTHORITATIVE OVERRIDE] Confirmed credential exfiltration form observed posting data to external third-party host"
        )
        what_cannot_be_concluded.append(
            "System cannot determine whether user has already entered authentication secrets on this page."
        )
        evidence.risk = RiskAssessment(
            level=RiskLevel.CRITICAL,
            category=UserCategory.HIGH_RISK,
            score=0.92,
            calibrated=True,
            evidence_sufficiency="SUFFICIENT",
            uncertainty_reasons=[],
            what_cannot_be_concluded=what_cannot_be_concluded,
            contributing_factors=contributing_factors,
        )
        return evidence

    # 4. Bank / Government Alert from Personal Mobile Phone (Severe Smishing Signal)
    has_mobile_bank_impersonation = any(
        item.type == EvidenceType.SENDER_ANALYSIS
        and item.severity == EvidenceSeverity.HIGH
        and (item.raw_data or {}).get("type") == "personal_mobile_impersonation"
        for item in evidence.evidence
    )
    if has_mobile_bank_impersonation:
        contributing_factors.append(
            "[AUTHORITATIVE OVERRIDE] Personal 10-digit mobile number impersonating institutional banking/KYC alert"
        )
        evidence.risk = RiskAssessment(
            level=RiskLevel.HIGH,
            category=UserCategory.HIGH_RISK,
            score=0.85,
            calibrated=True,
            evidence_sufficiency="SUFFICIENT",
            uncertainty_reasons=["Sender operator lookup depends on telecom registry."],
            what_cannot_be_concluded=what_cannot_be_concluded,
            contributing_factors=contributing_factors,
        )
        return evidence

    # ─────────────────────────────────────────────────────────────
    # Tier 2: Probabilistic Aggregation with Correlation Dampening
    # ─────────────────────────────────────────────────────────────

    total_score = 0.0
    group_counts: dict[str, int] = {}
    type_contributions: dict[str, float] = {}

    active_suspicious_items = [
        item for item in evidence.evidence
        if getattr(item, "risk_direction", None) == RiskDirection.INCREASES_RISK
    ]

    for item in evidence.evidence:
        # Factual observations and misses do not contribute to risk score
        if getattr(item, "risk_direction", None) == RiskDirection.NEUTRAL:
            continue

        weight = _WEIGHTS.get(item.type, 0.05)
        conf = item.confidence if item.confidence is not None else 1.0

        # Apply correlation dampening for multiple signals in the same correlation group
        group = getattr(item, "correlation_group", None)
        if group:
            hit_rank = group_counts.get(group, 0)
            dampening = 1.0 / (1.0 + 0.5 * hit_rank)
            group_counts[group] = hit_rank + 1
        else:
            dampening = 1.0

        contribution = weight * conf * dampening
        total_score += contribution

        type_key = item.type.value
        type_contributions[type_key] = type_contributions.get(type_key, 0.0) + contribution

        if contribution > 0.04:
            contributing_factors.append(
                f"{item.source}: {item.description[:80]} (+{contribution:.2f})"
            )

    # ─────────────────────────────────────────────────────────────
    # Contradictory Signal Resolution: Verified Official Brand Domains & Government Infrastructure
    # ─────────────────────────────────────────────────────────────

    has_verified_official_domain = False
    verified_domains: list[str] = []
    if evidence.urls:
        for u in evidence.urls:
            if is_official_brand_domain(u.domain):
                has_verified_official_domain = True
                verified_domains.append(u.domain)

    # Check if sender header is a verified TRAI Government entity header
    has_gov_sender = any(
        item.type == EvidenceType.SENDER_ANALYSIS
        and (item.raw_data or {}).get("is_government") is True
        for item in evidence.evidence
    )

    is_trusted_entity = has_verified_official_domain or has_gov_sender

    if is_trusted_entity and not has_strong_brand_mismatch:
        # Check if any hard malicious behavior was confirmed (threat intel, credential theft, external exfiltration, fake mobile bank)
        has_real_attack_intent = bool(
            confirmed_ti_hits
            or has_credential_request
            or has_financial_demand
            or has_cred_exfiltration
            or has_mobile_bank_impersonation
        )

        if not has_real_attack_intent:
            # Trusted infrastructure + absence of scam payload = Legitimate / Safe broadcast
            # Suppress heuristic keyword noise, statutory disclosures, and statistical fluctuations
            total_score = 0.0
            domain_label = ", ".join(verified_domains) if verified_domains else "TRAI Government DLT sender"
            contributing_factors = [
                f"[OFFICIAL INFRASTRUCTURE VERIFIED] Domain/sender matches confirmed official portal ({domain_label}). "
                "Absence of credential demands, suspicious forms, or brand mismatch confirms legitimate communication; "
                "statutory regulatory disclosures and civic campaign context do not elevate threat level."
            ]
        else:
            # If sensitive demands exist on an official domain (e.g. routine bank OTP notice), dampen heuristic score
            total_score = min(total_score, 0.15)
            contributing_factors.append(
                "Verified official brand domain matches message context — heuristic risk dampened"
            )

    final_score = max(0.0, min(1.0, total_score))

    # ─────────────────────────────────────────────────────────────
    # Evidentiary Sufficiency & Unknown Assessment
    # ─────────────────────────────────────────────────────────────

    text_words = len((evidence.message or "").strip().split())
    has_verifiable_indicators = bool(
        evidence.urls or evidence.iocs or evidence.brands or evidence.rule_matches
    )

    if is_trusted_entity and not (confirmed_ti_hits or has_strong_brand_mismatch or has_credential_request or has_financial_demand or has_cred_exfiltration or has_mobile_bank_impersonation):
        evidence_sufficiency = "SUFFICIENT"
        final_level = RiskLevel.LOW
        final_category = UserCategory.LOW_CONCERN
        final_score = 0.0
    elif not active_suspicious_items and (text_words < 6 or not has_verifiable_indicators):
        # Input lacks sufficient substance to evaluate
        evidence_sufficiency = "INSUFFICIENT"
        final_level = RiskLevel.UNKNOWN
        final_category = UserCategory.UNKNOWN
        final_score = 0.0
        uncertainty_reasons.append(
            "Input contains insufficient content or verifiable indicators to evaluate risk."
        )
        what_cannot_be_concluded.append(
            "Cannot conclude whether message is benign or part of an unknown attack due to lack of verifiable indicators."
        )
    elif active_suspicious_items:
        evidence_sufficiency = "PARTIAL"
        final_level = _score_to_level(final_score)
        if final_level == RiskLevel.CRITICAL:
            final_category = UserCategory.HIGH_RISK
        elif final_level == RiskLevel.HIGH:
            final_category = UserCategory.HIGH_RISK
        elif final_level == RiskLevel.MEDIUM:
            final_category = UserCategory.SUSPICIOUS
        else:
            final_category = UserCategory.LOW_CONCERN

        uncertainty_reasons.append(
            "Risk assessment is derived from heuristic and pattern signals without external database confirmation."
        )
    else:
        # Message has substance (words >= 6) and passed checks without suspicious signals
        evidence_sufficiency = "PARTIAL"
        final_score = round(final_score, 3)
        final_level = _score_to_level(final_score)
        final_category = UserCategory.LOW_CONCERN

    # Epistemic bounds on threat intelligence
    if evidence.threat_intel:
        what_cannot_be_concluded.append(
            "Absence of threat intelligence matches indicates the URL is unlisted or newly active; "
            "it does not prove the website is safe or legitimate."
        )

    if not evidence.urls:
        what_cannot_be_concluded.append(
            "Evaluation is limited to message lexical patterns; sender infrastructure could not be analyzed."
        )

    evidence.risk = RiskAssessment(
        level=final_level,
        category=final_category,
        score=round(final_score, 3),
        calibrated=True,
        evidence_sufficiency=evidence_sufficiency,
        uncertainty_reasons=uncertainty_reasons,
        what_cannot_be_concluded=what_cannot_be_concluded,
        contributing_factors=contributing_factors if contributing_factors else ["No notable risk factors detected."],
    )

    return evidence
