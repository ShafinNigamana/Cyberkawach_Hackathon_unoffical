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

import re
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


# ─── Two-Tier Evidence Fusion Engine: Mathematical Formulation ───
#
# Tier 1 (Deterministic / Authoritative Hard Overrides):
# If authoritative ground-truth evidence is observed (confirmed threat feed match, verified credential theft form,
# brand impersonation with financial/credential coercion, personal mobile smishing, or deceptive anchor mismatch),
# the risk score is clamped deterministically to HIGH (0.85-0.88) or CRITICAL (0.92-0.98), bypassing heuristic summation.
#
# Tier 2 (Dampened Weighted Evidence Accumulation):
# When no single signal is authoritative, the overall risk score S is computed as:
#
#     S = clamp( sum_{i in Active} w_{T(i)} * c_i * delta(g(i), k_i), 0.0, 1.0 )
#
# where:
#   - w_{T(i)} is the calibrated weight for evidence type T(i)
#   - c_i in [0.0, 1.0] is the epistemic confidence of indicator i
#   - delta(g, k) = 1.0 / (1.0 + 0.5 * k) is the hyperbolic correlation dampener for the k-th hit
#     within correlation group g (preventing multiple co-linear signals from artificially blowing up risk)
#   - Contradictory signal suppression: if the sender or destination domain is verified official infrastructure
#     and no real attack intent (exfiltration/credential demand) exists, S is reset to 0.0 (Legitimate).
#
# Weight calibration rationale:
# - Deterministic/Threat Intel (w = 0.30): Authoritative third-party consensus.
# - Behavioral/Financial/Website Form (w = 0.22): Direct active fraud mechanics (fake login, mule VPA, extortion).
# - Brand & Identity Spoofing (w = 0.20): High-fidelity typosquatting and identity diversion.
# - Telecom / DLT Sender & Rules (w = 0.18-0.22): Regulatory header mismatch and structured forensic patterns.
# - Infrastructure & Linguistic Obfuscation (w = 0.16): Zero-width chars, homoglyphs, ASN/hosting anomalies.
# - ML & Semantic Classifiers (w = 0.12-0.15): Statistical probability scores, prone to out-of-distribution drift.
# - Passive Network Signals (w = 0.08-0.12): Domain age, TLS self-signed, URL entropy (weak standalone signals).
# - Neutral Facts / Misses (w = 0.00): Absence of a threat intelligence match is NOT evidence of benign nature.

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
    EvidenceType.FINANCIAL_ANALYSIS: 0.22,
    EvidenceType.INFRASTRUCTURE_ANALYSIS: 0.16,
    EvidenceType.TELECOM_ANALYSIS: 0.18,
    EvidenceType.LINGUISTIC_ANALYSIS: 0.16,
}

# ─── Risk level thresholds ───

_THRESHOLDS = {
    RiskLevel.CRITICAL: 0.80,
    RiskLevel.HIGH: 0.55,
    RiskLevel.MEDIUM: 0.25,
    RiskLevel.LOW: 0.10,
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


def _assess_text_only_legitimacy(evidence: IncidentEvidence) -> tuple[bool, list[str]]:
    """
    For text-only messages (no URLs), assess if the message matches known
    legitimate transactional SMS / notification patterns that should suppress heuristic noise.
    """
    msg = (evidence.message or "").strip()
    if not msg:
        return False, []

    reasons: list[str] = []

    # Pattern 1: Standard bank debit/credit alert format with masked account & balance/ref
    has_account_mask = bool(re.search(r'(?:a/c|account|card)\s*(?:no\.?|num(?:ber)?|ending(?:\s+in)?|\*{2,}|x{2,})\s*[\dXx*]{3,}', msg, re.I))
    has_financial_verb = bool(re.search(r'\b(?:debited|credited|withdrawn|swiped|deposited|transferred|cleared|added|received|paid|spent|refunded|charged)\b', msg, re.I))
    has_balance_or_ref = bool(re.search(r'(?:avail(?:able)?\s*bal|clear\s*bal|balance|upi\s*ref|ref\s*(?:no|id)?|txn\s*(?:id|no)|rrn\b)', msg, re.I))

    if has_account_mask and has_financial_verb and has_balance_or_ref:
        reasons.append("Standard institutional banking transaction alert with account masking and balance/reference confirmation")
        return True, reasons

    # Pattern 1b: Customer-initiated request confirmation (e.g. card blocked on user request)
    if re.search(r'(?:as\s+per\s+your(?:\s+\w+)*\s+request|on\s+your\s+request|requested\s+by\s+you|per\s+your\s+instruction)', msg, re.I):
        if has_account_mask and not re.search(r'(?:http|www\.|\.xyz|\.top|\.icu|\.cc|\.club)', msg, re.I):
            reasons.append("Customer-initiated banking service confirmation with account masking")
            return True, reasons

    # Pattern 2: "Never share OTP / PIN" warning without malicious link or external urgency demand
    if re.search(r'(?:never|do\s+not)\s+share.*?(?:otp|password|pin|cvv)', msg, re.I):
        if not re.search(r'(?:click|tap|http|www\.|\.xyz|\.top|\.icu|\.cc|\.club|call\s+\+?91[\d-]{10})', msg, re.I):
            reasons.append("Contains 'never share OTP' security warning without external links or suspicious redirection")
            return True, reasons

    # Pattern 3: Genuine UPI payment confirmation with transaction reference number
    if re.search(r'(?:paid|sent|received|transferred)\s+(?:rs\.?|inr|₹)\s*[\d,]+', msg, re.I):
        if re.search(r'(?:upi\s*ref|ref\s*(?:no|id)?|txn\s*id|transaction\s*id|utr\b)\s*[:\s]*\d{8,}', msg, re.I):
            reasons.append("UPI payment confirmation with verified transaction reference number")
            return True, reasons

    # Pattern 4: Official utility billing receipt or LPG booking confirmation
    if re.search(r'(?:bill|payment|consumer|service\s*id|lpg\s*cylinder|booking\s*(?:ref|#))\s*(?:id|no\.?|#)?\s*[:\s]*\d{5,}', msg, re.I):
        if re.search(r'\b(?:received\s*successfully|auto[\s-]?pay|subsidy\s*of|cash\s*memo|booking\s*(?:is\s*)?confirmed)\b', msg, re.I):
            reasons.append("Institutional utility billing / LPG service receipt with verified consumer identifier")
            return True, reasons

    # Pattern 5: Official telco plan expiry / balance reminder pointing to official app or USSD
    if re.search(r'\b(?:jio|airtel|vi|bsnl)\b', msg, re.I) and re.search(r'\b(?:plan|pack|validity|data\s*plan|recharge)\b', msg, re.I):
        if re.search(r'\b(?:myjio|airtel\s*thanks|vi\s*app|dial\s*\*[\d#]+)\b', msg, re.I):
            if not re.search(r'(?:http|www\.|\.xyz|\.top|\.icu|\.cc|\.club)', msg, re.I):
                reasons.append("Official telecommunications subscription notice directing to authorized telecom application")
                return True, reasons

    # Pattern 6: Civic infrastructure / DISCOM maintenance announcement with official short helpline
    if re.search(r'\b(?:maintenance|outage|grid|scheduled\s*power|inconvenience\s*regretted)\b', msg, re.I):
        if re.search(r'\b(?:helpline|call|toll[\s-]?free)?\s*[:\s]*(?:1912|1930|112|100|1800[\d-]{6,10})\b', msg, re.I):
            if not re.search(r'(?:http|www\.|\.xyz|\.top|\.icu|\.cc|\.club|apk|install)', msg, re.I):
                reasons.append("Civic utility service advisory with recognized statutory helpline")
                return True, reasons

    # Pattern 7: Official Government public service message (e.g. CoWIN, Income Tax, EPFO)
    if re.search(r'\b(?:cowin|aarogya\s*setu|income\s*tax|epfo|digilocker|ministry\s*of)\b', msg, re.I):
        if not evidence.urls or all(
            any((u.domain or "").lower().endswith(tld) for tld in ('.gov.in', '.nic.in', 'gov.in', 'nic.in'))
            for u in evidence.urls
        ):
            reasons.append("Official government public service notification hosted on verified .gov.in / .nic.in infrastructure")
            return True, reasons

    return False, []


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
        getattr(item, "correlation_group", "") in ("payment_diversion", "crypto_settlement", "payment_mule_vector", "fee_extortion")
        or (
            item.type in (EvidenceType.RULE_MATCH, EvidenceType.PATTERN_MATCH)
            and any(kw in item.description.lower() for kw in ('processing fee', 'registration fee', 'customs fee', 'penalty fee', 'extortion', 'upfront fee', 'joining fee'))
        )
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

    # 5. Deceptive Hyperlink Anchor Mismatch (Phishing Lure)
    has_anchor_mismatch = any(
        item.correlation_group == "deceptive_link"
        and item.status == EvidenceStatus.CONFIRMED
        for item in evidence.evidence
    )
    if has_anchor_mismatch:
        contributing_factors.append(
            "[AUTHORITATIVE OVERRIDE] Deceptive hyperlink detected: visible link anchor text misrepresents actual destination URL"
        )
        evidence.risk = RiskAssessment(
            level=RiskLevel.HIGH,
            category=UserCategory.HIGH_RISK,
            score=0.86,
            calibrated=True,
            evidence_sufficiency="SUFFICIENT",
            uncertainty_reasons=["Destination server payload not dynamically executed in sandbox."],
            what_cannot_be_concluded=what_cannot_be_concluded,
            contributing_factors=contributing_factors,
        )
        return evidence

    # 6. Malicious Unicode Smuggling / Bidi Override Evasion
    has_unicode_evasion = any(
        item.correlation_group == "unicode_obfuscation"
        and item.status == EvidenceStatus.CONFIRMED
        for item in evidence.evidence
    )
    if has_unicode_evasion:
        contributing_factors.append(
            "[AUTHORITATIVE OVERRIDE] Intentional Unicode character smuggling (Zero-Width / RTL Override) detected to disguise file extensions or evade keyword filtering"
        )
        evidence.risk = RiskAssessment(
            level=RiskLevel.HIGH,
            category=UserCategory.HIGH_RISK,
            score=0.88,
            calibrated=True,
            evidence_sufficiency="SUFFICIENT",
            uncertainty_reasons=[],
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
        # Dynamically scale weight for high-confidence model detections & suspicious indicators
        if item.type == EvidenceType.ML_SIGNAL:
            if item.severity in (EvidenceSeverity.HIGH, EvidenceSeverity.CRITICAL) or "phishing" in (item.description or "").lower():
                weight = max(weight, 0.40)
            elif item.status == EvidenceStatus.SUSPICIOUS:
                weight = max(weight, 0.25)
        elif item.type == EvidenceType.LAYA_SIGNAL:
            if item.severity in (EvidenceSeverity.HIGH, EvidenceSeverity.CRITICAL) or (item.confidence or 0.0) >= 0.70:
                weight = max(weight, 0.35)
            elif item.status == EvidenceStatus.SUSPICIOUS:
                weight = max(weight, 0.25)
        elif item.type == EvidenceType.URL_ANALYSIS and getattr(item, "status", None) == EvidenceStatus.SUSPICIOUS:
            weight = max(weight, 0.20)

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

    # Ensure high-confidence model phishing detection establishes a proportional risk floor
    for item in evidence.evidence:
        if getattr(item, "risk_direction", None) == RiskDirection.INCREASES_RISK:
            desc_l = (item.description or "").lower()
            conf = item.confidence or 0.0
            if (
                item.type == EvidenceType.ML_SIGNAL
                and ("phishing" in desc_l or item.severity in (EvidenceSeverity.HIGH, EvidenceSeverity.CRITICAL))
                and conf >= 0.70
            ):
                min_phish_score = round(conf * 0.85, 2)
                if total_score < min_phish_score:
                    total_score = min_phish_score
                    contributing_factors.append(
                        f"[ML PHISHING ELEVATION] High-confidence machine learning classification ({conf:.0%}) set risk floor to {min_phish_score:.2f}"
                    )

    # ─────────────────────────────────────────────────────────────
    # Contradictory Signal Resolution: Verified Official Brand Domains & Government Infrastructure
    # ─────────────────────────────────────────────────────────────

    has_verified_official_domain = False
    verified_domains: list[str] = []
    if evidence.urls:
        for u in evidence.urls:
            dom = (u.domain or "").lower().strip()
            if is_official_brand_domain(dom) or any(dom.endswith(tld) for tld in ('.gov.in', '.nic.in')):
                has_verified_official_domain = True
                verified_domains.append(dom)

    # Check if sender header is a verified TRAI Government entity header
    has_gov_sender = any(
        item.type == EvidenceType.SENDER_ANALYSIS
        and (item.raw_data or {}).get("is_government") is True
        for item in evidence.evidence
    )

    is_trusted_entity = has_verified_official_domain or has_gov_sender

    # Check transactional legitimacy: if no URLs, or if all present URLs are verified official/government domains
    all_urls_trusted = bool(evidence.urls) and all(
        is_official_brand_domain((u.domain or "").lower())
        or any((u.domain or "").lower().endswith(tld) for tld in ('.gov.in', '.nic.in'))
        for u in evidence.urls
    )
    is_text_legit = False
    text_legit_reasons: list[str] = []
    if not evidence.urls or all_urls_trusted:
        is_text_legit, text_legit_reasons = _assess_text_only_legitimacy(evidence)

    is_trusted = is_trusted_entity or is_text_legit

    if is_trusted and not has_strong_brand_mismatch:
        # Check if any hard malicious behavior was confirmed (threat intel, credential theft, external exfiltration, fake mobile bank)
        has_real_attack_intent = bool(
            confirmed_ti_hits
            or has_credential_request
            or has_financial_demand
            or has_cred_exfiltration
            or has_mobile_bank_impersonation
        )

        if not has_real_attack_intent:
            # Trusted infrastructure or verified transactional pattern + absence of scam payload = Legitimate / Safe broadcast
            # Suppress heuristic keyword noise, statutory disclosures, and statistical fluctuations
            total_score = 0.0
            if is_text_legit:
                contributing_factors = [
                    f"[LEGITIMATE TRANSACTIONAL FORMAT] {text_legit_reasons[0]}. "
                    "Absence of phishing links, credential demands, or threat coercion confirms routine transactional communication."
                ]
            else:
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
                "Verified institutional context matches message — heuristic risk dampened"
            )

    final_score = max(0.0, min(1.0, total_score))

    # ─────────────────────────────────────────────────────────────
    # Evidentiary Sufficiency & Unknown Assessment
    # ─────────────────────────────────────────────────────────────

    text_words = len((evidence.message or "").strip().split())
    has_verifiable_indicators = bool(
        evidence.urls or evidence.iocs or evidence.brands or evidence.rule_matches
    )

    if is_trusted and not (confirmed_ti_hits or has_strong_brand_mismatch or has_credential_request or has_financial_demand or has_cred_exfiltration or has_mobile_bank_impersonation):
        evidence_sufficiency = "SUFFICIENT"
        final_level = RiskLevel.LOW
        final_category = UserCategory.LOW_CONCERN
        final_score = 0.0
    elif not active_suspicious_items and (text_words < 6 and not has_verifiable_indicators):
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
