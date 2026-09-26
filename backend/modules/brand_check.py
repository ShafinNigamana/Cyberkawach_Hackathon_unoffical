"""
Brand impersonation check — known brand registry + string similarity.

BRD-01: Detects when a URL domain or message content impersonates a known brand.
Uses a registry of Indian + international brands with their legitimate domains,
plus fuzzy string matching to catch typosquatting and lookalikes.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher

from backend.models.evidence import (
    BrandMatch,
    EvidenceItem,
    EvidenceReliability,
    EvidenceSeverity,
    EvidenceStatus,
    EvidenceType,
    IncidentEvidence,
    RiskDirection,
)


def is_official_brand_domain(domain: str) -> bool:
    """Check if domain is a registered legitimate brand domain."""
    d = domain.lower().strip().removeprefix('www.')
    for _, (legit_domains, _) in _BRAND_REGISTRY.items():
        if any(d == ld or d.endswith('.' + ld) for ld in legit_domains):
            return True
    return False


# ─── Brand registry: brand_name → (legitimate_domains, keywords_in_messages) ───

_BRAND_REGISTRY: dict[str, tuple[list[str], list[str]]] = {
    # Indian banks
    "SBI": (["sbi.co.in", "onlinesbi.sbi", "bank.sbi"], ["state bank", "sbi"]),
    "HDFC Bank": (["hdfcbank.com"], ["hdfc"]),
    "ICICI Bank": (["icicibank.com"], ["icici"]),
    "Axis Bank": (["axisbank.com"], ["axis bank"]),
    "Kotak Bank": (["kotak.com", "kotak811.com"], ["kotak"]),
    "PNB": (["pnbindia.in", "netpnb.com"], ["punjab national"]),
    "Bank of Baroda": (["bankofbaroda.in"], ["baroda", "bob"]),
    "Canara Bank": (["canarabank.com"], ["canara"]),
    "Union Bank": (["unionbankofindia.co.in"], ["union bank"]),
    "IDBI Bank": (["idbibank.in"], ["idbi"]),
    "RBI": (["rbi.org.in"], ["reserve bank"]),

    # Indian UPI/payments
    "PayTM": (["paytm.com"], ["paytm"]),
    "PhonePe": (["phonepe.com"], ["phonepe", "phone pe"]),
    "Google Pay": (["pay.google.com"], ["google pay", "gpay"]),
    "BHIM": (["bhimupi.org.in"], ["bhim"]),

    # Indian government
    "Income Tax India": (["incometax.gov.in", "incometaxindia.gov.in"], ["income tax"]),
    "EPFO": (["epfindia.gov.in"], ["epfo", "provident fund"]),
    "Aadhaar": (["uidai.gov.in"], ["aadhaar", "aadhar", "uidai"]),
    "DigiLocker": (["digilocker.gov.in"], ["digilocker"]),
    "India Post": (["indiapost.gov.in"], ["india post"]),

    # Indian e-commerce/delivery
    "Flipkart": (["flipkart.com"], ["flipkart"]),
    "Amazon India": (["amazon.in", "amazon.com"], ["amazon"]),
    "Myntra": (["myntra.com"], ["myntra"]),
    "Swiggy": (["swiggy.com"], ["swiggy"]),
    "Zomato": (["zomato.com"], ["zomato"]),

    # Indian telecom
    "Jio": (["jio.com"], ["jio", "reliance jio"]),
    "Airtel": (["airtel.in"], ["airtel"]),
    "Vi": (["myvi.in"], ["vodafone", "idea", " vi "]),

    # Couriers
    "Delhivery": (["delhivery.com"], ["delhivery"]),
    "BlueDart": (["bluedart.com"], ["bluedart", "blue dart"]),
    "DTDC": (["dtdc.in"], ["dtdc"]),
    "FedEx": (["fedex.com"], ["fedex"]),
    "DHL": (["dhl.com"], ["dhl"]),

    # International tech
    "Microsoft": (["microsoft.com", "live.com", "outlook.com"], ["microsoft"]),
    "Apple": (["apple.com", "icloud.com"], ["apple", "icloud"]),
    "Google": (["google.com", "gmail.com"], ["google"]),
    "WhatsApp": (["whatsapp.com"], ["whatsapp"]),
    "Netflix": (["netflix.com"], ["netflix"]),
}

# Minimum similarity threshold for domain fuzzy matching
_DOMAIN_SIMILARITY_THRESHOLD = 0.65
# Minimum similarity for brand name in domain
_BRAND_IN_DOMAIN_THRESHOLD = 0.70


def _domain_similarity(domain: str, legit_domain: str) -> float:
    """Calculate similarity between two domains using SequenceMatcher."""
    # Strip www. for comparison
    d1 = domain.lower().removeprefix('www.')
    d2 = legit_domain.lower().removeprefix('www.')
    return SequenceMatcher(None, d1, d2).ratio()


def _brand_name_in_domain(brand_name: str, domain: str) -> float:
    """Check if brand name appears (possibly misspelled) in the domain."""
    brand_lower = brand_name.lower().replace(' ', '')
    domain_lower = domain.lower().replace('.', '').replace('-', '')

    # Exact substring
    if brand_lower in domain_lower:
        return 1.0

    # Fuzzy match — slide a window of brand length across the domain
    if len(brand_lower) >= 3:
        best = 0.0
        for i in range(len(domain_lower) - len(brand_lower) + 1):
            window = domain_lower[i:i + len(brand_lower)]
            sim = SequenceMatcher(None, brand_lower, window).ratio()
            best = max(best, sim)
        return best

    return 0.0


def check_brands(evidence: IncidentEvidence) -> IncidentEvidence:
    """
    Check all extracted URLs and message text for brand impersonation.
    Adds BrandMatch entries and evidence items.
    """
    text_lower = evidence.message.lower()

    # ─── Check which brands are mentioned in the message ───
    mentioned_brands: set[str] = set()
    for brand_name, (_, keywords) in _BRAND_REGISTRY.items():
        for keyword in keywords:
            if keyword.lower() in text_lower:
                mentioned_brands.add(brand_name)
                break

    # ─── Check URL domains against mentioned brands ───
    for url_signal in evidence.urls:
        domain = url_signal.domain

        for brand_name in mentioned_brands:
            legit_domains, _ = _BRAND_REGISTRY[brand_name]

            # Check if domain IS a legitimate domain for this brand
            is_legit = any(
                domain == ld or domain.endswith('.' + ld)
                for ld in legit_domains
            )

            if is_legit:
                continue  # No impersonation — domain matches

            # Check if domain LOOKS LIKE a legitimate domain (typosquatting)
            best_similarity = 0.0
            best_legit = ''
            for ld in legit_domains:
                sim = _domain_similarity(domain, ld)
                if sim > best_similarity:
                    best_similarity = sim
                    best_legit = ld

            # Check if brand name appears in the domain
            brand_in_domain = _brand_name_in_domain(brand_name, domain)

            if best_similarity >= _DOMAIN_SIMILARITY_THRESHOLD or brand_in_domain >= _BRAND_IN_DOMAIN_THRESHOLD:
                match_type = "similarity"
                confidence = max(best_similarity, brand_in_domain)

                brand_match = BrandMatch(
                    brand_name=brand_name,
                    confidence=confidence,
                    match_type=match_type,
                    legitimate_domain=best_legit or legit_domains[0],
                )
                evidence.brands.append(brand_match)

                url_signal.signals.append('brand_mismatch')
                evidence.evidence.append(EvidenceItem(
                    type=EvidenceType.BRAND_MISMATCH,
                    source="brand_check",
                    description=(
                        f"Possible {brand_name} impersonation: domain '{domain}' "
                        f"resembles legitimate domain '{best_legit or legit_domains[0]}' "
                        f"(similarity: {confidence:.0%})"
                    ),
                    confidence=confidence,
                    status=EvidenceStatus.SUSPICIOUS,
                    reliability=EvidenceReliability.HEURISTIC,
                    severity=EvidenceSeverity.HIGH if confidence >= 0.8 else EvidenceSeverity.MEDIUM,
                    risk_direction=RiskDirection.INCREASES_RISK,
                    observed_value=f"{domain} (similarity to {best_legit or legit_domains[0]}: {confidence:.0%})",
                    interpretation=f"Host is a lookalike domain potentially impersonating brand '{brand_name}'",
                    correlation_group="brand_impersonation",
                    raw_data={
                        "brand": brand_name,
                        "suspicious_domain": domain,
                        "legitimate_domain": best_legit or legit_domains[0],
                        "domain_similarity": best_similarity,
                        "brand_in_domain": brand_in_domain,
                    },
                ))
            elif brand_in_domain > 0.5:
                # Brand name partially in domain but not on legit domain list
                brand_match = BrandMatch(
                    brand_name=brand_name,
                    confidence=brand_in_domain * 0.8,
                    match_type="domain_mismatch",
                    legitimate_domain=legit_domains[0],
                )
                evidence.brands.append(brand_match)

                evidence.evidence.append(EvidenceItem(
                    type=EvidenceType.BRAND_MISMATCH,
                    source="brand_check",
                    description=(
                        f"Domain '{domain}' contains brand name '{brand_name}' "
                        f"but is not a known legitimate domain (expected: {legit_domains[0]})"
                    ),
                    confidence=brand_in_domain * 0.8,
                    status=EvidenceStatus.SUSPICIOUS,
                    reliability=EvidenceReliability.HEURISTIC,
                    severity=EvidenceSeverity.MEDIUM,
                    risk_direction=RiskDirection.INCREASES_RISK,
                    observed_value=f"{domain} (contains brand: {brand_name})",
                    interpretation=f"Domain incorporates brand keyword '{brand_name}' without being on official registrar list",
                    correlation_group="brand_impersonation",
                    raw_data={
                        "brand": brand_name,
                        "suspicious_domain": domain,
                        "legitimate_domain": legit_domains[0],
                        "brand_in_domain_score": brand_in_domain,
                    },
                ))

    # ─── Brand mentioned in text without any matching URL ───
    for brand_name in mentioned_brands:
        legit_domains, _ = _BRAND_REGISTRY[brand_name]
        has_legit_url = any(
            any(
                url_signal.domain == ld or url_signal.domain.endswith('.' + ld)
                for ld in legit_domains
            )
            for url_signal in evidence.urls
        )
        has_brand_match = any(
            bm.brand_name == brand_name
            for bm in evidence.brands
        )

        # Brand mentioned + URLs present but none are legit = suspicious
        if evidence.urls and not has_legit_url and not has_brand_match:
            evidence.evidence.append(EvidenceItem(
                type=EvidenceType.BRAND_MISMATCH,
                source="brand_check",
                description=(
                    f"Message mentions '{brand_name}' but no URL points to "
                    f"known legitimate domain ({', '.join(legit_domains)})"
                ),
                confidence=0.5,
                status=EvidenceStatus.SUSPICIOUS,
                reliability=EvidenceReliability.HEURISTIC,
                severity=EvidenceSeverity.MEDIUM,
                risk_direction=RiskDirection.INCREASES_RISK,
                observed_value=f"Claimed: {brand_name}, URL domains: {', '.join(u.domain for u in evidence.urls)}",
                interpretation=f"Sender references {brand_name} but directs user to unrelated domain infrastructure",
                correlation_group="brand_impersonation",
                raw_data={
                    "brand": brand_name,
                    "legitimate_domains": legit_domains,
                    "urls_found": [u.domain for u in evidence.urls],
                },
            ))

    return evidence
