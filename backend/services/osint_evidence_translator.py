"""
OSINT Evidence Translator.

Converts raw OSINT findings (WHOIS domain age, crt.sh Certificate Transparency logs)
into typed, epistemically grounded EvidenceItem objects complying with the Evidence Contract.
"""

from __future__ import annotations

from typing import Any

from backend.models.evidence import (
    EvidenceItem,
    EvidenceReliability,
    EvidenceSeverity,
    EvidenceStatus,
    EvidenceType,
    RiskDirection,
)

NEW_DOMAIN_HIGH_RISK_DAYS = 7
NEW_DOMAIN_MEDIUM_RISK_DAYS = 30


def translate_osint_evidence(osint_result: dict[str, Any]) -> list[EvidenceItem]:
    """
    Translates dictionary from get_osint_enrichment() into strongly-typed EvidenceItem objects.
    Returns empty list if result is unavailable or has no notable findings.
    """
    items: list[EvidenceItem] = []

    if not osint_result or osint_result.get("status") == "unavailable":
        return items

    domain = osint_result.get("domain", "")

    # 1. Translate Domain Age
    domain_age = osint_result.get("domain_age")
    if domain_age and domain_age.get("days_old") is not None:
        days = int(domain_age["days_old"])
        registrar = str(domain_age.get("registrar") or "an unknown registrar").strip()

        if days <= NEW_DOMAIN_HIGH_RISK_DAYS:
            items.append(EvidenceItem(
                type=EvidenceType.DOMAIN_AGE,
                source="whois",
                description=(
                    f"Domain was registered only {days} day{'s' if days != 1 else ''} ago "
                    f"({registrar}) — right before message receipt"
                ),
                observed_value=f"{days} days old ({registrar})",
                interpretation="Freshly registered domain created immediately prior to lure delivery",
                status=EvidenceStatus.CONFIRMED,
                reliability=EvidenceReliability.EXTERNAL_DB,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.HIGH,
                confidence=0.85,
                correlation_group="domain_registration",
                raw_data={"days_old": days, "registrar": registrar, "domain": domain},
            ))
        elif days <= NEW_DOMAIN_MEDIUM_RISK_DAYS:
            items.append(EvidenceItem(
                type=EvidenceType.DOMAIN_AGE,
                source="whois",
                description=(
                    f"Domain is relatively new ({days} days old, registered via {registrar})"
                ),
                observed_value=f"{days} days old ({registrar})",
                interpretation="Recently registered domain; common in seasonal or disposable scam campaigns",
                status=EvidenceStatus.CONFIRMED,
                reliability=EvidenceReliability.EXTERNAL_DB,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.MEDIUM,
                confidence=0.60,
                correlation_group="domain_registration",
                raw_data={"days_old": days, "registrar": registrar, "domain": domain},
            ))
        else:
            items.append(EvidenceItem(
                type=EvidenceType.DOMAIN_AGE,
                source="whois",
                description=f"Domain has existed for {days} days, consistent with established infrastructure",
                observed_value=f"{days} days old ({registrar})",
                interpretation="Established domain age reduces probability of an ephemeral disposable lure",
                status=EvidenceStatus.OBSERVED,
                reliability=EvidenceReliability.EXTERNAL_DB,
                risk_direction=RiskDirection.NEUTRAL,
                severity=EvidenceSeverity.INFORMATIONAL,
                confidence=0.50,
                correlation_group="domain_registration",
                raw_data={"days_old": days, "registrar": registrar, "domain": domain},
            ))

    # 2. Translate Certificate Transparency Logs
    cert_info = osint_result.get("cert_transparency")
    if cert_info:
        related = cert_info.get("shared_cert_domains") or []
        if related:
            preview = ", ".join(related[:3])
            more = f" and {len(related) - 3} more" if len(related) > 3 else ""

            items.append(EvidenceItem(
                type=EvidenceType.CAMPAIGN_LINK,
                source="crt.sh",
                description=(
                    f"Website security certificate is shared with other domains "
                    f"({preview}{more}) — campaign syndicate signature"
                ),
                observed_value=preview + more,
                interpretation="Shared SSL/TLS certificate subjects indicate coordinated campaign infrastructure",
                status=EvidenceStatus.OBSERVED,
                reliability=EvidenceReliability.CRYPTOGRAPHIC,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.HIGH,
                confidence=0.70,
                correlation_group="campaign_link",
                raw_data={"shared_cert_domains": related, "domain": domain},
            ))

    return items
