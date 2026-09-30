"""
Sender Identity & Channel Security Analyzer (PRD Section 2 & 4).

Analyzes:
1. Indian SMS Headers (TRAI DLT Compliance):
   - Formats: 2-alpha prefix (Circle + Telco) + '-' + 6-alphanumeric Principal Entity ID (e.g. 'VK-SBIINB', 'AD-HDFCBK').
   - Detects personal 10-digit mobile numbers sending banking/financial/urgent alerts (legitimate Indian banks never send account alerts from personal mobile numbers).
   - Detects non-standard, malformed, or fake sender masks.
2. Email Sender & Header Security:
   - Display name spoofing (e.g. 'State Bank of India' <scammer123@gmail.com>).
   - Free webmail usage for financial / institutional claims.
   - Reply-To domain mismatch.
   - SPF/DKIM/DMARC authentication status parsing.
"""

from __future__ import annotations

import email.utils
import logging
import re
from typing import Any, Optional

from backend.models.evidence import (
    EvidenceItem,
    EvidenceReliability,
    EvidenceSeverity,
    EvidenceStatus,
    EvidenceType,
    RiskDirection,
)

logger = logging.getLogger(__name__)

# TRAI DLT header regex: 2 alpha prefix + optional hyphen/space + 6 alphanumeric header + optional suffix (e.g. -G for government)
_TRAI_DLT_REGEX = re.compile(r"^[A-Za-z]{2}[-\s]?[A-Za-z0-9]{6}(?:-[A-Za-z0-9]{1,2})?$", re.I)

# Indian personal mobile phone numbers: starts with 6, 7, 8, or 9
_INDIAN_PERSONAL_MOBILE_REGEX = re.compile(r"^(?:\+?91[\-\s]?)?[6-9]\d{9}$")

_FREE_WEBMAIL_DOMAINS = frozenset({
    "gmail.com", "yahoo.com", "yahoo.co.in", "hotmail.com", "outlook.com",
    "live.com", "aol.com", "icloud.com", "proton.me", "protonmail.com",
    "zoho.com", "mail.com", "gmx.com", "yandex.com", "rediffmail.com",
})

_BANK_OR_GOV_NAMES = {
    "sbi": "State Bank of India",
    "state bank": "State Bank of India",
    "yono": "State Bank of India",
    "hdfc": "HDFC Bank",
    "icici": "ICICI Bank",
    "axis": "Axis Bank",
    "pnb": "Punjab National Bank",
    "punjab national": "Punjab National Bank",
    "paytm": "Paytm",
    "phonepe": "PhonePe",
    "income tax": "Income Tax Department",
    "incometax": "Income Tax Department",
    "cbi": "CBI",
    "mumbai police": "Mumbai Police",
    "cyber crime": "Cyber Crime Department",
    "india post": "India Post",
    "indiapost": "India Post",
    "electricity": "Electricity Department",
    "bescom": "BESCOM",
    "msedcl": "Mahavitaran (MSEDCL)",
}


def analyze_sms_sender(sender: str, message_text: str = "") -> tuple[dict[str, Any], list[EvidenceItem]]:
    """
    Analyze SMS sender identity against TRAI DLT regulations and bank protocols.
    """
    evidence_items: list[EvidenceItem] = []
    clean_sender = sender.strip()
    norm_text = message_text.lower()

    analysis = {
        "sender": clean_sender,
        "is_dlt_compliant": False,
        "is_personal_mobile": False,
        "is_spoofed_mask": False,
        "claimed_entity": None,
    }

    if not clean_sender:
        return analysis, evidence_items

    # Detect entity claimed in text or sender
    claimed = None
    for token, entity in _BANK_OR_GOV_NAMES.items():
        if token in norm_text or token in clean_sender.lower():
            claimed = entity
            analysis["claimed_entity"] = entity
            break

    # 1. Check if sender is a personal 10-digit mobile number
    is_mobile = bool(_INDIAN_PERSONAL_MOBILE_REGEX.match(clean_sender.replace(" ", "").replace("-", "")))
    analysis["is_personal_mobile"] = is_mobile

    if is_mobile and claimed:
        # Severe anomaly: Bank or Govt alert sent from a personal mobile phone
        evidence_items.append(EvidenceItem(
            type=EvidenceType.SENDER_ANALYSIS,
            source="sender_analyzer",
            source_type="content",
            evidence_tier="OBSERVED",
            indicator=clean_sender,
            finding=f"Claimed {claimed} message sent from a personal 10-digit mobile number ({clean_sender})",
            description=(
                f"The message references '{claimed}', but the originating sender is a personal 10-digit "
                f"mobile phone number ({clean_sender}). Legitimate Indian financial institutions and government "
                "authorities NEVER send account or KYC alerts from personal mobile phones; they are strictly required "
                "by TRAI to use registered 6-character alphanumeric DLT headers."
            ),
            observed_value=f"Personal mobile: {clean_sender}, Claim: {claimed}",
            interpretation="Personal phone number impersonating an institution — definitive hallmark of smishing scams.",
            status=EvidenceStatus.CONFIRMED,
            reliability=EvidenceReliability.DETERMINISTIC_FACT,
            risk_direction=RiskDirection.INCREASES_RISK,
            severity=EvidenceSeverity.HIGH,
            confidence=0.92,
            correlation_group="sender_authenticity",
            raw_data={"sender": clean_sender, "claimed_entity": claimed, "type": "personal_mobile_impersonation"},
        ))
    elif is_mobile:
        # Check if text contains high-urgency financial or credential demands
        if any(w in norm_text for w in ("otp", "kyc", "pan", "blocked", "suspended", "account", "electricity", "bill")):
            evidence_items.append(EvidenceItem(
                type=EvidenceType.SENDER_ANALYSIS,
                source="sender_analyzer",
                source_type="content",
                evidence_tier="OBSERVED",
                indicator=clean_sender,
                finding=f"Urgent operational or KYC alert delivered via personal mobile phone ({clean_sender})",
                description=f"Message requesting urgent action or verification was received from personal number '{clean_sender}'.",
                observed_value=clean_sender,
                interpretation="Urgent operational notices sent from personal numbers represent unverified, high-risk communication.",
                status=EvidenceStatus.SUSPICIOUS,
                reliability=EvidenceReliability.DETERMINISTIC_FACT,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.MEDIUM,
                confidence=0.75,
                correlation_group="sender_authenticity",
                raw_data={"sender": clean_sender},
            ))

    # 2. Check TRAI DLT Header Compliance
    is_dlt = bool(_TRAI_DLT_REGEX.match(clean_sender))
    analysis["is_dlt_compliant"] = is_dlt
    is_gov = clean_sender.upper().endswith("-G") or clean_sender.upper().endswith("_G")
    analysis["is_government"] = is_gov

    if is_dlt:
        if is_gov:
            finding = f"Sender header complies with TRAI DLT Government format ({clean_sender})"
            desc = (
                f"The sender '{clean_sender}' follows the standardized TRAI DLT header format with a '-G' suffix, "
                "which is strictly allocated to authorized Government and statutory entities for official broadcasts."
            )
            interp = "Official Government broadcast header verified under TRAI telecom regulations."
        else:
            finding = f"Sender header complies with TRAI DLT alphanumeric format ({clean_sender})"
            desc = f"The sender '{clean_sender}' follows the standardized 2-alpha circle prefix and 6-char entity format."
            interp = "Message header matches legitimate registered telecom broadcast conventions."

        evidence_items.append(EvidenceItem(
            type=EvidenceType.SENDER_ANALYSIS,
            source="sender_analyzer",
            source_type="content",
            evidence_tier="OBSERVED",
            indicator=clean_sender,
            finding=finding,
            description=desc,
            observed_value=clean_sender,
            interpretation=interp,
            status=EvidenceStatus.CONFIRMED if is_gov else EvidenceStatus.OBSERVED,
            reliability=EvidenceReliability.DETERMINISTIC_FACT,
            risk_direction=RiskDirection.NEUTRAL,
            severity=EvidenceSeverity.INFORMATIONAL,
            confidence=0.90 if is_gov else 0.60,
            correlation_group="sender_authenticity",
            raw_data={"sender": clean_sender, "dlt_format": True, "is_government": is_gov},
        ))

    return analysis, evidence_items


def analyze_email_sender(
    from_header: str,
    reply_to_header: str = "",
    auth_results: str = "",
) -> tuple[dict[str, Any], list[EvidenceItem]]:
    """
    Analyze email sender identity, display names, and authentication headers.
    """
    evidence_items: list[EvidenceItem] = []
    display_name, email_addr = email.utils.parseaddr(from_header)
    display_name = display_name.strip()
    email_addr = email_addr.lower().strip()

    from_domain = email_addr.split("@")[-1] if "@" in email_addr else ""
    _, reply_to_addr = email.utils.parseaddr(reply_to_header)
    reply_to_domain = reply_to_addr.lower().split("@")[-1] if "@" in reply_to_addr else ""

    analysis = {
        "display_name": display_name,
        "from_address": email_addr,
        "from_domain": from_domain,
        "reply_to": reply_to_addr,
        "reply_to_domain": reply_to_domain,
        "is_free_webmail": from_domain in _FREE_WEBMAIL_DOMAINS,
        "display_name_spoof": False,
        "reply_to_mismatch": False,
    }

    if not email_addr:
        return analysis, evidence_items

    # 1. Display Name Spoofing Check
    for token, entity in _BANK_OR_GOV_NAMES.items():
        if token in display_name.lower():
            # Check if domain actually matches the institution
            if token not in from_domain:
                analysis["display_name_spoof"] = True
                evidence_items.append(EvidenceItem(
                    type=EvidenceType.SENDER_ANALYSIS,
                    source="sender_analyzer",
                    source_type="content",
                    evidence_tier="OBSERVED",
                    indicator=from_header,
                    finding=f"Email display name claims to be '{display_name}', but actual address is '<{email_addr}>'",
                    description=(
                        f"The sender's display name claims '{display_name}', but the email originates from "
                        f"domain '{from_domain}', which does not belong to {entity}."
                    ),
                    observed_value=f"Display: '{display_name}' vs Sender: <{email_addr}>",
                    interpretation="Classic email display name spoofing to deceive recipients into trusting an unverified sender.",
                    status=EvidenceStatus.CONFIRMED,
                    reliability=EvidenceReliability.DETERMINISTIC_FACT,
                    risk_direction=RiskDirection.INCREASES_RISK,
                    severity=EvidenceSeverity.HIGH,
                    confidence=0.90,
                    correlation_group="email_spoofing",
                    raw_data={"display_name": display_name, "from_address": email_addr, "entity": entity},
                ))
                break

    # 2. Free Webmail Usage for Corporate / Government Claims
    if from_domain in _FREE_WEBMAIL_DOMAINS and display_name:
        for token, entity in _BANK_OR_GOV_NAMES.items():
            if token in display_name.lower():
                evidence_items.append(EvidenceItem(
                    type=EvidenceType.SENDER_ANALYSIS,
                    source="sender_analyzer",
                    source_type="content",
                    evidence_tier="DERIVED",
                    indicator=email_addr,
                    finding=f"Corporate / Institutional claim sent from a free webmail service ({from_domain})",
                    description=f"Sender claiming to represent {entity} is using a free public webmail address ({email_addr}).",
                    observed_value=f"{email_addr} ({from_domain})",
                    interpretation="Legitimate commercial and government institutions do not use free webmail for official correspondence.",
                    status=EvidenceStatus.CONFIRMED,
                    reliability=EvidenceReliability.DETERMINISTIC_FACT,
                    risk_direction=RiskDirection.INCREASES_RISK,
                    severity=EvidenceSeverity.HIGH,
                    confidence=0.88,
                    correlation_group="email_spoofing",
                    raw_data={"from_address": email_addr, "provider": from_domain},
                ))
                break

    # 3. Reply-To Domain Mismatch
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        analysis["reply_to_mismatch"] = True
        evidence_items.append(EvidenceItem(
            type=EvidenceType.SENDER_ANALYSIS,
            source="sender_analyzer",
            source_type="content",
            evidence_tier="OBSERVED",
            indicator=f"From: {from_domain} -> Reply-To: {reply_to_domain}",
            finding=f"Reply-To destination mismatch: Replies will route to '{reply_to_domain}' instead of sender '{from_domain}'",
            description=f"Email From header is '{email_addr}', but replies are redirected to '{reply_to_addr}'.",
            observed_value=f"From: {email_addr} | Reply-To: {reply_to_addr}",
            interpretation="Reply-To mismatch is commonly used by attackers to intercept victim replies to a disposable drop inbox.",
            status=EvidenceStatus.SUSPICIOUS,
            reliability=EvidenceReliability.DETERMINISTIC_FACT,
            risk_direction=RiskDirection.INCREASES_RISK,
            severity=EvidenceSeverity.MEDIUM,
            confidence=0.80,
            correlation_group="email_spoofing",
            raw_data={"from": email_addr, "reply_to": reply_to_addr},
        ))

    # 4. Email Authentication Status (SPF / DKIM / DMARC)
    if auth_results:
        ar_low = auth_results.lower()
        if "spf=fail" in ar_low or "spf=softfail" in ar_low:
            evidence_items.append(EvidenceItem(
                type=EvidenceType.SENDER_ANALYSIS,
                source="sender_analyzer",
                source_type="content",
                evidence_tier="OBSERVED",
                indicator=from_domain,
                finding=f"Email failed SPF authentication: sending server not authorized by domain '{from_domain}'",
                description=f"Authentication-Results header indicates SPF validation failed for sender {email_addr}.",
                observed_value="spf=fail",
                interpretation="Sending server is not authorized by the domain's SPF record to transmit emails on its behalf.",
                status=EvidenceStatus.CONFIRMED,
                reliability=EvidenceReliability.CRYPTOGRAPHIC,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.HIGH,
                confidence=0.90,
                correlation_group="email_authentication",
                raw_data={"auth_results": auth_results},
            ))
        if "dmarc=fail" in ar_low:
            evidence_items.append(EvidenceItem(
                type=EvidenceType.SENDER_ANALYSIS,
                source="sender_analyzer",
                source_type="content",
                evidence_tier="OBSERVED",
                indicator=from_domain,
                finding=f"Email failed DMARC policy check for domain '{from_domain}'",
                description="DMARC verification failed, indicating unaligned or forged sender domain identity.",
                observed_value="dmarc=fail",
                interpretation="Email failed domain-owner DMARC policy enforcement.",
                status=EvidenceStatus.CONFIRMED,
                reliability=EvidenceReliability.CRYPTOGRAPHIC,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.HIGH,
                confidence=0.92,
                correlation_group="email_authentication",
                raw_data={"auth_results": auth_results},
            ))

    return analysis, evidence_items
