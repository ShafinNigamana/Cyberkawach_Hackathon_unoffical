"""
Rule-based fraud detection — deterministic pattern matching + optional ML baseline.

DET-02: Two layers:
  1. Deterministic rules: keyword patterns, urgency signals, fraud categories.
     These ALWAYS run and are the reliable detection backbone.
  2. Optional TF-IDF/Logistic Regression ML baseline: trained on known scam patterns.
     Adds a probability score but is NOT rule-based detection — it's a separate signal.
"""

from __future__ import annotations

import re
from backend.models.evidence import (
    EvidenceItem,
    EvidenceReliability,
    EvidenceSeverity,
    EvidenceStatus,
    EvidenceType,
    IncidentEvidence,
    RiskDirection,
)


# ─── Fraud category patterns ───
# Each category: (category_name, [(pattern, weight), ...])

_FRAUD_CATEGORIES: list[tuple[str, list[tuple[re.Pattern, float]]]] = [
    ("banking", [
        (re.compile(r'\b(?:bank|account|debit|credit|atm|card|cvv|pin|otp|ifsc|neft|rtgs|imps|upi)\b', re.I), 0.3),
        (re.compile(r'\b(?:sbi|hdfc|icici|axis|kotak|pnb|bob|canara|union|idbi|rbi)\b', re.I), 0.4),
        (re.compile(r'\b(?:block(?:ed)?|suspend(?:ed)?|frozen|deactivat(?:ed?|ing)|limit(?:ed)?)\b', re.I), 0.3),
        (re.compile(r'\b(?:kyc|pan|aadhaar|aadhar|verify|verification|update)\b', re.I), 0.25),
    ]),
    ("courier", [
        (re.compile(r'\b(?:parcel|package|delivery|courier|shipment|dispatch|customs|tracking)\b', re.I), 0.3),
        (re.compile(r'\b(?:delhivery|bluedart|dtdc|fedex|dhl|india\s*post|ecom\s*express|ekart)\b', re.I), 0.4),
        (re.compile(r'\b(?:address|reschedule|failed\s*delivery|undelivered|return)\b', re.I), 0.2),
    ]),
    ("government", [
        (re.compile(r'\b(?:government|govt|ministry|income\s*tax|gst|epfo|aadhaar|digilocker)\b', re.I), 0.35),
        (re.compile(r'\b(?:refund|subsidy|scheme|yojana|pension|challan|notice|summon)\b', re.I), 0.3),
        (re.compile(r'\b(?:police|cyber\s*cell|legal|court|arrest|warrant|fir)\b', re.I), 0.35),
    ]),
    ("lottery_prize", [
        (re.compile(r'\b(?:lottery|prize|winner|won|congratulat|lucky|jackpot|reward)\b', re.I), 0.5),
        (re.compile(r'\b(?:claim|collect|processing\s*fee|registration\s*fee)\b', re.I), 0.3),
        (re.compile(r'\b(?:lakh|crore|million|billion|\$|₹|rs\.?|rupee)\b', re.I), 0.2),
    ]),
    ("job_offer", [
        (re.compile(r'\b(?:job|hiring|vacancy|recruit|salary|earn|income|work\s*from\s*home)\b', re.I), 0.3),
        (re.compile(r'\b(?:part[\s-]?time|full[\s-]?time|daily\s*(?:earn|income|pay)|per\s*(?:day|hour))\b', re.I), 0.35),
        (re.compile(r'\b(?:registration|joining)\s*(?:fee|charge|amount)\b', re.I), 0.4),
    ]),
    ("investment", [
        (re.compile(r'\b(?:invest|trading|stock|crypto|bitcoin|forex|mutual\s*fund)\b', re.I), 0.3),
        (re.compile(r'\b(?:guaranteed|assured|fixed)\s*(?:return|profit|income)\b', re.I), 0.5),
        (re.compile(r'\b(?:double|triple|10x|100x)\s*(?:your|money|investment)\b', re.I), 0.5),
    ]),
    ("tech_support", [
        (re.compile(r'\b(?:virus|malware|hack(?:ed)?|compromise(?:d)?|breach)\b', re.I), 0.3),
        (re.compile(r'\b(?:microsoft|apple|google|amazon)\s*(?:support|helpline|customer\s*care)\b', re.I), 0.4),
        (re.compile(r'\b(?:remote\s*access|teamviewer|anydesk|quick\s*support)\b', re.I), 0.5),
    ]),
    ("electricity", [
        (re.compile(r'\b(?:electricity|power|power\s*cut|electric|light\s*bill|bill\s*update)\b', re.I), 0.45),
        (re.compile(r'\b(?:disconnect(?:ed|ion)?|cut\s*off|suspended)\b', re.I), 0.35),
        (re.compile(r'\b(?:electricity\s*office|electricity\s*officer|discom|bescom|tneb|mseb|bses|uppcl)\b', re.I), 0.4),
    ]),
    ("telecom", [
        (re.compile(r'\b(?:sim|telecom|cellular|network|5g|4g|esim)\b', re.I), 0.35),
        (re.compile(r'\b(?:jio|airtel|vi|vodafone|bsnl)\b', re.I), 0.4),
        (re.compile(r'\b(?:deactivat(?:ed|ion)|block(?:ed)?|disconnect(?:ed)?)\b', re.I), 0.35),
    ]),
    ("loan_fraud", [
        (re.compile(r'\b(?:loan|personal\s*loan|instant\s*loan|credit\s*line|lending|emi)\b', re.I), 0.4),
        (re.compile(r'\b(?:pre[\s-]?approved|zero\s*documents?|no\s*cibil|instant\s*disburs(?:al|ement))\b', re.I), 0.45),
        (re.compile(r'\b(?:apk|download\s*app|interest\s*rate)\b', re.I), 0.25),
    ]),
    ("extortion_legal", [
        (re.compile(r'\b(?:cbi|customs|cyber\s*crime|police|narcotics|ncb|court|enforcement\s*directorate|ed)\b', re.I), 0.45),
        (re.compile(r'\b(?:arrest|warrant|summons?|contraband|illegal\s*parcel|fir|ipc)\b', re.I), 0.45),
        (re.compile(r'\b(?:digital\s*arrest|skype|surrender|police\s*station)\b', re.I), 0.4),
    ]),
    ("upi_fraud", [
        (re.compile(r'\b(?:upi|gpay|google\s*pay|phonepe|paytm|bhim)\b', re.I), 0.35),
        (re.compile(r'\b(?:collect\s*request|approve\s*(?:request|collect)|enter\s*pin\s*to\s*receive|refund)\b', re.I), 0.45),
    ]),
]

# ─── Urgency/pressure signals ───

_URGENCY_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\b(?:immediate(?:ly)?|urgent(?:ly)?|right\s*now|asap|at\s*once)\b', re.I), "urgency_pressure"),
    (re.compile(r'\b(?:within\s*\d+\s*(?:hour|minute|hr|min)s?|last\s*chance|final\s*warning)\b', re.I), "time_pressure"),
    (re.compile(r'\b(?:act\s*now|don\'?t\s*delay|hurry|limited\s*(?:time|offer|period))\b', re.I), "time_pressure"),
    (re.compile(r'\b(?:expire|expir(?:ed|ing|es)|deadline)\b', re.I), "expiry_pressure"),
    (re.compile(r'\b(?:or\s*else|otherwise|fail(?:ure)?|consequence|penalty|fine|legal\s*action)\b', re.I), "threat_pressure"),
]

# ─── Credential request signals ───

_CREDENTIAL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\b(?:enter|provide|share|send|submit|type|input)\s*(?:your\s*)?(?:otp|pin|password|cvv|card\s*number)\b', re.I), "credential_request"),
    (re.compile(r'\b(?:click|tap|open)\s*(?:this|the|below|here|on)\s*(?:link|url|button)\b', re.I), "click_bait"),
    (re.compile(r'\b(?:login|log\s*in|sign\s*in|verify)\s*(?:here|now|to|at|using)\b', re.I), "login_redirect"),
    (re.compile(r'\b(?:scan|use)\s*(?:this|the|below)?\s*(?:qr|barcode)\b', re.I), "qr_redirect"),
    (re.compile(r'\b(?:call|contact|whatsapp|reach)\s*(?:our|the|this)?\s*(?:officer|executive|manager|care|center|agent|helpline)?\s*(?:at|on|immediately|urgently|now)?\s*(?:at\s*)?\+?\d{7,12}\b', re.I), "contact_demand"),
]

# ─── Financial action signals ───

_FINANCIAL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\b(?:transfer|send|pay|deposit|remit)\s*(?:money|amount|fund|rs\.?|₹|\$)\b', re.I), "money_request"),
    (re.compile(r'\b(?:processing|registration|activation|verification)\s*(?:fee|charge|amount)\b', re.I), "fee_request"),
    (re.compile(r'\b(?:google\s*pay|phonepe|paytm|bhim|upi|neft|rtgs|imps)\b', re.I), "payment_method_mention"),
]


def apply_rules(evidence: IncidentEvidence) -> IncidentEvidence:
    """
    Apply deterministic rule-based fraud detection.
    Sets fraud_category and adds rule_match evidence items.
    """
    text = evidence.message
    if not text:
        return evidence

    # ─── Category detection ───
    category_scores: dict[str, float] = {}
    for category, patterns in _FRAUD_CATEGORIES:
        score = 0.0
        for pattern, weight in patterns:
            if pattern.search(text):
                score += weight
        if score > 0:
            category_scores[category] = min(score, 1.0)

    # Pick top category
    if category_scores:
        top_category = max(category_scores, key=category_scores.get)  # type: ignore[arg-type]
        evidence.fraud_category = top_category
        evidence.evidence.append(EvidenceItem(
            type=EvidenceType.RULE_MATCH,
            source="rules",
            description=f"Message matches fraud category: {top_category} (score: {category_scores[top_category]:.2f})",
            confidence=category_scores[top_category],
            status=EvidenceStatus.OBSERVED,
            reliability=EvidenceReliability.DETERMINISTIC_FACT,
            severity=EvidenceSeverity.MEDIUM if category_scores[top_category] >= 0.5 else EvidenceSeverity.LOW,
            risk_direction=RiskDirection.INCREASES_RISK,
            observed_value=f"Lexical category match: {top_category} (score: {category_scores[top_category]:.2f})",
            interpretation=f"Text vocabulary aligns with known {top_category} scam solicitation patterns",
            correlation_group="rules_category",
            raw_data={"category_scores": category_scores},
        ))

    # ─── Urgency signals ───
    urgency_hits = []
    for pattern, signal_type in _URGENCY_PATTERNS:
        match = pattern.search(text)
        if match:
            urgency_hits.append((signal_type, match.group()))

    if urgency_hits:
        evidence.rule_matches.extend([h[0] for h in urgency_hits])
        evidence.evidence.append(EvidenceItem(
            type=EvidenceType.PATTERN_MATCH,
            source="rules",
            description=f"Urgency/pressure tactics detected: {', '.join(set(h[0] for h in urgency_hits))}",
            confidence=min(0.55 + 0.20 * len(urgency_hits), 0.95),
            status=EvidenceStatus.OBSERVED,
            reliability=EvidenceReliability.HEURISTIC,
            severity=EvidenceSeverity.MEDIUM,
            risk_direction=RiskDirection.INCREASES_RISK,
            observed_value=f"Urgency tokens: {', '.join(set(h[1] for h in urgency_hits))}",
            interpretation="Message uses psychological time pressure to bypass critical reflection",
            correlation_group="rules_urgency",
            raw_data={"urgency_signals": [{"type": h[0], "text": h[1]} for h in urgency_hits]},
        ))

    # ─── Credential request signals ───
    credential_hits = []
    for pattern, signal_type in _CREDENTIAL_PATTERNS:
        match = pattern.search(text)
        if match:
            credential_hits.append((signal_type, match.group()))

    if credential_hits:
        evidence.rule_matches.extend([h[0] for h in credential_hits])
        evidence.evidence.append(EvidenceItem(
            type=EvidenceType.PATTERN_MATCH,
            source="rules",
            description=f"Credential/action request detected: {', '.join(set(h[0] for h in credential_hits))}",
            confidence=min(0.60 + 0.20 * len(credential_hits), 0.95),
            status=EvidenceStatus.OBSERVED,
            reliability=EvidenceReliability.HEURISTIC,
            severity=EvidenceSeverity.HIGH,
            risk_direction=RiskDirection.INCREASES_RISK,
            observed_value=f"Credential request tokens: {', '.join(set(h[1] for h in credential_hits))}",
            interpretation="Message actively solicits personal authentication credentials or sensitive information",
            correlation_group="rules_credential",
            raw_data={"credential_signals": [{"type": h[0], "text": h[1]} for h in credential_hits]},
        ))

    # ─── Financial signals ───
    financial_hits = []
    for pattern, signal_type in _FINANCIAL_PATTERNS:
        match = pattern.search(text)
        if match:
            financial_hits.append((signal_type, match.group()))

    if financial_hits:
        evidence.rule_matches.extend([h[0] for h in financial_hits])
        evidence.evidence.append(EvidenceItem(
            type=EvidenceType.PATTERN_MATCH,
            source="rules",
            description=f"Financial action signals: {', '.join(set(h[0] for h in financial_hits))}",
            confidence=min(0.55 + 0.20 * len(financial_hits), 0.95),
            status=EvidenceStatus.OBSERVED,
            reliability=EvidenceReliability.HEURISTIC,
            severity=EvidenceSeverity.MEDIUM,
            risk_direction=RiskDirection.INCREASES_RISK,
            observed_value=f"Financial tokens: {', '.join(set(h[1] for h in financial_hits))}",
            interpretation="Message prompts monetary transfers, fees, or account financial actions",
            correlation_group="rules_financial",
            raw_data={"financial_signals": [{"type": h[0], "text": h[1]} for h in financial_hits]},
        ))

    return evidence
