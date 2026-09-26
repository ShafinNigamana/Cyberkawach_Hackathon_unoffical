"""
Adaptive response state machine.

RSP-01: Branches guidance based on user's interaction state with the scam:
  - received: User only received the message
  - clicked: User clicked a link
  - entered_credentials: User entered login/OTP/card details
  - paid: User made a payment

Phase 8 Accuracy Refinements:
- Epistemic proportionality: LOW and UNKNOWN risks receive calm, educational guidance
  instead of alarmist account-freezing emergency procedures.
- High-fidelity Indian cyber infrastructure: Surfaces 1930 (Golden Hour inter-bank fund freeze),
  cybercrime.gov.in, 1909 (TRAI DND), and DoT Chakshu portal (sancharsaathi.gov.in/sfc).
- Contextual enrichment: Tailored actions for identified brands (official domains),
  UPI payment dispute steps, and specific scam typologies (electricity, courier).
"""

from __future__ import annotations

from backend.models.evidence import (
    AdaptiveResponse,
    IncidentEvidence,
    RiskLevel,
    UserState,
)


# ─── Standard Response Guidance by Interaction State ───

_DEFAULT_RESPONSES: dict[UserState, dict] = {
    UserState.RECEIVED: {
        "urgency": "normal",
        "immediate_actions": [
            "Do NOT click any links in this message",
            "Do NOT call any phone numbers mentioned",
            "Do NOT reply to the sender or share OTPs",
            "Do NOT forward this message to others",
        ],
        "recovery_steps": [
            "Block the sender's number/email address",
            "Mark the message as spam/junk in your messaging app",
            "If the message claims to be from a known organization, verify by contacting them through their official website or helpline",
        ],
        "reporting_info": [
            "Report at cybercrime.gov.in (National Cyber Crime Reporting Portal)",
            "Call 1930 (National Cyber Crime Helpline)",
            "Forward fraudulent SMS to DoT Chakshu portal (sancharsaathi.gov.in/sfc)",
            "Forward spam SMS to 1909 (TRAI DND service)",
        ],
    },
    UserState.CLICKED: {
        "urgency": "urgent",
        "immediate_actions": [
            "CLOSE the website/page immediately",
            "Do NOT enter any information, passwords, or OTPs on the page",
            "Clear your browser history, cache, and cookies for that site",
            "If on mobile, close all browser tabs and check recent downloads",
        ],
        "recovery_steps": [
            "Run a security scan on your device using a trusted antivirus tool",
            "Check if any unknown apps, profiles, or APKs were installed — remove them immediately",
            "Monitor your accounts for the next 48 hours for unusual activity",
            "Enable two-factor authentication on important accounts if not already active",
            "Change passwords for any accounts accessed recently from that device",
        ],
        "reporting_info": [
            "Report at cybercrime.gov.in with details and screenshot of the link clicked",
            "Call 1930 (National Cyber Crime Helpline)",
            "Report the malicious URL to Google Safe Browsing: safebrowsing.google.com/safebrowsing/report_phish/",
            "Report fraudulent communication on DoT Chakshu portal: sancharsaathi.gov.in/sfc",
        ],
    },
    UserState.ENTERED_CREDENTIALS: {
        "urgency": "critical",
        "immediate_actions": [
            "IMMEDIATELY change the password for the affected account",
            "IMMEDIATELY change passwords for any other accounts sharing the same password",
            "Contact your bank's official emergency helpline immediately to lock netbanking or block cards",
            "Request your bank to temporarily freeze online transactions and UPI access",
            "Enable two-factor authentication (prefer authenticator app over SMS)",
        ],
        "recovery_steps": [
            "Log out of all active sessions across devices for compromised accounts",
            "Review recent account activity and audit active login sessions",
            "Check if email forwarding rules or secondary recovery numbers were modified",
            "Set up instant transaction alerts on all linked accounts",
            "Monitor credit reports and bank statements for unauthorized inquiries",
            "Consider a credit freeze if national identity documents (Aadhaar/PAN) were shared",
        ],
        "reporting_info": [
            "File an immediate complaint at cybercrime.gov.in",
            "Call 1930 (National Cyber Crime Helpline) — available 24/7",
            "Contact your bank's fraud prevention department through their official helpline",
            "File a complaint with the local cyber police station",
            "Preserve all evidence (messages, screenshots, URLs, call logs)",
        ],
    },
    UserState.PAID: {
        "urgency": "critical",
        "immediate_actions": [
            "IMMEDIATELY contact your bank to report unauthorized debit and request transaction reversal",
            "Call 1930 IMMEDIATELY — the first 'Golden Hour' is critical for inter-bank fund freezing via I4C",
            "Request your bank to freeze your account / UPI ID to prevent further unauthorized debits",
            "If paid via UPI, report the transaction immediately inside your UPI app under 'Report Dispute'",
            "Do NOT make any additional payments even if the scammer promises a refund or fee release",
        ],
        "recovery_steps": [
            "File a cybercrime report at cybercrime.gov.in with UTR number, transaction IDs, and bank statements",
            "File an FIR at the nearest cyber police station with all gathered evidence",
            "Gather evidence: transaction UTR reference, screenshots, call logs, message records",
            "Change all banking PINs, netbanking passwords, and UPI PINs",
            "Contact the RBI Banking Ombudsman (cms.rbi.org.in) if your bank does not provide timely assistance",
            "Monitor all linked accounts for additional unauthorized debits",
        ],
        "reporting_info": [
            "Call 1930 — National Cyber Crime Helpline (24/7, critical for Golden Hour fund freezing)",
            "File complaint at cybercrime.gov.in (Citizen Financial Cyber Fraud Reporting System)",
            "Raise dispute with National Payments Corporation of India (NPCI) at npci.org.in if UPI transfer",
            "Contact your bank's fraud response desk and note the complaint acknowledgement number",
            "Follow up on your complaint within 24-48 hours",
        ],
    },
}

# ─── Proportional Guidance for Low / Unknown Risk (Received State) ───

_LOW_RISK_RECEIVED_GUIDANCE = {
    "urgency": "normal",
    "immediate_actions": [
        "Verify sender details before taking any requested action",
        "If this was an expected message (such as a requested OTP or transaction alert), proceed securely via the official app or website",
        "Do NOT click unverified third-party links or share OTPs with callers",
        "Never share OTPs, PINs, passwords, or CVV numbers with anyone over call or chat",
    ],
    "recovery_steps": [
        "Keep official bank and utility helpline numbers saved from verified official websites",
        "Ensure two-factor authentication is active on your primary accounts",
    ],
    "reporting_info": [
        "If you did not initiate this communication, notify your service provider's verified helpline",
        "Forward unsolicited promotional or spam SMS to 1909 (TRAI DND service)",
    ],
}

_UNKNOWN_RISK_RECEIVED_GUIDANCE = {
    "urgency": "normal",
    "immediate_actions": [
        "Do NOT click any links in this unverified message",
        "Do NOT share OTPs, passwords, or personal identity details",
        "Treat unsolicited or ambiguous messages with standard caution",
        "Avoid downloading any unverified attachments or apps",
    ],
    "recovery_steps": [
        "If the message claims to represent an organization, contact them directly through their verified official website",
        "Do not rely on contact numbers or links provided within an unverified message",
    ],
    "reporting_info": [
        "Forward unsolicited promotional SMS to 1909 (TRAI DND)",
        "For suspected cyber fraud, report to cybercrime.gov.in or helpline 1930",
    ],
}


def generate_response(evidence: IncidentEvidence, user_state: UserState) -> IncidentEvidence:
    """
    Generate adaptive response based on user's interaction state.
    Enforces epistemic proportionality and context-aware enrichment.
    """
    risk_level = evidence.risk.level

    # 1. Base template selection
    if user_state == UserState.RECEIVED:
        if risk_level == RiskLevel.LOW:
            base = _LOW_RISK_RECEIVED_GUIDANCE
        elif risk_level == RiskLevel.UNKNOWN:
            base = _UNKNOWN_RISK_RECEIVED_GUIDANCE
        else:
            base = _DEFAULT_RESPONSES[UserState.RECEIVED]
    else:
        # In escalated interaction states (CLICKED, ENTERED_CREDENTIALS, PAID),
        # use the escalated response protocols regardless of initial message risk score.
        base = _DEFAULT_RESPONSES.get(user_state, _DEFAULT_RESPONSES[UserState.RECEIVED])

    immediate_actions = list(base["immediate_actions"])
    recovery_steps = list(base["recovery_steps"])
    reporting_info = list(base["reporting_info"])
    urgency = base["urgency"]

    # 2. Urgency adjustment based on risk and state
    if risk_level == RiskLevel.CRITICAL:
        if user_state == UserState.RECEIVED:
            urgency = "urgent"
        else:
            urgency = "critical"
    elif risk_level == RiskLevel.HIGH and user_state in (UserState.ENTERED_CREDENTIALS, UserState.PAID):
        urgency = "critical"

    # 3. Contextual Enrichment
    # Brand impersonation enrichment
    if evidence.brands:
        primary_brand = evidence.brands[0]
        if primary_brand.legitimate_domain:
            recovery_steps.append(
                f"Official {primary_brand.brand_name} channel: Visit only https://{primary_brand.legitimate_domain} or use their official mobile app"
            )

    # UPI fraud enrichment
    category = (evidence.fraud_category or "").lower()
    has_upi = category == "upi" or any("upi" in item.description.lower() for item in evidence.evidence) or any("upi" in str(ioc).lower() or "@" in str(ioc) for ioc in evidence.iocs)
    if has_upi and user_state in (UserState.CLICKED, UserState.ENTERED_CREDENTIALS, UserState.PAID):
        reporting_info.append(
            "UPI Dispute: In your UPI app (Google Pay, PhonePe, Paytm, BHIM), navigate to transaction history and select 'Raise Dispute / Report Problem'"
        )

    # Typology-specific advisories
    if category in ("electricity", "electricity_bill") and user_state == UserState.RECEIVED:
        immediate_actions.append(
            "Electricity disconnection notices are never issued via individual mobile numbers; check dues only on your state power utility portal"
        )
    elif category == "courier" and user_state == UserState.RECEIVED:
        immediate_actions.append(
            "Legitimate postal/courier services do not require small fee payments via SMS links to release packages"
        )
    elif category in ("upi", "upi_fraud") and user_state == UserState.RECEIVED:
        immediate_actions.append(
            "Never enter your UPI PIN or approve collect requests to receive refunds or payments; receiving money on UPI never requires entering a PIN"
        )

    evidence.response = AdaptiveResponse(
        user_state=user_state,
        immediate_actions=immediate_actions,
        recovery_steps=recovery_steps,
        reporting_info=reporting_info,
        urgency=urgency,
    )

    return evidence
