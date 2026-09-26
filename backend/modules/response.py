"""
Adaptive response state machine.

RSP-01: Branches guidance based on user's interaction state with the scam:
  - received: User only received the message
  - clicked: User clicked a link
  - entered_credentials: User entered login/OTP/card details
  - paid: User made a payment

Each state escalates urgency and changes the recommended actions.
"""

from __future__ import annotations

from backend.models.evidence import (
    AdaptiveResponse,
    IncidentEvidence,
    RiskLevel,
    UserState,
)


# ─── Response templates by state ───

_RESPONSES: dict[UserState, dict] = {
    UserState.RECEIVED: {
        "urgency": "normal",
        "immediate_actions": [
            "Do NOT click any links in this message",
            "Do NOT call any phone numbers mentioned",
            "Do NOT reply to the sender",
            "Do NOT forward this message to others",
        ],
        "recovery_steps": [
            "Block the sender's number/email",
            "Mark the message as spam/junk",
            "If the message claims to be from a known organization, verify by contacting them through their official website or helpline",
        ],
        "reporting_info": [
            "Report at cybercrime.gov.in",
            "Call 1930 (National Cyber Crime Helpline)",
            "Forward SMS to 1909 (TRAI DND service)",
            "Report to your telecom provider",
        ],
    },
    UserState.CLICKED: {
        "urgency": "urgent",
        "immediate_actions": [
            "CLOSE the website/page immediately",
            "Do NOT enter any information on the page",
            "Clear your browser history and cookies for that site",
            "If on mobile, close all browser tabs",
        ],
        "recovery_steps": [
            "Run a security scan on your device",
            "Check if any unknown apps were installed — remove them",
            "Monitor your accounts for the next 48 hours for unusual activity",
            "Enable two-factor authentication on important accounts if not already active",
            "Change passwords for any accounts you accessed recently from the same device",
        ],
        "reporting_info": [
            "Report at cybercrime.gov.in with details of the link clicked",
            "Call 1930 (National Cyber Crime Helpline)",
            "Report the URL to Google Safe Browsing: safebrowsing.google.com/safebrowsing/report_phish/",
        ],
    },
    UserState.ENTERED_CREDENTIALS: {
        "urgency": "critical",
        "immediate_actions": [
            "IMMEDIATELY change the password for the compromised account",
            "IMMEDIATELY change passwords for any other accounts using the same password",
            "Enable two-factor authentication on all affected accounts",
            "Contact your bank immediately if banking credentials were entered",
            "Request your bank to temporarily freeze online transactions",
        ],
        "recovery_steps": [
            "Log out of all active sessions for compromised accounts",
            "Review recent account activity for unauthorized access",
            "Check if your email forwarding rules were changed (common attacker tactic)",
            "Set up transaction alerts on all bank accounts",
            "Monitor credit reports for unauthorized loans or accounts",
            "Consider a credit freeze if identity documents were shared",
        ],
        "reporting_info": [
            "File an immediate complaint at cybercrime.gov.in",
            "Call 1930 (National Cyber Crime Helpline) — available 24/7",
            "Contact your bank's fraud department through their official helpline",
            "File a complaint with the local cyber police station",
            "Keep all evidence (messages, screenshots, URLs)",
        ],
    },
    UserState.PAID: {
        "urgency": "critical",
        "immediate_actions": [
            "IMMEDIATELY contact your bank to request a transaction reversal",
            "Call 1930 IMMEDIATELY — the first 'golden hour' is critical for fund recovery",
            "Request your bank to freeze your account to prevent further unauthorized debits",
            "If paid via UPI, contact your UPI app's support for dispute resolution",
            "Do NOT make any additional payments even if the scammer requests them",
        ],
        "recovery_steps": [
            "File an FIR at the nearest cyber police station with all evidence",
            "File a complaint at cybercrime.gov.in with transaction details",
            "Contact RBI Banking Ombudsman if bank does not cooperate",
            "Document all communication with the scammer",
            "Gather evidence: transaction receipts, message screenshots, bank statements",
            "Change all banking passwords and PINs",
            "Monitor all accounts for additional unauthorized transactions",
        ],
        "reporting_info": [
            "Call 1930 — National Cyber Crime Helpline (24/7, critical for fund recovery)",
            "File FIR at cybercrime.gov.in",
            "Contact your bank's fraud department — ask for transaction reversal/chargeback",
            "RBI Banking Ombudsman: rbi.org.in/scripts/Complaints.aspx",
            "Keep a copy of the FIR number for bank follow-up",
            "Follow up on your complaint within 24-48 hours",
        ],
    },
}


def generate_response(evidence: IncidentEvidence, user_state: UserState) -> IncidentEvidence:
    """
    Generate adaptive response based on user's interaction state.
    Adjusts urgency based on both user state and risk level.
    """
    template = _RESPONSES.get(user_state, _RESPONSES[UserState.RECEIVED])

    # Override urgency to critical if risk is CRITICAL regardless of state
    urgency = template["urgency"]
    if evidence.risk.level == RiskLevel.CRITICAL and urgency == "normal":
        urgency = "urgent"

    evidence.response = AdaptiveResponse(
        user_state=user_state,
        immediate_actions=template["immediate_actions"],
        recovery_steps=template["recovery_steps"],
        reporting_info=template["reporting_info"],
        urgency=urgency,
    )

    return evidence
