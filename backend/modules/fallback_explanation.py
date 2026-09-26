"""
Deterministic/template-based explanation fallback.

EXP-01 (fallback path): Generates a structured explanation from the verified
evidence objects using templates. No LLM call. Guaranteed to succeed.

This runs when Gemini fails, times out, hits quota, or has no API key.
The demo must NEVER fail because Gemini is unavailable.
"""

from __future__ import annotations

from backend.models.evidence import (
    EvidenceType,
    GeminiExplanation,
    IncidentEvidence,
    RiskLevel,
)


# ─── Summary templates by risk level ───

_SUMMARY_TEMPLATES = {
    RiskLevel.CRITICAL: "This message shows strong indicators of a {category} scam with multiple verified threat signals.",
    RiskLevel.HIGH: "This message has significant fraud indicators consistent with a {category} scam attempt.",
    RiskLevel.MEDIUM: "This message contains some suspicious elements that suggest a possible {category} scam.",
    RiskLevel.LOW: "This message has minor suspicious indicators but limited evidence of fraud.",
    RiskLevel.UNKNOWN: "Insufficient evidence to determine if this message is fraudulent.",
}

# ─── Attack path templates by fraud category ───

_ATTACK_PATHS = {
    "banking": [
        "Victim receives message impersonating a bank notification",
        "Message creates urgency (account blocked/KYC required/suspicious activity)",
        "Victim is directed to click a link to a fake banking portal",
        "Fake portal harvests login credentials, OTP, or card details",
        "Attacker uses stolen credentials to drain the account",
    ],
    "courier": [
        "Victim receives fake delivery notification",
        "Message claims a package needs rescheduling or customs payment",
        "Victim clicks link to a fake courier tracking page",
        "Page requests payment or personal details for 'redelivery'",
        "Attacker collects payment credentials or personal data",
    ],
    "government": [
        "Victim receives message impersonating a government agency",
        "Message threatens penalties, legal action, or loss of benefits",
        "Victim is directed to click a link or call a number",
        "Fake page/agent requests personal details, Aadhaar, or payment",
        "Attacker harvests identity documents or money",
    ],
    "lottery_prize": [
        "Victim receives message claiming they've won a prize",
        "Message asks for a 'processing fee' or personal details to claim",
        "Victim is directed to pay a fee or provide bank details",
        "Attacker collects the fee and/or bank credentials",
        "No prize exists — victim loses money and personal data",
    ],
    "job_offer": [
        "Victim receives unsolicited job offer with attractive salary",
        "Message requests a 'registration fee' or personal documents",
        "Victim pays fee or shares sensitive personal information",
        "No real job exists — attacker disappears with money/data",
    ],
    "investment": [
        "Victim receives message promising guaranteed returns",
        "Initial small investment shows fake 'profits' to build trust",
        "Victim invests larger amounts based on fabricated returns",
        "Attacker blocks withdrawal or disappears with funds",
    ],
    "tech_support": [
        "Victim receives alert about a virus or security breach",
        "Message directs to call a fake tech support number",
        "Fake agent requests remote access to victim's device",
        "Attacker installs malware or steals data via remote access",
    ],
}

_DEFAULT_ATTACK_PATH = [
    "Victim receives a suspicious message with fraudulent content",
    "Message attempts to manipulate victim into taking action",
    "Action leads to data theft, financial loss, or malware",
]

# ─── User action templates by risk level ───

_USER_ACTIONS = {
    RiskLevel.CRITICAL: [
        "Do NOT click any links in this message",
        "Do NOT reply or call any numbers mentioned",
        "If you shared any credentials, change your passwords immediately",
        "Contact your bank's official helpline to report and block transactions",
        "File a complaint at cybercrime.gov.in or call 1930 (National Cyber Crime Helpline)",
        "Save this message as evidence — do not delete it",
    ],
    RiskLevel.HIGH: [
        "Do NOT click any links or call numbers in this message",
        "Verify the claim by contacting the organization through their official website",
        "If you already clicked a link, do not enter any information",
        "Report this message to cybercrime.gov.in or call 1930",
        "Block the sender",
    ],
    RiskLevel.MEDIUM: [
        "Exercise caution — verify the sender's identity independently",
        "Do not click links — visit the official website directly if action is needed",
        "Report suspicious messages to your telecom provider",
        "If unsure, contact the organization through verified official channels",
    ],
    RiskLevel.LOW: [
        "The message has limited suspicious indicators",
        "Verify the sender if the message requests any personal information or action",
        "When in doubt, do not click links — visit official websites directly",
    ],
    RiskLevel.UNKNOWN: [
        "Insufficient evidence to determine the nature of this message",
        "Exercise standard caution with unsolicited messages",
        "Do not share personal or financial information with unknown senders",
    ],
}


def generate_fallback_explanation(evidence: IncidentEvidence) -> IncidentEvidence:
    """
    Generate a deterministic explanation from evidence objects.
    Guaranteed to succeed — no external calls. Uses templates grounded
    in the verified evidence items.
    """
    risk = evidence.risk
    category = evidence.fraud_category or "unknown"

    # ─── Build summary from template + evidence ───
    template = _SUMMARY_TEMPLATES.get(risk.level, _SUMMARY_TEMPLATES[RiskLevel.UNKNOWN])
    summary = template.format(category=category)

    # ─── Build reasons from evidence items ───
    reasons = []
    for item in evidence.evidence:
        if item.confidence >= 0.3 and item.type not in (EvidenceType.THREAT_INTEL_MISS, EvidenceType.IOC_EXTRACTED):
            reasons.append(f"[{item.source}] {item.description}")

    if not reasons:
        reasons = ["No strong fraud indicators detected in the available evidence."]

    # ─── Attack path ───
    attack_path = _ATTACK_PATHS.get(category, _DEFAULT_ATTACK_PATH)

    # ─── User actions ───
    user_action = _USER_ACTIONS.get(risk.level, _USER_ACTIONS[RiskLevel.UNKNOWN])

    # ─── Uncertainty ───
    uncertainty_parts = []
    failed_sources = [
        ti.source for ti in evidence.threat_intel
        if ti.error is not None
    ]
    if failed_sources:
        uncertainty_parts.append(
            f"Threat intelligence from {', '.join(failed_sources)} was unavailable"
        )
    if not evidence.urls:
        uncertainty_parts.append("No URLs were found to analyze")
    if not evidence.brands:
        uncertainty_parts.append("No brand impersonation signals detected")
    if risk.level == RiskLevel.UNKNOWN:
        uncertainty_parts.append("Insufficient evidence for a confident assessment")

    uncertainty = ". ".join(uncertainty_parts) + "." if uncertainty_parts else ""

    evidence.explanation = GeminiExplanation(
        summary=summary,
        reasons=reasons,
        attack_path=attack_path,
        user_action=user_action,
        uncertainty=uncertainty,
        model_used="deterministic-fallback",
        evidence_cited=[str(i + 1) for i in range(len(evidence.evidence))],
        is_fallback=True,
    )

    return evidence
