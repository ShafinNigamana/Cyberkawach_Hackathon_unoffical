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

# ─── Attack path templates by fraud category (Conditional / Intent-focused) ───

_ATTACK_PATHS = {
    "banking": [
        "Sender impersonates a trusted financial institution or banking service",
        "Message creates artificial urgency (e.g. account suspension or KYC deadline)",
        "Recipient is directed to an unauthorized external link or form",
        "The external form attempts to capture login credentials, OTP, or card numbers",
        "Captured credentials could be used to attempt unauthorized account access",
    ],
    "courier": [
        "Sender presents an unverified parcel delivery or tracking alert",
        "Message asserts a customs fee or reschedule payment is pending",
        "Recipient is directed to a lookalike tracking page",
        "The page attempts to capture payment card details or identity information",
        "Submitted payment data could lead to fraudulent card transactions",
    ],
    "government": [
        "Sender claims authority from a government ministry, court, or police department",
        "Message exerts psychological pressure regarding fines, legal action, or subsidies",
        "Recipient is directed to an unofficial portal or contact channel",
        "Unauthorized channel solicits identity documents, Aadhaar, or monetary transfer",
        "Collected information risks identity impersonation or financial loss",
    ],
    "lottery_prize": [
        "Sender informs recipient of an unverified prize, lottery, or cash reward",
        "Message demands an upfront 'processing fee' or bank account details to claim",
        "Recipient is directed to transfer advance fees to third-party accounts",
        "Advance fees are captured without any genuine prize distribution",
    ],
    "job_offer": [
        "Sender promotes an unsolicited high-paying employment opportunity",
        "Message requests advance 'registration fees' or personal background documents",
        "Recipient is guided to make advance payments or provide sensitive documents",
        "Attacker collects advance fees without providing bona fide employment",
    ],
    "investment": [
        "Sender promises guaranteed or inflated returns in trading or crypto schemes",
        "Communication directs recipient to join private unmonitored channels",
        "Victim is induced to deposit funds into unverified platforms",
        "Deposited capital is withheld with withdrawal restrictions",
    ],
    "tech_support": [
        "Sender displays simulated security warnings or malware infection notices",
        "Message prompts recipient to call an unverified helpline or install software",
        "Unauthorized agent attempts to acquire remote device access",
        "Remote access risks software tampering or sensitive file access",
    ],
}

_DEFAULT_ATTACK_PATH = [
    "Sender delivers an unverified message containing coercive or deceptive elements",
    "Message attempts to induce recipient to click external links or execute actions",
    "Subsequent actions risk exposure of personal credentials or unauthorized transfers",
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
        conf = item.confidence if item.confidence is not None else 1.0
        if conf >= 0.3 and item.type not in (EvidenceType.THREAT_INTEL_MISS, EvidenceType.IOC_EXTRACTED):
            reasons.append(f"[{item.source}] {item.description}")

    if not reasons:
        reasons = ["No strong fraud indicators detected in the available evidence."]

    # ─── Attack path ───
    attack_path = _ATTACK_PATHS.get(category, _DEFAULT_ATTACK_PATH)

    # ─── User actions ───
    user_action = _USER_ACTIONS.get(risk.level, _USER_ACTIONS[RiskLevel.UNKNOWN])

    # ─── Uncertainty ───
    uncertainty_parts = list(evidence.risk.uncertainty_reasons)
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

    uncertainty = ". ".join(dict.fromkeys(uncertainty_parts)) + "." if uncertainty_parts else ""

    evidence.explanation = GeminiExplanation(
        summary=summary,
        reasons=reasons,
        attack_path=attack_path,
        user_action=user_action,
        uncertainty=uncertainty,
        what_cannot_be_concluded=list(evidence.risk.what_cannot_be_concluded),
        model_used="deterministic-fallback",
        evidence_cited=[str(i + 1) for i in range(len(evidence.evidence))],
        is_fallback=True,
    )

    return evidence
