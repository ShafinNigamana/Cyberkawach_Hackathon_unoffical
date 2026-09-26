"""
Deterministic/template-based explanation fallback.

EXP-01 (fallback path): Generates a structured explanation from the verified
evidence objects using templates. No LLM call. Guaranteed to succeed.

This runs when Gemini fails, times out, hits quota, or has no API key.
The demo must NEVER fail because Gemini is unavailable.
"""

from __future__ import annotations

from backend.models.evidence import (
    AttackStep,
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


def _build_traceable_fallback_attack_path(
    evidence: IncidentEvidence,
) -> tuple[list[str], list[AttackStep]]:
    """
    Construct an explicit causal graph:
    Evidence Item -> Attack Step -> Potential Risk / Harm
    Without ungrounded assumptions.
    """
    structured_steps: list[AttackStep] = []
    category = evidence.fraud_category or "suspicious"
    risk_level = evidence.risk.level

    # Collect indices and categorize evidence items (1-indexed for citations)
    lure_indices: list[int] = []
    infra_indices: list[int] = []
    exploit_indices: list[int] = []

    for i, item in enumerate(evidence.evidence, 1):
        grp = item.correlation_group or ""
        desc_lower = item.description.lower()
        if grp in ("rules_urgency", "rules_coercion", "rules_category", "rules_threat") or item.source in ("laya", "ml_baseline"):
            lure_indices.append(i)
        elif item.type in (EvidenceType.BRAND_MISMATCH, EvidenceType.URL_ANALYSIS, EvidenceType.THREAT_INTEL_HIT) or item.source in ("url_analyzer", "brand_check", "threat_intel"):
            infra_indices.append(i)
        elif grp in ("rules_credential", "rules_financial") or any(k in desc_lower for k in ("credential", "otp", "password", "bank", "payment", "upi")):
            exploit_indices.append(i)

    step_num = 1

    # Stage 1: Lure / Initial Contact
    if risk_level == RiskLevel.UNKNOWN or evidence.risk.evidence_sufficiency == "INSUFFICIENT":
        structured_steps.append(
            AttackStep(
                step_number=step_num,
                description="Sender delivers an unverified message with insufficient indicators to establish fraudulent intent",
                causal_stage="lure",
                evidence_indices=[1] if evidence.evidence else [],
                intended_consequence="Initial outreach; intent cannot be definitively confirmed without further evidence",
            )
        )
    elif lure_indices:
        cite_str = f" [Evidence {', '.join(str(idx) for idx in lure_indices[:3])}]"
        structured_steps.append(
            AttackStep(
                step_number=step_num,
                description=f"Attacker delivers unsolicited communication designed to create psychological urgency or authority pretexts regarding {category}{cite_str}",
                causal_stage="lure",
                evidence_indices=lure_indices[:3],
                observed_basis=evidence.evidence[lure_indices[0] - 1].observed_value or evidence.evidence[lure_indices[0] - 1].description,
                intended_consequence="Manipulate recipient into hasty engagement before verifying authenticity",
            )
        )
    else:
        structured_steps.append(
            AttackStep(
                step_number=step_num,
                description=f"Sender initiates contact with an unsolicited communication regarding {category}",
                causal_stage="lure",
                evidence_indices=[1] if evidence.evidence else [],
                intended_consequence="Engage recipient in communication",
            )
        )
    step_num += 1

    # Stage 2: Redirection / Infrastructure
    if infra_indices:
        cite_str = f" [Evidence {', '.join(str(idx) for idx in infra_indices[:3])}]"
        target_domain = ""
        if evidence.urls:
            target_domain = evidence.urls[0].domain
        elif evidence.brands:
            target_domain = evidence.brands[0].suspicious_domain
        if not target_domain:
            for idx in infra_indices:
                if evidence.evidence[idx - 1].observed_value:
                    target_domain = evidence.evidence[idx - 1].observed_value
                    break
        domain_part = f" '{target_domain}'" if target_domain else ""

        structured_steps.append(
            AttackStep(
                step_number=step_num,
                description=f"Recipient is prompted to access unauthorized external domain{domain_part}{cite_str}",
                causal_stage="redirection",
                evidence_indices=infra_indices[:3],
                observed_basis=target_domain or "Suspicious URL/infrastructure",
                intended_consequence="Bypass verified organizational channels and steer victim to unverified external infrastructure",
            )
        )
        step_num += 1
    elif evidence.iocs:
        ioc_val = evidence.iocs[0]
        ioc_indices = [i for i, item in enumerate(evidence.evidence, 1) if item.type == EvidenceType.IOC_EXTRACTED][:2]
        cite_str = f" [Evidence {', '.join(str(idx) for idx in ioc_indices)}]" if ioc_indices else ""
        structured_steps.append(
            AttackStep(
                step_number=step_num,
                description=f"Recipient is directed to communicate with an unverified direct contact '{ioc_val}'{cite_str}",
                causal_stage="redirection",
                evidence_indices=ioc_indices,
                observed_basis=ioc_val,
                intended_consequence="Bypass formal support channels and establish unmonitored communication",
            )
        )
        step_num += 1

    # Stage 3: Exploitation / Solicitation
    if exploit_indices:
        cite_str = f" [Evidence {', '.join(str(idx) for idx in exploit_indices[:3])}]"
        structured_steps.append(
            AttackStep(
                step_number=step_num,
                description=f"Attacker attempts to solicit sensitive credentials or financial transfer{cite_str}",
                causal_stage="exploitation",
                evidence_indices=exploit_indices[:3],
                observed_basis=evidence.evidence[exploit_indices[0] - 1].observed_value or "Credential/financial demand",
                intended_consequence="Capture authentication factors or extract unauthorized funds",
            )
        )
        step_num += 1
    elif risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        cat_exploit_map = {
            "banking": "Attacker typically attempts to solicit netbanking credentials, OTP, or card details via deceptive portal",
            "courier": "Attacker typically prompts victim for payment card details under pretext of delivery or customs fee",
            "lottery_prize": "Attacker typically demands advance fee or deposit transfer to claim promised funds",
            "investment": "Attacker typically induces victim to transfer capital into unverified investment schemes",
            "job_offer": "Attacker typically solicits advance registration fees or identity records",
            "government": "Attacker typically demands urgent fine settlement or identity document submission",
            "tech_support": "Attacker typically attempts to persuade victim to install remote device management tools",
        }
        exploit_desc = cat_exploit_map.get(
            category,
            "Attacker typically attempts to solicit confidential authentication factors or personal data",
        )
        structured_steps.append(
            AttackStep(
                step_number=step_num,
                description=exploit_desc,
                causal_stage="exploitation",
                evidence_indices=[],
                intended_consequence="Acquire victim secrets or monetary transfers",
            )
        )
        step_num += 1

    # Stage 4: Risk / Consequence (Epistemically modest & non-assumptive)
    if risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        structured_steps.append(
            AttackStep(
                step_number=step_num,
                description="Potential consequence: Unauthorized financial loss or account takeover if recipient complies with requested actions",
                causal_stage="monetization",
                evidence_indices=[],
                intended_consequence="Financial loss or account compromise (unconfirmed, contingent on user compliance)",
            )
        )
    elif risk_level == RiskLevel.MEDIUM:
        structured_steps.append(
            AttackStep(
                step_number=step_num,
                description="Potential consequence: Exposure of personal contact details, credentials, or vulnerability to follow-up fraud attempts",
                causal_stage="monetization",
                evidence_indices=[],
                intended_consequence="Information disclosure or secondary targeting",
            )
        )
    else:
        structured_steps.append(
            AttackStep(
                step_number=step_num,
                description="Potential consequence: Unconfirmed without verified recipient interaction; standard caution advised",
                causal_stage="monetization",
                evidence_indices=[],
                intended_consequence="Minimal or unknown risk",
            )
        )

    attack_path_strings = [s.description for s in structured_steps]
    return attack_path_strings, structured_steps


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

    # ─── Attack path (Traceable Causal Graph) ───
    attack_path, structured_attack_path = _build_traceable_fallback_attack_path(evidence)

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
        structured_attack_path=structured_attack_path,
        user_action=user_action,
        uncertainty=uncertainty,
        what_cannot_be_concluded=list(evidence.risk.what_cannot_be_concluded),
        model_used="deterministic-fallback",
        evidence_cited=[str(i + 1) for i in range(len(evidence.evidence))],
        is_fallback=True,
    )

    return evidence
