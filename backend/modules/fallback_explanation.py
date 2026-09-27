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

_SUMMARY_TEMPLATES_HI = {
    RiskLevel.CRITICAL: "इस संदेश में {category} धोखाधड़ी (स्कैम) के कई पुष्ट और अत्यधिक गंभीर खतरे पाए गए हैं।",
    RiskLevel.HIGH: "इस संदेश में {category} धोखाधड़ी के महत्वपूर्ण संकेत पाए गए हैं। सावधान रहें।",
    RiskLevel.MEDIUM: "इस संदेश में कुछ संदिग्ध तत्व हैं जो {category} स्कैम की संभावना दर्शाते हैं।",
    RiskLevel.LOW: "इस संदेश में धोखाधड़ी के बहुत कम संकेत हैं।",
    RiskLevel.UNKNOWN: "इस संदेश का धोखाधड़ी होना तय करने के लिए पर्याप्त साक्ष्य उपलब्ध नहीं हैं।",
}

_SUMMARY_TEMPLATES_GU = {
    RiskLevel.CRITICAL: "આ સંદેશામાં {category} છેતરપિંડી (સ્કેમ) ના અત્યંત ગંભીર સંકેતો મળી આવ્યા છે.",
    RiskLevel.HIGH: "આ સંદેશામાં {category} છેતરપિંડીના નોંધપાત્ર જોખમી સંકેતો મળ્યા છે.",
    RiskLevel.MEDIUM: "આ સંદેશામાં કેટલીક શંકાસ્પદ બાબતો છે જે {category} સ્કેમ સૂચવે છે.",
    RiskLevel.LOW: "આ સંદેશામાં છેતરપિંડીના ખૂબ ઓછા સંકેતો છે.",
    RiskLevel.UNKNOWN: "આ સંદેશ છેતરપિંડીયુક્ત છે કે નહીં તે નક્કી કરવા માટે પૂરતા પુરાવા નથી.",
}

_SUMMARY_TEMPLATES_TA = {
    RiskLevel.CRITICAL: "இந்த செய்தியில் {category} மோசடி தொடர்பான கடுமையான அச்சுறுத்தல்கள் கண்டறியப்பட்டுள்ளன.",
    RiskLevel.HIGH: "இந்த செய்தியில் {category} மோசடிக்கான முக்கிய அச்சுறுத்தல் அறிகுறிகள் உள்ளன. எச்சரிக்கையுடன் இருக்கவும்.",
    RiskLevel.MEDIUM: "இந்த செய்தியில் {category} மோசடியைக் குறிக்கும் சில சந்தேகத்திற்குரிய கூறுகள் உள்ளன.",
    RiskLevel.LOW: "இந்த செய்தியில் மிகக் குறைந்த மோசடி அறிகுறிகளே உள்ளன.",
    RiskLevel.UNKNOWN: "இது மோசடி செய்தியா என்பதை உறுதிப்படுத்த போதுமான ஆதாரங்கள் இல்லை.",
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

_CATEGORY_NAMES = {
    "en": {
        "banking": "banking",
        "electricity": "electricity disconnection",
        "courier": "parcel delivery",
        "digital_arrest": "digital arrest law enforcement",
        "lottery_prize": "lottery prize",
        "job_offer": "fake job offer",
        "investment": "investment scheme",
        "tech_support": "tech support",
        "unknown": "suspicious communication",
    },
    "hi": {
        "banking": "बैंक/केवाईसी",
        "electricity": "बिजली बिल डिस्कनेक्शन",
        "courier": "पार्सल/कूरियर डिलीवरी",
        "digital_arrest": "डिजिटल अरेस्ट/पुलिस वसूली",
        "lottery_prize": "लॉटरी/इनाम",
        "job_offer": "फर्जी नौकरी",
        "investment": "निवेश घोटाला",
        "tech_support": "तकनीकी सहायता",
        "unknown": "संदिग्ध संदेश",
    },
    "gu": {
        "banking": "બેંકિંગ/KYC",
        "electricity": "વીજળી બિલ કટઓફ",
        "courier": "કુરિયર/પાર્સલ ડિલિવરી",
        "digital_arrest": "ડિજિટલ ધરપકડ",
        "lottery_prize": "લોટરી/ઇનામ",
        "job_offer": "નોકરી છેતરપિંડી",
        "investment": "રોકાણ કૌભાંડ",
        "tech_support": "ટેકનિકલ સપોર્ટ",
        "unknown": "શંકાસ્પદ સંદેશ",
    },
    "ta": {
        "banking": "வங்கி/KYC",
        "electricity": "மின் கட்டண துண்டிப்பு",
        "courier": "கூரியர்/பார்சல்",
        "digital_arrest": "டிஜிட்டல் கைது",
        "lottery_prize": "பரிசு/லாட்டரி",
        "job_offer": "போலி வேலை வாய்ப்பு",
        "investment": "முதலீட்டு மோசடி",
        "tech_support": "தொழில்நுட்ப ஆதரவு",
        "unknown": "சந்தேகத்திற்குரிய செய்தி",
    },
}

_USER_ACTIONS = {
    RiskLevel.CRITICAL: [
        "Do NOT click any links or download attachments from this message",
        "Do NOT call any phone numbers listed in the message",
        "If you entered credentials, IMMEDIATELY change passwords on affected accounts",
        "If you made a payment, call 1930 immediately to freeze transactions (Golden Hour)",
        "Report the incident at cybercrime.gov.in and to your local police",
        "Preserve this message as evidence — do not delete it",
    ],
    RiskLevel.HIGH: [
        "Do NOT click any links in this message",
        "Verify the sender independently through official websites or known contact numbers",
        "If you clicked a link, do NOT enter OTPs, passwords, or personal details",
        "Report to cybercrime.gov.in or call helpline 1930",
        "Block the sender's number or email",
    ],
    RiskLevel.MEDIUM: [
        "Exercise caution — verify the sender's identity through official channels",
        "Do NOT click links unless you have independently verified the source",
        "Forward suspicious SMS to 1909 (TRAI DND service)",
    ],
    RiskLevel.LOW: [
        "Low threat detected — standard caution recommended",
        "Verify the sender if sensitive information was requested",
    ],
    RiskLevel.UNKNOWN: [
        "Insufficient evidence to determine risk — treat with caution",
        "Do NOT share sensitive personal or financial information",
    ],
}

_USER_ACTIONS_HI = {
    RiskLevel.CRITICAL: [
        "इस संदेश में दिए किसी भी लिंक पर क्लिक न करें",
        "उल्लिखित किसी भी नंबर पर कॉल या संदेश का उत्तर न दें",
        "यदि आपने कोई विवरण साझा किया है, तो तत्काल अपने पासवर्ड बदलें",
        "अनधिकृत लेन-देन रोकने हेतु तत्काल 1930 पर कॉल करें अथवा अपने बैंक से संपर्क करें",
        "cybercrime.gov.in पर तत्काल आधिकारिक शिकायत दर्ज करें",
        "इस संदेश को साक्ष्य के रूप में सुरक्षित रखें — इसे डिलीट न करें",
    ],
    RiskLevel.HIGH: [
        "संदेश में दिए लिंक पर क्लिक न करें और न ही दिए गए नंबरों पर कॉल करें",
        "संबंधित संस्था की आधिकारिक वेबसाइट के माध्यम से सीधे सत्यता जांचें",
        "यदि आपने लिंक खोल लिया है, तो कोई गोपनीय जानकारी या ओटीपी दर्ज न करें",
        "cybercrime.gov.in पर रिपोर्ट करें अथवा 1930 पर कॉल करें",
        "संदेश भेजने वाले को तुरंत ब्लॉक करें",
    ],
    RiskLevel.MEDIUM: [
        "सावधानी बरतें — संदेश भेजने वाले की पहचान की स्वतंत्र रूप से पुष्टि करें",
        "लिंक पर क्लिक न करें — आवश्यकता होने पर केवल आधिकारिक वेबसाइट पर जाएं",
        "संदिग्ध संदेश को 1909 पर स्पैम रिपोर्ट करें",
    ],
    RiskLevel.LOW: [
        "इस संदेश में धोखाधड़ी के बहुत कम संकेत हैं",
        "यदि कोई व्यक्तिगत विवरण मांगा गया हो, तो आधिकारिक स्रोतों से पुष्टि करें",
    ],
    RiskLevel.UNKNOWN: [
        "संदेश की प्रकृति निर्धारित करने के लिए साक्ष्य अपर्याप्त हैं",
        "अज्ञात प्रेषकों से प्राप्त संदेशों में मानक सावधानी बरतें",
    ],
}

_USER_ACTIONS_GU = {
    RiskLevel.CRITICAL: [
        "આ સંદેશામાં આવેલી કોઈપણ લિંક પર ક્લિક કરશો નહીં",
        "દર્શાવેલ કોઈપણ નંબર પર કૉલ કરશો નહીં અથવા જવાબ આપશો નહીં",
        "જો તમે માહિતી દાખલ કરી હોય, તો તાત્કાલિક તમારા પાસવર્ડ બદલો",
        "નાણાકીય છેતરપિંડી રોકવા માટે તાત્કાલિક ૧૯૩૦ પર કૉલ કરો અથવા બેંકનો સંપર્ક કરો",
        "cybercrime.gov.in પર ફરિયાદ નોંધાવો",
        "આ સંદેશને પુરાવા તરીકે સાચવી રાખો — ડિલીટ કરશો નહીં",
    ],
    RiskLevel.HIGH: [
        "કોઈપણ લિંક પર ક્લિક કરશો નહીં અથવા કૉલ કરશો નહીં",
        "સંસ્થાની સત્તાવાર વેબસાઇટ દ્વારા સીધી ખાતરી કરો",
        "જો લિંક ખોલી હોય, તો કોઈ ગુપ્ત માહિતી અથવા OTP દાખલ કરશો નહીં",
        "૧૯૩૦ પર કૉલ કરો અથવા cybercrime.gov.in પર રિપોર્ટ કરો",
        "મોકલનારને તરત જ બ્લૉક કરો",
    ],
    RiskLevel.MEDIUM: [
        "સાવચેતી રાખો — મોકલનારની ઓળખ ચકાસો",
        "સત્તાવાર વેબસાઇટની સીધી મુલાકાત લો",
    ],
    RiskLevel.LOW: [
        "આ સંદેશમાં છેતરપિંડીના બહુ ઓછા સંકેતો છે",
        "જો કોઈ માહિતી માંગી હોય તો સત્તાવાર ચેનલ પરથી ચકાસો",
    ],
    RiskLevel.UNKNOWN: [
        "ચોક્કસ મૂલ્યાંકન માટે પુરાવા અપૂરતા છે",
        "અજાણ્યા સંદેશાઓથી સાવચેત રહો",
    ],
}

_USER_ACTIONS_TA = {
    RiskLevel.CRITICAL: [
        "இந்த செய்தியில் உள்ள எந்த இணைப்பையும் கிளிக் செய்ய வேண்டாம்",
        "குறிப்பிடப்பட்ட எந்த எண்ணிற்கும் அழைக்கவோ பதிலளிக்கவோ வேண்டாம்",
        "ரகசிய விவரங்களை உள்ளிட்டிருந்தால், உடனடியாக கடவுச்சொற்களை மாற்றவும்",
        "பண இழப்பைத் தடுக்க உடனே 1930 ஐ அழைக்கவும் அல்லது வங்கியைத் தொடர்பு கொள்ளவும்",
        "cybercrime.gov.in இல் உடனடியாக புகாரளிக்கவும்",
        "இந்த செய்தியை ஆதாரமாக சேமிக்கவும் — நீக்க வேண்டாம்",
    ],
    RiskLevel.HIGH: [
        "இணைப்புகளை கிளிக் செய்யவோ எண்களுக்கு அழைக்கவோ வேண்டாம்",
        "அதிகாரப்பூர்வ இணையதளம் மூலம் நிறுவனத்தை நேரடியாக சரிபார்க்கவும்",
        "இணைப்பைத் திறந்திருந்தால், எந்த ரகசிய தகவலையும் OTP ஐயும் உள்ளிட வேண்டாம்",
        "1930 அல்லது cybercrime.gov.in இல் புகாரளிக்கவும்",
        "அனுப்பியவரை உடனே பிளாக் செய்யவும்",
    ],
    RiskLevel.MEDIUM: [
        "எச்சரிக்கையுடன் இருக்கவும் — அனுப்பியவரின் நம்பகத்தன்மையை சரிபார்க்கவும்",
        "தேவைப்பட்டால் அதிகாரப்பூர்வ இணையதளத்தை மட்டும் அணுகவும்",
    ],
    RiskLevel.LOW: [
        "இந்த செய்தியில் குறைந்த அளவிலான அச்சுறுத்தலே உள்ளது",
    ],
    RiskLevel.UNKNOWN: [
        "முடிவெடுக்க போதுமான ஆதாரங்கள் இல்லை. எச்சரிக்கையுடன் இருக்கவும்",
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
    lang = (evidence.response_language or evidence.language or "en").lower().split("-")[0]
    cat_map = _CATEGORY_NAMES.get(lang, _CATEGORY_NAMES["en"])
    localized_category = cat_map.get(category, category)

    if lang == "hi":
        template = _SUMMARY_TEMPLATES_HI.get(risk.level, _SUMMARY_TEMPLATES_HI[RiskLevel.UNKNOWN])
        user_action = _USER_ACTIONS_HI.get(risk.level, _USER_ACTIONS_HI[RiskLevel.UNKNOWN])
        no_reasons_msg = "उपलब्ध साक्ष्यों में कोई गंभीर धोखाधड़ी संकेत नहीं मिले।"
    elif lang == "gu":
        template = _SUMMARY_TEMPLATES_GU.get(risk.level, _SUMMARY_TEMPLATES_GU[RiskLevel.UNKNOWN])
        user_action = _USER_ACTIONS_GU.get(risk.level, _USER_ACTIONS_GU[RiskLevel.UNKNOWN])
        no_reasons_msg = "ઉપલબ્ધ પુરાવાઓમાં છેતરપિંડીના કોઈ ગંભીર સંકેતો મળ્યા નથી."
    elif lang == "ta":
        template = _SUMMARY_TEMPLATES_TA.get(risk.level, _SUMMARY_TEMPLATES_TA[RiskLevel.UNKNOWN])
        user_action = _USER_ACTIONS_TA.get(risk.level, _USER_ACTIONS_TA[RiskLevel.UNKNOWN])
        no_reasons_msg = "கிடைக்கப்பெற்ற ஆதாரங்களில் எவ்வித தீவிர அச்சுறுத்தலும் கண்டறியப்படவில்லை."
    else:
        template = _SUMMARY_TEMPLATES.get(risk.level, _SUMMARY_TEMPLATES[RiskLevel.UNKNOWN])
        user_action = _USER_ACTIONS.get(risk.level, _USER_ACTIONS[RiskLevel.UNKNOWN])
        no_reasons_msg = "No strong fraud indicators detected in the available evidence."

    summary = template.format(category=localized_category)

    # ─── Build reasons from evidence items ───
    reasons = []
    for item in evidence.evidence:
        conf = item.confidence if item.confidence is not None else 1.0
        if conf >= 0.3 and item.type not in (EvidenceType.THREAT_INTEL_MISS, EvidenceType.IOC_EXTRACTED):
            reasons.append(f"[{item.source}] {item.description}")

    if not reasons:
        reasons = [no_reasons_msg]

    # ─── Attack path (Traceable Causal Graph) ───
    attack_path, structured_attack_path = _build_traceable_fallback_attack_path(evidence)

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
