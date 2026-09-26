"""
Unit tests for Native Indic script parsing (Hindi, Gujarati, Tamil) and multilingual fallback.
"""

import pytest
from backend.models.evidence import IncidentEvidence, RiskAssessment, RiskLevel
from backend.modules.fallback_explanation import generate_fallback_explanation
from backend.modules.ingestion import detect_script_language, extract_iocs
from backend.modules.rules import apply_rules


def test_detect_script_language():
    # Hindi Devanagari
    assert detect_script_language("आपका बैंक खाता ब्लॉक है") == "hi"
    # Gujarati
    assert detect_script_language("તમારું વીજળી બિલ બાકી છે") == "gu"
    # Tamil
    assert detect_script_language("உங்கள் வங்கி கணக்கு") == "ta"
    # English default
    assert detect_script_language("Dear customer your account is suspended") == "en"


def test_extract_iocs_auto_detects_indic_language():
    evidence = IncidentEvidence(
        message="प्रिय ग्राहक आपका एसबीआई खाता ब्लॉक है http://sbi.xyz",
        language="en",  # Default provided by client
    )
    evidence = extract_iocs(evidence)

    assert evidence.language == "hi"
    assert len(evidence.urls) == 1
    assert evidence.urls[0].domain == "sbi.xyz"


def test_hindi_rules_detection():
    evidence = IncidentEvidence(
        message="प्रिय ग्राहक, आपका बैंक खाता ब्लॉक कर दिया गया है। तुरंत केवाईसी अपडेट करें।",
        language="hi",
    )
    evidence = apply_rules(evidence)

    assert evidence.fraud_category == "banking"
    assert any("urgency" in r for r in evidence.rule_matches)


def test_gujarati_rules_detection():
    evidence = IncidentEvidence(
        message="તમારું વીજળી બિલ બાકી છે, આજે રાત્રે લાઈટ કનેક્શન કપાઈ જશે. તાત્કાલિક સંપર્ક કરો.",
        language="gu",
    )
    evidence = apply_rules(evidence)

    assert evidence.fraud_category == "electricity"
    assert any("urgency" in r for r in evidence.rule_matches)


def test_tamil_rules_detection():
    evidence = IncidentEvidence(
        message="உங்கள் வங்கி கணக்கு முடக்கப்பட்டது உடனடியாக கேஒய்சி புதுப்பிக்கவும்",
        language="ta",
    )
    evidence = apply_rules(evidence)

    assert evidence.fraud_category == "banking"
    assert any("urgency" in r for r in evidence.rule_matches)


def test_localized_fallback_explanation():
    # Hindi explanation
    hi_evidence = IncidentEvidence(
        message="खाता ब्लॉक",
        fraud_category="banking",
        language="hi",
        risk=RiskAssessment(level=RiskLevel.CRITICAL, score=0.9),
    )
    hi_evidence = generate_fallback_explanation(hi_evidence)
    assert "धोखाधड़ी" in hi_evidence.explanation.summary

    # Gujarati explanation
    gu_evidence = IncidentEvidence(
        message="ખાતું બ્લોક",
        fraud_category="banking",
        language="gu",
        risk=RiskAssessment(level=RiskLevel.HIGH, score=0.75),
    )
    gu_evidence = generate_fallback_explanation(gu_evidence)
    assert "છેતરપિંડી" in gu_evidence.explanation.summary

    # Tamil explanation
    ta_evidence = IncidentEvidence(
        message="வங்கி கணக்கு",
        fraud_category="banking",
        language="ta",
        risk=RiskAssessment(level=RiskLevel.CRITICAL, score=0.9),
    )
    ta_evidence = generate_fallback_explanation(ta_evidence)
    assert "மோசடி" in ta_evidence.explanation.summary
