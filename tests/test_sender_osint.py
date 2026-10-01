import pytest
from backend.services.sender_analyzer import enrich_phone_number, analyze_sms_sender


def test_enrich_phone_number_valid_airtel():
    # 9876543210 is an active allocated Airtel India series
    info = enrich_phone_number("9876543210")
    assert info["valid"] is True
    assert info["is_mobile"] is True
    assert "Airtel" in info["carrier"]


def test_enrich_phone_number_with_country_code():
    info = enrich_phone_number("+919876543210")
    assert info["valid"] is True
    assert info["is_mobile"] is True


def test_analyze_sms_sender_personal_mobile_with_bank_claim():
    analysis, evidence = analyze_sms_sender("9876543210", "Your SBI bank account has been locked. Update KYC.")
    assert analysis["is_personal_mobile"] is True
    assert analysis["claimed_entity"] == "State Bank of India"
    assert len(evidence) >= 1
    assert "Claimed State Bank of India message sent from a personal 10-digit mobile number" in evidence[0].finding
    assert "Airtel" in evidence[0].finding
