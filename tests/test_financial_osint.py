import asyncio
import pytest
from backend.services.financial_osint import (
    extract_ifsc_codes,
    extract_upi_vpas,
    lookup_ifsc_razorpay,
    analyze_upi_vpa,
)


def test_extract_ifsc_codes():
    text = "Please deposit fee to IFSC HDFC0000123 or SBI branch SBIN0001234 urgently"
    codes = extract_ifsc_codes(text)
    assert "HDFC0000123" in codes
    assert "SBIN0001234" in codes


def test_extract_upi_vpas():
    text = "Pay to electricity bill officer at bescom.refund@okhdfcbank or rahul99@ybl"
    vpas = extract_upi_vpas(text)
    assert "bescom.refund@okhdfcbank" in vpas
    assert "rahul99@ybl" in vpas


def test_lookup_ifsc_razorpay_valid():
    res = asyncio.run(lookup_ifsc_razorpay("HDFC0000123"))
    assert res["valid"] is True
    assert "HDFC" in res["bank"]


def test_lookup_ifsc_offline_fallback():
    # Synthetic code with valid SBI prefix - bank prefix recognized even if unlisted
    res = asyncio.run(lookup_ifsc_razorpay("SBIN0999999"))
    assert "State Bank of India" in res["bank"]


def test_analyze_upi_vpa_deceptive():
    res = analyze_upi_vpa("bescom.officer@okhdfcbank")
    assert res["valid"] is True
    assert res["deceptive"] is True
    assert "bescom" in res["matched_institutional_keywords"]
    assert res["is_consumer_psp"] is True


def test_analyze_upi_vpa_normal_consumer():
    res = analyze_upi_vpa("rohit.kumar@okhdfcbank")
    assert res["valid"] is True
    assert res["deceptive"] is False
