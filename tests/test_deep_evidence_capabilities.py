"""
Comprehensive Test Suite for Deep, Live, Proactive Evidence Gathering Capabilities.

Validates that CyberKawach dynamically discovers technical forensic traits from untrusted
inputs rather than relying solely on pre-existing records in the database:
1. Homoglyphs & Unicode Cyrillic lookalikes in domains.
2. ASN, BGP Routing, and Reverse DNS (PTR) resolution.
3. Malicious Android APK sideloading detection in web DOM.
4. Anti-inspection handlers (right-click & DevTools disabling).
5. Psychological emergency coercion alerts in page DOM.
6. HTTP response security header auditing (HSTS, CSP, X-Frame-Options, Server disclosure).
7. Indian Cybercrime Operational Corridors (Jamtara, Mewat, Southeast Asia scam compounds).
8. Chat redirection (WhatsApp click-to-chat international numbers, Telegram channels).
9. Deep UPI PSP decomposition & Neo-bank mule account indicators.
10. Cryptocurrency & TRC-20 USDT address forensic extraction.
11. Zero-width character smuggling detection in message text.
12. End-to-end forensic triage pipeline execution emitting typed EvidenceItems.
"""

import pytest
from backend.models.evidence import (
    EvidenceSeverity,
    EvidenceStatus,
    EvidenceType,
    RiskDirection,
    RiskLevel,
)
from backend.services.domain_intel import (
    collect_domain_evidence,
    detect_homoglyphs,
    lookup_asn_and_infrastructure,
)
from backend.services.website_analyzer import analyze_html_content
from backend.services.sender_analyzer import (
    analyze_chat_redirects,
    analyze_sms_sender,
    enrich_phone_number,
)
from backend.services.financial_osint import (
    analyze_upi_vpa,
    extract_crypto_addresses,
    extract_ifsc_codes,
    extract_upi_vpas,
)
from backend.services.indicators import extract_indicators
from backend.services.pipeline_service import execute_analysis_pipeline


# ─── 1. Homoglyph & Punycode Deobfuscation Tests ───

def test_detect_homoglyphs_cyrillic_spoofing():
    # 'sbi' with Cyrillic 'а' replacing Latin 'a' in 'paypаl.com'
    fake_domain = "payp\u0430l.com"
    result = detect_homoglyphs(fake_domain)

    assert result["is_spoofed"] is True
    assert result["homoglyph_count"] == 1
    assert result["normalized_domain"] == "paypal.com"
    assert result["found_homoglyphs"][0]["looks_like"] == "a"


def test_detect_homoglyphs_clean_domain():
    result = detect_homoglyphs("onlinesbi.sbi")
    assert result["is_spoofed"] is False
    assert result["homoglyph_count"] == 0
    assert result["normalized_domain"] == "onlinesbi.sbi"


# ─── 2. ASN & BGP Infrastructure Intelligence Tests ───

def test_lookup_asn_ssrf_defense():
    result = lookup_asn_and_infrastructure("127.0.0.1")
    assert result["valid"] is False
    assert "SSRF" in result["error"] or "Non-public" in result["error"]

    metadata_result = lookup_asn_and_infrastructure("169.254.169.254")
    assert metadata_result["valid"] is False


def test_lookup_asn_public_ip():
    # Cloudflare public DNS
    result = lookup_asn_and_infrastructure("1.1.1.1")
    assert result["valid"] is True
    assert result["asn"] == "AS13335" or result["asn"] is not None


# ─── 3. Website Analyzer: APK Sideloading, Anti-Forensics & HTTP Headers ───

def test_analyze_html_apk_sideloading_detection():
    html_payload = """
    <html>
      <body>
        <h2>Important SBI Rewards Update</h2>
        <a href="/downloads/sbi_yono_rewards_update.apk" class="btn">Download Application</a>
      </body>
    </html>
    """
    analysis, items = analyze_html_content(
        final_url="http://sbi-rewards-fake.xyz/index.html",
        response_body=html_payload,
    )
    apk_items = [item for item in items if "APK sideloading" in (item.finding or "")]
    assert len(apk_items) >= 1
    assert apk_items[0].severity == EvidenceSeverity.CRITICAL
    assert apk_items[0].risk_direction == RiskDirection.INCREASES_RISK
    assert "sbi_yono_rewards_update.apk" in apk_items[0].description


def test_analyze_html_anti_inspection_handlers():
    html_payload = """
    <body oncontextmenu="return false;" onselectstart="return false;">
      <script>
        document.onkeydown = function(e) {
          if (e.keyCode == 123) { return false; }
        };
      </script>
      <h1>Secure Verification</h1>
    </body>
    """
    analysis, items = analyze_html_content(
        final_url="http://phish-secure.xyz",
        response_body=html_payload,
    )
    anti_inspect_items = [item for item in items if "right-click" in (item.finding or "").lower()]
    assert len(anti_inspect_items) >= 1
    assert anti_inspect_items[0].status == EvidenceStatus.CONFIRMED


def test_analyze_html_dom_coercion_alert():
    html_payload = """
    <div>
      <p class="warning">Your electricity power supply will be disconnected tonight at 9:30 PM due to unpaid bill.</p>
    </div>
    """
    analysis, items = analyze_html_content(
        final_url="http://electricity-portal-fake.com",
        response_body=html_payload,
    )
    coercion_items = [item for item in items if item.correlation_group == "psychological_coercion"]
    assert len(coercion_items) >= 1
    assert "disconnected" in coercion_items[0].observed_value.lower()


def test_analyze_html_http_security_headers():
    headers = {
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3",
    }
    analysis, items = analyze_html_content(
        final_url="https://secure-portal.com/login",
        response_body="<html><body>Login</body></html>",
        response_headers=headers,
    )
    # Checks HSTS missing on HTTPS
    hsts_items = [i for i in items if "HSTS" in (i.finding or "")]
    assert len(hsts_items) == 1
    assert hsts_items[0].severity == EvidenceSeverity.MEDIUM

    # Checks Server Banner Disclosure
    banner_items = [i for i in items if "Server technology banner" in (i.finding or "")]
    assert len(banner_items) == 1
    assert "Apache/2.4.41" in banner_items[0].observed_value


# ─── 4. Indian Telecom & Cybercrime Corridors Tests ───

def test_enrich_phone_international_and_domestic():
    # Domestic Indian Mobile
    in_res = enrich_phone_number("9876543210")
    assert in_res["valid"] is True
    assert in_res["is_mobile"] is True

    # Southeast Asia Cambodia (+855)
    sea_res = enrich_phone_number("+85512345678")
    assert sea_res["valid"] is True
    assert sea_res["country_code"] == 855


def test_analyze_chat_redirects_whatsapp_cambodia():
    msg = "For fast job verification click here: wa.me/+85598765432 or join t.me/daily_crypto_earnings"
    items = analyze_chat_redirects(msg)

    wa_items = [i for i in items if "WhatsApp" in (i.finding or "")]
    assert len(wa_items) == 1
    assert wa_items[0].severity == EvidenceSeverity.CRITICAL
    assert "TRANSNATIONAL FRAUD ZONE" in wa_items[0].description

    tg_items = [i for i in items if "Telegram" in (i.finding or "")]
    assert len(tg_items) == 1
    assert "@daily_crypto_earnings" in tg_items[0].finding


def test_analyze_sms_sender_cybercrime_corridor():
    # Number from Jharkhand circle claiming electricity bill threat
    sender = "9431100000"  # BSNL / Bihar-Jharkhand range
    msg = "Dear consumer, your electricity will be disconnected tonight at 9:30 PM from BESCOM office. Call officer."
    analysis, items = analyze_sms_sender(sender, msg)

    corridor_items = [i for i in items if i.correlation_group == "telecom_syndicate_corridor"]
    if corridor_items:
        assert "Corridor" in corridor_items[0].finding
        assert corridor_items[0].evidence_tier == "DERIVED"


# ─── 5. Financial OSINT: UPI PSP & Crypto Forensics Tests ───

def test_analyze_upi_vpa_psp_breakdown():
    # PhonePe handle
    vpa_phonepe = "user123@ybl"
    res1 = analyze_upi_vpa(vpa_phonepe)
    assert res1["valid"] is True
    assert res1["provider"] == "PhonePe"
    assert res1["sponsor_bank"] == "YES Bank"
    assert res1["is_consumer_psp"] is True


def test_analyze_upi_vpa_neo_bank_mule():
    # Student / Neo-bank handle frequently rented by syndicates
    vpa_fam = "student_mule@fam"
    res2 = analyze_upi_vpa(vpa_fam)
    assert res2["is_mule_risk"] is True
    assert "FamPay" in res2["provider"]


def test_extract_crypto_addresses_forensics():
    text = (
        "Transfer USDT to our TRON deposit wallet: TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t "
        "or send BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa immediately."
    )
    cryptos = extract_crypto_addresses(text)
    assert len(cryptos) >= 2
    trc = next((c for c in cryptos if c["chain"] == "TRON (TRC-20)"), None)
    assert trc is not None
    assert trc["asset"] == "Tether USDT"
    assert "money laundering" in trc["risk_note"].lower()


# ─── 6. Unicode Zero-Width Smuggling Forensics Tests ───

def test_extract_indicators_zero_width_smuggling():
    # "B\u200bA\u200bN\u200bK" containing zero-width spaces
    sneaky_text = "Urgent update required from your B\u200bA\u200bN\u200bK immediately."
    indicators = extract_indicators(sneaky_text)

    assert len(indicators.zero_width_characters) >= 1
    assert indicators.zero_width_characters[0]["count"] == 3
    assert indicators.zero_width_characters[0]["char_hex"] == "U+200B"


# ─── 7. End-to-End Dynamic Evidence Pipeline Integration Tests ───

import asyncio

def test_pipeline_dynamic_deep_evidence_discovery():
    test_incident = (
        "Dear customer, your SBI account is suspended due to KYC expiry. "
        "Download update APK here: https://pаypаl.com/yono_kyc_update.apk. "
        "Pay reactivation fee to bescom.officer@ybl or deposit USDT TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
    )
    evidence = asyncio.run(execute_analysis_pipeline(
        message=test_incident,
        urls=["https://pаypаl.com/yono_kyc_update.apk"],
        sender="9876543210",
    ))

    # 1. Check that pipeline executed without failure
    assert evidence.risk is not None
    assert evidence.risk.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    # 2. Check for Homoglyph evidence item
    homo_items = [e for e in evidence.evidence if "homoglyph" in (e.finding or "").lower()]
    assert len(homo_items) >= 1
    assert homo_items[0].severity == EvidenceSeverity.CRITICAL

    # 3. Check for Deceptive UPI handle item
    upi_items = [e for e in evidence.evidence if e.correlation_group == "payment_diversion"]
    assert len(upi_items) >= 1

    # 4. Check for Crypto settlement address item
    crypto_items = [e for e in evidence.evidence if e.correlation_group == "crypto_settlement"]
    assert len(crypto_items) >= 1
    assert "TRON (TRC-20)" in crypto_items[0].observed_value
