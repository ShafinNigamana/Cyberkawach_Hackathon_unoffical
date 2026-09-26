"""
Unit tests for hardened OSINT enrichment module (WHOIS and crt.sh).
Verifies caching, timeouts, error handling, and SSRF/private-IP protection.
All external network calls are mocked.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import pytest

from backend.services.osint_enrichment import (
    clear_osint_cache,
    get_cert_transparency,
    get_domain_age,
    get_osint_enrichment,
)


@pytest.fixture(autouse=True)
def clean_cache():
    clear_osint_cache()
    yield
    clear_osint_cache()


def test_get_domain_age_success():
    mock_whois_record = MagicMock()
    mock_whois_record.creation_date = datetime.now(timezone.utc) - timedelta(days=10)
    mock_whois_record.registrar = "TestRegistrar Inc."

    with patch("backend.services.osint_enrichment.whois.whois", return_value=mock_whois_record):
        age_data = get_domain_age("scam-domain.xyz")

    assert age_data is not None
    assert age_data["days_old"] == 10
    assert age_data["registrar"] == "TestRegistrar Inc."
    assert "creation_date" in age_data


def test_get_domain_age_fails_safe_on_exception():
    with patch("backend.services.osint_enrichment.whois.whois", side_effect=Exception("WHOIS server down")):
        age_data = get_domain_age("nonexistent.xyz")

    assert age_data is None


def test_get_domain_age_ssrf_protection():
    # Loopback, private IPs, and cloud metadata should be blocked before whois lookup
    with patch("backend.services.osint_enrichment.whois.whois") as mock_whois_fn:
        assert get_domain_age("127.0.0.1") is None
        assert get_domain_age("169.254.169.254") is None
        assert get_domain_age("10.0.0.1") is None
        assert mock_whois_fn.call_count == 0


def test_get_cert_transparency_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {"name_value": "target.com\nother-phish.xyz\n*.campaign-domain.top"},
        {"name_value": "target.com\nsub.target.com"},
    ]

    with patch("httpx.Client.get", return_value=mock_resp):
        cert_data = get_cert_transparency("target.com")

    assert cert_data is not None
    shared = cert_data["shared_cert_domains"]
    assert "other-phish.xyz" in shared
    assert "campaign-domain.top" in shared
    assert "sub.target.com" not in shared


def test_get_cert_transparency_fails_safe_on_http_error():
    mock_resp = MagicMock()
    mock_resp.status_code = 502
    with patch("httpx.Client.get", return_value=mock_resp):
        cert_data = get_cert_transparency("error-domain.com")

    assert cert_data is None


def test_get_cert_transparency_ssrf_protection():
    with patch("httpx.Client.get") as mock_get_fn:
        assert get_cert_transparency("169.254.169.254") is None
        assert get_cert_transparency("127.0.0.1") is None
        assert mock_get_fn.call_count == 0


def test_get_osint_enrichment_caching():
    mock_whois_record = MagicMock()
    mock_whois_record.creation_date = datetime.now(timezone.utc) - timedelta(days=3)
    mock_whois_record.registrar = "FastRegistrar"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = []

    with patch("backend.services.osint_enrichment.whois.whois", return_value=mock_whois_record) as mock_whois_fn:
        with patch("httpx.Client.get", return_value=mock_resp) as mock_requests_fn:
            res1 = get_osint_enrichment("cached-domain.com")
            res2 = get_osint_enrichment("cached-domain.com")

    assert res1 == res2
    assert res1["status"] in ("complete", "partial")
    assert mock_whois_fn.call_count == 1
    assert mock_requests_fn.call_count == 1


def test_get_osint_enrichment_status_unavailable():
    with patch("backend.services.osint_enrichment.get_domain_age", return_value=None):
        with patch("backend.services.osint_enrichment.get_cert_transparency", return_value=None):
            res = get_osint_enrichment("unavailable.test")

    assert res["status"] == "unavailable"
    assert res["domain_age"] is None
    assert res["cert_transparency"] is None
