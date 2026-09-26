"""
Comprehensive unit tests for Threat Intelligence providers:
- Google Safe Browsing
- PhishTank
- PhishStats
- OpenPhish de-integration verification

All external network calls are mocked. No secrets required.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
import pytest

from backend.config import Settings
from backend.models.evidence import (
    IncidentEvidence,
    InputType,
    ThreatIntelResult,
    ThreatIntelStatus,
)
from backend.services.safe_browsing import check_safe_browsing
from backend.services.phishtank import check_phishtank
from backend.services.phishstats import (
    check_phishstats,
    clear_phishstats_cache,
    set_phishstats_cache_for_testing,
)
from backend.modules.threat_intel import query_threat_intel


@pytest.fixture(autouse=True)
def clean_cache():
    clear_phishstats_cache()
    yield
    clear_phishstats_cache()


# ─────────────────────────────────────────────────────────────
# 1. Google Safe Browsing Tests
# ─────────────────────────────────────────────────────────────

def test_safe_browsing_missing_key():
    mock_settings = Settings(safe_browsing_api_key=None)
    with patch("backend.services.safe_browsing.get_settings", return_value=mock_settings):
        results = asyncio.run(check_safe_browsing(["https://test-example.com"]))
    assert len(results) == 1
    assert results[0].intel_status == ThreatIntelStatus.SOURCE_UNAVAILABLE
    assert results[0].match is None


def test_safe_browsing_match():
    mock_settings = Settings(safe_browsing_api_key="mock_key")
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {
        "matches": [
            {
                "threatType": "MALWARE",
                "platformType": "ANY_PLATFORM",
                "threat": {"url": "https://malware-site.example.com"},
            }
        ]
    }

    with patch("backend.services.safe_browsing.get_settings", return_value=mock_settings):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            results = asyncio.run(check_safe_browsing(["https://malware-site.example.com"]))

    assert len(results) == 1
    assert results[0].match is True
    assert results[0].intel_status == ThreatIntelStatus.KNOWN_MALICIOUS
    assert "MALWARE" in (results[0].details or "")


def test_safe_browsing_no_match():
    mock_settings = Settings(safe_browsing_api_key="mock_key")
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {}  # Empty matches

    with patch("backend.services.safe_browsing.get_settings", return_value=mock_settings):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            results = asyncio.run(check_safe_browsing(["https://clean-site.example.com"]))

    assert len(results) == 1
    assert results[0].match is False
    assert results[0].intel_status == ThreatIntelStatus.NO_KNOWN_MATCH


# ─────────────────────────────────────────────────────────────
# 2. PhishTank Tests
# ─────────────────────────────────────────────────────────────

def test_phishtank_missing_key():
    mock_settings = Settings(phishtank_api_key=None)
    with patch("backend.services.phishtank.get_settings", return_value=mock_settings):
        results = asyncio.run(check_phishtank(["https://test-phish.example.com"]))
    assert len(results) == 1
    assert results[0].intel_status == ThreatIntelStatus.SOURCE_UNAVAILABLE
    assert results[0].match is None


def test_phishtank_match():
    mock_settings = Settings(phishtank_api_key="mock_key")
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {
        "results": {
            "in_database": True,
            "valid": True,
            "phish_id": "123456",
        }
    }

    with patch("backend.services.phishtank.get_settings", return_value=mock_settings):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            results = asyncio.run(check_phishtank(["https://verified-phish.com"]))

    assert len(results) == 1
    assert results[0].match is True
    assert results[0].intel_status == ThreatIntelStatus.KNOWN_MALICIOUS
    assert "123456" in (results[0].details or "")


def test_phishtank_no_match():
    mock_settings = Settings(phishtank_api_key="mock_key")
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {
        "results": {
            "in_database": False,
        }
    }

    with patch("backend.services.phishtank.get_settings", return_value=mock_settings):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            results = asyncio.run(check_phishtank(["https://clean-site.com"]))

    assert len(results) == 1
    assert results[0].match is False
    assert results[0].intel_status == ThreatIntelStatus.NO_KNOWN_MATCH


# ─────────────────────────────────────────────────────────────
# 3. PhishStats Tests
# ─────────────────────────────────────────────────────────────

def test_phishstats_missing_key():
    mock_settings = Settings(phishstats_api_key=None)
    with patch("backend.services.phishstats.get_settings", return_value=mock_settings):
        results = asyncio.run(check_phishstats(["https://phishstats-test.com"]))
    assert len(results) == 1
    assert results[0].intel_status == ThreatIntelStatus.SOURCE_UNAVAILABLE
    assert results[0].match is None


def test_phishstats_match():
    mock_settings = Settings(phishstats_api_key="psk_mock_key")
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {
            "id": 998811,
            "url": "https://malicious-bank-login.xyz",
            "ip": "198.51.100.25",
            "asn": "AS12345",
            "isp": "BadHost Ltd",
            "countryname": "United States",
            "countrycode": "US",
            "score": 8.7,
            "date": "2026-09-26T12:00:00Z",
        }
    ]

    with patch("backend.services.phishstats.get_settings", return_value=mock_settings):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response):
            results = asyncio.run(check_phishstats(["https://malicious-bank-login.xyz"]))

    assert len(results) == 1
    assert results[0].match is True
    assert results[0].intel_status == ThreatIntelStatus.KNOWN_MALICIOUS
    assert "8.7/10" in (results[0].details or "")
    assert "United States" in (results[0].details or "")


def test_phishstats_no_match():
    mock_settings = Settings(phishstats_api_key="psk_mock_key")
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = []  # Empty array from PhishStats

    with patch("backend.services.phishstats.get_settings", return_value=mock_settings):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response):
            results = asyncio.run(check_phishstats(["https://legitimate-domain.com"]))

    assert len(results) == 1
    assert results[0].match is False
    assert results[0].intel_status == ThreatIntelStatus.NO_KNOWN_MATCH


def test_phishstats_invalid_key():
    mock_settings = Settings(phishstats_api_key="psk_invalid_key")
    mock_response = MagicMock()
    mock_response.status_code = 401

    with patch("backend.services.phishstats.get_settings", return_value=mock_settings):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response):
            results = asyncio.run(check_phishstats(["https://test-site.com"]))

    assert len(results) == 1
    assert results[0].match is None
    assert results[0].intel_status == ThreatIntelStatus.SOURCE_ERROR
    assert "Invalid API key" in (results[0].error or "")


def test_phishstats_rate_limited_429():
    mock_settings = Settings(phishstats_api_key="psk_mock_key")
    mock_response = MagicMock()
    mock_response.status_code = 429

    with patch("backend.services.phishstats.get_settings", return_value=mock_settings):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response):
            results = asyncio.run(check_phishstats(["https://rate-limited.com"]))

    assert len(results) == 1
    assert results[0].match is None
    assert results[0].intel_status == ThreatIntelStatus.SOURCE_ERROR
    assert "429" in (results[0].error or "")


def test_phishstats_timeout():
    mock_settings = Settings(phishstats_api_key="psk_mock_key")

    with patch("backend.services.phishstats.get_settings", return_value=mock_settings):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=httpx.TimeoutException("Timeout")):
            results = asyncio.run(check_phishstats(["https://timeout-site.com"]))

    assert len(results) == 1
    assert results[0].match is None
    assert results[0].intel_status == ThreatIntelStatus.SOURCE_ERROR
    assert "timed out" in (results[0].error or "").lower()


def test_phishstats_malformed_json():
    mock_settings = Settings(phishstats_api_key="psk_mock_key")
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.side_effect = ValueError("Invalid JSON")

    with patch("backend.services.phishstats.get_settings", return_value=mock_settings):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response):
            results = asyncio.run(check_phishstats(["https://malformed-json.com"]))

    assert len(results) == 1
    assert results[0].match is None
    assert results[0].intel_status == ThreatIntelStatus.SOURCE_ERROR


def test_phishstats_empty_response():
    mock_settings = Settings(phishstats_api_key="psk_mock_key")
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = []

    with patch("backend.services.phishstats.get_settings", return_value=mock_settings):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response):
            results = asyncio.run(check_phishstats(["https://empty-response.com"]))

    assert len(results) == 1
    assert results[0].match is False
    assert results[0].intel_status == ThreatIntelStatus.NO_KNOWN_MATCH


def test_phishstats_unavailable():
    mock_settings = Settings(phishstats_api_key="psk_mock_key")
    mock_response = MagicMock()
    mock_response.status_code = 503

    with patch("backend.services.phishstats.get_settings", return_value=mock_settings):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response):
            results = asyncio.run(check_phishstats(["https://service-down.com"]))

    assert len(results) == 1
    assert results[0].match is None
    assert results[0].intel_status == ThreatIntelStatus.SOURCE_ERROR
    assert "503" in (results[0].error or "")


def test_safe_browsing_unavailable_http_error():
    mock_settings = Settings(safe_browsing_api_key="mock_key")
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.raise_for_status.side_effect = httpx.HTTPStatusError("Server Error", request=MagicMock(), response=mock_response)

    with patch("backend.services.safe_browsing.get_settings", return_value=mock_settings):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            results = asyncio.run(check_safe_browsing(["https://down-site.com"]))

    assert len(results) == 1
    assert results[0].intel_status == ThreatIntelStatus.SOURCE_ERROR
    assert results[0].match is None


def test_phishtank_unavailable_http_error():
    mock_settings = Settings(phishtank_api_key="mock_key")
    mock_response = MagicMock()
    mock_response.status_code = 502
    mock_response.raise_for_status.side_effect = httpx.HTTPStatusError("Bad Gateway", request=MagicMock(), response=mock_response)

    with patch("backend.services.phishtank.get_settings", return_value=mock_settings):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            results = asyncio.run(check_phishtank(["https://down-site.com"]))

    assert len(results) == 1
    assert results[0].intel_status == ThreatIntelStatus.SOURCE_ERROR
    assert results[0].match is None


# ─────────────────────────────────────────────────────────────
# 4. OpenPhish Total Removal Verification
# ─────────────────────────────────────────────────────────────

def test_openphish_removal_repo_verification():
    """Verify that OpenPhish has zero runtime integration anywhere in the backend."""
    import importlib.util

    # 1. openphish.py file must not exist
    spec = importlib.util.find_spec("backend.services.openphish")
    assert spec is None, "backend.services.openphish should be deleted"

    # 2. settings must not have openphish_enabled
    settings = Settings()
    assert not hasattr(settings, "openphish_enabled") or getattr(settings, "openphish_enabled") is None
    assert "openphish" not in settings.api_availability()
