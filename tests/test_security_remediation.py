"""
Targeted Verification Tests for the 6 Security Remediation Fixes.

Covers:
1. CYBERKAWACH-AUTH-RL-EVASION: Token rotation quota evasion blocked.
2. CYBERKAWACH-RATELIMIT-XFF-SPOOF: XFF header spoofing blocked from untrusted clients.
3. CYBERKAWACH-IDOR-ANON-INCIDENTS: Claim token required for anonymous incident access.
4. CYBERKAWACH-DOS-UNBOUNDED-SCAN-REGISTRY: LRU bounded store memory protection.
5. CYBERKAWACH-SSRF-TOCTOU-REBINDING: Anti-rebinding pre-request validation.
6. CYBERKAWACH-SEC-PLAINTEXT-SECRETS & Neo4j fallback: Clean offline SQLite operation.
"""

import asyncio
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from backend.config import get_settings
from backend.main import app
from backend.models.evidence import IncidentEvidence, InputType, RiskAssessment, RiskLevel
from backend.services.file_scanner import BoundedScanStore
from backend.services.incident_store import incident_store
from backend.services.neo4j_repository import neo4j_repo
from backend.utils.rate_limiter import get_client_identification, rate_limiter
from backend.utils.ssrf import safe_fetch_url, validate_url_for_ssrf

client = TestClient(app)


# ─── 1. CYBERKAWACH-AUTH-RL-EVASION ───
def test_remediation_unvalidated_bearer_cannot_elevate_quota():
    """Unvalidated Bearer tokens must not receive auth limit tier."""
    scope = {
        "type": "http",
        "client": ("198.51.100.22", 40000),
        "headers": [(b"authorization", b"Bearer arbitrary_fake_token_attempting_evasion")],
    }
    req = Request(scope)
    with patch("backend.services.neo4j_repository.neo4j_repo.validate_session", return_value=None):
        key, tier, limit = get_client_identification(req)
        assert tier == "anon"
        assert limit == rate_limiter.anon_limit
        assert "anon:198.51.100.22" in key


# ─── 2. CYBERKAWACH-RATELIMIT-XFF-SPOOF ───
def test_remediation_xff_spoofing_ignored_from_untrusted_peer():
    """X-Forwarded-For is ignored if client.host is not in trusted_proxies."""
    scope = {
        "type": "http",
        "client": ("198.51.100.50", 40001),
        "headers": [(b"x-forwarded-for", b"8.8.8.8")],
    }
    req = Request(scope)
    key, tier, limit = get_client_identification(req)
    assert key == "anon:198.51.100.50"
    assert "8.8.8.8" not in key


# ─── 3. CYBERKAWACH-IDOR-ANON-INCIDENTS ───
def test_remediation_anonymous_incident_requires_claim_token():
    """Anonymous incidents created via /api/analyze return a claim_token and block unauthorized third parties."""
    # 1. Submit analysis as anonymous user
    resp = client.post(
        "/api/analyze",
        json={"message": "Urgent SBI account block notice, update KYC immediately", "input_type": "text"},
    )
    assert resp.status_code == 200
    data = resp.json()
    incident_id = data["incident_id"]
    claim_token = data.get("claim_token")

    # Must provide claim token
    assert claim_token is not None
    assert len(claim_token) >= 32

    # 2. Third party without claim token gets 404
    resp_no_auth = client.get(f"/api/incidents/{incident_id}")
    assert resp_no_auth.status_code == 404

    resp_dossier_no_auth = client.get(f"/api/incidents/{incident_id}/dossier")
    assert resp_dossier_no_auth.status_code == 404

    resp_export_no_auth = client.get(f"/api/incidents/{incident_id}/export")
    assert resp_export_no_auth.status_code == 404

    resp_stix_no_auth = client.get(f"/api/incidents/{incident_id}/stix")
    assert resp_stix_no_auth.status_code == 404

    # 3. Third party with invalid claim token gets 404
    resp_wrong_token = client.get(
        f"/api/incidents/{incident_id}",
        headers={"X-Incident-Claim-Token": "invalid_wrong_claim_token"},
    )
    assert resp_wrong_token.status_code == 404

    # 4. Legitimate client WITH claim token succeeds
    resp_authorized = client.get(
        f"/api/incidents/{incident_id}",
        headers={"X-Incident-Claim-Token": claim_token},
    )
    assert resp_authorized.status_code == 200
    assert resp_authorized.json()["incident_id"] == incident_id

    resp_dossier = client.get(
        f"/api/incidents/{incident_id}/dossier",
        headers={"X-Incident-Claim-Token": claim_token},
    )
    assert resp_dossier.status_code == 200


# ─── 4. CYBERKAWACH-DOS-UNBOUNDED-SCAN-REGISTRY ───
def test_remediation_bounded_scan_store_eviction():
    """BoundedScanStore must evict oldest items when capacity is reached."""
    store = BoundedScanStore(capacity=5)

    for i in range(10):
        store[f"scan_{i}"] = {"scan_id": f"scan_{i}", "file": f"file_{i}.bin"}

    # Store must not grow past capacity
    assert len(store) == 5
    # Oldest entries (scan_0 through scan_4) evicted
    for i in range(5):
        assert f"scan_{i}" not in store
    # Newest entries (scan_5 through scan_9) present
    for i in range(5, 10):
        assert f"scan_{i}" in store


# ─── 5. CYBERKAWACH-SSRF-TOCTOU-REBINDING ───
def test_remediation_ssrf_anti_rebinding():
    """safe_fetch_url blocks requests when host validation returns blocked range."""
    async def _run():
        with pytest.raises(ValueError) as exc:
            with patch("backend.utils.ssrf.validate_url_for_ssrf", return_value=(False, "SSRF blocked")):
                await safe_fetch_url("http://rebind.attacker.com")
        assert "SSRF blocked" in str(exc.value)

    asyncio.run(_run())


# ─── 6. CYBERKAWACH-SEC-PLAINTEXT-SECRETS & Offline SQLite Fallback ───
def test_remediation_neo4j_disabled_fallback_to_sqlite():
    """When Neo4j is disabled, repository reports unavailable and local SQLite operates cleanly."""
    settings = get_settings()
    assert settings.neo4j_enabled is False
    assert neo4j_repo.is_available() is False

    # Offline registration and session management in local SQLite
    test_email = "citizen_offline_test@example.com"
    pwd = "SecurePassword123!"

    # Clean up prior test runs if any
    conn = neo4j_repo._get_sqlite_conn()
    with conn:
        conn.execute("DELETE FROM citizen_users WHERE email_normalized = ?", (test_email.lower(),))

    user = neo4j_repo.create_user(
        email=test_email,
        password=pwd,
        display_name="Offline Citizen",
        preferred_language="hi",
    )
    assert user is not None
    assert user["email"] == test_email

    # Authenticate via SQLite
    auth = neo4j_repo.authenticate_user(test_email, pwd)
    assert auth is not None
    assert auth["user_id"] == user["user_id"]

    # Create and validate session
    session_token, sess = neo4j_repo.create_session(user["user_id"])
    assert session_token is not None

    # Validate session
    validated = neo4j_repo.validate_session(session_token)
    assert validated is not None
    assert validated["user"]["user_id"] == user["user_id"]
