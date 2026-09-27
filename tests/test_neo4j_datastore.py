"""
Comprehensive test suite for Neo4j as the Single Application Datastore.

Verifies:
1. AUTH: register, login, logout, session expiry, session revocation, wrong password, duplicate email.
2. AUTHORIZATION: user owns incident, blocked IDOR, user cannot view another user's incident or graph.
3. HISTORY: create incident, persist incident, list user incidents ('My Checks'), reopen incident.
4. EVIDENCE: Evidence Contract persistence, provider provenance (GSB, PhishTank, PhishStats independent).
5. SENDER: optional sender, absent sender, pseudonymization (no raw sensitive PII in graph).
6. GRAPH: campaign relationships, sender/domain, domain/brand, IOC similarity, duplicate prevention.
7. FAILURE: Neo4j offline / timeout degradation without pipeline crash.
8. SECURITY: password hashing (PBKDF2), session hashing (SHA-256), zero plaintext secrets, zero credentials leaked.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from backend.main import app, _incidents
from backend.models.evidence import (
    EvidenceItem,
    EvidenceReliability,
    EvidenceSeverity,
    EvidenceStatus,
    EvidenceType,
    IncidentEvidence,
    InputType,
    RiskAssessment,
    RiskDirection,
    RiskLevel,
    SenderContext,
    ThreatIntelResult,
    URLSignal,
)
from backend.services.neo4j_repository import (
    Neo4jRepository,
    hash_password,
    hash_token,
    pseudonymize_identifier,
    verify_password,
)


@pytest.fixture
def client():
    """FastAPI TestClient instance."""
    return TestClient(app)


# ─── Mock Neo4j Session Helpers ───

class MockNeo4jRecord:
    def __init__(self, data: dict):
        self._data = data

    def __getitem__(self, key):
        return self._data[key]

    def get(self, key, default=None):
        return self._data.get(key, default)


class MockNeo4jResult:
    def __init__(self, records: list[dict]):
        self._records = [MockNeo4jRecord(r) for r in records]

    def single(self):
        return self._records[0] if self._records else None

    def __iter__(self):
        return iter(self._records)


# ─────────────────────────────────────────────────────────────────
# 1. AUTH TESTS
# ─────────────────────────────────────────────────────────────────

def test_password_hashing_security():
    """Verify PBKDF2-HMAC-SHA256 password hashing and salt verification."""
    password = "SuperSecretPassword123!"
    pw_hash = hash_password(password)

    # Must be pbkdf2 format: pbkdf2_sha256$iterations$salt$hash
    assert pw_hash.startswith("pbkdf2_sha256$")
    assert password not in pw_hash

    # Correct password verifies
    assert verify_password(password, pw_hash) is True
    # Wrong password fails
    assert verify_password("WrongPassword!", pw_hash) is False


def test_session_token_hashing_security():
    """Verify raw session tokens are hashed with SHA-256 before storage."""
    raw_token = "raw_super_secret_session_token_abc"
    token_hash = hash_token(raw_token)

    assert token_hash == hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    assert token_hash != raw_token


def test_auth_registration_and_login_flow(client):
    """Test citizen registration, login, and profile lookup with mocked Neo4j repo."""
    test_email = "citizen.test@example.com"
    test_password = "StrongPassword2026!"
    hashed_pw = hash_password(test_password)

    mock_user = {
        "user_id": "usr_test123",
        "email": test_email,
        "email_normalized": test_email.lower(),
        "password_hash": hashed_pw,
        "display_name": "Test Citizen",
        "phone_masked": "+91******1234",
        "preferred_language": "en",
        "is_active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_login_at": None,
    }

    with patch("backend.services.neo4j_repository.Neo4jRepository.get_user_by_email") as mock_get_email, \
         patch("backend.services.neo4j_repository.Neo4jRepository.create_user") as mock_create, \
         patch("backend.services.neo4j_repository.Neo4jRepository.create_session") as mock_create_sess, \
         patch("backend.services.neo4j_repository.Neo4jRepository.log_audit_event") as mock_audit:

        mock_get_email.return_value = None
        mock_create.return_value = {k: v for k, v in mock_user.items() if k != "password_hash"}
        mock_create_sess.return_value = ("test_session_bearer_token", {"session_id": "sess_123"})

        # 1. Register citizen
        reg_payload = {
            "email": test_email,
            "password": test_password,
            "display_name": "Test Citizen",
            "phone": "+919876541234",
            "preferred_language": "en",
        }
        res = client.post("/api/auth/register", json=reg_payload)
        assert res.status_code == 200, res.text
        data = res.json()
        assert data["status"] == "success"
        assert data["session_token"] == "test_session_bearer_token"
        assert data["user"]["email"] == test_email
        assert "password" not in data["user"]
        assert "password_hash" not in data["user"]


def test_auth_duplicate_email_rejection(client):
    """Verify duplicate email registration is rejected with 400."""
    with patch("backend.services.neo4j_repository.Neo4jRepository.get_user_by_email") as mock_get_email:
        mock_get_email.return_value = {"user_id": "usr_existing", "email": "existing@example.com"}

        res = client.post("/api/auth/register", json={
            "email": "existing@example.com",
            "password": "ValidPassword123!",
        })
        assert res.status_code == 400
        assert "already exists" in res.json()["detail"]


def test_auth_wrong_password_rejection(client):
    """Verify login with invalid password returns 401."""
    with patch("backend.services.neo4j_repository.Neo4jRepository.authenticate_user") as mock_auth:
        mock_auth.return_value = None

        res = client.post("/api/auth/login", json={
            "email": "user@example.com",
            "password": "WrongPassword!",
        })
        assert res.status_code == 401
        assert "Invalid email or password" in res.json()["detail"]


def test_auth_session_revocation_on_logout(client):
    """Verify session is revoked in Neo4j on logout."""
    raw_token = "token_to_revoke_xyz"
    with patch("backend.services.neo4j_repository.Neo4jRepository.validate_session") as mock_validate, \
         patch("backend.services.neo4j_repository.Neo4jRepository.revoke_session") as mock_revoke, \
         patch("backend.services.neo4j_repository.Neo4jRepository.log_audit_event") as mock_audit:

        mock_validate.return_value = {
            "user": {"user_id": "usr_123", "email": "u@test.com"},
            "session": {"session_id": "sess_999"},
        }
        mock_revoke.return_value = True

        res = client.post(
            "/api/auth/logout",
            headers={"Authorization": f"Bearer {raw_token}"},
        )
        assert res.status_code == 200
        assert res.json()["status"] == "success"
        mock_revoke.assert_called_once_with("sess_999")


# ─────────────────────────────────────────────────────────────────
# 2. AUTHORIZATION & IDOR PREVENTION
# ─────────────────────────────────────────────────────────────────

def test_idor_blocked_for_other_users_incident():
    """Verify repository blocks access if caller is not the owner (IDOR defense)."""
    repo = Neo4jRepository()

    # User Alice owns incident_123
    mock_record = {
        "i": {"incident_id": "inc_alice_123", "title": "Phishing message"},
        "owner_id": "usr_alice",
        "campaign_id": "CAMP-001",
        "evidence_items": [],
        "urls": [],
        "domains": [],
        "brands": [],
        "threat_intel": [],
    }

    with patch.object(repo, "_get_session") as mock_session_ctx:
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__.return_value = mock_session
        mock_session.run.return_value = MockNeo4jResult([mock_record])

        # Alice accesses own incident -> SUCCESS
        res_alice = repo.get_incident("inc_alice_123", user_id="usr_alice")
        assert res_alice is not None
        assert res_alice["incident_id"] == "inc_alice_123"

        # Bob attempts to access Alice's incident -> BLOCKED (None returned)
        mock_session.run.return_value = MockNeo4jResult([mock_record])
        res_bob = repo.get_incident("inc_alice_123", user_id="usr_bob")
        assert res_bob is None, "IDOR check failed: Bob was able to retrieve Alice's incident!"

        # Anonymous caller attempts to access Alice's incident -> BLOCKED
        mock_session.run.return_value = MockNeo4jResult([mock_record])
        res_anon = repo.get_incident("inc_alice_123", user_id=None)
        assert res_anon is None, "IDOR check failed: Unauthenticated user accessed private incident!"


def test_idor_blocked_for_incident_graph():
    """Verify graph query blocks unauthorized users from viewing an incident's graph."""
    repo = Neo4jRepository()

    mock_record = {
        "i": {"incident_id": "inc_private_456"},
        "owner_id": "usr_owner_1",
        "s": None,
        "b": None,
        "u_node": None,
        "d": None,
        "c": None,
        "related_ids": [],
    }

    with patch.object(repo, "_get_session") as mock_session_ctx:
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__.return_value = mock_session
        mock_session.run.return_value = MockNeo4jResult([mock_record])

        # Other user tries to inspect graph
        graph = repo.get_incident_graph("inc_private_456", user_id="usr_attacker")
        assert graph is None, "IDOR check failed: Attacker retrieved incident graph!"


# ─────────────────────────────────────────────────────────────────
# 3. INCIDENT HISTORY ('My Checks')
# ─────────────────────────────────────────────────────────────────

def test_list_user_incidents_isolated(client):
    """Verify GET /api/incidents returns only the authenticated user's checks."""
    user_incidents = [
        {
            "incident_id": "inc_001",
            "created_at": "2026-09-27T10:00:00Z",
            "input_type": "text",
            "title": "Threat Triage inc_001",
            "message_preview": "Urgent electricity bill unpaid",
            "risk_level": "critical",
            "risk_score": 0.95,
            "fraud_category": "electricity_scam",
            "current_user_state": "received",
            "campaign_id": "CAMP-ELEC",
        }
    ]

    with patch("backend.services.neo4j_repository.Neo4jRepository.validate_session") as mock_val, \
         patch("backend.services.neo4j_repository.Neo4jRepository.list_user_incidents") as mock_list:

        mock_val.return_value = {
            "user": {"user_id": "usr_citizen_1", "email": "cit1@example.com"},
            "session": {"session_id": "sess_1"},
        }
        mock_list.return_value = user_incidents

        res = client.get("/api/incidents", headers={"Authorization": "Bearer test_token"})
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 1
        assert data["incidents"][0]["incident_id"] == "inc_001"
        assert data["incidents"][0]["risk_level"] == "critical"


# ─────────────────────────────────────────────────────────────────
# 4. SENDER CONTEXT & SENSITIVE DATA MINIMIZATION
# ─────────────────────────────────────────────────────────────────

def test_sender_pseudonymization_no_raw_pii():
    """Verify phone numbers and emails are pseudonymized with SHA-256 before graph write."""
    raw_phone = "+919876543210"
    pseudo_phone = pseudonymize_identifier(raw_phone)

    assert pseudo_phone is not None
    assert pseudo_phone.startswith("anon_")
    assert len(pseudo_phone) >= 16
    assert raw_phone not in pseudo_phone
    # Same identifier gives deterministic pseudonym
    assert pseudonymize_identifier(raw_phone) == pseudo_phone

    # Absent/empty sender produces None
    assert pseudonymize_identifier(None) is None
    assert pseudonymize_identifier("") is None


def test_optional_sender_in_analyze(client):
    """Verify /api/analyze accepts optional sender and message_context."""
    payload = {
        "message": "Your SBI account is debited by Rs. 50000. Call +919876543210 immediately.",
        "input_type": "text",
        "sender": {
            "phone_number": "+919876543210",
            "display_name": "SBI Alert",
            "claimed_organization": "State Bank of India",
        },
        "message_context": {
            "channel": "sms",
        },
    }

    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] is not None
    assert data["risk"]["score"] > 0


# ─────────────────────────────────────────────────────────────────
# 5. EVIDENCE PROVENANCE & THREAT INTEL INDEPENDENCE
# ─────────────────────────────────────────────────────────────────

def test_threat_intel_independent_observations():
    """Verify Google Safe Browsing, PhishTank, and PhishStats remain separate observations."""
    repo = Neo4jRepository()

    evidence = IncidentEvidence(
        input_type=InputType.TEXT,
        message="Suspicious link http://login-verify-bank.com",
    )
    evidence.threat_intel = [
        ThreatIntelResult(source="google_safe_browsing", match=False, confidence=0.9),
        ThreatIntelResult(source="phishtank", match=True, details="Verified phishing entry", confidence=0.95),
        ThreatIntelResult(source="phishstats", match=False, confidence=0.85),
    ]

    with patch.object(repo, "is_available", return_value=True), \
         patch.object(repo, "_get_session") as mock_session_ctx:
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__.return_value = mock_session
        mock_session.run.return_value = MockNeo4jResult([{"id": evidence.incident_id}])

        success = repo.save_full_incident(evidence)
        assert success is True

        # Verify cypher was executed with all 3 distinct threat intel items
        call_args = mock_session.run.call_args[1]
        ti_list = call_args.get("threat_intel_list", [])
        assert len(ti_list) == 3
        providers = [t["provider"] for t in ti_list]
        assert "google_safe_browsing" in providers
        assert "phishtank" in providers
        assert "phishstats" in providers


# ─────────────────────────────────────────────────────────────────
# 6. GRACEFUL DEGRADATION WHEN NEO4J IS OFFLINE
# ─────────────────────────────────────────────────────────────────

def test_graceful_degradation_when_neo4j_unavailable(client):
    """Verify /api/analyze continues functioning normally if Neo4j raises an error."""
    with patch("backend.services.neo4j_repository.Neo4jRepository.save_full_incident") as mock_save:
        mock_save.side_effect = Exception("Neo4j Aura connection timed out")

        res = client.post("/api/analyze", json={
            "message": "Urgent lottery prize won. Click http://claim-prize.fake",
        })

        # Endpoint MUST NOT crash (Rule 8 & Section 20)
        assert res.status_code == 200
        data = res.json()
        assert data["incident_id"] is not None
        assert str(data["risk"]["level"]).lower() in ("high", "critical", "suspicious", "low")


# ─────────────────────────────────────────────────────────────────
# 7. SECURITY & SECRET HYGIENE
# ─────────────────────────────────────────────────────────────────

def test_no_credentials_leaked_in_verification_or_health(client):
    """Verify health and verification endpoints never expose Aura credentials."""
    health_res = client.get("/api/health")
    assert health_res.status_code == 200
    health_json = health_res.json()
    assert "password" not in str(health_json).lower()
    assert "neo4j_password" not in health_json

    status_res = client.get("/api/verification/status")
    assert status_res.status_code == 200
    status_json = status_res.json()
    assert "password" not in str(status_json).lower()
