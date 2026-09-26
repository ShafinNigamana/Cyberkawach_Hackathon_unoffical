"""
Unit tests for Law Enforcement / 1930 Forensic Dossier Export endpoint.
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import _incidents, app
from backend.models.evidence import (
    EvidenceItem,
    EvidenceType,
    IncidentEvidence,
    RiskAssessment,
    RiskLevel,
    URLSignal,
)
from backend.utils.rate_limiter import get_rate_limiter


@pytest.fixture(autouse=True)
def reset_state():
    get_rate_limiter().reset()
    _incidents.clear()
    yield
    get_rate_limiter().reset()
    _incidents.clear()


@pytest.fixture
def client():
    return TestClient(app)


def test_export_incident_json(client):
    incident_id = "INC-2026-F1A2B3C4"
    inc = IncidentEvidence(
        incident_id=incident_id,
        message="Electricity disconnected tonight at 9:30 PM call 9876543210 http://bijli.xyz",
        fraud_category="electricity",
        urls=[URLSignal(url="http://bijli.xyz", domain="bijli.xyz")],
        evidence=[
            EvidenceItem(
                type=EvidenceType.RULE_MATCH,
                source="rules",
                description="Artificial urgency: power cut tonight",
                confidence=0.85,
            )
        ],
        risk=RiskAssessment(level=RiskLevel.HIGH, score=0.85),
    )
    _incidents[incident_id] = inc

    resp = client.get(f"/api/incidents/{incident_id}/export?format=json")
    assert resp.status_code == 200
    data = resp.json()

    assert data["incident_id"] == incident_id
    assert data["risk_level"].lower() == "high"
    assert data["fraud_category"] == "electricity"
    assert len(data["evidence_dossier"]) == 1
    assert "1930" in data["helpline_1930_advisory"]
    assert "sha256_message_hash" in data


def test_export_incident_html(client):
    incident_id = "INC-2026-D5E6F7A8"
    inc = IncidentEvidence(
        incident_id=incident_id,
        message="Urgent SBI KYC suspension http://sbi-fake.top",
        fraud_category="banking",
        urls=[URLSignal(url="http://sbi-fake.top", domain="sbi-fake.top")],
        risk=RiskAssessment(level=RiskLevel.CRITICAL, score=0.92),
    )
    _incidents[incident_id] = inc

    resp = client.get(f"/api/incidents/{incident_id}/export?format=html")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    text = resp.text
    assert "CYBER FRAUD FORENSIC INCIDENT DOSSIER" in text
    assert incident_id in text
    assert "1930" in text
    assert "cybercrime.gov.in" in text


def test_export_incident_invalid_id_format(client):
    resp = client.get("/api/incidents/INVALID-ID-123/export")
    assert resp.status_code == 400
    assert "Invalid incident ID format" in resp.json()["detail"]


def test_export_incident_not_found(client):
    resp = client.get("/api/incidents/INC-2026-00000000/export")
    assert resp.status_code == 404
    assert "Incident not found" in resp.json()["detail"]
