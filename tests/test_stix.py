"""
Unit and integration tests for STIX 2.1 Threat Intelligence export.
"""

from __future__ import annotations

from datetime import datetime, timezone
import pytest
from starlette.testclient import TestClient

from backend.main import app
from backend.models.evidence import IncidentEvidence, RiskAssessment, RiskLevel, URLSignal
from backend.services.incident_store import incident_store
from backend.services.stix_service import generate_stix_bundle


@pytest.fixture
def test_client():
    return TestClient(app)


def _build_test_evidence(incident_id: str, user_id: str = None) -> IncidentEvidence:
    return IncidentEvidence(
        incident_id=incident_id,
        created_at=datetime.now(timezone.utc),
        user_id=user_id,
        message="BESCOM Notice: Power disconnection order. Download bill update: http://bescom-bill.apk",
        fraud_category="apk_malware",
        risk=RiskAssessment(
            score=0.95,
            level=RiskLevel.CRITICAL,
            factors=["unverified_apk_download", "urgent_disconnection_lure"],
            evidence_sufficiency="HIGH",
        ),
        urls=[URLSignal(url="http://bescom-bill.apk", domain="bescom-bill.apk")],
        brands=[],
        iocs=["198.51.100.89", "scammer@okhdfcbank", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        evidence=[],
    )


def test_stix_bundle_structure():
    inc_id = "INC-2026-A1B2C3D4"
    evidence = _build_test_evidence(inc_id)
    bundle = generate_stix_bundle(evidence)

    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    assert "id" in bundle
    assert bundle["id"].startswith("bundle--")
    assert len(bundle["objects"]) >= 4

    types = [obj["type"] for obj in bundle["objects"]]
    assert "identity" in types
    assert "malware" in types
    assert "indicator" in types
    assert "relationship" in types

    # Check indicator patterns
    indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
    patterns = [ind["pattern"] for ind in indicators]
    assert any("url:value" in p for p in patterns)
    assert any("ipv4-addr:value" in p for p in patterns)
    assert any("file:hashes.'SHA-256'" in p for p in patterns)

    # Check relationships
    relationships = [obj for obj in bundle["objects"] if obj["type"] == "relationship"]
    assert all(rel["relationship_type"] == "indicates" for rel in relationships)


def test_stix_api_endpoint(test_client):
    inc_id = "INC-2026-B2C3D4E5"
    evidence = _build_test_evidence(inc_id)
    incident_store[inc_id] = evidence

    response = test_client.get(f"/api/incidents/{inc_id}/stix")
    assert response.status_code == 200
    assert "application/vnd.oasis.stix+json" in response.headers.get("content-type", "")

    data = response.json()
    assert data["type"] == "bundle"
    assert data["spec_version"] == "2.1"
    assert any(obj["type"] == "identity" for obj in data["objects"])
