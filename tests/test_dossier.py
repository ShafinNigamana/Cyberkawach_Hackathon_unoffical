"""
Unit tests for Section 65B Certified Cyber Crime FIR Evidentiary Dossier.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from backend.main import app
from backend.models.evidence import IncidentEvidence, RiskLevel, RiskAssessment
from backend.services.incident_store import incident_store
from backend.services.dossier_service import generate_certified_dossier


@pytest.fixture
def anyio_backend():
    return "asyncio"


def test_dossier_generation_structure():
    ev = IncidentEvidence(message="Immediate electricity disconnection alert. Pay immediately to avoid outage.")
    ev.incident_id = "INC-2026-TEST65B"
    ev.fraud_category = "electricity_bill"
    ev.risk = RiskAssessment(level=RiskLevel.HIGH, score=0.85, evidence_sufficiency="SUFFICIENT")

    dossier = generate_certified_dossier(ev)

    assert dossier["incident_id"] == "INC-2026-TEST65B"
    assert dossier["certificate_type"] == "SECTION_63_BSA_2023"
    assert dossier["legacy_certificate_type"] == "SECTION_65B_EVIDENCE_ACT"
    assert "schedule_custody_affidavit" in dossier
    assert len(dossier["sha256_hash"]) == 64
    assert dossier["classification"]["risk_level"] == "HIGH"
    assert "NATIONAL CYBER CRIME REPORTING PORTAL" in dossier["fir_ready_text"]
    assert "BHARATIYA SAKSHYA ADHINIYAM" in dossier["fir_ready_text"]
    assert "1930" in dossier["fir_ready_text"]


@pytest.mark.anyio
async def test_dossier_api_endpoint():
    ev = IncidentEvidence(message="Test SBI KYC urgent suspension SMS.")
    ev.incident_id = "INC-2026-A1B2C3D4"
    ev.fraud_category = "banking"
    ev.risk = RiskAssessment(level=RiskLevel.CRITICAL, score=0.95, evidence_sufficiency="SUFFICIENT")
    incident_store["INC-2026-A1B2C3D4"] = ev

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/incidents/INC-2026-A1B2C3D4/dossier")
        assert resp.status_code == 200
        data = resp.json()
        assert data["incident_id"] == "INC-2026-A1B2C3D4"
        assert data["certificate_type"] == "SECTION_63_BSA_2023"
        assert data["legacy_certificate_type"] == "SECTION_65B_EVIDENCE_ACT"
        assert "schedule_custody_affidavit" in data
        assert "fir_ready_text" in data
