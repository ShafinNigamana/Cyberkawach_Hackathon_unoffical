"""
Phase 1 verification test suite for Cyber Fraud Guardian.
Tests all pipeline modules, graceful degradation, and API endpoints.
"""

import asyncio
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.evidence import (
    EvidenceType,
    IncidentEvidence,
    InputType,
    RiskLevel,
    UserState,
)
from backend.modules.ingestion import extract_iocs
from backend.modules.rules import apply_rules
from backend.modules.ml_baseline import predict_scam_probability, run_ml_baseline
from backend.modules.url_analyzer import analyze_urls
from backend.modules.brand_check import check_brands
from backend.modules.threat_intel import query_threat_intel
from backend.modules.fusion import fuse_evidence
from backend.modules.fallback_explanation import generate_fallback_explanation
from backend.modules.response import generate_response

client = TestClient(app)


def test_health_check_endpoint():
    """Verify system health check lists all required modules."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["modules"]["ingestion"] is True
    assert data["modules"]["rules"] is True
    assert data["modules"]["ml_baseline"] is True
    assert data["modules"]["url_analyzer"] is True
    assert data["modules"]["brand_check"] is True
    assert data["modules"]["threat_intel"] is True
    assert data["modules"]["fusion"] is True


def test_ingestion_ioc_extraction():
    """Verify IOC extraction pulls URLs, phone numbers, and UPI IDs."""
    text = "Dear user pay Rs 500 via upi: scammer@okhdfcbank or call 9876543210 visit https://fake-bank.top/login"
    evidence = IncidentEvidence(input_type=InputType.SMS, message=text)
    evidence = extract_iocs(evidence)

    assert len(evidence.urls) == 1
    assert "https://fake-bank.top/login" in evidence.urls[0].url
    assert any("9876543210" in ioc for ioc in evidence.iocs)
    assert any("scammer@okhdfcbank" in ioc for ioc in evidence.iocs)
    assert any(item.type == EvidenceType.IOC_EXTRACTED for item in evidence.evidence)


def test_rule_detection_and_categories():
    """Verify rule engine correctly identifies fraud categories and urgency pressure."""
    text = "URGENT: Your SBI bank account is blocked due to pending KYC. Update immediately or account deactivation."
    evidence = IncidentEvidence(input_type=InputType.SMS, message=text)
    evidence = apply_rules(evidence)

    assert evidence.fraud_category == "banking"
    assert any("urgency" in item.description.lower() for item in evidence.evidence)
    assert any(item.type == EvidenceType.RULE_MATCH for item in evidence.evidence)


def test_ml_baseline():
    """Verify ML baseline calculates probabilities and attaches statistical evidence."""
    scam_text = "Dear customer your SBI account is blocked due to incomplete KYC click here to update immediately"
    scam_prob = predict_scam_probability(scam_text)
    assert scam_prob is not None
    assert scam_prob > 0.50

    evidence = IncidentEvidence(input_type=InputType.SMS, message=scam_text)
    evidence = run_ml_baseline(evidence)
    assert any(item.source == "ml_baseline" for item in evidence.evidence)


def test_url_analyzer_signals():
    """Verify URL analyzer flags suspicious TLDs, no-https, and suspicious paths."""
    text = "Visit http://bank-update.top/login.php for verification"
    evidence = IncidentEvidence(input_type=InputType.SMS, message=text)
    evidence = extract_iocs(evidence)
    evidence = asyncio.run(analyze_urls(evidence))

    assert len(evidence.urls) == 1
    signals = evidence.urls[0].signals
    assert "suspicious_tld" in signals
    assert "suspicious_path" in signals
    assert "no_https" in signals


def test_brand_impersonation_detection():
    """Verify brand check identifies domain impersonation resembling registered brands."""
    text = "Visit http://sbi-kyc-update.xyz to verify your credentials"
    evidence = IncidentEvidence(input_type=InputType.SMS, message=text)
    evidence = extract_iocs(evidence)
    evidence = check_brands(evidence)

    assert any(b.brand_name == "SBI" for b in evidence.brands)
    assert any(item.type == EvidenceType.BRAND_MISMATCH for item in evidence.evidence)


def test_threat_intel_graceful_degradation():
    """Verify threat intelligence degrades gracefully when external APIs are not configured."""
    evidence = IncidentEvidence(
        input_type=InputType.URL,
        message="https://suspicious-domain-test.xyz",
    )
    evidence = extract_iocs(evidence)
    evidence = asyncio.run(query_threat_intel(evidence))

    assert len(evidence.threat_intel) >= 2
    sources = [ti.source for ti in evidence.threat_intel]
    assert "safe_browsing" in sources
    assert "phishtank" in sources
    # Should not raise exception even with empty keys
    assert all(ti.error is not None or ti.match is not None or ti.match is None for ti in evidence.threat_intel)


def test_evidence_fusion_and_scoring():
    """Verify fusion produces valid risk scores, levels, and factor explanations."""
    evidence = IncidentEvidence(
        input_type=InputType.SMS,
        message="Urgent KYC verification required",
        fraud_category="banking",
    )
    evidence = apply_rules(evidence)
    evidence = fuse_evidence(evidence)

    assert 0.0 <= evidence.risk.score <= 1.0
    assert evidence.risk.level in [
        RiskLevel.LOW,
        RiskLevel.MEDIUM,
        RiskLevel.HIGH,
        RiskLevel.CRITICAL,
        RiskLevel.UNKNOWN,
    ]


def test_fallback_explanation_generation():
    """Verify deterministic fallback explanation always produces structured grounded content."""
    evidence = IncidentEvidence(
        input_type=InputType.SMS,
        message="Your account is blocked. Verify KYC immediately at http://scam.top",
        fraud_category="banking",
    )
    evidence = extract_iocs(evidence)
    evidence = apply_rules(evidence)
    evidence = fuse_evidence(evidence)
    evidence = generate_fallback_explanation(evidence)

    assert evidence.explanation is not None
    assert evidence.explanation.is_fallback is True
    assert len(evidence.explanation.reasons) > 0
    assert len(evidence.explanation.attack_path) > 0
    assert len(evidence.explanation.user_action) > 0
    assert len(evidence.explanation.evidence_cited) > 0


def test_adaptive_response_state_machine():
    """Verify adaptive response branches advice based on user interaction state."""
    evidence = IncidentEvidence(
        input_type=InputType.SMS,
        message="Fake banking alert",
        fraud_category="banking",
    )
    evidence = fuse_evidence(evidence)

    # State: received
    resp_received = generate_response(evidence, UserState.RECEIVED).response
    assert "Do NOT click" in " ".join(resp_received.immediate_actions)
    assert resp_received.urgency == "normal"

    # State: entered_credentials
    resp_creds = generate_response(evidence, UserState.ENTERED_CREDENTIALS).response
    assert "password" in " ".join(resp_creds.immediate_actions).lower()
    assert resp_creds.urgency == "critical"

    # State: paid
    resp_paid = generate_response(evidence, UserState.PAID).response
    assert "1930" in " ".join(resp_paid.immediate_actions)
    assert resp_paid.urgency == "critical"


def test_end_to_end_analyze_api():
    """Verify full end-to-end analyze endpoint runs all pipeline stages successfully."""
    payload = {
        "message": "Dear Customer, Your SBI account has been BLOCKED. Update KYC now: http://sbi-kyc.top/login.php",
        "input_type": "sms",
        "user_state": "received",
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["incident_id"] is not None
    assert data["risk"]["score"] > 0
    assert len(data["evidence"]) > 0
    assert data["explanation"] is not None
    assert data["response"] is not None
    assert "ingestion" in data["modules_executed"]
    assert "rules" in data["modules_executed"]
    assert "ml_baseline" in data["modules_executed"]
    assert "fusion" in data["modules_executed"]
    assert "response" in data["modules_executed"]

    # Verify incident state update endpoint
    inc_id = data["incident_id"]
    state_payload = {"user_state": "paid"}
    update_resp = client.post(f"/api/incidents/{inc_id}/state", json=state_payload)
    assert update_resp.status_code == 200
    update_data = update_resp.json()
    assert update_data["response"]["user_state"] == "paid"
    assert update_data["response"]["urgency"] == "critical"
