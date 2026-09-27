"""
Unit and integration tests for Scikit-Learn TF-IDF ML Classifier (PRD Section 8 & Section 33).
Verifies that BOTH Laya AND Scikit-Learn ML Classifier execute concurrently without conflict.
"""

import asyncio
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.evidence import IncidentEvidence, InputType
from backend.modules.laya import run_laya_triage
from backend.modules.ml_classifier import run_ml_classification

client = TestClient(app)


def test_ml_classifier_phishing_detection():
    """Verify Scikit-Learn ML classifier detects phishing with calibrated confidence and top features."""
    evidence = IncidentEvidence(
        message="Dear Customer, your SBI account has been BLOCKED due to incomplete KYC verification. Click http://sbi-kyc.top to update PAN",
        input_type=InputType.TEXT,
    )
    result = asyncio.run(run_ml_classification(evidence))

    assert result.ml_classifier.available is True
    assert result.ml_classifier.classification in ("phishing", "suspicious")
    assert result.ml_classifier.confidence >= 0.60
    assert result.ml_classifier.model_version == "v1.2-sklearn-tfidf"
    assert isinstance(result.ml_classifier.top_features, list)
    assert len(result.ml_classifier.top_features) > 0
    assert result.ml_classifier.latency_ms is not None and result.ml_classifier.latency_ms < 50.0


def test_ml_classifier_benign_detection():
    """Verify Scikit-Learn ML classifier correctly identifies benign messages as legitimate."""
    evidence = IncidentEvidence(
        message="Your account XX5678 was credited with INR 65,000.00 on 28-Aug-2026 towards monthly salary. Available balance INR 89,200.00",
        input_type=InputType.TEXT,
    )
    result = asyncio.run(run_ml_classification(evidence))

    assert result.ml_classifier.available is True
    assert result.ml_classifier.classification == "legitimate"
    assert result.ml_classifier.confidence >= 0.60


def test_both_models_coexist_in_api():
    """Verify /api/analyze executes BOTH Laya AND Scikit-Learn ML Classifier simultaneously without conflict."""
    response = client.post(
        "/api/analyze",
        json={
            "message": "URGENT: Your electricity connection will be disconnected tonight at 9:30 PM due to unpaid bill. Pay immediately at http://vidhyut-bill.apk",
            "input_type": "text",
        },
    )
    assert response.status_code == 200
    data = response.json()

    # 1. Verify Laya fast typed-decision engine is intact
    assert "laya" in data and data["laya"] is not None
    assert data["laya"]["available"] is True
    assert "fraud" in data["laya"]
    assert "fraud_category" in data["laya"]
    assert "credential_request" in data["laya"]

    # 2. Verify Scikit-Learn ML classifier is intact
    assert "ml_classifier" in data and data["ml_classifier"] is not None
    assert data["ml_classifier"]["available"] is True
    assert data["ml_classifier"]["model_version"] == "v1.2-sklearn-tfidf"
    assert data["ml_classifier"]["classification"] in ("phishing", "suspicious")
    assert isinstance(data["ml_classifier"]["top_features"], list)

    # 3. Verify top-level PRD Section 33 schema
    assert "classification" in data
    assert "model_confidence" in data
    assert data["model_confidence"] is not None
