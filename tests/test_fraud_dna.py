"""
Unit tests for Fraud DNA & Campaign Syndicate Correlation.
"""

import pytest
from backend.models.evidence import (
    BrandMatch,
    IncidentEvidence,
    URLSignal,
)
from backend.modules.fraud_dna import compute_fraud_dna, get_campaign_tracker


@pytest.fixture(autouse=True)
def clean_tracker():
    tracker = get_campaign_tracker()
    tracker.clear()
    yield
    tracker.clear()


def test_compute_fraud_dna_generates_fingerprint():
    evidence = IncidentEvidence(
        incident_id="INC-2026-AAA11111",
        message="Dear SBI user your YONO account is blocked click http://sbi-kyc.xyz",
        fraud_category="banking",
        brands=[BrandMatch(brand_name="SBI", confidence=0.9)],
        urls=[URLSignal(url="http://sbi-kyc.xyz", domain="sbi-kyc.xyz")],
    )

    dna = compute_fraud_dna(evidence)

    assert dna.available is True
    assert dna.fingerprint is not None
    assert len(dna.fingerprint) == 16
    assert dna.campaign_id is not None
    assert dna.campaign_id.startswith("CAMP-")


def test_compute_fraud_dna_correlates_similar_campaigns():
    tracker = get_campaign_tracker()
    tracker.clear()

    # First incident
    inc1 = IncidentEvidence(
        incident_id="INC-2026-BBB22222",
        message="Dear SBI customer update KYC immediately at http://sbi-portal.xyz/login",
        fraud_category="banking",
        brands=[BrandMatch(brand_name="SBI", confidence=0.9)],
        urls=[URLSignal(url="http://sbi-portal.xyz/login", domain="sbi-portal.xyz")],
    )
    dna1 = compute_fraud_dna(inc1)

    # Second incident from same campaign (same brand + banking category + related domain)
    inc2 = IncidentEvidence(
        incident_id="INC-2026-CCC33333",
        message="SBI alert: Account blocked update KYC at http://sbi-portal-verify.xyz/login",
        fraud_category="banking",
        brands=[BrandMatch(brand_name="SBI", confidence=0.9)],
        urls=[URLSignal(url="http://sbi-portal-verify.xyz/login", domain="sbi-portal-verify.xyz")],
    )
    dna2 = compute_fraud_dna(inc2)

    # Should be grouped into the same campaign
    assert dna2.campaign_id == dna1.campaign_id
    assert "INC-2026-BBB22222" in dna2.related_incidents


def test_compute_fraud_dna_distinct_for_different_threats():
    tracker = get_campaign_tracker()
    tracker.clear()

    # Incident 1: Banking
    inc1 = IncidentEvidence(
        incident_id="INC-2026-DDD44444",
        message="Dear SBI customer update KYC at http://sbi-kyc.xyz",
        fraud_category="banking",
        brands=[BrandMatch(brand_name="SBI", confidence=0.9)],
        urls=[URLSignal(url="http://sbi-kyc.xyz", domain="sbi-kyc.xyz")],
    )
    dna1 = compute_fraud_dna(inc1)

    # Incident 2: Lottery / Prize
    inc2 = IncidentEvidence(
        incident_id="INC-2026-EEE55555",
        message="Congratulations you won Google Lottery Rs 25 lakh claim now",
        fraud_category="lottery_prize",
        brands=[],
        urls=[],
    )
    dna2 = compute_fraud_dna(inc2)

    # Should have distinct campaign IDs
    assert dna2.campaign_id != dna1.campaign_id
    assert "INC-2026-DDD44444" not in dna2.related_incidents
