"""
Tests for OSINT evidence translator.
Verifies conversion of raw OSINT findings into valid EvidenceItem Pydantic objects.
"""

from backend.models.evidence import (
    EvidenceItem,
    EvidenceSeverity,
    EvidenceStatus,
    EvidenceType,
    RiskDirection,
)
from backend.services.osint_evidence_translator import translate_osint_evidence


def test_new_domain_produces_high_severity_evidence_item():
    result = {
        "status": "complete",
        "domain": "fake-scam.xyz",
        "domain_age": {"days_old": 4, "registrar": "BadRegistrar Ltd"},
        "cert_transparency": {"shared_cert_domains": []},
    }
    items = translate_osint_evidence(result)
    assert len(items) == 1
    assert isinstance(items[0], EvidenceItem)
    assert items[0].type == EvidenceType.DOMAIN_AGE
    assert items[0].severity == EvidenceSeverity.HIGH
    assert items[0].risk_direction == RiskDirection.INCREASES_RISK
    assert "4 day" in items[0].description
    assert items[0].status == EvidenceStatus.CONFIRMED


def test_old_domain_produces_informational_item():
    result = {
        "status": "complete",
        "domain": "established.com",
        "domain_age": {"days_old": 900, "registrar": "Reliable Registrar"},
        "cert_transparency": {"shared_cert_domains": []},
    }
    items = translate_osint_evidence(result)
    assert len(items) == 1
    assert items[0].severity == EvidenceSeverity.INFORMATIONAL
    assert items[0].risk_direction == RiskDirection.NEUTRAL
    assert items[0].status == EvidenceStatus.OBSERVED


def test_shared_cert_domains_flagged_as_campaign_link():
    result = {
        "status": "complete",
        "domain": "targeted-portal.top",
        "domain_age": {"days_old": 900, "registrar": "Old Registrar"},
        "cert_transparency": {"shared_cert_domains": ["sbi-kyc-update.tk", "sbi-verify.xyz"]},
    }
    items = translate_osint_evidence(result)
    assert len(items) == 2
    types = [i.type for i in items]
    assert EvidenceType.CAMPAIGN_LINK in types

    campaign_item = next(i for i in items if i.type == EvidenceType.CAMPAIGN_LINK)
    assert campaign_item.severity == EvidenceSeverity.HIGH
    assert campaign_item.risk_direction == RiskDirection.INCREASES_RISK
    assert "sbi-kyc-update.tk" in campaign_item.description


def test_unavailable_status_returns_no_items():
    result = {"status": "unavailable", "domain_age": None, "cert_transparency": None}
    assert translate_osint_evidence(result) == []
