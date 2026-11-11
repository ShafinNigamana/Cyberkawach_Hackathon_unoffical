"""
Unit and integration tests for ACID SQLite WAL Incident Persistence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import pytest

from backend.models.evidence import IncidentEvidence, RiskAssessment, RiskLevel
from backend.services.incident_store import BoundedIncidentStore


def _create_mock_incident(incident_id: str, message: str = "Test phishing alert", user_id: str = "user-123") -> IncidentEvidence:
    return IncidentEvidence(
        incident_id=incident_id,
        created_at=datetime.now(timezone.utc),
        user_id=user_id,
        message=message,
        fraud_category="phishing",
        risk=RiskAssessment(
            score=0.92,
            level=RiskLevel.HIGH,
            factors=["suspicious_url", "apk_lure"],
            evidence_sufficiency="HIGH",
        ),
        urls=[],
        brands=[],
        iocs=["198.51.100.22", "scam@paytm"],
        evidence=[],
    )


def test_write_and_read_persistence():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "test_incidents.db"
        store1 = BoundedIncidentStore(max_capacity=50, db_path=db_file)

        inc_id = "INC-2026-F1A2B3C4"
        evidence = _create_mock_incident(inc_id, message="PM Kisan Yojana APK Scam")
        store1.set(inc_id, evidence)

        # In-memory check
        assert inc_id in store1
        retrieved1 = store1.get(inc_id)
        assert retrieved1 is not None
        assert retrieved1.message == "PM Kisan Yojana APK Scam"
        assert retrieved1.user_id == "user-123"

        # Simulate full server restart by creating a new store instance pointing to same DB
        store2 = BoundedIncidentStore(max_capacity=50, db_path=db_file)

        # Verify rehydration from SQLite WAL
        assert inc_id in store2
        retrieved2 = store2.get(inc_id)
        assert retrieved2 is not None
        assert retrieved2.incident_id == inc_id
        assert retrieved2.message == "PM Kisan Yojana APK Scam"
        assert retrieved2.risk.score == 0.92


def test_cache_miss_falls_back_to_sqlite():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "test_incidents.db"
        # Small capacity to trigger memory eviction
        store = BoundedIncidentStore(max_capacity=2, db_path=db_file)

        inc1 = _create_mock_incident("INC-2026-00000001", "Alert 1")
        inc2 = _create_mock_incident("INC-2026-00000002", "Alert 2")
        inc3 = _create_mock_incident("INC-2026-00000003", "Alert 3")

        store.set("INC-2026-00000001", inc1)
        store.set("INC-2026-00000002", inc2)
        store.set("INC-2026-00000003", inc3)  # inc1 gets evicted from in-memory LRU

        # Verify inc1 was evicted from in-memory cache
        assert "INC-2026-00000001" not in store._store

        # Verify inc1 is still retrieved successfully via SQLite fallback
        retrieved_inc1 = store.get("INC-2026-00000001")
        assert retrieved_inc1 is not None
        assert retrieved_inc1.incident_id == "INC-2026-00000001"
        assert retrieved_inc1.message == "Alert 1"
