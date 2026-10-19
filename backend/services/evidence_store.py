"""
SQLite Evidence Store & Indicator Cache (PRD Section 5 & 6).

Persists investigations, extracted indicators, and evidence items in SQLite
with an in-memory TTL caching layer.
Tracks LIVE vs CACHED provenance for every evidence item and indicator.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Optional

from backend.models.evidence import (
    EvidenceItem,
    EvidenceReliability,
    EvidenceSeverity,
    EvidenceStatus,
    EvidenceType,
    IncidentEvidence,
    RiskDirection,
    RiskLevel,
    UserCategory,
)
from backend.config import get_settings
from backend.utils.security_logging import safe_error_message

logger = logging.getLogger(__name__)
settings = get_settings()

# Database location
_DB_DIR = Path(__file__).resolve().parent.parent / "data"
_DB_PATH = _DB_DIR / "investigations.db"

_LOCK = threading.Lock()
_MEM_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}


def _get_connection() -> sqlite3.Connection:
    """Return a thread-safe connection with ROW factory."""
    _DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize database tables if they do not exist."""
    with _LOCK:
        try:
            conn = _get_connection()
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS investigations (
                        incident_id TEXT PRIMARY KEY,
                        created_at TEXT NOT NULL,
                        input_type TEXT NOT NULL,
                        raw_input TEXT,
                        risk_score REAL DEFAULT 0.0,
                        risk_level TEXT DEFAULT 'UNKNOWN',
                        user_category TEXT DEFAULT 'UNKNOWN',
                        processing_time_ms REAL,
                        fraud_category TEXT
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS indicators (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        incident_id TEXT NOT NULL,
                        indicator_type TEXT NOT NULL,
                        indicator_value TEXT NOT NULL,
                        FOREIGN KEY (incident_id) REFERENCES investigations(incident_id)
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS evidence_records (
                        id TEXT PRIMARY KEY,
                        incident_id TEXT NOT NULL,
                        type TEXT NOT NULL,
                        source TEXT NOT NULL,
                        source_type TEXT DEFAULT 'rule',
                        evidence_tier TEXT DEFAULT 'OBSERVED',
                        indicator TEXT,
                        finding TEXT,
                        observed_value TEXT,
                        interpretation TEXT,
                        status TEXT DEFAULT 'OBSERVED',
                        reliability TEXT,
                        severity TEXT DEFAULT 'MEDIUM',
                        risk_direction TEXT DEFAULT 'INCREASES_RISK',
                        confidence REAL,
                        is_cached INTEGER DEFAULT 0,
                        raw_reference TEXT,
                        raw_data_json TEXT,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (incident_id) REFERENCES investigations(incident_id)
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS indicator_cache (
                        indicator_key TEXT NOT NULL,
                        provider TEXT NOT NULL,
                        data_json TEXT NOT NULL,
                        expires_at REAL NOT NULL,
                        PRIMARY KEY (indicator_key, provider)
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_indicators_incident ON indicators(incident_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence_records(incident_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_cache_expires ON indicator_cache(expires_at)")
            conn.close()
        except Exception as e:
            logger.error("Failed to initialize investigations database: %s", safe_error_message(e))


def save_investigation(incident: IncidentEvidence) -> bool:
    """Save an entire IncidentEvidence dossier to SQLite."""
    with _LOCK:
        try:
            conn = _get_connection()
            with conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO investigations (
                        incident_id, created_at, input_type, raw_input,
                        risk_score, risk_level, user_category, processing_time_ms, fraud_category
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident.incident_id,
                        incident.created_at.isoformat(),
                        incident.input_type.value if hasattr(incident.input_type, "value") else str(incident.input_type),
                        incident.original_input or incident.message,
                        incident.risk.score,
                        incident.risk.level.value if hasattr(incident.risk.level, "value") else str(incident.risk.level),
                        incident.risk.category.value if hasattr(incident.risk.category, "value") else str(incident.risk.category),
                        incident.processing_time_ms,
                        incident.fraud_category,
                    ),
                )

                # Save indicators
                for u in incident.urls:
                    conn.execute(
                        "INSERT INTO indicators (incident_id, indicator_type, indicator_value) VALUES (?, ?, ?)",
                        (incident.incident_id, "url", u.url),
                    )
                    if u.domain:
                        conn.execute(
                            "INSERT INTO indicators (incident_id, indicator_type, indicator_value) VALUES (?, ?, ?)",
                            (incident.incident_id, "domain", u.domain),
                        )

                for ioc in incident.iocs:
                    conn.execute(
                        "INSERT INTO indicators (incident_id, indicator_type, indicator_value) VALUES (?, ?, ?)",
                        (incident.incident_id, "ioc", ioc),
                    )

                # Save evidence items
                for item in incident.evidence:
                    raw_json = json.dumps(item.raw_data) if item.raw_data else None
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO evidence_records (
                            id, incident_id, type, source, source_type, evidence_tier,
                            indicator, finding, observed_value, interpretation, status,
                            reliability, severity, risk_direction, confidence,
                            is_cached, raw_reference, raw_data_json, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            item.id,
                            incident.incident_id,
                            item.type.value if hasattr(item.type, "value") else str(item.type),
                            item.source,
                            item.source_type,
                            item.evidence_tier,
                            item.indicator,
                            item.finding or item.description,
                            item.observed_value,
                            item.interpretation,
                            item.status.value if hasattr(item.status, "value") else str(item.status),
                            item.reliability.value if hasattr(item.reliability, "value") else str(item.reliability),
                            item.severity.value if hasattr(item.severity, "value") else str(item.severity),
                            item.risk_direction.value if hasattr(item.risk_direction, "value") else str(item.risk_direction),
                            item.confidence,
                            1 if item.is_cached else 0,
                            item.raw_reference,
                            raw_json,
                            item.timestamp.isoformat(),
                        ),
                    )
            conn.close()
            return True
        except Exception as e:
            logger.error("Failed to save investigation %s: %s", incident.incident_id, safe_error_message(e))
            return False


def get_cached_indicator(indicator: str, provider: str) -> Optional[dict[str, Any]]:
    """Retrieve cached indicator data from L1 LRU -> L2 Redis -> SQLite fallback."""
    from backend.services.cache_service import cache_manager

    clean_ind = indicator.strip().lower()
    cache_key = cache_manager.make_ioc_key(provider, clean_ind)

    # 1. Fast two-tier cache lookup (L1 In-Memory LRU + L2 Redis)
    fast_val = cache_manager.get(cache_key)
    if fast_val is not None:
        return fast_val

    # 2. Check local SQLite cache table as persistent fallback
    now = time.time()
    try:
        conn = _get_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT data_json, expires_at FROM indicator_cache WHERE indicator_key = ? AND provider = ?",
            (clean_ind, provider),
        )
        row = cur.fetchone()
        conn.close()

        if row:
            data_json, expires_at = row["data_json"], row["expires_at"]
            if now < expires_at:
                parsed = json.loads(data_json)
                rem_ttl = max(1.0, expires_at - now)
                cache_manager.set(cache_key, parsed, ttl_seconds=int(rem_ttl))
                return parsed
    except Exception as e:
        logger.debug("SQLite cache lookup error for %s: %s", cache_key, safe_error_message(e))

    return None


def set_cached_indicator(
    indicator: str,
    provider: str,
    data: dict[str, Any],
    ttl_seconds: Optional[int] = None,
) -> None:
    """
    Store indicator result with TTL expiration across two-tier cache and SQLite.
    Never caches provider errors or inconclusive/unavailable states.
    """
    # Guard against caching errors as clean results
    status_str = str(data.get("intel_status", "") or data.get("status", "")).upper()
    if "ERROR" in status_str or "UNAVAILABLE" in status_str or data.get("error"):
        return

    from backend.services.cache_service import cache_manager

    clean_ind = indicator.strip().lower()
    cache_key = cache_manager.make_ioc_key(provider, clean_ind)

    # Use fine-grained TTL: 24 hours for confirmed malicious hits, 15m for unlisted, default 1 hour
    actual_ttl = ttl_seconds
    if actual_ttl is None:
        if data.get("match") is True or "MALICIOUS" in status_str:
            actual_ttl = 86400  # 24 hours
        else:
            actual_ttl = settings.cache_threat_intel_ttl_seconds

    now = time.time()
    expires_at = now + actual_ttl

    # 1. Store in Two-Tier Cache (L1 LRU + L2 Redis)
    cache_manager.set(cache_key, data, ttl_seconds=actual_ttl)

    # 2. Store in local SQLite database
    try:
        conn = _get_connection()
        with conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO indicator_cache (indicator_key, provider, data_json, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (clean_ind, provider, json.dumps(data), expires_at),
            )
        conn.close()
    except Exception as e:
        logger.debug("Failed to set SQLite indicator cache for %s: %s", clean_ind, safe_error_message(e))


# Auto-initialize database schema on module load
try:
    init_db()
except Exception as e:
    logger.warning("Database initialization deferred: %s", safe_error_message(e))
