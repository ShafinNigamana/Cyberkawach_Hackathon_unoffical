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
from backend.utils.security_logging import safe_error_message

logger = logging.getLogger(__name__)

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
    """Retrieve cached indicator data if not expired."""
    key = f"{provider}:{indicator.strip().lower()}"
    now = time.time()

    # 1. Check in-memory cache
    with _LOCK:
        if key in _MEM_CACHE:
            exp, val = _MEM_CACHE[key]
            if now < exp:
                return val

    # 2. Check SQLite cache
    try:
        conn = _get_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT data_json, expires_at FROM indicator_cache WHERE indicator_key = ? AND provider = ?",
            (indicator.strip().lower(), provider),
        )
        row = cur.fetchone()
        conn.close()

        if row:
            data_json, expires_at = row["data_json"], row["expires_at"]
            if now < expires_at:
                parsed = json.loads(data_json)
                with _LOCK:
                    _MEM_CACHE[key] = (expires_at, parsed)
                return parsed
    except Exception as e:
        logger.debug("Cache lookup error for %s: %s", key, safe_error_message(e))

    return None


def set_cached_indicator(indicator: str, provider: str, data: dict[str, Any], ttl_seconds: int = 3600) -> None:
    """Store indicator result with TTL expiration."""
    clean_ind = indicator.strip().lower()
    key = f"{provider}:{clean_ind}"
    now = time.time()
    expires_at = now + ttl_seconds

    with _LOCK:
        _MEM_CACHE[key] = (expires_at, data)

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
        logger.debug("Failed to set indicator cache for %s: %s", key, safe_error_message(e))


# Auto-initialize database schema on module load
try:
    init_db()
except Exception as e:
    logger.warning("Database initialization deferred: %s", safe_error_message(e))
