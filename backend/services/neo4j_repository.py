"""
Single Data Access Layer — Neo4j AuraDB as the Sole Persistent Application Datastore.

Centralizes all application persistence:
- User registration, authentication, sessions, and preferences
- Incident, evidence, analysis run, and threat intelligence history
- Sender & message context, domain, brand, and IOC relationships
- Fraud DNA syndicate campaign clustering & graph queries
- Audit event logging and IDOR-safe authorization checks
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
import threading
from datetime import datetime, timezone, timedelta
from typing import Any, Optional
from urllib.parse import urlparse

import neo4j
from neo4j.exceptions import Neo4jError, ServiceUnavailable, AuthError

from backend.config import get_settings
from backend.models.evidence import (
    EvidenceItem,
    IncidentEvidence,
    ThreatIntelResult,
    ThreatIntelStatus,
)

logger = logging.getLogger(__name__)

# Security constants
_PBKDF2_ROUNDS = 100_000
_HASH_ALGO = "sha256"


def hash_password(password: str) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with a cryptographically secure 16-byte salt."""
    salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac(
        _HASH_ALGO,
        password.encode("utf-8"),
        salt.encode("utf-8"),
        _PBKDF2_ROUNDS,
    ).hex()
    return f"pbkdf2_{_HASH_ALGO}${_PBKDF2_ROUNDS}${salt}${pw_hash}"


def verify_password(password: str, hashed: str) -> bool:
    """Verify password against stored PBKDF2 hash."""
    try:
        parts = hashed.split("$")
        if len(parts) != 4:
            return False
        algo, rounds_str, salt, expected_hash = parts
        rounds = int(rounds_str)
        actual_hash = hashlib.pbkdf2_hmac(
            _HASH_ALGO,
            password.encode("utf-8"),
            salt.encode("utf-8"),
            rounds,
        ).hex()
        return hmac.compare_digest(actual_hash, expected_hash)
    except Exception:
        return False


def hash_token(token: str) -> str:
    """Hash a session/bearer token with SHA-256 for secure database storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def pseudonymize_identifier(val: Optional[str]) -> Optional[str]:
    """
    Pseudonymize sensitive phone number or email address with SHA-256.
    Allows correlation across incidents without storing unnecessary raw personal data.
    """
    if not val or not str(val).strip():
        return None
    cleaned = re.sub(r"\s+", "", str(val).lower().strip())
    digest = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:16]
    return f"anon_{digest}"


class Neo4jRepository:
    """
    Production-grade repository encapsulating all Neo4j Cypher transactions.
    Ensures single driver singleton, safe parameterization, and zero secret leakage.
    """

    def __init__(self):
        self._driver: Optional[neo4j.Driver] = None
        self._lock = threading.Lock()
        self._schema_initialized = False

    def get_driver(self) -> Optional[neo4j.Driver]:
        """Get or initialize the reusable application-level Neo4j driver."""
        settings = get_settings()
        if not settings.neo4j_enabled or not settings.neo4j_uri:
            return None

        if self._driver is not None:
            return self._driver

        with self._lock:
            if self._driver is not None:
                return self._driver

            uri = settings.neo4j_uri.strip()
            username = (settings.neo4j_username or "").strip()
            password = (settings.neo4j_password or "").strip()

            auth = (username, password) if username and password else None

            # Attempt connection with configured URI (with automatic fallback and retry)
            target_uris = [uri]
            if uri.startswith("neo4j+s://"):
                target_uris.append(uri.replace("neo4j+s://", "neo4j+ssc://"))
            elif uri.startswith("neo4j+ssc://"):
                target_uris.append(uri.replace("neo4j+ssc://", "neo4j+s://"))

            for candidate_uri in target_uris:
                for attempt in range(2):
                    try:
                        self._driver = neo4j.GraphDatabase.driver(
                            candidate_uri,
                            auth=auth,
                            max_connection_lifetime=60,
                            liveness_check_timeout=1.0,
                            max_connection_pool_size=50,
                            connection_acquisition_timeout=30.0,
                        )
                        self._driver.verify_connectivity()
                        logger.info("Connected to Neo4j Aura at %s", candidate_uri)
                        return self._driver
                    except Exception as e:
                        if self._driver is not None:
                            try:
                                self._driver.close()
                            except Exception:
                                pass
                            self._driver = None
                        if attempt == 0:
                            time.sleep(1.0)

            logger.warning("All Neo4j Aura driver connection attempts failed.")
            self._driver = None
            return None

    def close(self) -> None:
        """Cleanly close driver on application shutdown."""
        with self._lock:
            if self._driver is not None:
                try:
                    self._driver.close()
                except Exception as e:
                    logger.warning("Error closing Neo4j driver: %s", type(e).__name__)
                finally:
                    self._driver = None
                    self._schema_initialized = False

    def is_available(self) -> bool:
        """Check if Neo4j datastore is available without raising."""
        try:
            driver = self.get_driver()
            if not driver:
                return False
            driver.verify_connectivity()
            return True
        except Exception:
            return False

    def _get_session(self):
        settings = get_settings()
        driver = self.get_driver()
        if not driver:
            raise ServiceUnavailable("Neo4j datastore is unavailable or not enabled")
        db = settings.neo4j_database.strip() if settings.neo4j_database else None
        return driver.session(database=db) if db else driver.session()

    def _run_in_session(self, fn):
        """Run an operation with retry and automatic reconnect if connection is defunct."""
        for attempt in range(2):
            try:
                with self._get_session() as session:
                    return fn(session)
            except Exception as e:
                err_str = str(e).lower()
                is_transient = any(k in err_str for k in ("connection reset", "session expired", "defunct", "10054", "serviceunavailable", "unable to retrieve routing"))
                if attempt == 0 and is_transient:
                    logger.warning("Neo4j Aura connection dropped (%s), reconnecting...", type(e).__name__)
                    with self._lock:
                        if self._driver is not None:
                            try:
                                self._driver.close()
                            except Exception:
                                pass
                            self._driver = None
                    time.sleep(0.5)
                    continue
                raise

    def init_schema(self) -> bool:
        """
        Create all database uniqueness constraints and indexes idempotently.
        Ensures data integrity and prevents duplicate entities across the graph.
        """
        if self._schema_initialized:
            return True

        if not self.is_available():
            return False

        constraints = [
            "CREATE CONSTRAINT user_id IF NOT EXISTS FOR (u:User) REQUIRE u.user_id IS UNIQUE",
            "CREATE CONSTRAINT user_email IF NOT EXISTS FOR (u:User) REQUIRE u.email_normalized IS UNIQUE",
            "CREATE CONSTRAINT session_id IF NOT EXISTS FOR (s:Session) REQUIRE s.session_id IS UNIQUE",
            "CREATE CONSTRAINT incident_id IF NOT EXISTS FOR (i:Incident) REQUIRE i.incident_id IS UNIQUE",
            "CREATE CONSTRAINT evidence_id IF NOT EXISTS FOR (e:Evidence) REQUIRE e.evidence_id IS UNIQUE",
            "CREATE CONSTRAINT analysis_run_id IF NOT EXISTS FOR (a:AnalysisRun) REQUIRE a.run_id IS UNIQUE",
            "CREATE CONSTRAINT sender_key IF NOT EXISTS FOR (s:Sender) REQUIRE s.sender_key IS UNIQUE",
            "CREATE CONSTRAINT brand_name IF NOT EXISTS FOR (b:Brand) REQUIRE b.name IS UNIQUE",
            "CREATE CONSTRAINT url_id IF NOT EXISTS FOR (u:URL) REQUIRE u.url_id IS UNIQUE",
            "CREATE CONSTRAINT domain_name IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE",
            "CREATE CONSTRAINT campaign_id IF NOT EXISTS FOR (c:Campaign) REQUIRE c.campaign_id IS UNIQUE",
            "CREATE CONSTRAINT report_id IF NOT EXISTS FOR (r:Report) REQUIRE r.report_id IS UNIQUE",
            "CREATE CONSTRAINT audit_event_id IF NOT EXISTS FOR (a:AuditEvent) REQUIRE a.event_id IS UNIQUE",
            "CREATE CONSTRAINT ioc_key IF NOT EXISTS FOR (o:IOC) REQUIRE o.key IS UNIQUE",
            "CREATE CONSTRAINT cert_fp IF NOT EXISTS FOR (crt:Certificate) REQUIRE crt.fingerprint IS UNIQUE",
        ]

        try:
            with self._get_session() as session:
                for c in constraints:
                    try:
                        session.run(c)
                    except Exception as e:
                        logger.debug("Constraint creation notice: %s", type(e).__name__)
            self._schema_initialized = True
            logger.info("Neo4j database schema constraints verified successfully")
            return True
        except Exception as e:
            logger.warning("Could not initialize Neo4j schema: %s", type(e).__name__)
            return False

    # ─────────────────────────────────────────────────────────────
    # User Authentication & Profile
    # ─────────────────────────────────────────────────────────────

    def create_user(
        self,
        email: str,
        password: str,
        display_name: str,
        phone: Optional[str] = None,
        preferred_language: str = "en",
    ) -> Optional[dict]:
        """Register a new application User in Neo4j."""
        norm_email = email.lower().strip()
        user_id = f"usr_{secrets.token_hex(8)}"
        pw_hash = hash_password(password)
        now_iso = datetime.now(timezone.utc).isoformat()

        cypher = """
        MERGE (u:User {email_normalized: $email_normalized})
        ON CREATE SET
            u.user_id = $user_id,
            u.email = $email,
            u.phone = $phone,
            u.password_hash = $password_hash,
            u.display_name = $display_name,
            u.preferred_language = $preferred_language,
            u.is_active = true,
            u.created_at = $created_at,
            u.updated_at = $created_at
        RETURN u, (u.user_id = $user_id) AS was_created
        """
        def _op(session):
            res = session.run(
                cypher,
                email_normalized=norm_email,
                user_id=user_id,
                email=email.strip(),
                phone=phone.strip() if phone else None,
                password_hash=pw_hash,
                display_name=display_name.strip(),
                preferred_language=preferred_language,
                created_at=now_iso,
            )
            record = res.single()
            if not record or not record["was_created"]:
                return None  # Duplicate email
            u = dict(record["u"])
            u.pop("password_hash", None)
            return u

        try:
            return self._run_in_session(_op)
        except Exception as e:
            logger.warning("create_user failed: %s", type(e).__name__)
            return None

    def get_user_by_email(self, email: str) -> Optional[dict]:
        """Retrieve user with password_hash for authentication."""
        norm_email = email.lower().strip()
        cypher = """
        MATCH (u:User {email_normalized: $email_normalized})
        RETURN u
        """
        def _op(session):
            res = session.run(cypher, email_normalized=norm_email)
            record = res.single()
            return dict(record["u"]) if record else None

        try:
            return self._run_in_session(_op)
        except Exception:
            return None

    def get_user_by_id(self, user_id: str) -> Optional[dict]:
        """Retrieve user profile without password hash."""
        cypher = """
        MATCH (u:User {user_id: $user_id})
        RETURN u
        """
        def _op(session):
            res = session.run(cypher, user_id=user_id)
            record = res.single()
            if not record:
                return None
            u = dict(record["u"])
            u.pop("password_hash", None)
            return u

        try:
            return self._run_in_session(_op)
        except Exception:
            return None

    def authenticate_user(self, email: str, password: str) -> Optional[dict]:
        """Validate password and update last_login_at."""
        user = self.get_user_by_email(email)
        if not user or not user.get("password_hash"):
            return None

        if not verify_password(password, user["password_hash"]):
            return None

        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            self._run_in_session(lambda s: s.run(
                "MATCH (u:User {user_id: $user_id}) SET u.last_login_at = $now",
                user_id=user["user_id"],
                now=now_iso,
            ))
        except Exception:
            pass

        user.pop("password_hash", None)
        return user

    # ─────────────────────────────────────────────────────────────
    # Session Management
    # ─────────────────────────────────────────────────────────────

    def create_session(self, user_id: str, ttl_hours: int = 72) -> tuple[str, dict]:
        """Create a new session, returning raw bearer token and session record."""
        raw_token = secrets.token_urlsafe(32)
        token_hash_val = hash_token(raw_token)
        session_id = f"sess_{secrets.token_hex(8)}"
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(hours=ttl_hours)).isoformat()
        now_iso = now.isoformat()

        cypher = """
        MATCH (u:User {user_id: $user_id})
        CREATE (s:Session {
            session_id: $session_id,
            user_id: $user_id,
            token_hash: $token_hash,
            created_at: $created_at,
            expires_at: $expires_at,
            last_seen_at: $created_at,
            revoked_at: null
        })
        CREATE (u)-[:HAS_SESSION]->(s)
        RETURN s
        """
        def _op(session):
            res = session.run(
                cypher,
                user_id=user_id,
                session_id=session_id,
                token_hash=token_hash_val,
                created_at=now_iso,
                expires_at=expires_at,
            )
            record = res.single()
            sess_dict = dict(record["s"]) if record else {"session_id": session_id}
            sess_dict.pop("token_hash", None)
            return raw_token, sess_dict

        try:
            return self._run_in_session(_op)
        except Exception as e:
            logger.warning("create_session failed: %s", type(e).__name__)
            # Return in-memory fallback session if DB error
            return raw_token, {
                "session_id": session_id,
                "user_id": user_id,
                "created_at": now_iso,
                "expires_at": expires_at,
            }

    def validate_session(self, raw_token: str) -> Optional[dict]:
        """Validate session token and return user & session."""
        if not raw_token:
            return None
        token_hash_val = hash_token(raw_token)
        now_iso = datetime.now(timezone.utc).isoformat()

        cypher = """
        MATCH (u:User)-[:HAS_SESSION]->(s:Session {token_hash: $token_hash})
        WHERE (s.revoked_at IS NULL) AND (s.expires_at > $now)
        SET s.last_seen_at = $now
        RETURN u, s
        """
        try:
            with self._get_session() as session:
                res = session.run(cypher, token_hash=token_hash_val, now=now_iso)
                record = res.single()
                if not record:
                    return None
                u = dict(record["u"])
                u.pop("password_hash", None)
                s = dict(record["s"])
                s.pop("token_hash", None)
                return {"user": u, "session": s}
        except Exception:
            return None

    def revoke_session(self, session_id: str) -> bool:
        """Revoke a session explicitly upon logout."""
        now_iso = datetime.now(timezone.utc).isoformat()
        cypher = """
        MATCH (s:Session {session_id: $session_id})
        SET s.revoked_at = $now
        RETURN count(s) AS count
        """
        try:
            with self._get_session() as session:
                res = session.run(cypher, session_id=session_id, now=now_iso)
                record = res.single()
                return bool(record and record["count"] > 0)
        except Exception:
            return False

    # ─────────────────────────────────────────────────────────────
    # User Preferences
    # ─────────────────────────────────────────────────────────────

    def update_user_preferences(self, user_id: str, preferences: dict) -> dict:
        """Persist user UI preferences (language, theme, font_size, accessibility)."""
        cypher = """
        MATCH (u:User {user_id: $user_id})
        MERGE (u)-[:HAS_PREFERENCES]->(p:UserPreferences)
        SET p += $preferences,
            p.updated_at = $now
        RETURN p
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            with self._get_session() as session:
                res = session.run(cypher, user_id=user_id, preferences=preferences, now=now_iso)
                record = res.single()
                return dict(record["p"]) if record else preferences
        except Exception:
            return preferences

    def get_user_preferences(self, user_id: str) -> Optional[dict]:
        """Fetch user preferences."""
        cypher = """
        MATCH (u:User {user_id: $user_id})-[:HAS_PREFERENCES]->(p:UserPreferences)
        RETURN p
        """
        try:
            with self._get_session() as session:
                res = session.run(cypher, user_id=user_id)
                record = res.single()
                return dict(record["p"]) if record else None
        except Exception:
            return None

    # ─────────────────────────────────────────────────────────────
    # Full Incident Graph Persistence (Atomically connects all nodes)
    # ─────────────────────────────────────────────────────────────

    def save_full_incident(self, evidence: IncidentEvidence, user_id: Optional[str] = None) -> bool:
        """
        Atomically persist an entire analyzed incident and its relationship graph into Neo4j:
        - Incident
        - User OWNS Incident (if user_id provided)
        - AnalysisRun
        - Evidence items
        - Sender & Message Context
        - URLs & Domains
        - Brand impersonations
        - Threat Intelligence observations (Google Safe Browsing, PhishTank, PhishStats)
        - Campaign syndicate & SIMILAR_TO incident relationships
        """
        if not self.is_available():
            return False

        now_iso = datetime.now(timezone.utc).isoformat()
        incident_id = evidence.incident_id
        preview = (evidence.message[:200] if evidence.message else "").strip()

        # Build parameterized payload
        incident_props = {
            "incident_id": incident_id,
            "user_id": user_id,
            "input_type": str(evidence.input_type.value if hasattr(evidence.input_type, "value") else evidence.input_type),
            "channel": (getattr(evidence, "message_context", None) and getattr(evidence.message_context, "channel", None)) or "web",
            "title": f"Threat Triage {incident_id}",
            "message_preview": preview,
            "language": evidence.language or "en",
            "fraud_category": evidence.fraud_category or "generic",
            "risk_level": str(evidence.risk.level.value if hasattr(evidence.risk.level, "value") else evidence.risk.level),
            "risk_score": float(evidence.risk.score),
            "confidence": float(getattr(evidence.risk, "confidence", 0.85) or 0.85),
            "created_at": evidence.created_at.isoformat() if hasattr(evidence.created_at, "isoformat") else now_iso,
            "updated_at": now_iso,
            "current_user_state": "received",
        }

        # Evidence list
        evidence_list = []
        for idx, item in enumerate(evidence.evidence):
            ev_id = f"{incident_id}_ev_{idx + 1}"
            evidence_list.append({
                "evidence_id": ev_id,
                "type": str(item.type.value if hasattr(item.type, "value") else item.type),
                "source": str(item.source),
                "status": str(item.status.value if hasattr(item.status, "value") else item.status),
                "reliability": str(item.reliability.value if hasattr(item.reliability, "value") else item.reliability),
                "risk_direction": str(item.risk_direction.value if hasattr(item.risk_direction, "value") else item.risk_direction),
                "severity": str(item.severity.value if hasattr(item.severity, "value") else item.severity),
                "correlation_group": str(item.correlation_group or ""),
                "confidence": float(item.confidence) if item.confidence is not None else None,
                "finding": str(item.description or item.interpretation or ""),
                "created_at": now_iso,
            })

        # URLs and Domains
        url_list = []
        for u in evidence.urls:
            raw_url = str(u.url).strip()
            norm_dom = str(u.domain).lower().strip() if u.domain else ""
            if not norm_dom and raw_url:
                try:
                    norm_dom = urlparse(raw_url).netloc.lower().split(":")[0]
                except Exception:
                    norm_dom = ""
            url_hash = hashlib.sha256(raw_url.encode()).hexdigest()[:12]
            url_list.append({
                "url_id": f"url_{url_hash}",
                "normalized_url": raw_url,
                "domain": norm_dom,
                "first_seen": now_iso,
                "last_seen": now_iso,
            })

        # Brands
        brand_list = []
        for b in evidence.brands:
            brand_list.append({
                "brand_id": f"brand_{hashlib.sha256(b.brand_name.lower().encode()).hexdigest()[:10]}",
                "name": b.brand_name.strip(),
                "created_at": now_iso,
            })

        # Threat Intel Observations (Preserving strict 3-provider separation)
        threat_intel_list = []
        for idx, ti in enumerate(evidence.threat_intel):
            obs_id = f"{incident_id}_ti_{ti.source}_{idx}"
            threat_intel_list.append({
                "observation_id": obs_id,
                "provider": str(ti.source),
                "source": str(ti.source),
                "lookup_url": str(ti.lookup_url or ""),
                "match": bool(ti.match),
                "status": str(ti.intel_status.value if hasattr(ti.intel_status, "value") else ti.intel_status),
                "intel_status": str(ti.intel_status.value if hasattr(ti.intel_status, "value") else ti.intel_status),
                "result": str(ti.details or ti.error or ("MATCH" if ti.match else "NO MATCH")),
                "details": str(ti.details or ""),
                "error": str(ti.error or "") if ti.error else "",
                "confidence": 0.95 if ti.match else 0.50,
                "observed_at": now_iso,
            })

        # Campaign Syndicate & Fraud DNA
        campaign_info = None
        if evidence.fraud_dna and evidence.fraud_dna.available and evidence.fraud_dna.campaign_id:
            campaign_info = {
                "campaign_id": str(evidence.fraud_dna.campaign_id),
                "fingerprint": str(evidence.fraud_dna.fingerprint or ""),
                "related_incidents": list(evidence.fraud_dna.related_incidents or []),
                "now": now_iso,
            }

        # Sender Context (Optional, Pseudonymized)
        sender_info = None
        raw_sender = getattr(evidence, "sender", None)
        if raw_sender and (raw_sender.phone_number or raw_sender.email_address or raw_sender.sender_id or raw_sender.claimed_organization):
            pseudo_key = (
                pseudonymize_identifier(raw_sender.phone_number) or
                pseudonymize_identifier(raw_sender.email_address) or
                pseudonymize_identifier(raw_sender.sender_id) or
                f"anon_{secrets.token_hex(6)}"
            )
            sender_info = {
                "sender_id": f"snd_{pseudo_key}",
                "sender_key": f"snd_{pseudo_key}",
                "pseudonymous_key": pseudo_key,
                "channel": (getattr(evidence, "message_context", None) and getattr(evidence.message_context, "channel", None)) or "sms",
                "display_name": raw_sender.display_name or "Unknown Sender",
                "claimed_organization": raw_sender.claimed_organization or (evidence.brands[0].brand_name if evidence.brands else None),
                "sender_domain": getattr(raw_sender, "sender_domain", None) or (evidence.urls[0].domain if evidence.urls else None),
                "created_at": now_iso,
            }

        # Analysis run metadata
        analysis_run = {
            "run_id": f"run_{incident_id}",
            "incident_id": incident_id,
            "started_at": now_iso,
            "completed_at": now_iso,
            "status": "COMPLETED",
            "pipeline_version": "1.0.0",
            "rules_version": "2.4.0",
            "ml_model_version": "logistic-regression-tfidf-v1",
            "laya_version": "0.1.0",
            "gemini_version": "gemini-3.5-flash-lite",
            "created_at": now_iso,
        }

        # Execute Transaction
        cypher = """
        // 1. Merge Incident
        MERGE (i:Incident {incident_id: $incident.incident_id})
        ON CREATE SET i = $incident
        ON MATCH SET i.updated_at = $incident.updated_at,
                     i.current_user_state = $incident.current_user_state

        // 2. Connect User Ownership if user_id present
        WITH i
        FOREACH (_ IN CASE WHEN $user_id IS NOT NULL THEN [1] ELSE [] END |
            MERGE (u:User {user_id: $user_id})
            MERGE (u)-[:OWNS]->(i)
        )

        // 3. Connect AnalysisRun
        MERGE (ar:AnalysisRun {run_id: $analysis_run.run_id})
        ON CREATE SET ar = $analysis_run
        MERGE (i)-[:HAS_ANALYSIS_RUN]->(ar)

        // 4. Connect Evidence Items
        WITH i
        UNWIND $evidence_list AS ev
            MERGE (e:Evidence {evidence_id: ev.evidence_id})
            ON CREATE SET e = ev
            MERGE (i)-[:HAS_EVIDENCE]->(e)

        // 5. Connect URLs and Domains
        WITH i
        UNWIND $url_list AS u_item
            MERGE (u:URL {url_id: u_item.url_id})
            ON CREATE SET u.normalized_url = u_item.normalized_url, u.first_seen = u_item.first_seen, u.last_seen = u_item.last_seen
            ON MATCH SET u.last_seen = u_item.last_seen
            MERGE (i)-[:CONTAINS_URL]->(u)
            FOREACH (_ IN CASE WHEN u_item.domain <> "" THEN [1] ELSE [] END |
                MERGE (d:Domain {name: u_item.domain})
                ON CREATE SET d.first_seen = u_item.first_seen, d.last_seen = u_item.last_seen
                ON MATCH SET d.last_seen = u_item.last_seen
                MERGE (u)-[:HAS_DOMAIN]->(d)
            )

        // 6. Connect Brands
        WITH i
        UNWIND $brand_list AS b_item
            MERGE (b:Brand {name: b_item.name})
            ON CREATE SET b.brand_id = b_item.brand_id, b.created_at = b_item.created_at
            MERGE (i)-[:CLAIMS_BRAND]->(b)

        // 7. Connect Threat Intelligence Observations
        WITH i
        UNWIND $threat_intel_list AS ti_item
            MERGE (ti:ThreatIntelObservation {observation_id: ti_item.observation_id})
            ON CREATE SET ti = ti_item
            MERGE (i)-[:HAS_THREAT_INTEL]->(ti)

        // 8. Connect Campaign & Related Incidents (if Fraud DNA present)
        WITH i
        FOREACH (_ IN CASE WHEN $campaign_info IS NOT NULL THEN [1] ELSE [] END |
            MERGE (c:Campaign {campaign_id: $campaign_info.campaign_id})
            ON CREATE SET c.fingerprint = $campaign_info.fingerprint, c.created_at = $campaign_info.now, c.updated_at = $campaign_info.now
            ON MATCH SET c.updated_at = $campaign_info.now
            MERGE (i)-[:BELONGS_TO]->(c)
        )

        // 9. Connect Sender Context (if present)
        WITH i
        FOREACH (_ IN CASE WHEN $sender_info IS NOT NULL THEN [1] ELSE [] END |
            MERGE (s:Sender {sender_key: $sender_info.sender_key})
            ON CREATE SET s = $sender_info
            MERGE (i)-[:SENT_BY]->(s)
        )

        RETURN i.incident_id AS id
        """

        try:
            with self._get_session() as session:
                session.run(
                    cypher,
                    incident=incident_props,
                    user_id=user_id,
                    analysis_run=analysis_run,
                    evidence_list=evidence_list,
                    url_list=url_list,
                    brand_list=brand_list,
                    threat_intel_list=threat_intel_list,
                    campaign_info=campaign_info,
                    sender_info=sender_info,
                )

                # Connect cross-incident SIMILAR_TO links for campaign syndicate
                if campaign_info and campaign_info["related_incidents"]:
                    similar_cypher = """
                    MATCH (current:Incident {incident_id: $incident_id})
                    UNWIND $related AS other_id
                        MATCH (other:Incident {incident_id: other_id})
                        WHERE current <> other
                        MERGE (current)-[:SIMILAR_TO {pattern_type: "syndicate_cluster"}]->(other)
                    """
                    session.run(similar_cypher, incident_id=incident_id, related=campaign_info["related_incidents"])

            evidence.fraud_dna.graph_persisted = True
            return True
        except Exception as e:
            logger.warning("save_full_incident transaction failed: %s", type(e).__name__)
            return False

    # ─────────────────────────────────────────────────────────────
    # Incident Queries & IDOR Protection
    # ─────────────────────────────────────────────────────────────

    def get_incident(self, incident_id: str, user_id: Optional[str] = None) -> Optional[dict]:
        """
        Fetch an incident. If user_id is provided, strictly enforces ownership check.
        Returns None if incident does not exist or user is unauthorized (preventing IDOR).
        """
        cypher = """
        MATCH (i:Incident {incident_id: $incident_id})
        OPTIONAL MATCH (u:User)-[:OWNS]->(i)
        OPTIONAL MATCH (i)-[:BELONGS_TO]->(c:Campaign)
        OPTIONAL MATCH (i)-[:HAS_EVIDENCE]->(e:Evidence)
        OPTIONAL MATCH (i)-[:CONTAINS_URL]->(url:URL)-[:HAS_DOMAIN]->(d:Domain)
        OPTIONAL MATCH (i)-[:CLAIMS_BRAND]->(b:Brand)
        OPTIONAL MATCH (i)-[:HAS_THREAT_INTEL]->(ti:ThreatIntelObservation)
        RETURN i, u.user_id AS owner_id, c.campaign_id AS campaign_id,
               collect(DISTINCT e) AS evidence_items,
               collect(DISTINCT url.normalized_url) AS urls,
               collect(DISTINCT d.name) AS domains,
               collect(DISTINCT b.name) AS brands,
               collect(DISTINCT ti) AS threat_intel
        """
        try:
            with self._get_session() as session:
                res = session.run(cypher, incident_id=incident_id)
                record = res.single()
                if not record or not record["i"]:
                    return None

                owner_id = record["owner_id"]
                # IDOR check: If incident has an owner, only that authenticated owner can access it
                if owner_id is not None and (user_id is None or str(owner_id) != str(user_id)):
                    logger.warning("IDOR attempt blocked: caller %s attempted to access incident %s owned by %s", user_id, incident_id, owner_id)
                    return None

                inc = dict(record["i"])
                inc["campaign_id"] = record["campaign_id"]
                inc["evidence"] = [dict(ev) for ev in record["evidence_items"] if ev]
                inc["urls"] = [str(u) for u in record["urls"] if u]
                inc["domains"] = [str(d) for d in record["domains"] if d]
                inc["brands"] = [str(b) for b in record["brands"] if b]
                inc["threat_intel"] = []
                for ti in record["threat_intel"]:
                    if ti:
                        d = dict(ti)
                        if "provider" in d and "source" not in d:
                            d["source"] = d["provider"]
                        if "result" in d and "details" not in d:
                            d["details"] = d["result"]
                        inc["threat_intel"].append(d)
                return inc
        except Exception as e:
            logger.warning("get_incident failed: %s", type(e).__name__)
            return None

    def list_user_incidents(self, user_id: str, limit: int = 50) -> list[dict]:
        """Fetch all incidents owned by a specific authenticated user for 'My Checks'."""
        cypher = """
        MATCH (u:User {user_id: $user_id})-[:OWNS]->(i:Incident)
        OPTIONAL MATCH (i)-[:BELONGS_TO]->(c:Campaign)
        RETURN i, c.campaign_id AS campaign_id
        ORDER BY i.created_at DESC
        LIMIT $limit
        """
        try:
            with self._get_session() as session:
                res = session.run(cypher, user_id=user_id, limit=limit)
                incidents = []
                for r in res:
                    item = dict(r["i"])
                    item["campaign_id"] = r["campaign_id"]
                    incidents.append(item)
                return incidents
        except Exception:
            return []

    def save_incident_action(self, incident_id: str, state: str, action_taken: str, user_id: Optional[str] = None) -> bool:
        """Persist adaptive response state transition (received -> clicked -> credentials -> paid)."""
        action_id = f"act_{incident_id}_{state}_{secrets.token_hex(4)}"
        now_iso = datetime.now(timezone.utc).isoformat()

        cypher = """
        MATCH (i:Incident {incident_id: $incident_id})
        SET i.current_user_state = $state,
            i.updated_at = $now
        CREATE (a:IncidentAction {
            action_id: $action_id,
            state: $state,
            action_taken: $action_taken,
            guidance_version: "2.1",
            created_at: $now
        })
        CREATE (i)-[:HAS_ACTION]->(a)
        RETURN a.action_id AS id
        """
        try:
            with self._get_session() as session:
                res = session.run(cypher, incident_id=incident_id, state=state, action_taken=action_taken, action_id=action_id, now=now_iso)
                return bool(res.single())
        except Exception:
            return False

    def save_report_metadata(self, report_id: str, incident_id: str, format: str, user_id: Optional[str] = None) -> bool:
        """Record forensic export generation in Neo4j."""
        now_iso = datetime.now(timezone.utc).isoformat()
        cypher = """
        MATCH (i:Incident {incident_id: $incident_id})
        CREATE (r:Report {
            report_id: $report_id,
            incident_id: $incident_id,
            user_id: $user_id,
            format: $format,
            generated_at: $now,
            status: "GENERATED"
        })
        CREATE (i)-[:HAS_REPORT]->(r)
        RETURN r.report_id AS id
        """
        try:
            with self._get_session() as session:
                res = session.run(cypher, report_id=report_id, incident_id=incident_id, user_id=user_id, format=format, now=now_iso)
                return bool(res.single())
        except Exception:
            return False

    # ─────────────────────────────────────────────────────────────
    # Graph Visualization Read Path (GET /api/incidents/{id}/graph)
    # ─────────────────────────────────────────────────────────────

    def get_incident_graph(self, incident_id: str, user_id: Optional[str] = None) -> Optional[dict]:
        """
        Query the incident's contextual relationship graph for visual exploration:
        Nodes: Incident, Sender, Brand, URL, Domain, Campaign, Shared indicator.
        Relationships: SENT_BY, CLAIMS_BRAND, CONTAINS_URL, HAS_DOMAIN, BELONGS_TO, SIMILAR_TO.
        Never exposes passwords, tokens, or raw sensitive phone/email numbers.
        """
        cypher = """
        MATCH (i:Incident {incident_id: $incident_id})
        OPTIONAL MATCH (u:User)-[:OWNS]->(i)

        // Neighbors
        OPTIONAL MATCH (i)-[r_send:SENT_BY]->(s:Sender)
        OPTIONAL MATCH (i)-[r_brand:CLAIMS_BRAND]->(b:Brand)
        OPTIONAL MATCH (i)-[r_url:CONTAINS_URL]->(u_node:URL)
        OPTIONAL MATCH (u_node)-[r_dom:HAS_DOMAIN]->(d:Domain)
        OPTIONAL MATCH (i)-[r_camp:BELONGS_TO]->(c:Campaign)
        OPTIONAL MATCH (i)-[r_sim:SIMILAR_TO]->(sim:Incident)

        RETURN i, u.user_id AS owner_id,
               s, b, u_node, d, c,
               collect(DISTINCT sim.incident_id) AS related_ids
        """
        try:
            with self._get_session() as session:
                res = session.run(cypher, incident_id=incident_id)
                records = list(res)
                if not records:
                    return None

                first = records[0]
                inc_node = dict(first["i"])
                owner_id = first["owner_id"]

                # IDOR authorization check: If incident has an owner, only that authenticated owner can access it
                if owner_id is not None and (user_id is None or str(owner_id) != str(user_id)):
                    logger.warning("IDOR attempt blocked for graph: caller %s attempted to access incident %s owned by %s", user_id, incident_id, owner_id)
                    return None

                nodes = []
                relationships = []
                seen_node_ids = set()

                def add_node(node_id: str, label: str, title: str, props: dict):
                    if node_id not in seen_node_ids:
                        seen_node_ids.add(node_id)
                        safe_props = {k: v for k, v in props.items() if not k.endswith("_hash") and k != "password"}
                        nodes.append({
                            "id": node_id,
                            "label": label,
                            "type": label,
                            "title": title,
                            "properties": safe_props,
                        })

                # Central Incident Node
                inc_id = inc_node["incident_id"]
                add_node(inc_id, "Incident", f"Incident {inc_id}", inc_node)

                campaign_dict = None
                related_incidents = []
                shared_domains = []
                brand_names = []
                sender_pattern = None

                for r in records:
                    # Campaign
                    if r["c"]:
                        c_data = dict(r["c"])
                        c_id = c_data["campaign_id"]
                        campaign_dict = {"campaign_id": c_id, "fingerprint": c_data.get("fingerprint")}
                        add_node(c_id, "Campaign", f"Campaign {c_id}", c_data)
                        relationships.append({
                            "source": inc_id,
                            "target": c_id,
                            "type": "BELONGS_TO",
                            "label": "belongs to campaign",
                        })

                    # Sender
                    if r["s"]:
                        s_data = dict(r["s"])
                        s_id = s_data["sender_id"]
                        sender_pattern = {
                            "display_name": s_data.get("display_name"),
                            "claimed_organization": s_data.get("claimed_organization"),
                            "sender_domain": s_data.get("sender_domain"),
                            "channel": s_data.get("channel"),
                        }
                        add_node(s_id, "Sender", s_data.get("display_name", "Sender"), s_data)
                        relationships.append({
                            "source": inc_id,
                            "target": s_id,
                            "type": "SENT_BY",
                            "label": "sent by sender pattern",
                        })

                    # Brand
                    if r["b"]:
                        b_data = dict(r["b"])
                        b_name = b_data["name"]
                        if b_name not in brand_names:
                            brand_names.append(b_name)
                        add_node(f"brand_{b_name}", "Brand", b_name, b_data)
                        relationships.append({
                            "source": inc_id,
                            "target": f"brand_{b_name}",
                            "type": "CLAIMS_BRAND",
                            "label": "impersonates brand",
                        })

                    # URL & Domain
                    if r["u_node"]:
                        u_data = dict(r["u_node"])
                        u_id = u_data.get("url_id", u_data.get("normalized_url"))
                        add_node(u_id, "URL", u_data.get("normalized_url", "URL"), u_data)
                        relationships.append({
                            "source": inc_id,
                            "target": u_id,
                            "type": "CONTAINS_URL",
                            "label": "contains link",
                        })

                        if r["d"]:
                            d_data = dict(r["d"])
                            d_name = d_data["name"]
                            if d_name not in shared_domains:
                                shared_domains.append(d_name)
                            add_node(f"dom_{d_name}", "Domain", d_name, d_data)
                            relationships.append({
                                "source": u_id,
                                "target": f"dom_{d_name}",
                                "type": "HAS_DOMAIN",
                                "label": "resolves to domain",
                            })

                    # Related incidents
                    if r["related_ids"]:
                        for other_id in r["related_ids"]:
                            if other_id and other_id != inc_id:
                                if other_id not in related_incidents:
                                    related_incidents.append(other_id)
                                add_node(other_id, "Incident", f"Related {other_id}", {"incident_id": other_id})
                                relationships.append({
                                    "source": inc_id,
                                    "target": other_id,
                                    "type": "SIMILAR_TO",
                                    "label": "shares signature pattern",
                                })

                return {
                    "incident": inc_node,
                    "incident_id": inc_id,
                    "nodes": nodes,
                    "relationships": relationships,
                    "edges": [
                        {
                            "source": r["source"],
                            "target": r["target"],
                            "relationship": r.get("type", "CONNECTED_TO"),
                            "properties": {"label": r.get("label", "")},
                        }
                        for r in relationships
                    ],
                    "node_count": len(nodes),
                    "edge_count": len(relationships),
                    "campaign": campaign_dict or {"campaign_id": "CAMP-UNCLUSTERED", "fingerprint": "standalone"},
                    "related_incidents": related_incidents,
                    "shared_domains": shared_domains,
                    "shared_indicators": [f"Domain: {d}" for d in shared_domains] + [f"Brand: {b}" for b in brand_names],
                    "sender_pattern": sender_pattern or {"pattern": "Unspecified sender"},
                    "brand": brand_names,
                }
        except Exception as e:
            logger.warning("get_incident_graph failed: %s", type(e).__name__)
            return None

    # ─────────────────────────────────────────────────────────────
    # Audit Logging
    # ─────────────────────────────────────────────────────────────

    def log_audit_event(
        self,
        event_type: str,
        actor_user_id: Optional[str],
        resource_type: str,
        resource_id: str,
        metadata: Optional[dict] = None,
    ) -> bool:
        """Record security-relevant audit event in Neo4j."""
        event_id = f"aud_{secrets.token_hex(8)}"
        now_iso = datetime.now(timezone.utc).isoformat()
        clean_metadata = {k: str(v) for k, v in (metadata or {}).items() if not k.endswith("_hash") and k != "password"}

        cypher = """
        CREATE (a:AuditEvent {
            event_id: $event_id,
            event_type: $event_type,
            actor_user_id: $actor_user_id,
            resource_type: $resource_type,
            resource_id: $resource_id,
            metadata: $metadata,
            created_at: $now
        })
        RETURN a.event_id AS id
        """
        try:
            with self._get_session() as session:
                session.run(
                    cypher,
                    event_id=event_id,
                    event_type=event_type,
                    actor_user_id=actor_user_id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    metadata=str(clean_metadata),
                    now=now_iso,
                )
            return True
        except Exception:
            return False


# Global repository singleton
_REPO: Optional[Neo4jRepository] = None
_REPO_LOCK = threading.Lock()


def get_neo4j_repo() -> Neo4jRepository:
    """Access the global single Neo4j repository instance."""
    global _REPO
    if _REPO is None:
        with _REPO_LOCK:
            if _REPO is None:
                _REPO = Neo4jRepository()
    return _REPO


# Single reusable repository instance
neo4j_repo = get_neo4j_repo()

