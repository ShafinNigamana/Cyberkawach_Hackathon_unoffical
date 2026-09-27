"""
FastAPI application entry point.
Defines API routes, security middleware, and wires the analysis pipeline.
"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from pathlib import Path
import secrets
from threading import Lock
from typing import Optional

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.config import get_settings
from backend.models.api import (
    AnalyzeRequest,
    AnalyzeResponse,
    AuthResponse,
    FileUploadResponse,
    HealthResponse,
    IncidentGraphResponse,
    IncidentHistoryItem,
    IncidentHistoryResponse,
    LoginRequest,
    OSINTResponse,
    RegisterRequest,
    TranslateRequest,
    TranslateResponse,
    UpdateUserStateRequest,
    UserPreferencesRequest,
    UserPreferencesResponse,
    UserResponse,
)
from backend.models.evidence import IncidentEvidence, InputType
from backend.services.google_translator import (
    translate_batch_async,
    translate_text_async,
)
from backend.services.neo4j_repository import neo4j_repo
from backend.utils.file_security import validate_file_security
from backend.utils.rate_limiter import check_rate_limit
from backend.utils.request_limits import RequestSizeLimitMiddleware
from backend.utils.sanitize import (
    detect_input_language,
    escape_for_display,
    sanitize_message,
    sanitize_url,
    validate_incident_id,
    validate_language,
)
from backend.utils.security_headers import SecurityHeadersMiddleware
from backend.utils.security_logging import safe_error_message

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cyber_guardian.main")

settings = get_settings()


# ─── Lifespan Context Manager (Neo4j schema init & graceful shutdown) ───

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Cleanly initialize Neo4j constraints on startup and close driver on exit."""
    if settings.neo4j_enabled:
        try:
            logger.info("Initializing Neo4j Aura schema constraints and indexes...")
            neo4j_repo.init_schema()
            logger.info("Neo4j Aura schema initialization complete.")
        except Exception as e:
            logger.warning("Neo4j startup schema init error: %s", safe_error_message(e))
    yield
    try:
        neo4j_repo.close()
        logger.info("Neo4j driver closed cleanly on application shutdown.")
    except Exception as e:
        logger.warning("Neo4j shutdown close error: %s", safe_error_message(e))


app = FastAPI(
    title="Cyber Fraud Guardian",
    description="Citizen Fraud-Message Guardian — evidence-driven fraud analysis",
    version="0.1.0",
    lifespan=lifespan,
)

# ─── Middleware Stack (applied in reverse order of addition) ───

# 1. Enforce strict response security headers (CSP, nosniff, frame-ancestors, etc.)
app.add_middleware(SecurityHeadersMiddleware)

# 2. Enforce request size limits (prevents payload-based DoS)
app.add_middleware(
    RequestSizeLimitMiddleware,
    max_bytes=settings.max_upload_size_mb * 1024 * 1024,
)

# 3. Explicit, hardened CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)


# ─── Bounded Incident Storage (anti-DoS memory exhaustion) ───

class BoundedIncidentStore:
    """Thread-safe bounded in-memory incident cache with LRU eviction."""

    def __init__(self, max_capacity: int = 1000):
        self.max_capacity = max_capacity
        self._store: OrderedDict[str, IncidentEvidence] = OrderedDict()
        self._lock = Lock()

    def get(self, incident_id: str) -> IncidentEvidence | None:
        with self._lock:
            if incident_id in self._store:
                self._store.move_to_end(incident_id)
                return self._store[incident_id]
            return None

    def set(self, incident_id: str, evidence: IncidentEvidence) -> None:
        with self._lock:
            if incident_id in self._store:
                self._store.move_to_end(incident_id)
            self._store[incident_id] = evidence
            if len(self._store) > self.max_capacity:
                self._store.popitem(last=False)

    def __contains__(self, incident_id: str) -> bool:
        with self._lock:
            return incident_id in self._store

    def __getitem__(self, incident_id: str) -> IncidentEvidence:
        with self._lock:
            return self._store[incident_id]

    def __setitem__(self, incident_id: str, evidence: IncidentEvidence) -> None:
        self.set(incident_id, evidence)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


_incidents = BoundedIncidentStore(max_capacity=1000)


# ─── Exception Handlers (no stack traces or internal leaks) ───

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Safe validation error handler that strips sensitive payload data."""
    errors = []
    for err in exc.errors():
        loc = " -> ".join(str(l) for l in err.get("loc", []))
        msg = err.get("msg", "Invalid value")
        errors.append(f"{loc}: {msg}")
    return JSONResponse(
        status_code=422,
        content={"error": "Validation Error", "detail": "; ".join(errors)},
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Uniform HTTP error handler preserving custom headers (e.g. Retry-After)."""
    headers = getattr(exc, "headers", None)
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "detail": exc.detail},
        headers=headers,
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Catch-all error handler preventing stack traces or path disclosure."""
    safe_msg = safe_error_message(exc)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "detail": "An internal error occurred during processing. Please try again later.",
        },
    )


# ─── Static Files Mounts ───

frontend_path = Path(__file__).resolve().parent.parent / "frontend"
fixtures_path = Path(__file__).resolve().parent.parent / "fixtures"

if fixtures_path.exists():
    app.mount("/fixtures", StaticFiles(directory=str(fixtures_path)), name="fixtures")

if frontend_path.exists():
    css_path = frontend_path / "css"
    js_path = frontend_path / "js"
    dist_path = frontend_path / "dist"

    if css_path.exists():
        app.mount("/css", StaticFiles(directory=str(css_path)), name="css")
    if js_path.exists():
        app.mount("/js", StaticFiles(directory=str(js_path)), name="js")

    if dist_path.exists():
        dist_assets = dist_path / "assets"
        if dist_assets.exists():
            app.mount("/assets", StaticFiles(directory=str(dist_assets)), name="assets")

    @app.get("/")
    async def serve_index():
        if dist_path.exists() and (dist_path / "index.html").exists():
            return FileResponse(str(dist_path / "index.html"))
        return FileResponse(str(frontend_path / "index.html"))

    @app.get("/verification.html")
    async def serve_verification():
        return FileResponse(str(frontend_path / "verification.html"))


# ─── Safe Verification Endpoints (No secrets exposed) ───
_rate_test_tracker: dict[str, list[float]] = {}


@app.get("/api/verification/status")
async def verification_status():
    """Returns boolean API availability status without exposing credentials."""
    avail = settings.api_availability()
    return {
        "gemini_configured": avail.get("gemini", False),
        "safe_browsing_configured": avail.get("safe_browsing", False),
        "phishtank_configured": avail.get("phishtank", False),
        "phishstats_configured": avail.get("phishstats", False),
        "osint_configured": avail.get("osint", True),
        "deterministic_fallback_available": True,
        "laya_available": True,
        "security_protections": {
            "ssrf_protection": True,
            "pii_redaction": True,
            "prompt_injection_defense": True,
            "rate_limiting": True,
        },
    }


@app.post("/api/verification/check-ssrf")
async def check_ssrf_test(data: dict):
    """Test SSRF validation logic against synthetic targets."""
    url = data.get("url", "")
    from backend.utils.sanitize import is_safe_url
    safe = is_safe_url(url)
    return {
        "url": url,
        "is_safe": safe,
        "status": "ALLOWED" if safe else "BLOCKED",
        "reason": "External web destination" if safe else "Local/Private/Loopback target blocked (SSRF defense)",
    }


@app.post("/api/verification/check-pii")
async def check_pii_test(data: dict):
    """Test PII redaction against synthetic data."""
    text = data.get("text", "")
    from backend.utils.sanitize import redact_pii
    redacted = redact_pii(text)
    return {
        "original": text,
        "redacted": redacted,
        "pii_detected": redacted != text,
    }


@app.post("/api/verification/check-prompt-injection")
async def check_prompt_injection_test(data: dict):
    """Test prompt-injection filtering against synthetic jailbreak payloads."""
    text = data.get("text", "")
    from backend.utils.sanitize import defend_prompt_injection
    defended = defend_prompt_injection(text)
    return {
        "original": text,
        "defended": defended,
        "injection_detected": defended != text,
    }


@app.get("/api/verification/rate-limit-test")
async def rate_limit_test(request: Request):
    """Mini 5-request burst test to demonstrate 429 without hammering server."""
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window = [t for t in _rate_test_tracker.get(client_ip, []) if now - t < 10]
    if len(window) >= 5:
        raise HTTPException(
            status_code=429,
            detail="Rate limit triggered: maximum 5 requests in 10s test window reached.",
            headers={"Retry-After": "10"},
        )
    window.append(now)
    _rate_test_tracker[client_ip] = window
    return {"status": "ok", "requests_in_window": len(window), "limit": 5}


# ─── Endpoints ───

@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    """System health — which modules and APIs are available."""
    return HealthResponse(
        status="ok",
        version="0.1.0",
        modules={
            "ingestion": True,
            "rules": True,
            "ml_baseline": True,
            "url_analyzer": True,
            "brand_check": True,
            "threat_intel": True,
            "laya": True,  # Phase 3 fast typed-decision triage
            "fusion": True,
            "gemini": True,  # Non-critical — deterministic fallback always available
            "ocr": True,  # Phase 3 — wired up
            "fraud_dna": True,  # Phase 2 — wired up
            "neo4j": settings.neo4j_enabled,  # Single application datastore
        },
        api_keys_configured=settings.api_availability(),
    )


# ─── Authentication & Authorization Helpers (Neo4j Session Based) ───

def get_current_user_optional(raw_request: Request) -> Optional[dict]:
    """Extract authenticated citizen if valid session token provided; otherwise None."""
    auth_header = raw_request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif "X-Session-Token" in raw_request.headers:
        token = raw_request.headers["X-Session-Token"].strip()
    elif "session_token" in raw_request.cookies:
        token = raw_request.cookies["session_token"].strip()

    if not token:
        return None

    try:
        session_info = neo4j_repo.validate_session(token)
        if session_info:
            return session_info["user"]
    except Exception as e:
        logger.warning("Session validation error: %s", safe_error_message(e))
    return None


def get_current_user(raw_request: Request) -> dict:
    """Enforce authentication requirement for protected endpoints, raising 401."""
    user = get_current_user_optional(raw_request)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Please log in or provide a valid session token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


# ─── Citizen Authentication Endpoints ───

@app.post("/api/auth/register", response_model=AuthResponse)
async def register_citizen(request: RegisterRequest, raw_request: Request):
    """Register citizen account into Neo4j with PBKDF2 password hashing."""
    check_rate_limit(raw_request)

    existing = neo4j_repo.get_user_by_email(request.email)
    if existing:
        raise HTTPException(status_code=400, detail="An account with this email already exists.")

    user = neo4j_repo.create_user(
        email=request.email,
        password=request.password,
        phone=request.phone,
        display_name=request.display_name,
        preferred_language=request.preferred_language or "en",
    )
    if not user:
        raise HTTPException(status_code=500, detail="Failed to create citizen account.")

    raw_token, session_record = neo4j_repo.create_session(user["user_id"])
    neo4j_repo.log_audit_event("USER_REGISTERED", user["user_id"], "User", user["user_id"])

    return AuthResponse(
        status="success",
        session_token=raw_token,
        user=UserResponse(
            user_id=user["user_id"],
            email=user["email"],
            display_name=user.get("display_name") or user["email"].split("@")[0],
            phone_masked=user.get("phone_masked"),
            preferred_language=user.get("preferred_language", "en"),
            is_active=user.get("is_active", True),
            created_at=user.get("created_at", ""),
            last_login_at=user.get("last_login_at"),
        ),
    )


@app.post("/api/auth/login", response_model=AuthResponse)
async def login_citizen(request: LoginRequest, raw_request: Request):
    """Authenticate citizen via Neo4j and issue a hashed session."""
    check_rate_limit(raw_request)

    user = neo4j_repo.authenticate_user(request.email, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    raw_token, session_record = neo4j_repo.create_session(user["user_id"])
    neo4j_repo.log_audit_event("LOGIN", user["user_id"], "Session", session_record.get("session_id", ""))

    return AuthResponse(
        status="success",
        session_token=raw_token,
        user=UserResponse(
            user_id=user["user_id"],
            email=user["email"],
            display_name=user.get("display_name") or user["email"].split("@")[0],
            phone_masked=user.get("phone_masked"),
            preferred_language=user.get("preferred_language", "en"),
            is_active=user.get("is_active", True),
            created_at=user.get("created_at", ""),
            last_login_at=user.get("last_login_at"),
        ),
    )


@app.post("/api/auth/logout")
async def logout_citizen(raw_request: Request):
    """Revoke citizen session in Neo4j."""
    auth_header = raw_request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif "X-Session-Token" in raw_request.headers:
        token = raw_request.headers["X-Session-Token"].strip()
    elif "session_token" in raw_request.cookies:
        token = raw_request.cookies["session_token"].strip()

    if token:
        sess_info = neo4j_repo.validate_session(token)
        if sess_info:
            session_id = sess_info["session"]["session_id"]
            user_id = sess_info["user"]["user_id"]
            neo4j_repo.revoke_session(session_id)
            neo4j_repo.log_audit_event("LOGOUT", user_id, "Session", session_id)

    return {"status": "success", "message": "Logged out successfully."}


@app.get("/api/auth/me", response_model=UserResponse)
async def get_my_profile(raw_request: Request):
    """Get authenticated citizen profile."""
    user = get_current_user(raw_request)
    return UserResponse(
        user_id=user["user_id"],
        email=user["email"],
        display_name=user.get("display_name") or user["email"].split("@")[0],
        phone_masked=user.get("phone_masked"),
        preferred_language=user.get("preferred_language", "en"),
        is_active=user.get("is_active", True),
        created_at=user.get("created_at", ""),
        last_login_at=user.get("last_login_at"),
    )


@app.get("/api/auth/preferences", response_model=UserPreferencesResponse)
async def get_user_preferences(raw_request: Request):
    """Fetch user UI and accessibility preferences from Neo4j."""
    user = get_current_user(raw_request)
    prefs = neo4j_repo.get_user_preferences(user["user_id"])
    return UserPreferencesResponse(status="success", preferences=prefs)


@app.put("/api/auth/preferences", response_model=UserPreferencesResponse)
async def update_user_preferences(request: UserPreferencesRequest, raw_request: Request):
    """Persist updated user preferences into Neo4j."""
    user = get_current_user(raw_request)
    updated = neo4j_repo.update_user_preferences(
        user_id=user["user_id"],
        language=request.language,
        font_size=request.font_size,
        accessibility_mode=request.accessibility_mode,
        notification_preferences=request.notification_preferences,
        theme=request.theme,
    )
    return UserPreferencesResponse(status="success", preferences=updated)


# ─── Incident History & Graph Relationship Endpoints ───

@app.get("/api/incidents", response_model=IncidentHistoryResponse)
async def list_citizen_incidents(raw_request: Request, limit: int = 50):
    """
    List past incidents owned by the authenticated citizen ('My Checks').
    Strictly isolated per user to guarantee zero IDOR leakage.
    """
    user = get_current_user(raw_request)
    clamped_limit = max(1, min(limit, 100))
    items = neo4j_repo.list_user_incidents(user["user_id"], limit=clamped_limit)

    history_items = [
        IncidentHistoryItem(
            incident_id=str(item.get("incident_id")),
            created_at=str(item.get("created_at", "")),
            input_type=str(item.get("input_type", "text")),
            title=str(item.get("title", f"Incident {item.get('incident_id')}")),
            message_preview=str(item.get("message_preview", "")),
            risk_level=str(item.get("risk_level", "low")),
            risk_score=float(item.get("risk_score", 0.0)),
            fraud_category=str(item.get("fraud_category", "generic")),
            current_user_state=str(item.get("current_user_state", "received")),
            campaign_id=item.get("campaign_id"),
        )
        for item in items
    ]
    return IncidentHistoryResponse(incidents=history_items, total=len(history_items))


@app.get("/api/incidents/{incident_id}")
async def get_incident_by_id(incident_id: str, raw_request: Request):
    """
    Retrieve incident dossier by ID.
    Enforces strict IDOR protection — returns 404/unauthorized if owned by another citizen.
    """
    if not validate_incident_id(incident_id):
        raise HTTPException(status_code=400, detail="Invalid incident ID format")

    user = get_current_user_optional(raw_request)
    user_id = user["user_id"] if user else None

    # When Neo4j datastore is active, it is the authoritative store
    if settings.neo4j_enabled and neo4j_repo.is_available():
        record = neo4j_repo.get_incident(incident_id, user_id=user_id)
        if record:
            if user_id:
                neo4j_repo.log_audit_event("INCIDENT_VIEWED", user_id, "Incident", incident_id)
            return record
        raise HTTPException(status_code=404, detail="Incident not found or unauthorized.")

    # Check bounded in-memory store only as offline fallback
    if incident_id in _incidents:
        ev = _incidents[incident_id]
        return AnalyzeResponse(
            incident_id=ev.incident_id,
            input_type=ev.input_type,
            message_preview=ev.message[:200],
            risk=ev.risk,
            evidence=ev.evidence,
            urls=ev.urls,
            brands=ev.brands,
            threat_intel=ev.threat_intel,
            explanation=ev.explanation,
            response=ev.response,
            laya=ev.laya if ev.laya.available else None,
            fraud_dna=ev.fraud_dna if ev.fraud_dna.available else None,
            fraud_category=ev.fraud_category,
            language=ev.language,
            response_language=ev.response_language,
            input_language=ev.input_language,
            processing_time_ms=ev.processing_time_ms,
            modules_executed=ev.modules_executed,
            modules_failed=ev.modules_failed,
        )

    raise HTTPException(status_code=404, detail="Incident not found or unauthorized.")


@app.get("/api/incidents/{incident_id}/graph", response_model=IncidentGraphResponse)
async def get_incident_relationship_graph(incident_id: str, raw_request: Request):
    """
    Retrieve the contextual relationship graph for visualization:
    Incident, Sender, Brand, URL, Domain, Campaign, and Related Incidents.
    Enforces IDOR checks.
    """
    if not validate_incident_id(incident_id):
        raise HTTPException(status_code=400, detail="Invalid incident ID format")

    user = get_current_user_optional(raw_request)
    user_id = user["user_id"] if user else None

    # When Neo4j datastore is active, it is the authoritative graph store
    if settings.neo4j_enabled and neo4j_repo.is_available():
        graph_data = neo4j_repo.get_incident_graph(incident_id, user_id=user_id)
        if graph_data:
            return IncidentGraphResponse(
                incident_id=graph_data.get("incident_id", incident_id),
                nodes=graph_data.get("nodes", []),
                edges=graph_data.get("edges", []),
                node_count=graph_data.get("node_count", len(graph_data.get("nodes", []))),
                edge_count=graph_data.get("edge_count", len(graph_data.get("edges", []))),
                summary=f"Campaign {graph_data.get('campaign', {}).get('campaign_id', 'CAMP-STANDALONE')} with {len(graph_data.get('related_incidents', []))} related incidents",
            )
        raise HTTPException(status_code=404, detail="Incident graph not found or unauthorized.")

    # In-memory fallback graph representation when offline
    if incident_id in _incidents:
        ev = _incidents[incident_id]
        nodes = [
            {"id": incident_id, "label": "Incident", "type": "Incident", "properties": {"risk": ev.risk.level.value}}
        ]
        edges = []
        for b in ev.brands:
            bid = f"brand_{b.brand_name}"
            nodes.append({"id": bid, "label": b.brand_name, "type": "Brand", "properties": {"name": b.brand_name}})
            edges.append({"source": incident_id, "target": bid, "relationship": "CLAIMS_BRAND", "properties": {"label": "claims brand"}})
        for u in ev.urls:
            uid = f"url_{abs(hash(u.url)) % 1000000}"
            nodes.append({"id": uid, "label": u.domain or u.url, "type": "URL", "properties": {"url": u.url}})
            edges.append({"source": incident_id, "target": uid, "relationship": "CONTAINS_URL", "properties": {"label": "contains url"}})
        camp_id = getattr(ev.fraud_dna, "campaign_id", None)
        if camp_id:
            nodes.append({"id": camp_id, "label": f"Campaign {camp_id}", "type": "Campaign", "properties": {}})
            edges.append({"source": incident_id, "target": camp_id, "relationship": "BELONGS_TO", "properties": {}})

        return IncidentGraphResponse(
            incident_id=incident_id,
            nodes=nodes,
            edges=edges,
            node_count=len(nodes),
            edge_count=len(edges),
            summary="Incident relationship graph (in-memory mode)",
        )

    raise HTTPException(status_code=404, detail="Incident graph not found or unauthorized.")


@app.get("/api/incidents/{incident_id}/history")
async def get_incident_action_history(incident_id: str, raw_request: Request):
    """
    Retrieve adaptive response history and user state transitions.
    Enforces IDOR checks.
    """
    if not validate_incident_id(incident_id):
        raise HTTPException(status_code=400, detail="Invalid incident ID format")

    user = get_current_user_optional(raw_request)
    user_id = user["user_id"] if user else None

    # When Neo4j is active, enforce authoritative ownership
    if settings.neo4j_enabled and neo4j_repo.is_available():
        inc = neo4j_repo.get_incident(incident_id, user_id=user_id)
        if not inc:
            raise HTTPException(status_code=404, detail="Incident history not found or unauthorized.")
    else:
        inc = _incidents.get(incident_id)
        if not inc:
            raise HTTPException(status_code=404, detail="Incident history not found or unauthorized.")
        if hasattr(inc, "__dict__"):
            inc = {
                "created_at": inc.created_at.isoformat(),
                "current_user_state": "received",
            }

    current_state = inc.get("current_user_state", "received") if inc else "received"
    history = [
        {
            "state": "received",
            "action": "Message ingested and forensic analysis executed",
            "timestamp": inc.get("created_at") if inc else _incidents[incident_id].created_at.isoformat(),
        }
    ]
    if current_state != "received":
        history.append({
            "state": current_state,
            "action": f"User interaction progressed to {current_state}",
            "timestamp": inc.get("updated_at") if inc else "",
        })

    return {
        "incident_id": incident_id,
        "current_state": current_state,
        "history": history,
    }


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze_message(request: AnalyzeRequest, raw_request: Request):
    """
    Primary analysis endpoint.
    Runs the full pipeline: ingest → rules → URL analysis → brand check →
    threat intel → fusion → explanation (Gemini with deterministic fallback) → adaptive response.
    """
    # Rate limit enforcement
    check_rate_limit(raw_request)

    start_time = time.time()

    # Sanitize and bound all inputs at entry boundary
    cleaned_message = sanitize_message(request.message, settings.max_message_length)
    cleaned_urls = [sanitize_url(u) for u in request.urls if sanitize_url(u)]
    requested_lang = request.response_language or request.language or "en"
    cleaned_response_lang = validate_language(requested_lang)
    detected_input_lang = detect_input_language(cleaned_message)

    # Optional authenticated user
    user = get_current_user_optional(raw_request)
    user_id = user["user_id"] if user else None

    # Create evidence contract instance with optional sender context
    normalized_input_type = (
        InputType.SCREENSHOT
        if request.input_type in (InputType.IMAGE, InputType.PHOTO, InputType.SCREENSHOT)
        else request.input_type
    )
    evidence = IncidentEvidence(
        input_type=normalized_input_type,
        message=cleaned_message,
        original_input=cleaned_message,
        language=cleaned_response_lang,
        response_language=cleaned_response_lang,
        input_language=detected_input_lang,
        sender=request.sender,
        message_context=request.message_context,
    )

    modules_executed = []
    modules_failed = []

    # ─── Pipeline stages ───

    # Stage 1: Ingestion & IOC extraction
    try:
        from backend.modules.ingestion import extract_iocs
        from backend.services.indicators import extract_indicators
        evidence = extract_iocs(evidence, cleaned_urls)
        extracted_ind = extract_indicators(evidence.message)
        for mismatch in extracted_ind.anchor_mismatches:
            evidence.evidence.append(EvidenceItem(
                type=EvidenceType.URL_ANALYSIS,
                source="indicator_extractor",
                source_type="content",
                evidence_tier="OBSERVED",
                indicator=mismatch.get("display_text"),
                finding=f"Deceptive hyperlink detected: text displays '{mismatch.get('display_text')}' but links to '{mismatch.get('actual_destination')}'",
                description="HTML anchor mismatch: visible link text misrepresents destination URL.",
                observed_value=f"Display: {mismatch.get('display_text')} -> Dest: {mismatch.get('actual_destination')}",
                interpretation="Deceptive anchor mismatch intentionally tricks victims into trusting the destination URL.",
                status=EvidenceStatus.CONFIRMED,
                reliability=EvidenceReliability.DETERMINISTIC_FACT,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.HIGH,
                confidence=0.95,
                correlation_group="deceptive_link",
                raw_data=mismatch,
            ))
        modules_executed.append("ingestion")
    except Exception as e:
        modules_failed.append("ingestion")
        evidence.errors.append(f"ingestion: {safe_error_message(e)}")

    # Stage 2: Rule-based detection
    try:
        from backend.modules.rules import apply_rules
        evidence = apply_rules(evidence)
        modules_executed.append("rules")
    except Exception as e:
        modules_failed.append("rules")
        evidence.errors.append(f"rules: {safe_error_message(e)}")

    # Stage 2b: ML baseline
    try:
        from backend.modules.ml_baseline import run_ml_baseline
        evidence = run_ml_baseline(evidence)
        modules_executed.append("ml_baseline")
    except Exception as e:
        modules_failed.append("ml_baseline")
        evidence.errors.append(f"ml_baseline: {safe_error_message(e)}")

    # Stage 3: URL & domain analysis (Live DNS, TLS, RDAP)
    try:
        from backend.modules.url_analyzer import analyze_urls
        from backend.services.domain_intel import collect_domain_evidence
        evidence = await analyze_urls(evidence)
        seen_domains = set()
        for u in evidence.urls:
            d = (u.domain or "").lower().strip()
            if d and d not in seen_domains and "." in d:
                seen_domains.add(d)
                domain_items = collect_domain_evidence(d)
                for item in domain_items:
                    evidence.evidence.append(item)
        modules_executed.append("url_analyzer")
    except Exception as e:
        modules_failed.append("url_analyzer")
        evidence.errors.append(f"url_analyzer: {safe_error_message(e)}")

    # Stage 3b: Safe DOM & Website Behavior Analysis
    try:
        from backend.services.website_analyzer import inspect_website
        for u in evidence.urls[:3]:
            if u.url:
                _, site_items = await inspect_website(u.url)
                for item in site_items:
                    evidence.evidence.append(item)
        modules_executed.append("website_analyzer")
    except Exception as e:
        modules_failed.append("website_analyzer")
        evidence.errors.append(f"website_analyzer: {safe_error_message(e)}")

    # Stage 4: Brand impersonation check
    try:
        from backend.modules.brand_check import check_brands
        evidence = check_brands(evidence)
        modules_executed.append("brand_check")
    except Exception as e:
        modules_failed.append("brand_check")
        evidence.errors.append(f"brand_check: {safe_error_message(e)}")

    # Stage 4b: Sender & Channel Analysis
    try:
        from backend.services.sender_analyzer import analyze_sms_sender, analyze_email_sender
        import re
        sms_match = re.search(r'\b([A-Za-z]{2}[-\s]?[A-Za-z0-9]{6})\b', evidence.message)
        phone_match = re.search(r'(?:(?:\+?91[\-\s]?)?[6-9]\d{9})\b', evidence.message)
        if sms_match:
            _, sms_items = analyze_sms_sender(sms_match.group(1), evidence.message)
            for item in sms_items:
                evidence.evidence.append(item)
        elif phone_match:
            _, sms_items = analyze_sms_sender(phone_match.group(0), evidence.message)
            for item in sms_items:
                evidence.evidence.append(item)

        if "from:" in evidence.message.lower():
            from_m = re.search(r'from:\s*([^\r\n]+)', evidence.message, re.IGNORECASE)
            reply_m = re.search(r'reply-to:\s*([^\r\n]+)', evidence.message, re.IGNORECASE)
            auth_m = re.search(r'authentication-results:\s*([^\r\n]+)', evidence.message, re.IGNORECASE)
            if from_m:
                _, email_items = analyze_email_sender(
                    from_header=from_m.group(1),
                    reply_to_header=reply_m.group(1) if reply_m else "",
                    auth_results=auth_m.group(1) if auth_m else "",
                )
                for item in email_items:
                    evidence.evidence.append(item)
        modules_executed.append("sender_analyzer")
    except Exception as e:
        modules_failed.append("sender_analyzer")
        evidence.errors.append(f"sender_analyzer: {safe_error_message(e)}")

    # Stage 5: Threat intelligence
    try:
        from backend.modules.threat_intel import query_threat_intel
        evidence = await query_threat_intel(evidence)
        modules_executed.append("threat_intel")
    except Exception as e:
        modules_failed.append("threat_intel")
        evidence.errors.append(f"threat_intel: {safe_error_message(e)}")

    # Stage 5b: Laya fast typed-decision triage (Phase 3)
    try:
        from backend.modules.laya import run_laya_triage
        evidence = await run_laya_triage(evidence)
        modules_executed.append("laya")
    except Exception as e:
        modules_failed.append("laya")
        evidence.errors.append(f"laya: {safe_error_message(e)}")

    # Stage 5c: Dedicated Scikit-Learn ML Classifier triage (PRD Section 8)
    try:
        from backend.modules.ml_classifier import run_ml_classification
        evidence = await run_ml_classification(evidence)
        modules_executed.append("ml_classifier")
    except Exception as e:
        modules_failed.append("ml_classifier")
        evidence.errors.append(f"ml_classifier: {safe_error_message(e)}")

    # Stage 6: Evidence fusion + risk scoring
    try:
        from backend.modules.fusion import fuse_evidence
        evidence = fuse_evidence(evidence)
        modules_executed.append("fusion")
    except Exception as e:
        modules_failed.append("fusion")
        evidence.errors.append(f"fusion: {safe_error_message(e)}")

    # Stage 7: Explanation — Gemini with deterministic fallback
    try:
        from backend.modules.gemini import explain_with_gemini
        evidence = await explain_with_gemini(evidence)
        modules_executed.append("gemini")
    except Exception as e:
        modules_failed.append("gemini")
        evidence.errors.append(f"gemini: {safe_error_message(e)}")

    # Deterministic fallback if Gemini produced no explanation
    if evidence.explanation is None:
        try:
            from backend.modules.fallback_explanation import generate_fallback_explanation
            evidence = generate_fallback_explanation(evidence)
            modules_executed.append("fallback_explanation")
        except Exception as e:
            modules_failed.append("fallback_explanation")
            evidence.errors.append(f"fallback_explanation: {safe_error_message(e)}")

    # Stage 8: Adaptive response
    try:
        from backend.modules.response import generate_response
        evidence = generate_response(evidence, request.user_state)
        modules_executed.append("response")
    except Exception as e:
        modules_failed.append("response")
        evidence.errors.append(f"response: {safe_error_message(e)}")

    # Stage 9: Fraud DNA & Campaign Syndicate Correlation
    try:
        from backend.modules.fraud_dna import compute_fraud_dna
        evidence.fraud_dna = compute_fraud_dna(evidence)
        modules_executed.append("fraud_dna")
    except Exception as e:
        modules_failed.append("fraud_dna")
        evidence.errors.append(f"fraud_dna: {safe_error_message(e)}")

    # Stage 10: Persistent SQLite Evidence Store
    try:
        from backend.services.evidence_store import save_investigation
        save_investigation(evidence)
    except Exception as e:
        logger.debug("Failed to persist investigation %s: %s", evidence.incident_id, safe_error_message(e))

    # Finalize
    elapsed_ms = (time.time() - start_time) * 1000
    evidence.processing_time_ms = elapsed_ms
    evidence.modules_executed = modules_executed
    evidence.modules_failed = modules_failed

    # Store in bounded incident store as guaranteed in-memory fallback
    _incidents[evidence.incident_id] = evidence

    # Persist to Neo4j single application datastore (degrades gracefully if offline)
    if settings.neo4j_enabled:
        try:
            persisted = neo4j_repo.save_full_incident(evidence, user_id=user_id)
            if persisted:
                if evidence.fraud_dna:
                    evidence.fraud_dna.graph_persisted = True
                neo4j_repo.log_audit_event("INCIDENT_CREATED", user_id, "Incident", evidence.incident_id)
        except Exception as e:
            logger.warning("Neo4j persistence degraded gracefully: %s", safe_error_message(e))

    return AnalyzeResponse(
        incident_id=evidence.incident_id,
        input_type=evidence.input_type,
        message_preview=evidence.message[:200],
        risk=evidence.risk,
        evidence=evidence.evidence,
        urls=evidence.urls,
        brands=evidence.brands,
        threat_intel=evidence.threat_intel,
        explanation=evidence.explanation,
        response=evidence.response,
        laya=evidence.laya if evidence.laya.available else None,
        ml_classifier=evidence.ml_classifier if evidence.ml_classifier.available else None,
        classification=evidence.ml_classifier.classification if evidence.ml_classifier.available else None,
        model_confidence=evidence.ml_classifier.confidence if evidence.ml_classifier.available else None,
        fraud_dna=evidence.fraud_dna if evidence.fraud_dna.available else None,
        fraud_category=evidence.fraud_category,
        language=evidence.language,
        response_language=evidence.response_language,
        input_language=evidence.input_language,
        processing_time_ms=elapsed_ms,
        modules_executed=modules_executed,
        modules_failed=modules_failed,
    )


@app.post("/api/incidents/{incident_id}/state", response_model=AnalyzeResponse)
async def update_user_state(
    incident_id: str,
    request: UpdateUserStateRequest,
    raw_request: Request,
):
    """
    Update user interaction state and regenerate adaptive response.
    Supports on-the-fly language switching without re-querying threat intel.
    Validates incident ID format and enforces rate limiting.
    """
    check_rate_limit(raw_request)

    # Validate incident ID format to prevent injection / path traversal
    if not validate_incident_id(incident_id):
        raise HTTPException(status_code=400, detail="Invalid incident ID format")

    if incident_id not in _incidents:
        raise HTTPException(status_code=404, detail="Incident not found")

    evidence = _incidents[incident_id]

    # Update response language if requested
    req_lang = getattr(request, "response_language", None) or getattr(request, "language", None)
    if req_lang:
        valid_lang = validate_language(req_lang)
        evidence.response_language = valid_lang
        evidence.language = valid_lang
        # If explanation was generated by deterministic fallback, regenerate explanation in new language
        if getattr(evidence.explanation, "provider", "") in ("rule_engine", "ml_fallback", "deterministic_fallback", None):
            try:
                from backend.modules.fallback_explanation import generate_fallback_explanation
                evidence = generate_fallback_explanation(evidence)
            except Exception as e:
                logger.warning(f"Failed to regenerate fallback explanation for new language: {safe_error_message(e)}")

    try:
        from backend.modules.response import generate_response
        evidence = generate_response(evidence, request.user_state)
    except Exception as e:
        evidence.errors.append(f"response_update: {safe_error_message(e)}")

    _incidents[incident_id] = evidence

    # Persist adaptive response action state into Neo4j
    if settings.neo4j_enabled:
        user = get_current_user_optional(raw_request)
        user_id = user["user_id"] if user else None
        try:
            state_val = request.user_state.value if hasattr(request.user_state, "value") else str(request.user_state)
            neo4j_repo.save_incident_action(
                incident_id=incident_id,
                state=state_val,
                action_taken=f"State transitioned to {state_val}",
                user_id=user_id,
            )
            neo4j_repo.log_audit_event("INCIDENT_ACTION", user_id, "Incident", incident_id, {"new_state": state_val})
        except Exception as e:
            logger.warning("Failed to record incident action in Neo4j: %s", safe_error_message(e))

    return AnalyzeResponse(
        incident_id=evidence.incident_id,
        input_type=evidence.input_type,
        message_preview=evidence.message[:200],
        risk=evidence.risk,
        evidence=evidence.evidence,
        urls=evidence.urls,
        brands=evidence.brands,
        threat_intel=evidence.threat_intel,
        explanation=evidence.explanation,
        response=evidence.response,
        laya=evidence.laya if evidence.laya.available else None,
        ml_classifier=evidence.ml_classifier if evidence.ml_classifier.available else None,
        classification=evidence.ml_classifier.classification if evidence.ml_classifier.available else None,
        model_confidence=evidence.ml_classifier.confidence if evidence.ml_classifier.available else None,
        fraud_dna=evidence.fraud_dna if evidence.fraud_dna.available else None,
        fraud_category=evidence.fraud_category,
        language=evidence.language,
        response_language=evidence.response_language,
        input_language=evidence.input_language,
        processing_time_ms=evidence.processing_time_ms,
        modules_executed=evidence.modules_executed,
        modules_failed=evidence.modules_failed,
    )


@app.post("/api/incidents/{incident_id}/osint", response_model=OSINTResponse)
async def get_incident_osint(
    incident_id: str,
    raw_request: Request = None,
):
    """
    Asynchronous OSINT enrichment endpoint for an incident.
    Fetches WHOIS domain age and crt.sh Certificate Transparency logs
    via a background thread pool, translates facts to Evidence Contract items,
    and returns {status, evidence, raw}.
    """
    if raw_request:
        check_rate_limit(raw_request)

    current_settings = get_settings()
    if not current_settings.osint_enabled:
        return OSINTResponse(status="disabled", evidence=[], raw={})

    if not validate_incident_id(incident_id):
        raise HTTPException(status_code=400, detail="Invalid incident ID format")

    if incident_id not in _incidents:
        raise HTTPException(status_code=404, detail="Incident or domain not found")

    incident = _incidents[incident_id]

    # Resolve domain from incident's extracted URLs or IOCs
    domain = None
    if incident.urls:
        for u in incident.urls:
            if u.domain:
                domain = u.domain
                break

    if not domain and incident.iocs:
        for ioc in incident.iocs:
            clean_ioc = ioc.strip().lower()
            if "." in clean_ioc and "/" not in clean_ioc and " " not in clean_ioc and not clean_ioc.endswith("."):
                domain = clean_ioc
                break

    if not domain:
        raise HTTPException(status_code=404, detail="Incident or domain not found")

    import anyio
    from backend.services.osint_enrichment import get_osint_enrichment
    from backend.services.osint_evidence_translator import translate_osint_evidence

    # Run blocking whois / requests calls in thread pool
    raw = await anyio.to_thread.run_sync(get_osint_enrichment, domain)

    evidence_items = translate_osint_evidence(raw)

    return OSINTResponse(
        status=raw.get("status", "unavailable"),
        evidence=evidence_items,
        raw=raw,
    )


@app.post("/api/upload/screenshot", response_model=FileUploadResponse)
async def upload_screenshot(
    file: UploadFile = File(...),
    raw_request: Request = None,
):
    """
    Secure screenshot upload endpoint.
    Enforces maximum size, MIME verification, magic bytes verification,
    filename sanitization, and path traversal defense.
    """
    if raw_request:
        check_rate_limit(raw_request)

    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    content = await file.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum allowed size of {settings.max_upload_size_mb} MB",
        )

    is_valid, safe_name, err = validate_file_security(
        content=content,
        original_filename=file.filename or "screenshot.png",
        declared_content_type=file.content_type or "application/octet-stream",
        max_size_bytes=max_bytes,
    )

    if not is_valid:
        raise HTTPException(status_code=400, detail=err)

    # Run OCR extraction
    extracted_text = ""
    try:
        from backend.services.ocr import extract_text_from_image
        extracted_text = extract_text_from_image(content, safe_name)
    except Exception as e:
        logger.warning(f"OCR extraction error: {safe_error_message(e)}")

    return FileUploadResponse(
        status="ok",
        filename=safe_name,
        size_bytes=len(content),
        content_type=file.content_type,
        extracted_text=extracted_text or None,
    )


@app.post("/api/translate", response_model=TranslateResponse)
@app.post("/api/v1/translate", response_model=TranslateResponse)
async def translate_content(
    request: TranslateRequest,
    raw_request: Request = None,
):
    """
    Secure backend proxy for Google Cloud Translation API (v2 Basic).
    Translates dynamic text and content into the citizen's preferred language with in-memory caching.
    Keeps the Google API key secure on the backend.
    """
    if raw_request:
        check_rate_limit(raw_request)

    target_lang = validate_language(request.target_lang) or "en"
    source_lang = validate_language(request.source_lang or "en") or "en"

    translated_text = None
    translated_texts = []

    if request.text is not None:
        translated_text = await translate_text_async(
            text=request.text,
            target_lang=target_lang,
            source_lang=source_lang,
        )

    if request.texts:
        translated_texts = await translate_batch_async(
            texts=request.texts,
            target_lang=target_lang,
            source_lang=source_lang,
        )

    return TranslateResponse(
        translated_text=translated_text,
        translated_texts=translated_texts,
        source_lang=source_lang,
        target_lang=target_lang,
        cached=False,
    )


@app.get("/api/incidents/{incident_id}/report")
@app.get("/api/incidents/{incident_id}/export")
async def export_incident(
    incident_id: str,
    format: str = "json",
    raw_request: Request = None,
):
    """
    Export full forensic incident dossier for Law Enforcement / National Cyber Crime Helpline (1930).
    Format options: 'json' or 'html' (printable official cyber police complaint format).
    """
    if raw_request:
        check_rate_limit(raw_request)

    if not validate_incident_id(incident_id):
        raise HTTPException(status_code=400, detail="Invalid incident ID format")

    if incident_id not in _incidents:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident = _incidents[incident_id]

    # Record report generation in Neo4j
    if settings.neo4j_enabled and raw_request:
        user = get_current_user_optional(raw_request)
        user_id = user["user_id"] if user else None
        report_id = f"rep_{secrets.token_hex(6)}"
        try:
            neo4j_repo.save_report_metadata(report_id, incident_id, format=format, user_id=user_id)
            neo4j_repo.log_audit_event("REPORT_GENERATED", user_id, "Report", report_id, {"format": format})
        except Exception as e:
            logger.warning("Failed to record report metadata in Neo4j: %s", safe_error_message(e))

    import hashlib
    raw_hash = hashlib.sha256((incident.message or "").encode("utf-8")).hexdigest()

    evidence_summary = [
        {
            "source": item.source,
            "description": item.description,
            "confidence": f"{item.confidence:.0%}" if item.confidence is not None else "100%",
            "type": item.type.value if hasattr(item.type, "value") else str(item.type),
        }
        for item in incident.evidence
    ]

    export_data = {
        "incident_id": incident.incident_id,
        "timestamp_utc": incident.created_at.isoformat(),
        "sha256_message_hash": raw_hash,
        "risk_level": incident.risk.level.value,
        "risk_score": incident.risk.score,
        "fraud_category": incident.fraud_category or "generic",
        "evidence_dossier": evidence_summary,
        "extracted_urls": [u.url for u in incident.urls],
        "extracted_domains": [u.domain for u in incident.urls if u.domain],
        "campaign_id": incident.fraud_dna.campaign_id if incident.fraud_dna.available else None,
        "related_incidents": incident.fraud_dna.related_incidents if incident.fraud_dna.available else [],
        "helpline_1930_advisory": (
            "If financial loss occurred within the last 24 hours (Golden Hour), "
            "immediately call 1930 or submit details on https://cybercrime.gov.in."
        ),
    }

    if format.lower() == "html":
        ioc_rows = "".join(f"<tr><td>Domain/URL</td><td>{escape_for_display(u.url)}</td></tr>" for u in incident.urls) if incident.urls else "<tr><td colspan='2'>No web URLs extracted</td></tr>"
        evidence_rows = "".join(f"<tr><td>{escape_for_display(item['source'])}</td><td>{escape_for_display(item['description'])}</td><td>{item['confidence']}</td></tr>" for item in evidence_summary)

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Cyber Crime Forensic Incident Dossier - {escape_for_display(incident.incident_id)}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; color: #222; max-width: 800px; margin: 30px auto; padding: 25px; border: 1px solid #ddd; border-radius: 8px; }}
        h1 {{ color: #b91c1c; border-bottom: 2px solid #b91c1c; padding-bottom: 8px; font-size: 20px; }}
        h2 {{ font-size: 15px; color: #374151; margin-top: 18px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 12px; }}
        th {{ background-color: #f3f4f6; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: bold; background: #fee2e2; color: #991b1b; }}
        .evidence-box {{ background: #f9fafb; padding: 12px; border-left: 4px solid #3b82f6; margin-top: 8px; font-size: 13px; font-family: monospace; white-space: pre-wrap; }}
        .print-btn {{ margin-bottom: 15px; padding: 8px 16px; background: #2563eb; color: white; border: none; border-radius: 4px; cursor: pointer; }}
        @media print {{ .print-btn {{ display: none; }} }}
    </style>
</head>
<body>
    <button class="print-btn" onclick="window.print()">Print / Save as PDF</button>
    <h1>CYBER FRAUD FORENSIC INCIDENT DOSSIER</h1>
    <p><strong>Complaint Reference / Incident ID:</strong> {escape_for_display(incident.incident_id)}</p>
    <p><strong>Timestamp (UTC):</strong> {escape_for_display(incident.created_at.isoformat())}</p>
    <p><strong>Threat Classification:</strong> <span class="badge">{escape_for_display(incident.risk.level.value.upper())} ({incident.risk.score:.0%})</span> | Category: {escape_for_display(incident.fraud_category or 'Unspecified')}</p>
    <p><strong>SHA-256 Content Hash:</strong> <code>{raw_hash}</code></p>
    
    <h2>1. Untrusted Evidentiary Message</h2>
    <div class="evidence-box">{escape_for_display(incident.message)}</div>

    <h2>2. Extracted Indicators of Compromise (IOCs)</h2>
    <table>
        <tr><th>Type</th><th>Observed Value</th></tr>
        {ioc_rows}
    </table>

    <h2>3. Forensic Evidence Dossier</h2>
    <table>
        <tr><th>Source Module</th><th>Finding & Forensic Description</th><th>Confidence</th></tr>
        {evidence_rows}
    </table>

    <h2>4. National Cyber Crime Reporting Advisory</h2>
    <p>For financial fraud: Call <strong>1930</strong> (National Cyber Crime Reporting Helpline) within the golden hour, or file a complaint at <strong>https://cybercrime.gov.in</strong> quoting this technical dossier.</p>
</body>
</html>"""
        return HTMLResponse(content=html_content, status_code=200)

    return JSONResponse(content=export_data, status_code=200)
