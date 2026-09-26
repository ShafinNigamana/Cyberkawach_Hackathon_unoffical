"""
FastAPI application entry point.
Defines API routes and wires the analysis pipeline.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.config import get_settings
from backend.models.api import (
    AnalyzeRequest,
    AnalyzeResponse,
    ErrorResponse,
    HealthResponse,
    UpdateUserStateRequest,
)
from backend.models.evidence import IncidentEvidence, InputType
from backend.utils.rate_limit import RateLimitMiddleware

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cyber_guardian.main")

settings = get_settings()

app = FastAPI(
    title="Cyber Fraud Guardian",
    description="Citizen Fraud-Message Guardian — evidence-driven fraud analysis",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware, max_requests=120, window_seconds=60)

# In-memory incident store — ponytail: no DB for hackathon demo
_incidents: dict[str, IncidentEvidence] = {}

# Static files mounts for frontend and demo fixtures
frontend_path = Path(__file__).resolve().parent.parent / "frontend"
fixtures_path = Path(__file__).resolve().parent.parent / "fixtures"

if fixtures_path.exists():
    app.mount("/fixtures", StaticFiles(directory=str(fixtures_path)), name="fixtures")

if frontend_path.exists():
    css_path = frontend_path / "css"
    js_path = frontend_path / "js"
    if css_path.exists():
        app.mount("/css", StaticFiles(directory=str(css_path)), name="css")
    if js_path.exists():
        app.mount("/js", StaticFiles(directory=str(js_path)), name="js")

    @app.get("/")
    async def serve_index():
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
            "ocr": False,  # P1 — not wired yet
            "fraud_dna": False,  # P2 — not wired yet
        },
        api_keys_configured=settings.api_availability(),
    )


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze_message(request: AnalyzeRequest):
    """
    Primary analysis endpoint.
    Runs the full pipeline: ingest → rules → URL analysis → brand check →
    threat intel → fusion → explanation (Gemini with deterministic fallback) → adaptive response.
    """
    start_time = time.time()

    # Create evidence contract instance
    evidence = IncidentEvidence(
        input_type=request.input_type,
        message=request.message,
        original_input=request.message,
        language=request.language,
    )

    modules_executed = []
    modules_failed = []

    # ─── Pipeline stages (each will be implemented in Phase 1) ───

    # Stage 1: Ingestion & IOC extraction
    try:
        from backend.modules.ingestion import extract_iocs
        evidence = extract_iocs(evidence, request.urls)
        modules_executed.append("ingestion")
    except Exception as e:
        modules_failed.append("ingestion")
        evidence.errors.append(f"ingestion: {str(e)}")

    # Stage 2: Rule-based detection
    try:
        from backend.modules.rules import apply_rules
        evidence = apply_rules(evidence)
        modules_executed.append("rules")
    except Exception as e:
        modules_failed.append("rules")
        evidence.errors.append(f"rules: {str(e)}")

    # Stage 2b: ML baseline (TF-IDF + Logistic Regression statistical classifier)
    try:
        from backend.modules.ml_baseline import run_ml_baseline
        evidence = run_ml_baseline(evidence)
        modules_executed.append("ml_baseline")
    except Exception as e:
        modules_failed.append("ml_baseline")
        evidence.errors.append(f"ml_baseline: {str(e)}")

    # Stage 3: URL & domain analysis
    try:
        from backend.modules.url_analyzer import analyze_urls
        evidence = await analyze_urls(evidence)
        modules_executed.append("url_analyzer")
    except Exception as e:
        modules_failed.append("url_analyzer")
        evidence.errors.append(f"url_analyzer: {str(e)}")

    # Stage 4: Brand impersonation check
    try:
        from backend.modules.brand_check import check_brands
        evidence = check_brands(evidence)
        modules_executed.append("brand_check")
    except Exception as e:
        modules_failed.append("brand_check")
        evidence.errors.append(f"brand_check: {str(e)}")

    # Stage 5: Threat intelligence
    try:
        from backend.modules.threat_intel import query_threat_intel
        evidence = await query_threat_intel(evidence)
        modules_executed.append("threat_intel")
    except Exception as e:
        modules_failed.append("threat_intel")
        evidence.errors.append(f"threat_intel: {str(e)}")

    # Stage 5b: Laya fast typed-decision triage (Phase 3)
    try:
        from backend.modules.laya import run_laya_triage
        evidence = await run_laya_triage(evidence)
        modules_executed.append("laya")
    except Exception as e:
        modules_failed.append("laya")
        evidence.errors.append(f"laya: {str(e)}")

    # Stage 6: Evidence fusion + risk scoring
    try:
        from backend.modules.fusion import fuse_evidence
        evidence = fuse_evidence(evidence)
        modules_executed.append("fusion")
    except Exception as e:
        modules_failed.append("fusion")
        evidence.errors.append(f"fusion: {str(e)}")

    # Stage 7: Explanation — Gemini with deterministic fallback
    try:
        from backend.modules.gemini import explain_with_gemini
        evidence = await explain_with_gemini(evidence)
        modules_executed.append("gemini")
    except Exception as e:
        modules_failed.append("gemini")
        evidence.errors.append(f"gemini: {str(e)}")

    # Deterministic fallback: if Gemini didn't produce an explanation, generate one from evidence
    if evidence.explanation is None:
        try:
            from backend.modules.fallback_explanation import generate_fallback_explanation
            evidence = generate_fallback_explanation(evidence)
            modules_executed.append("fallback_explanation")
        except Exception as e:
            modules_failed.append("fallback_explanation")
            evidence.errors.append(f"fallback_explanation: {str(e)}")

    # Stage 8: Adaptive response
    try:
        from backend.modules.response import generate_response
        evidence = generate_response(evidence, request.user_state)
        modules_executed.append("response")
    except Exception as e:
        modules_failed.append("response")
        evidence.errors.append(f"response: {str(e)}")

    # Finalize
    elapsed_ms = (time.time() - start_time) * 1000
    evidence.processing_time_ms = elapsed_ms
    evidence.modules_executed = modules_executed
    evidence.modules_failed = modules_failed

    # Store for later state updates
    _incidents[evidence.incident_id] = evidence

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
        fraud_dna=evidence.fraud_dna if evidence.fraud_dna.available else None,
        fraud_category=evidence.fraud_category,
        language=evidence.language,
        processing_time_ms=elapsed_ms,
        modules_executed=modules_executed,
        modules_failed=modules_failed,
    )


@app.post("/api/incidents/{incident_id}/state", response_model=AnalyzeResponse)
async def update_user_state(incident_id: str, request: UpdateUserStateRequest):
    """
    Update user interaction state and regenerate adaptive response.
    Demo feature: shows response branching when user state changes.
    """
    if incident_id not in _incidents:
        raise HTTPException(status_code=404, detail="Incident not found")

    evidence = _incidents[incident_id]

    try:
        from backend.modules.response import generate_response
        evidence = generate_response(evidence, request.user_state)
    except Exception as e:
        evidence.errors.append(f"response_update: {str(e)}")

    _incidents[incident_id] = evidence

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
        fraud_dna=evidence.fraud_dna if evidence.fraud_dna.available else None,
        fraud_category=evidence.fraud_category,
        language=evidence.language,
        processing_time_ms=evidence.processing_time_ms,
        modules_executed=evidence.modules_executed,
        modules_failed=evidence.modules_failed,
    )
