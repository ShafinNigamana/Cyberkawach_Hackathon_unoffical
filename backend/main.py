"""
FastAPI application entry point.
Defines API routes and wires the analysis pipeline.
"""

from __future__ import annotations

import time

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from backend.config import get_settings
from backend.models.api import (
    AnalyzeRequest,
    AnalyzeResponse,
    ErrorResponse,
    HealthResponse,
    UpdateUserStateRequest,
)
from backend.models.evidence import IncidentEvidence, InputType

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

# In-memory incident store — ponytail: no DB for hackathon demo
_incidents: dict[str, IncidentEvidence] = {}


@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    """System health — which modules and APIs are available."""
    return HealthResponse(
        status="ok",
        version="0.1.0",
        modules={
            "ingestion": True,
            "rules": True,
            "url_analyzer": True,
            "brand_check": True,
            "threat_intel": True,
            "fusion": True,
            "gemini": True,  # Non-critical — deterministic fallback always available
            "laya": False,  # P1 — not wired yet
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
        fraud_dna=evidence.fraud_dna if evidence.fraud_dna.available else None,
        fraud_category=evidence.fraud_category,
        language=evidence.language,
        processing_time_ms=evidence.processing_time_ms,
        modules_executed=evidence.modules_executed,
        modules_failed=evidence.modules_failed,
    )
