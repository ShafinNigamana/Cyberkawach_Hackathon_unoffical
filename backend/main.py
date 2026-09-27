"""
FastAPI application entry point.
Defines API routes, security middleware, and wires the analysis pipeline.
"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict
from pathlib import Path
from threading import Lock

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.config import get_settings
from backend.models.api import (
    AnalyzeRequest,
    AnalyzeResponse,
    FileUploadResponse,
    HealthResponse,
    OSINTResponse,
    UpdateUserStateRequest,
)
from backend.models.evidence import IncidentEvidence, InputType
from backend.utils.file_security import validate_file_security
from backend.utils.rate_limiter import check_rate_limit
from backend.utils.request_limits import RequestSizeLimitMiddleware
from backend.utils.sanitize import (
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

app = FastAPI(
    title="Cyber Fraud Guardian",
    description="Citizen Fraud-Message Guardian — evidence-driven fraud analysis",
    version="0.1.0",
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
    allow_methods=["GET", "POST"],
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
        },
        api_keys_configured=settings.api_availability(),
    )


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
    cleaned_lang = validate_language(request.language)

    # Create evidence contract instance
    evidence = IncidentEvidence(
        input_type=request.input_type,
        message=cleaned_message,
        original_input=cleaned_message,
        language=cleaned_lang,
    )

    modules_executed = []
    modules_failed = []

    # ─── Pipeline stages ───

    # Stage 1: Ingestion & IOC extraction
    try:
        from backend.modules.ingestion import extract_iocs
        evidence = extract_iocs(evidence, cleaned_urls)
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

    # Stage 3: URL & domain analysis
    try:
        from backend.modules.url_analyzer import analyze_urls
        evidence = await analyze_urls(evidence)
        modules_executed.append("url_analyzer")
    except Exception as e:
        modules_failed.append("url_analyzer")
        evidence.errors.append(f"url_analyzer: {safe_error_message(e)}")

    # Stage 4: Brand impersonation check
    try:
        from backend.modules.brand_check import check_brands
        evidence = check_brands(evidence)
        modules_executed.append("brand_check")
    except Exception as e:
        modules_failed.append("brand_check")
        evidence.errors.append(f"brand_check: {safe_error_message(e)}")

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

    # Finalize
    elapsed_ms = (time.time() - start_time) * 1000
    evidence.processing_time_ms = elapsed_ms
    evidence.modules_executed = modules_executed
    evidence.modules_failed = modules_failed

    # Store in bounded incident store
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
async def update_user_state(
    incident_id: str,
    request: UpdateUserStateRequest,
    raw_request: Request,
):
    """
    Update user interaction state and regenerate adaptive response.
    Validates incident ID format and enforces rate limiting.
    """
    check_rate_limit(raw_request)

    # Validate incident ID format to prevent injection / path traversal
    if not validate_incident_id(incident_id):
        raise HTTPException(status_code=400, detail="Invalid incident ID format")

    if incident_id not in _incidents:
        raise HTTPException(status_code=404, detail="Incident not found")

    evidence = _incidents[incident_id]

    try:
        from backend.modules.response import generate_response
        evidence = generate_response(evidence, request.user_state)
    except Exception as e:
        evidence.errors.append(f"response_update: {safe_error_message(e)}")

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
