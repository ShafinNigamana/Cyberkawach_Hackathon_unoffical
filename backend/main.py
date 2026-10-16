"""
FastAPI application entry point.
Configures security middleware, static asset routing, modular API routers,
and graceful application lifecycle management.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.config import get_settings
from backend.routes.analysis import analysis_router
from backend.routes.auth import (
    auth_router,
    get_current_user,
    get_current_user_optional,
)
from backend.routes.file_scan import file_scan_router
from backend.routes.incidents import incidents_router
from backend.routes.tools import tools_router
from backend.routes.verification import verification_router
from backend.services.incident_store import (
    BoundedIncidentStore,
    incident_store,
)
from backend.services.neo4j_repository import neo4j_repo
from backend.utils.request_limits import RequestSizeLimitMiddleware
from backend.utils.security_headers import SecurityHeadersMiddleware
from backend.utils.security_logging import safe_error_message

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cyber_guardian.main")

settings = get_settings()

# Backward-compatible reference for tests importing `from backend.main import _incidents`
_incidents = incident_store


# ─── Lifespan Context Manager (Schema init & graceful teardown) ───

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Cleanly initialize datastore schema constraints on startup and close cleanly on shutdown."""
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
    description="Citizen Fraud-Message Guardian — high-assurance, evidence-driven cyber fraud triage",
    version="1.0.0",
    lifespan=lifespan,
)

# ─── Security Middleware Stack (Applied in reverse order of addition) ───

# 1. Enforce strict response security headers (HSTS, CSP, nosniff, frame-ancestors, etc.)
app.add_middleware(SecurityHeadersMiddleware)

# 2. Enforce request size limits (prevents payload-based memory exhaustion / DoS)
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


# ─── Exception Handlers (Prevent stack traces and sensitive path leaks) ───

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Safe validation error handler that strips internal representation."""
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
    """Catch-all error handler preventing internal disclosures."""
    safe_msg = safe_error_message(exc)
    logger.error("Unhandled server exception: %s", safe_msg)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "detail": "An internal error occurred during processing. Please try again later.",
        },
    )


# ─── Register Modular API Routers ───

app.include_router(verification_router)
app.include_router(auth_router)
app.include_router(incidents_router)
app.include_router(analysis_router)
app.include_router(tools_router)
app.include_router(file_scan_router)


# ─── Observability Endpoint (Phase 6) ───

@app.get("/metrics", tags=["observability"])
async def get_metrics():
    """Exposes real-time Prometheus telemetry metrics for scraping."""
    from fastapi.responses import Response
    from backend.utils.telemetry import get_prometheus_metrics_payload

    payload, content_type = get_prometheus_metrics_payload()
    return Response(content=payload, media_type=content_type)


# ─── Static Files & Single Page App Fallback Mounts ───

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


# Compatibility exports for test suites
__all__ = [
    "app",
    "_incidents",
    "get_current_user",
    "get_current_user_optional",
    "BoundedIncidentStore",
]
