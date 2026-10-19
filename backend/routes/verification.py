"""
Verification & Security Self-Test Endpoints.
Enables automated health, sanity, and security test suites without exposing sensitive secrets.
"""

from __future__ import annotations

import time
from fastapi import APIRouter, HTTPException, Request

from backend.config import get_settings

verification_router = APIRouter(prefix="/api/verification", tags=["verification"])
settings = get_settings()

_rate_test_tracker: dict[str, list[float]] = {}


@verification_router.get("/status")
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


@verification_router.post("/check-ssrf")
async def check_ssrf_test(data: dict):
    """Test SSRF validation logic against synthetic targets."""
    url = data.get("url", "")
    from backend.utils.sanitize import is_safe_url

    safe = is_safe_url(url)
    return {
        "url": url,
        "is_safe": safe,
        "status": "ALLOWED" if safe else "BLOCKED",
        "reason": (
            "External web destination"
            if safe
            else "Local/Private/Loopback target blocked (SSRF defense)"
        ),
    }


@verification_router.post("/check-pii")
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


@verification_router.post("/check-prompt-injection")
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


@verification_router.get("/rate-limit-test")
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
