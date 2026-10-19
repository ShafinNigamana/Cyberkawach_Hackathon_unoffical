"""
Primary Forensic Triage Analysis Router.
Exposes the core citizen message and URL evaluation endpoint /api/analyze and system /api/health.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from backend.config import get_settings
from backend.models.api import AnalyzeRequest, AnalyzeResponse, HealthResponse
from backend.routes.auth import get_current_user_optional
from backend.services.incident_store import incident_store
from backend.services.pipeline_service import execute_analysis_pipeline
from backend.utils.rate_limiter import check_rate_limit
from backend.utils.security_logging import safe_error_message

logger = logging.getLogger("cyber_guardian.analysis")
settings = get_settings()

analysis_router = APIRouter(prefix="/api", tags=["analysis"])


@analysis_router.get("/health", response_model=HealthResponse)
async def health_check():
    """System health — which modules and external threat intel APIs are available."""
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
            "laya": True,
            "fusion": True,
            "gemini": True,
            "ocr": True,
            "fraud_dna": True,
            "neo4j": settings.neo4j_enabled,
        },
        api_keys_configured=settings.api_availability(),
    )


@analysis_router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_message(request: AnalyzeRequest, raw_request: Request):
    """
    Primary analysis endpoint.
    Runs the full 10-stage forensic pipeline:
    Ingestion → Rules → URL/OSINT Analysis → Brand Check → Threat Intel →
    Laya Triage → ML Classifier → Risk Fusion → Epistemic Explanation →
    Adaptive Guidance → Fraud DNA Persistence.
    """
    check_rate_limit(raw_request)

    user = get_current_user_optional(raw_request)
    user_id = user["user_id"] if user else None

    evidence = await execute_analysis_pipeline(
        message=request.message,
        urls=request.urls,
        user_state=request.user_state,
        response_language=request.response_language,
        language=request.language,
        input_type=request.input_type,
        sender=request.sender,
        message_context=request.message_context,
        user_id=user_id,
    )

    # Save to bounded LRU cache
    incident_store[evidence.incident_id] = evidence

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


@analysis_router.post("/analyze/stream")
async def analyze_message_stream(request: AnalyzeRequest, raw_request: Request):
    """
    Real-Time Server-Sent Events (SSE) Streaming Analysis Endpoint (Phase 3).
    Progressively yields actual forensic discovery events as the pipeline executes:
    - pipeline_started: Initial ingestion and parameter validation
    - ioc_discovered: URLs, phone numbers, UPI handles, IFSC routing codes extracted
    - infrastructure_resolved: DNS, BGP ASN, and SSL certificate telemetry completed
    - threat_intel_hits: Live checks against Google Safe Browsing, PhishTank, URLhaus completed
    - provider_degraded: Emitted if any downstream threat provider or datastore circuit is tripped
    - final_verdict: Full synthesized risk assessment, epistemic bounds, and adaptive response
    """
    check_rate_limit(raw_request)

    user = get_current_user_optional(raw_request)
    user_id = user["user_id"] if user else None

    async def event_generator():
        queue: asyncio.Queue = asyncio.Queue()

        async def stream_callback(event_name: str, event_data: dict[str, Any]):
            await queue.put((event_name, event_data))

        # Check circuit breaker statuses for degraded providers
        try:
            from backend.utils.circuit_breaker import get_all_circuit_breakers

            cb_statuses = get_all_circuit_breakers()
            for name, status in cb_statuses.items():
                if not status.get("is_available"):
                    await stream_callback(
                        "provider_degraded",
                        {
                            "provider": name,
                            "state": status.get("state"),
                            "cooldown_remaining": status.get("cooldown_remaining_seconds"),
                        },
                    )
        except Exception as e:
            logger.debug("Failed to inspect circuit breakers for stream: %s", safe_error_message(e))

        # Run pipeline in background task while yielding events from queue
        pipeline_task = asyncio.create_task(
            execute_analysis_pipeline(
                message=request.message,
                urls=request.urls,
                user_state=request.user_state,
                response_language=request.response_language,
                language=request.language,
                input_type=request.input_type,
                sender=request.sender,
                message_context=request.message_context,
                user_id=user_id,
                event_callback=stream_callback,
            )
        )

        try:
            # 1. Immediate pipeline_started event
            yield f"event: pipeline_started\ndata: {json.dumps({'status': 'initiated', 'timestamp': time.time()})}\n\n"

            # 2. Yield streaming events as milestones complete
            while not pipeline_task.done():
                try:
                    event_name, event_data = await asyncio.wait_for(queue.get(), timeout=0.25)
                    yield f"event: {event_name}\ndata: {json.dumps(event_data, default=str)}\n\n"
                except asyncio.TimeoutError:
                    # Keep-alive heartbeat comment to prevent proxy idle drop
                    yield ": ping\n\n"

            # 3. Flush any remaining events in queue
            while not queue.empty():
                event_name, event_data = queue.get_nowait()
                yield f"event: {event_name}\ndata: {json.dumps(event_data, default=str)}\n\n"

            evidence = await pipeline_task
            incident_store[evidence.incident_id] = evidence

            # 4. Synthesize final AnalyzeResponse payload
            final_resp = AnalyzeResponse(
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

            yield f"event: final_verdict\ndata: {final_resp.model_dump_json()}\n\n"

        except asyncio.CancelledError:
            logger.info("Client disconnected from analysis stream; canceling pipeline task.")
            pipeline_task.cancel()
            raise
        except Exception as exc:
            logger.error("Analysis stream error: %s", safe_error_message(exc))
            yield f"event: error\ndata: {json.dumps({'error': safe_error_message(exc)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
