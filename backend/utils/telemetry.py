"""
Observability Framework: Prometheus Metrics & Tracing Spans (Phase 6).

Implements:
- Production Prometheus metrics:
  * cyberkawach_pipeline_latency_seconds (Histogram by stage)
  * cyberkawach_verdict_count (Counter labeled by risk_level)
  * cyberkawach_threat_intel_cache_hit_total / miss_total
  * cyberkawach_circuit_breaker_state (Gauge per provider)
  * cyberkawach_active_requests (Gauge for in-flight requests)
  * cyberkawach_rate_limit_rejections_total (Counter labeled by tier)
  * cyberkawach_file_scans_total (Counter labeled by status)
- OpenTelemetry-compatible tracing span context manager.
- Zero-cardinality leak: strict label bounds.
- Resilient design: Telemetry recording failures can never interrupt forensic triage.
"""

from __future__ import annotations

import contextlib
import logging
import time
from typing import Any, Generator, Optional

try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        Counter,
        Gauge,
        Histogram,
        REGISTRY,
        generate_latest,
    )
    _PROMETHEUS_AVAILABLE = True
except ImportError:
    _PROMETHEUS_AVAILABLE = False

logger = logging.getLogger("cyber_guardian.telemetry")

# ─── Metric Definitions ───

if _PROMETHEUS_AVAILABLE:
    # 1. Pipeline Stage Latency Histogram
    PIPELINE_LATENCY = Histogram(
        "cyberkawach_pipeline_latency_seconds",
        "Duration of forensic triage pipeline and individual stages in seconds",
        ["stage"],
        buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0),
    )

    # 2. Final Verdicts Emitted
    VERDICT_COUNT = Counter(
        "cyberkawach_verdict_count",
        "Total number of cyber fraud triage verdicts emitted",
        ["risk_level"],
    )

    # 3. Cache Hits and Misses
    CACHE_OPERATIONS = Counter(
        "cyberkawach_cache_operations_total",
        "Two-tier cache hits and misses",
        ["tier", "outcome"],  # tier: L1, L2; outcome: hit, miss
    )

    # 4. Circuit Breaker Current State
    CIRCUIT_BREAKER_STATE = Gauge(
        "cyberkawach_circuit_breaker_state",
        "Current operational state of circuit breakers (0=CLOSED, 1=HALF_OPEN, 2=OPEN)",
        ["provider"],
    )

    # 5. In-flight Active Requests
    ACTIVE_REQUESTS = Gauge(
        "cyberkawach_active_requests",
        "Number of concurrent analysis and streaming requests currently processing",
        ["endpoint"],
    )

    # 6. Rate Limit Rejections
    RATE_LIMIT_REJECTIONS = Counter(
        "cyberkawach_rate_limit_rejections_total",
        "Number of requests rejected by sliding-window rate limiting",
        ["tier"],
    )

    # 7. File Security Scans (Phase 7)
    FILE_SCANS_COUNT = Counter(
        "cyberkawach_file_scans_total",
        "Total platform-managed files and downloads inspected",
        ["status"],
    )
else:
    PIPELINE_LATENCY = None
    VERDICT_COUNT = None
    CACHE_OPERATIONS = None
    CIRCUIT_BREAKER_STATE = None
    ACTIVE_REQUESTS = None
    RATE_LIMIT_REJECTIONS = None
    FILE_SCANS_COUNT = None


# ─── Telemetry Recording Helpers ───

def record_stage_latency(stage_name: str, duration_seconds: float) -> None:
    """Record duration of a pipeline stage in the Prometheus latency histogram."""
    if PIPELINE_LATENCY:
        try:
            PIPELINE_LATENCY.labels(stage=stage_name).observe(duration_seconds)
        except Exception as e:
            logger.debug("Failed to record stage latency metric: %s", e)


def record_verdict(risk_level: str) -> None:
    """Increment verdict counter labeled by bounded risk level."""
    if VERDICT_COUNT:
        try:
            safe_level = risk_level.upper() if risk_level else "UNKNOWN"
            if safe_level not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE", "UNKNOWN"):
                safe_level = "UNKNOWN"
            VERDICT_COUNT.labels(risk_level=safe_level).inc()
        except Exception as e:
            logger.debug("Failed to record verdict metric: %s", e)


def update_circuit_breaker_metric(provider: str, state_str: str) -> None:
    """Update gauge for circuit breaker state (0=CLOSED, 1=HALF_OPEN, 2=OPEN)."""
    if CIRCUIT_BREAKER_STATE:
        try:
            val = 0.0
            if state_str == "HALF_OPEN":
                val = 1.0
            elif state_str == "OPEN":
                val = 2.0
            CIRCUIT_BREAKER_STATE.labels(provider=provider).set(val)
        except Exception as e:
            logger.debug("Failed to update circuit breaker metric: %s", e)


def record_rate_limit_rejection(tier: str) -> None:
    """Increment counter for rate limit rejections."""
    if RATE_LIMIT_REJECTIONS:
        try:
            safe_tier = "auth" if tier == "auth" else "anon"
            RATE_LIMIT_REJECTIONS.labels(tier=safe_tier).inc()
        except Exception as e:
            logger.debug("Failed to record rate limit rejection metric: %s", e)


def record_file_scan_result(status_label: str) -> None:
    """Increment file scan counter (clean, suspicious, malicious, error)."""
    if FILE_SCANS_COUNT:
        try:
            safe_status = status_label.lower()
            if safe_status not in ("clean", "suspicious", "malicious", "quarantined", "error"):
                safe_status = "error"
            FILE_SCANS_COUNT.labels(status=safe_status).inc()
        except Exception as e:
            logger.debug("Failed to record file scan metric: %s", e)


@contextlib.contextmanager
def trace_span(span_name: str, attributes: Optional[dict[str, Any]] = None) -> Generator[None, None, None]:
    """
    OpenTelemetry-compatible span context manager.
    Measures duration, records stage latency metric, and ensures safety.
    """
    start = time.time()
    try:
        yield
    finally:
        duration = time.time() - start
        record_stage_latency(span_name, duration)


def get_prometheus_metrics_payload() -> tuple[bytes, str]:
    """Render latest metrics in Prometheus text exposition format."""
    if _PROMETHEUS_AVAILABLE:
        # Sync current circuit breaker states into Prometheus gauges before export
        try:
            from backend.utils.circuit_breaker import get_all_circuit_breakers
            for name, cb_data in get_all_circuit_breakers().items():
                update_circuit_breaker_metric(name, cb_data.get("state", "CLOSED"))
        except Exception:
            pass

        return generate_latest(REGISTRY), CONTENT_TYPE_LATEST

    # Minimal fallback text
    return b"# Prometheus metrics library not installed\n", "text/plain; version=0.0.4"
