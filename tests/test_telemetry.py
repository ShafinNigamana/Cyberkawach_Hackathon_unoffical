"""
Unit and integration tests for Phase 6: Observability with OpenTelemetry and Prometheus.
"""

from fastapi.testclient import TestClient
import pytest

from backend.main import app
from backend.utils.telemetry import (
    record_file_scan_result,
    record_rate_limit_rejection,
    record_stage_latency,
    record_verdict,
    trace_span,
    update_circuit_breaker_metric,
)

client = TestClient(app)


def test_metrics_endpoint_exposition():
    # 1. Exercise metric helpers
    record_stage_latency("domain_intelligence", 0.125)
    record_verdict("CRITICAL")
    record_verdict("SAFE")
    update_circuit_breaker_metric("neo4j_aura", "CLOSED")
    record_rate_limit_rejection("anon")
    record_file_scan_result("clean")

    # 2. Query /metrics endpoint
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers.get("content-type", "")

    body = response.text
    assert "cyberkawach_pipeline_latency_seconds" in body
    assert "cyberkawach_verdict_count" in body
    assert "cyberkawach_circuit_breaker_state" in body
    assert "cyberkawach_rate_limit_rejections_total" in body
    assert "cyberkawach_file_scans_total" in body


def test_trace_span_context_manager():
    # Verify trace_span measures execution time without throwing
    with trace_span("synthetic_stage"):
        x = sum(i for i in range(1000))
        assert x > 0

    response = client.get("/metrics")
    assert response.status_code == 200
    assert 'stage="synthetic_stage"' in response.text
