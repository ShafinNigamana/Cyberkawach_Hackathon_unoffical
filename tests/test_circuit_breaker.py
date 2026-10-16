"""
Unit tests for Phase 2: Circuit Breaker and Fail-Fast handling.
"""

import asyncio
import time
import pytest

from backend.utils.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerOpenException,
    CircuitState,
    get_circuit_breaker,
)
from backend.services.threat_intel_providers import (
    ThreatIntelManager,
    ThreatIntelProvider,
    ThreatIntelResult,
    ThreatIntelStatus,
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


def test_circuit_breaker_transitions():
    cb = CircuitBreaker("test_provider", failure_threshold=3, recovery_timeout=0.1)
    assert cb.state == CircuitState.CLOSED
    assert cb.is_available() is True

    # 1. Record two failures - should still be CLOSED
    cb.record_failure(Exception("Connection timeout 1"))
    cb.record_failure(Exception("Connection timeout 2"))
    assert cb.state == CircuitState.CLOSED

    # 2. Third failure trips to OPEN
    cb.record_failure(Exception("Connection timeout 3"))
    assert cb.state == CircuitState.OPEN
    assert cb.is_available() is False

    # 3. Synchronous execution while OPEN raises CircuitBreakerOpenException immediately
    def sample_func():
        return "called"

    with pytest.raises(CircuitBreakerOpenException) as excinfo:
        cb.execute_sync(sample_func)
    assert "cooldown remaining" in str(excinfo.value)

    # 4. Wait for recovery timeout (0.1s timeout -> sleep 0.2s for Windows timer resolution)
    time.sleep(0.2)
    assert cb.state == CircuitState.HALF_OPEN
    assert cb.is_available() is True
    assert cb.is_available() is True

    # 5. Successful probe trial resets to CLOSED
    result = cb.execute_sync(sample_func)
    assert result == "called"
    assert cb.state == CircuitState.CLOSED
    assert cb.is_available() is True


def test_circuit_breaker_immediate_trip_on_auth_failure():
    cb = CircuitBreaker("auth_sensitive_provider", failure_threshold=5, recovery_timeout=10.0)
    assert cb.state == CircuitState.CLOSED

    # 401 Unauthorized should trip immediately on 1st error without waiting for 5 failures
    cb.record_failure(Exception("HTTP 401 Unauthorized: Invalid API token"))
    assert cb.state == CircuitState.OPEN
    assert cb.is_available() is False


@pytest.mark.anyio
async def test_threat_intel_manager_circuit_breaker_fail_fast():
    class DummyFailingProvider(ThreatIntelProvider):
        @property
        def name(self) -> str:
            return "dummy_failing_provider"

        @property
        def is_available(self) -> bool:
            return True

        async def check_url(self, url: str) -> ThreatIntelResult:
            raise Exception("500 Server Internal Error")

    manager = ThreatIntelManager()
    failing_provider = DummyFailingProvider()
    manager.providers = [failing_provider]

    cb = get_circuit_breaker("threat_intel_dummy_failing_provider", failure_threshold=2, recovery_timeout=0.2)
    # Reset state for test
    cb.record_success()

    # 1. Call twice to trip circuit
    await manager.query_all("https://malicious-test.example.com")
    await manager.query_all("https://malicious-test.example.com")
    assert cb.state == CircuitState.OPEN

    # 2. Third call must fail fast without waiting for provider
    ti_results, ev_items = await manager.query_all("https://malicious-test.example.com")
    assert len(ti_results) == 1
    assert ti_results[0].intel_status == ThreatIntelStatus.SOURCE_UNAVAILABLE
    assert "Circuit breaker OPEN" in (ti_results[0].error or "")

    # Evidence items must mark it as UNAVAILABLE, never assuming safe
    assert len(ev_items) == 1
    assert ev_items[0].evidence_tier == "UNAVAILABLE"
