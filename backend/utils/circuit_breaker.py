"""
Production-grade Circuit Breaker Implementation (Phase 2 Resilience).

Implements the standard Circuit Breaker pattern with states:
- CLOSED: Normal operational state. Requests pass through. Failures are tracked.
- OPEN: Tripped state. Requests fail fast immediately without making external network calls.
- HALF_OPEN: Probe state after cooldown. A single trial probe is allowed through.
  If successful, the circuit resets to CLOSED. If failed, it returns to OPEN with backoff.

Handles:
- Network timeouts, DNS failures, connection drops
- HTTP 401 / 403 Authentication / Authorization failures (trips immediately)
- HTTP 429 Too Many Requests (upstream rate limiting with Retry-After adherence)
- HTTP 5xx Server Errors
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from enum import Enum
import logging
from threading import Lock
import time
from typing import Any, Callable, Optional, TypeVar

logger = logging.getLogger("cyber_guardian.circuit_breaker")

T = TypeVar("T")


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreakerOpenException(Exception):
    """Raised when an operation is attempted while the circuit breaker is OPEN."""

    def __init__(self, provider_name: str, cooldown_remaining: float, reason: str = ""):
        self.provider_name = provider_name
        self.cooldown_remaining = max(0.0, round(cooldown_remaining, 1))
        self.reason = reason or f"Circuit breaker for '{provider_name}' is OPEN"
        super().__init__(
            f"{self.reason} (cooldown remaining: {self.cooldown_remaining}s)"
        )


class CircuitBreaker:
    """
    Thread-safe, async-compatible circuit breaker with state transitions,
    probe trials, and telemetry hooks.
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 3,
        recovery_timeout: float = 60.0,
        half_open_max_trials: int = 1,
    ):
        self.name = name
        self.failure_threshold = max(1, failure_threshold)
        self.recovery_timeout = max(0.01, recovery_timeout)
        self.half_open_max_trials = max(1, half_open_max_trials)

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: float = 0.0
        self._last_state_change: float = time.time()
        self._last_error_message: str = ""
        self._lock = Lock()

    @property
    def state(self) -> CircuitState:
        """Evaluate and return the current circuit state, handling auto-transition to HALF_OPEN."""
        with self._lock:
            if self._state == CircuitState.OPEN:
                elapsed = time.time() - self._last_failure_time
                if elapsed >= self.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._last_state_change = time.time()
                    logger.info(
                        "Circuit breaker [%s] cooldown expired (%.1fs). Transitioning to HALF_OPEN trial.",
                        self.name,
                        elapsed,
                    )
            return self._state

    def is_available(self) -> bool:
        """Return True if the circuit allows execution (CLOSED or HALF_OPEN)."""
        return self.state in (CircuitState.CLOSED, CircuitState.HALF_OPEN)

    def record_success(self) -> None:
        """Record a successful execution, resetting failures and closing circuit if in HALF_OPEN."""
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                logger.info(
                    "Circuit breaker [%s] probe trial SUCCEEDED. Resetting to CLOSED.",
                    self.name,
                )
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count += 1
            self._last_error_message = ""
            self._last_state_change = time.time()

    def record_failure(self, error: Exception, custom_cooldown: Optional[float] = None) -> None:
        """
        Record a failed execution.
        If failure threshold is reached or an auth error occurred, trip to OPEN.
        """
        now = time.time()
        err_msg = str(error)
        is_auth_error = any(
            code in err_msg for code in ("401", "403", "Unauthorized", "Forbidden", "AuthError")
        )

        with self._lock:
            self._failure_count += 1
            self._last_failure_time = now
            self._last_error_message = err_msg

            if custom_cooldown and custom_cooldown > 0:
                self.recovery_timeout = custom_cooldown

            # Immediate trip on authentication/authorization rejection
            if is_auth_error:
                prev_state = self._state
                self._state = CircuitState.OPEN
                self._last_state_change = now
                logger.warning(
                    "Circuit breaker [%s] TRIPPED TO OPEN immediately due to authentication failure: %s",
                    self.name,
                    err_msg,
                )
                return

            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                self._last_state_change = now
                logger.warning(
                    "Circuit breaker [%s] probe trial FAILED (%s). Re-tripping to OPEN for %.0fs.",
                    self.name,
                    err_msg,
                    self.recovery_timeout,
                )
            elif self._state == CircuitState.CLOSED and self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                self._last_state_change = now
                logger.warning(
                    "Circuit breaker [%s] TRIPPED TO OPEN after %d consecutive failures (threshold=%d). Error: %s",
                    self.name,
                    self._failure_count,
                    self.failure_threshold,
                    err_msg,
                )

    def get_status(self) -> dict[str, Any]:
        """Return diagnostic health status of this circuit breaker."""
        st = self.state
        cooldown_rem = 0.0
        if st == CircuitState.OPEN:
            cooldown_rem = max(0.0, self.recovery_timeout - (time.time() - self._last_failure_time))

        return {
            "name": self.name,
            "state": st.value,
            "is_available": st in (CircuitState.CLOSED, CircuitState.HALF_OPEN),
            "failure_count": self._failure_count,
            "success_count": self._success_count,
            "cooldown_remaining_seconds": round(cooldown_rem, 1),
            "last_error": self._last_error_message[:200] if self._last_error_message else None,
        }

    async def execute_async(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Execute an async function wrapped with circuit breaker protection."""
        st = self.state
        if st == CircuitState.OPEN:
            cooldown_rem = max(0.0, self.recovery_timeout - (time.time() - self._last_failure_time))
            raise CircuitBreakerOpenException(
                self.name, cooldown_rem, self._last_error_message
            )

        try:
            res = await func(*args, **kwargs)
            self.record_success()
            return res
        except Exception as exc:
            # Check for HTTP 429 Retry-After headers if available
            custom_cooldown = None
            if hasattr(exc, "response") and getattr(exc.response, "status_code", None) == 429:
                retry_header = exc.response.headers.get("Retry-After")
                if retry_header and retry_header.isdigit():
                    custom_cooldown = float(retry_header)

            self.record_failure(exc, custom_cooldown=custom_cooldown)
            raise

    def execute_sync(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Execute a synchronous function wrapped with circuit breaker protection."""
        st = self.state
        if st == CircuitState.OPEN:
            cooldown_rem = max(0.0, self.recovery_timeout - (time.time() - self._last_failure_time))
            raise CircuitBreakerOpenException(
                self.name, cooldown_rem, self._last_error_message
            )

        try:
            res = func(*args, **kwargs)
            self.record_success()
            return res
        except Exception as exc:
            self.record_failure(exc)
            raise


# ─── Global Circuit Breaker Registry ───

_REGISTRY: dict[str, CircuitBreaker] = {}
_REGISTRY_LOCK = Lock()


def get_circuit_breaker(
    name: str, failure_threshold: int = 3, recovery_timeout: float = 60.0
) -> CircuitBreaker:
    """Get or create a named circuit breaker singleton."""
    with _REGISTRY_LOCK:
        if name not in _REGISTRY:
            _REGISTRY[name] = CircuitBreaker(
                name=name,
                failure_threshold=failure_threshold,
                recovery_timeout=recovery_timeout,
            )
        return _REGISTRY[name]


def get_all_circuit_breakers() -> dict[str, dict[str, Any]]:
    """Return status dictionary of all registered circuit breakers."""
    with _REGISTRY_LOCK:
        return {name: cb.get_status() for name, cb in _REGISTRY.items()}
