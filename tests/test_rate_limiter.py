"""
Unit tests for Phase 5: Tiered Sliding-Window Rate Limiting.
Includes security verification against:
- Dummy Bearer token rotation quota evasion
- X-Forwarded-For IP spoofing from untrusted peers
"""

from unittest.mock import patch
import time
import pytest
from fastapi import HTTPException
from starlette.requests import Request

from backend.utils.rate_limiter import (
    SlidingWindowRateLimiter,
    check_rate_limit,
    get_client_identification,
    rate_limiter,
)


def test_sliding_window_rate_limiter_allows_and_blocks():
    limiter = SlidingWindowRateLimiter(default_limit=5, window_seconds=0.2)
    client_key = "test_client_ip_1"

    # 1. First 5 requests must be allowed
    for _ in range(5):
        allowed, retry_after = limiter.is_allowed(client_key)
        assert allowed is True
        assert retry_after == 0

    # 2. 6th request must be blocked
    allowed, retry_after = limiter.is_allowed(client_key)
    assert allowed is False
    assert retry_after >= 1

    # 3. Wait for sliding window to expire
    time.sleep(0.25)

    # 4. Request should now be allowed again
    allowed, retry_after = limiter.is_allowed(client_key)
    assert allowed is True
    assert retry_after == 0


def test_rate_limiter_client_tier_identification():
    # Anonymous request
    scope_anon = {
        "type": "http",
        "client": ("192.168.1.100", 12345),
        "headers": [],
    }
    req_anon = Request(scope_anon)
    key, tier, limit = get_client_identification(req_anon)
    assert tier == "anon"
    assert limit == 15
    assert "anon:192.168.1.100" in key

    # Authenticated request with VALID Bearer session
    scope_auth = {
        "type": "http",
        "client": ("192.168.1.100", 12345),
        "headers": [(b"authorization", b"Bearer valid_session_token_123")],
    }
    req_auth = Request(scope_auth)
    with patch("backend.services.neo4j_repository.neo4j_repo.validate_session", return_value={"user_id": "usr_analyst_01"}):
        key_auth, tier_auth, limit_auth = get_client_identification(req_auth)
        assert tier_auth == "auth"
        assert limit_auth == 120
        assert key_auth == "auth:usr_analyst_01"

    # Attack attempt: Dummy / rotating Bearer tokens without valid session must NOT elevate to auth
    scope_dummy = {
        "type": "http",
        "client": ("192.168.1.100", 12345),
        "headers": [(b"authorization", b"Bearer arbitrary_attacker_token_xyz")],
    }
    req_dummy = Request(scope_dummy)
    with patch("backend.services.neo4j_repository.neo4j_repo.validate_session", return_value=None):
        key_dummy, tier_dummy, limit_dummy = get_client_identification(req_dummy)
        assert tier_dummy == "anon"
        assert limit_dummy == 15
        assert "anon:192.168.1.100" in key_dummy


def test_rate_limiter_xff_spoofing_defense():
    """Verify that X-Forwarded-For is ignored when the direct client is not a trusted proxy."""
    # Untrusted client 203.0.113.5 attempts to spoof X-Forwarded-For
    scope_untrusted = {
        "type": "http",
        "client": ("203.0.113.5", 54321),
        "headers": [(b"x-forwarded-for", b"1.1.1.1")],
    }
    req_untrusted = Request(scope_untrusted)
    key, tier, limit = get_client_identification(req_untrusted)
    assert key == "anon:203.0.113.5"

    # Trusted proxy 127.0.0.1 forwarding for 203.0.113.99
    scope_trusted = {
        "type": "http",
        "client": ("127.0.0.1", 54321),
        "headers": [(b"x-forwarded-for", b"203.0.113.99, 10.0.0.1")],
    }
    req_trusted = Request(scope_trusted)
    key_t, tier_t, limit_t = get_client_identification(req_trusted)
    assert key_t == "anon:203.0.113.99"


def test_check_rate_limit_emits_429_with_retry_after():
    limiter = SlidingWindowRateLimiter(default_limit=2, window_seconds=10.0)
    client = "client_quota_test"

    assert limiter.is_allowed(client)[0] is True
    assert limiter.is_allowed(client)[0] is True

    # 3rd is blocked
    allowed, retry_after = limiter.is_allowed(client)
    assert allowed is False
    assert retry_after >= 1
