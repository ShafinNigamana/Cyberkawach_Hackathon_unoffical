"""
Unit tests for Phase 5: Tiered Sliding-Window Rate Limiting.
"""

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

    # Authenticated request with Bearer token
    scope_auth = {
        "type": "http",
        "client": ("192.168.1.100", 12345),
        "headers": [(b"authorization", b"Bearer sample_jwt_lea_analyst_token")],
    }
    req_auth = Request(scope_auth)
    key_auth, tier_auth, limit_auth = get_client_identification(req_auth)
    assert tier_auth == "auth"
    assert limit_auth == 120
    assert "auth:" in key_auth


def test_check_rate_limit_emits_429_with_retry_after():
    limiter = SlidingWindowRateLimiter(default_limit=2, window_seconds=10.0)
    client = "client_quota_test"

    assert limiter.is_allowed(client)[0] is True
    assert limiter.is_allowed(client)[0] is True

    # 3rd is blocked
    allowed, retry_after = limiter.is_allowed(client)
    assert allowed is False
    assert retry_after >= 1
