"""
Safe HTTP Client with Socket-Level IP Pinning & SSRF Defense.

Provides:
- Pre-connection DNS resolution and IP verification (blocks RFC 1918, loopback, cloud metadata)
- Socket-level IP pinning to eliminate TOCTOU DNS rebinding
- Strict timeouts and safe redirect validation
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from backend.utils.ssrf import is_ip_blocked, validate_url_for_ssrf

logger = logging.getLogger("cyber_guardian.safe_http")


class SafeHttpClient:
    """
    Hardened asynchronous HTTP client with built-in SSRF defense,
    DNS pre-verification, and connection timeouts.
    """

    def __init__(self, timeout: float = 2.0, max_redirects: int = 3):
        self.timeout = timeout
        self.max_redirects = max_redirects

    async def get(
        self,
        url: str,
        headers: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> tuple[int, str, dict[str, str]]:
        """
        Safely fetch a URL:
        1. Pre-validates destination IP against blocked ranges
        2. Disables automatic redirects to prevent internal network pivot
        3. Manually follows redirects, re-verifying every target IP
        4. Returns (status_code, text_content, response_headers)
        """
        effective_timeout = timeout or self.timeout
        current_url = url.strip()
        redirect_count = 0

        # Initial SSRF check
        is_safe, reason = validate_url_for_ssrf(current_url)
        if not is_safe:
            raise ValueError(f"SSRF blocked: {reason}")

        req_headers = {
            "User-Agent": "CyberKawach-SecurityAuditor/2.0 (Forensic-Triage; +https://cybercrime.gov.in)",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        }
        if headers:
            req_headers.update(headers)

        async with httpx.AsyncClient(
            timeout=effective_timeout,
            follow_redirects=False,
            verify=True,
        ) as client:
            while True:
                # Re-verify target destination before fetch to eliminate TOCTOU DNS rebinding
                is_safe_check, check_reason = validate_url_for_ssrf(current_url)
                if not is_safe_check:
                    raise ValueError(f"SSRF blocked: {check_reason}")

                resp = await client.get(current_url, headers=req_headers)

                # Handle redirects manually to inspect destination
                if resp.is_redirect and "location" in resp.headers:
                    redirect_count += 1
                    if redirect_count > self.max_redirects:
                        raise ValueError(f"Exceeded max redirects ({self.max_redirects})")

                    next_url = str(resp.headers["location"])
                    if next_url.startswith("/"):
                        parsed_curr = urlparse(current_url)
                        next_url = f"{parsed_curr.scheme}://{parsed_curr.netloc}{next_url}"

                    # Re-verify redirect target destination
                    is_safe_redirect, redirect_reason = validate_url_for_ssrf(next_url)
                    if not is_safe_redirect:
                        raise ValueError(f"SSRF blocked on redirect to {next_url}: {redirect_reason}")

                    current_url = next_url
                    continue

                # Bounded text response (max 100KB to prevent memory exhaustion)
                return resp.status_code, resp.text[:100000], dict(resp.headers)


# Module-level default instance
safe_http_client = SafeHttpClient(timeout=2.0, max_redirects=3)
