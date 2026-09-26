"""
SSRF (Server-Side Request Forgery) protection and safe outbound network utilities.

Defends against:
- SSRF to localhost (127.0.0.1, ::1)
- SSRF to private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- SSRF to link-local / cloud metadata services (169.254.169.254)
- Open redirect chains into internal network spaces
- Dangerous URI schemes (file://, dict://, gopher://)
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import httpx

# Blocked IP networks
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # IPv4 loopback
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918 private
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918 private
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918 private
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local / AWS/GCP metadata
    ipaddress.ip_network("100.64.0.0/10"),     # Carrier grade NAT
    ipaddress.ip_network("0.0.0.0/8"),         # Current network
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]

_ALLOWED_SCHEMES = frozenset({"http", "https"})


def is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address belongs to any private or reserved network."""
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        return True
    for net in _BLOCKED_NETWORKS:
        if ip in net:
            return True
    return False


def validate_url_for_ssrf(url: str) -> tuple[bool, str]:
    """
    Validate that a URL does not target localhost, private IP spaces,
    cloud metadata endpoints, or unsupported protocols.

    Returns:
        (is_safe: bool, reason: str)
    """
    if not url:
        return False, "Empty URL"

    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"Malformed URL: {str(e)}"

    # Scheme check
    if not parsed.scheme or parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        return False, f"Blocked scheme: '{parsed.scheme}'. Only HTTP/HTTPS allowed."

    hostname = parsed.hostname
    if not hostname:
        return False, "Missing hostname in URL"

    hostname_lower = hostname.lower().strip("[]")

    # Fast-check common localhost hostnames
    if hostname_lower in {"localhost", "localhost.localdomain", "127.0.0.1", "::1"}:
        return False, "Access to localhost is prohibited (SSRF defense)"

    # Check if host is a direct IP
    try:
        ip = ipaddress.ip_address(hostname_lower)
        if is_ip_blocked(ip):
            return False, f"Access to private/local IP {ip} is prohibited (SSRF defense)"
        return True, "Safe IP target"
    except ValueError:
        # Host is a domain name, resolve DNS
        pass

    # Resolve hostname to all addresses and check every resolved IP
    try:
        addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        if not addr_info:
            return False, f"DNS resolution failed for {hostname}"

        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            try:
                resolved_ip = ipaddress.ip_address(ip_str)
                if is_ip_blocked(resolved_ip):
                    return False, f"Host {hostname} resolves to blocked IP {resolved_ip} (SSRF defense)"
            except ValueError:
                return False, f"Invalid resolved IP format: {ip_str}"

    except socket.gaierror:
        # Unresolvable domains cannot be SSRF targets for live internal networks,
        # but for external fetch attempts we consider resolution failure unsafe.
        return False, f"Cannot resolve host {hostname}"
    except Exception as e:
        return False, f"DNS verification error: {str(e)}"

    return True, "Safe domain target"


async def safe_fetch_url(
    url: str,
    timeout: float = 5.0,
    max_redirects: int = 3,
) -> tuple[int, str, dict]:
    """
    Safely fetch a URL with SSRF defense:
    - Pre-validates destination IP
    - Does not follow redirects to private/local IPs
    - Bounded redirects and strict timeout
    """
    is_safe, reason = validate_url_for_ssrf(url)
    if not is_safe:
        raise ValueError(f"SSRF blocked: {reason}")

    current_url = url
    redirect_count = 0

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        while True:
            resp = await client.get(
                current_url,
                headers={"User-Agent": "CyberFraudGuardian/SecurityAuditor-1.0"},
            )

            # Handle redirects manually to re-verify target destination for SSRF
            if resp.is_redirect and "location" in resp.headers:
                redirect_count += 1
                if redirect_count > max_redirects:
                    raise ValueError(f"Exceeded max redirects ({max_redirects})")

                next_url = str(resp.headers["location"])
                if next_url.startswith("/"):
                    parsed_curr = urlparse(current_url)
                    next_url = f"{parsed_curr.scheme}://{parsed_curr.netloc}{next_url}"

                # Re-validate redirect target!
                is_safe_redirect, redirect_reason = validate_url_for_ssrf(next_url)
                if not is_safe_redirect:
                    raise ValueError(f"SSRF blocked on redirect to {next_url}: {redirect_reason}")

                current_url = next_url
                continue

            return resp.status_code, resp.text[:50000], dict(resp.headers)
