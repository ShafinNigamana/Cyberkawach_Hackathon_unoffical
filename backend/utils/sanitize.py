"""
Input sanitization and security utilities.

Security boundary: all user input passes through here before processing.
Scam message content is treated as untrusted data at every layer.
SEC-01: Input validation
SEC-04: SSRF protection
SEC-06: Prompt-injection defense
SEC-07: PII redaction before external API calls
"""

from __future__ import annotations

import html
import ipaddress
import re
from urllib.parse import urlparse

_INCIDENT_ID_PATTERN = re.compile(r"^INC-\d{4}-[A-Fa-f0-9]{8}$")
_LANGUAGE_PATTERN = re.compile(r"^[a-zA-Z]{2}(-[a-zA-Z0-9]{2,4})?$")
_DANGEROUS_SCHEMES = ('javascript:', 'data:', 'vbscript:', 'file:', 'blob:', 'about:')


def sanitize_message(text: str, max_length: int = 10000) -> str:
    """
    Sanitize user-submitted message text.
    - Truncate to max length
    - Strip null bytes
    - Strip control characters (except newline, tab, carriage return)
    - Strip bidirectional override characters used in spoofing attacks
    """
    if not text:
        return ""

    text = str(text)[:max_length]
    text = text.replace('\x00', '')
    text = re.sub(r'[\u202A-\u202E\u2066-\u2069]', '', text)
    text = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return text


def sanitize_url(url: str, max_length: int = 2048) -> str:
    """
    Basic URL sanitization.
    - Truncate to max length
    - Strip whitespace and control characters
    - Reject dangerous schemes (javascript:, data:, file:, etc.)
    """
    if not url:
        return ""

    url = str(url).strip()[:max_length]
    url = url.replace('\x00', '')
    url = re.sub(r'[\x01-\x1f\x7f]', '', url)

    lower = url.lower().strip()
    if lower.startswith(_DANGEROUS_SCHEMES):
        return ""

    return url


def is_safe_url(url: str) -> bool:
    """
    SSRF Protection (SEC-04):
    Ensure URL is an external web destination and cannot target private infrastructure.
    Rejects:
    - Non-http/https schemes
    - Loopback addresses (127.0.0.1, localhost, ::1)
    - Private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    - Cloud metadata addresses (169.254.169.254)
    - Link-local and multicast addresses
    """
    if not url:
        return False

    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ('http', 'https'):
            return False

        hostname = (parsed.hostname or '').lower().strip()
        if not hostname:
            return False

        # Known local / internal hostnames
        if hostname in ('localhost', '127.0.0.1', '::1', '0.0.0.0', 'local', 'internal'):
            return False

        if hostname.endswith(('.local', '.internal', '.lan', '.corp', '.home')):
            return False

        # Check if hostname is an IP address
        try:
            ip = ipaddress.ip_address(hostname)
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
                or str(ip) == '169.254.169.254'
            ):
                return False
        except ValueError:
            # Not an IP address literal, domain name is allowed
            pass

        return True
    except Exception:
        return False


def redact_pii(text: str) -> str:
    """
    PII Redaction (SEC-07):
    Redacts sensitive personal financial and identity credentials before passing
    to any external LLM or cloud API.
    """
    if not text:
        return ""

    # Credit / Debit card numbers (13-19 digits, with optional spaces or dashes)
    text = re.sub(r'\b(?:\d{4}[ -]?){3}\d{4}\b', '[REDACTED_CARD_NUMBER]', text)

    # Indian Aadhaar numbers (12 digits grouped into 4-4-4)
    text = re.sub(r'\b\d{4}\s\d{4}\s\d{4}\b', '[REDACTED_AADHAAR]', text)

    # Indian PAN numbers (5 letters, 4 numbers, 1 letter)
    text = re.sub(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b', '[REDACTED_PAN]', text)

    # OTP codes mentioned with context
    text = re.sub(r'(?i)\b(?:otp|one[-\s]?time[-\s]?password|code|pin)\s*(?:is|:)?\s*(\d{4,8})\b', r'OTP [REDACTED]', text)

    # CVV codes mentioned with context
    text = re.sub(r'(?i)\b(?:cvv|cvc|security[-\s]?code)\s*(?:is|:)?\s*(\d{3,4})\b', r'CVV [REDACTED]', text)

    return text


def defend_prompt_injection(text: str) -> str:
    """
    Prompt Injection Defense (SEC-06):
    Neutralizes common jailbreak triggers, role overrides, and system-level directives
    embedded inside user scam text before LLM context construction.
    """
    if not text:
        return ""

    patterns = [
        r'(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|rules)\b',
        r'(?i)\b(?:you\s+are\s+now|act\s+as)\s+(?:a|an)?\s*(?:new|unrestricted|developer|dan|jailbreak)\b',
        r'(?i)\b(?:system\s*prompt|system\s*instruction|reveal\s+secret|hidden\s+instruction)\b',
        r'(?i)\b(?:as\s+an\s+ai\s+assistant\s+do\s+the\s+opposite)\b',
        r'(?i)\b(?:developer\s*mode\s*enabled|disable\s*safety\s*filters)\b',
    ]

    sanitized = text
    for pat in patterns:
        sanitized = re.sub(pat, '[FILTERED_COMMAND]', sanitized)

    return sanitized


def validate_incident_id(incident_id: str) -> bool:
    """Validate incident ID matches canonical format (e.g. INC-2026-A1B2C3D4)."""
    if not incident_id or not isinstance(incident_id, str):
        return False
    return bool(_INCIDENT_ID_PATTERN.match(incident_id.strip()))


def validate_language(lang: str) -> str:
    """Validate and sanitize language code, defaulting to 'en' if invalid."""
    if not lang or not isinstance(lang, str):
        return "en"
    clean = lang.strip().lower()
    if _LANGUAGE_PATTERN.match(clean):
        return clean
    return "en"


def escape_for_display(text: str) -> str:
    """HTML-escape text for safe display in UI."""
    return html.escape(str(text), quote=True)
