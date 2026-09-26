"""
Input sanitization utilities.

Security boundary: all user input passes through here before processing.
Scam message content is treated as untrusted data at every layer.
"""

from __future__ import annotations

import re
import html


def sanitize_message(text: str, max_length: int = 10000) -> str:
    """
    Sanitize user-submitted message text.
    - Truncate to max length
    - Strip null bytes and control characters (except newlines/tabs)
    - HTML-escape to prevent injection
    """
    if not text:
        return ""

    # Truncate
    text = text[:max_length]

    # Remove null bytes
    text = text.replace('\x00', '')

    # Remove control characters except \n, \r, \t
    text = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)

    return text


def sanitize_url(url: str, max_length: int = 2048) -> str:
    """
    Basic URL sanitization.
    - Truncate to max length
    - Strip whitespace
    - Reject javascript: and data: URIs
    """
    if not url:
        return ""

    url = url.strip()[:max_length]

    # Block dangerous URI schemes
    lower = url.lower().strip()
    if lower.startswith(('javascript:', 'data:', 'vbscript:', 'file:')):
        return ""

    return url


def escape_for_display(text: str) -> str:
    """HTML-escape text for safe display in UI."""
    return html.escape(text, quote=True)
