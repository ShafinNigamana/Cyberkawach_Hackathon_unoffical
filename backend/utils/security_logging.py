"""
Security logging and secrets scrubbing utilities.

Prevents:
- Log injection (CWE-117) by neutralizing newlines/carriage returns
- API key / credential leakage in logs and exception strings
"""

from __future__ import annotations

import re


# Pattern for Google API keys, generic tokens, hex tokens, and URL key params
_KEY_PATTERNS = [
    re.compile(r'AIza[0-9A-Za-z-_]{35}'),
    re.compile(r'(?i)(?:key|token|secret|password|app_key|api_key|apikey)=([^&\s"\']+)'),
    re.compile(r'(?i)(?:authorization:\s*(?:bearer|basic)\s+)[^\s]+'),
]


def scrub_secrets(text: str) -> str:
    """
    Scrub potential API keys, query parameter tokens, and secrets from text.
    """
    if not text:
        return ""

    scrubbed = str(text)

    # Replace AIza... style keys
    scrubbed = re.sub(r'AIza[0-9A-Za-z-_]{35}', '[REDACTED_API_KEY]', scrubbed)

    # Replace URL query parameters or key=value tokens
    scrubbed = re.sub(
        r'(?i)(key|token|secret|password|app_key|api_key|apikey)=([^&\s"\']+)',
        r'\1=[REDACTED]',
        scrubbed,
    )

    # Replace Bearer tokens
    scrubbed = re.sub(
        r'(?i)(authorization:\s*(?:bearer|basic)\s+)[^\s]+',
        r'\1[REDACTED_AUTH]',
        scrubbed,
    )

    return scrubbed


def sanitize_for_log(message: str, max_length: int = 2000) -> str:
    """
    Sanitize text before writing to logs:
    - Neutralize CR/LF to prevent log injection (CWE-117)
    - Scrub API keys and secrets
    - Truncate length
    """
    if not message:
        return ""

    scrubbed = scrub_secrets(str(message)[:max_length])

    # Replace CRLF / control characters to prevent log forging
    scrubbed = scrubbed.replace('\r', '\\r').replace('\n', '\\n')

    return scrubbed


def safe_error_message(err: Exception | str) -> str:
    """
    Produce a safe, scrubbed error description that never leaks credentials
    or internal file system paths.
    """
    err_str = str(err)
    scrubbed = scrub_secrets(err_str)

    # Remove internal Windows/Linux filesystem paths if present
    scrubbed = re.sub(r'[A-Za-z]:\\[^:\s]+', '[REDACTED_PATH]', scrubbed)
    scrubbed = re.sub(r'/(?:home|var|usr|etc|tmp)/[^\s]+', '[REDACTED_PATH]', scrubbed)

    return scrubbed
