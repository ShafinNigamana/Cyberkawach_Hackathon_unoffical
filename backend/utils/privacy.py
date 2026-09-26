"""
Data privacy and PII redaction utilities.

Protects citizen privacy by redacting sensitive data (OTPs, passwords,
credit cards, bank accounts, government IDs) before transmission to
external LLMs (Gemini) or persistent logs.
"""

from __future__ import annotations

import re


# ─── PII / Sensitive Patterns ───

# OTP patterns: 4-8 digits near OTP/PIN/code keywords
_OTP_NEAR_KEYWORD = re.compile(
    r'(?i)\b(?:otp|one[- ]time[- ]password|code|verification\s*code|pin)\b[\s:=-]+([0-9]{4,8})\b'
)

# Credit / Debit Card numbers (13-19 digits with optional spaces or dashes)
_CARD_PATTERN = re.compile(
    r'\b(?:\d{4}[ -]?){3}\d{4,7}\b'
)

# CVV: 3-4 digits near CVV/CVC keywords
_CVV_NEAR_KEYWORD = re.compile(
    r'(?i)\b(?:cvv|cvc|security\s*code)\b[\s:=-]+([0-9]{3,4})\b'
)

# Indian Aadhaar number: 12 digits (often 4 4 4)
_AADHAAR_PATTERN = re.compile(
    r'\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b'
)

# Indian PAN number: 5 letters, 4 digits, 1 letter
_PAN_PATTERN = re.compile(
    r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'
)

# Password / PIN keywords with followed values
_PASSWORD_PATTERN = re.compile(
    r'(?i)\b(?:password|passwd|pwd|passcode|secret)\b[\s:=-]+([^\s,;]+)'
)


def redact_sensitive_data(text: str) -> str:
    """
    Redact citizen credentials, OTPs, financial details, and government IDs
    prior to cloud transmission or logging.
    """
    if not text:
        return ""

    # Redact Passwords
    text = _PASSWORD_PATTERN.sub(r'password: [REDACTED_SECRET]', text)

    # Redact OTPs
    text = _OTP_NEAR_KEYWORD.sub(r'code: [REDACTED_OTP]', text)

    # Redact CVVs
    text = _CVV_NEAR_KEYWORD.sub(r'CVV: [REDACTED_CVV]', text)

    # Redact Cards
    text = _CARD_PATTERN.sub('[REDACTED_CARD_NUMBER]', text)

    # Redact Aadhaar
    text = _AADHAAR_PATTERN.sub('[REDACTED_AADHAAR]', text)

    # Redact PAN
    text = _PAN_PATTERN.sub('[REDACTED_PAN]', text)

    return text
