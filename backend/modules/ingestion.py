"""
Ingestion module — Text/URL extraction, normalization, IOC extraction.

Handles DET-01: Takes raw message text, extracts URLs, email addresses,
phone numbers, and other indicators of compromise (IOCs).
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from backend.models.evidence import (
    EvidenceItem,
    EvidenceType,
    IncidentEvidence,
    URLSignal,
)


# ─── IOC extraction patterns ───

# URL pattern — catches http(s), shortened URLs, and bare domains with paths
_URL_PATTERN = re.compile(
    r'https?://[^\s<>"\'}\])+]+|'       # Full URLs
    r'(?<!\w)(?:www\.)[^\s<>"\'}\])+]+|'  # www. prefixed
    r'(?<!\w)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'  # bare domain
    r'(?:com|org|net|in|co\.in|gov\.in|io|xyz|tk|ml|ga|cf|gq|top|'
    r'info|biz|online|site|club|live|shop|store|app|dev|page|link|click)'
    r'(?:/[^\s<>"\'}\])*]*)?',
    re.IGNORECASE,
)

# Email pattern
_EMAIL_PATTERN = re.compile(
    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    re.IGNORECASE,
)

# Phone pattern — Indian numbers primarily
_PHONE_PATTERN = re.compile(
    r'(?:\+91[\s-]?)?(?:\d[\s-]?){10}|'  # Indian mobile
    r'(?:\+\d{1,3}[\s-]?)?(?:\d[\s-]?){7,15}',  # International
)

# IP address pattern
_IP_PATTERN = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)

# UPI ID pattern — common in Indian scams
_UPI_PATTERN = re.compile(
    r'[a-zA-Z0-9._%+-]+@(?:upi|paytm|ybl|oksbi|okicici|okaxis|okhdfcbank|'
    r'apl|ibl|sbi|pnb|boi|cnrb|idbi|mahb|cbin|airtel|freecharge|jio)',
    re.IGNORECASE,
)

# ─── Known URL shorteners ───

_SHORTENER_DOMAINS = frozenset({
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy',
    'tiny.cc', 'lnkd.in', 'surl.li', 'short.io',
})


def _normalize_text(text: str) -> str:
    """Basic text normalization — collapse whitespace, strip control chars."""
    # Replace common unicode confusables used in phishing
    confusable_map = {
        '\u200b': '',   # zero-width space
        '\u200c': '',   # zero-width non-joiner
        '\u200d': '',   # zero-width joiner
        '\ufeff': '',   # BOM
        '\u00a0': ' ',  # non-breaking space
        '\u2028': '\n', # line separator
        '\u2029': '\n', # paragraph separator
    }
    for char, replacement in confusable_map.items():
        text = text.replace(char, replacement)
    return ' '.join(text.split())


def _extract_urls(text: str) -> list[str]:
    """Extract all URLs from text."""
    urls = _URL_PATTERN.findall(text)
    # Deduplicate preserving order
    seen = set()
    result = []
    for url in urls:
        url = url.rstrip('.,;:!?)')
        if url not in seen:
            seen.add(url)
            result.append(url)
    return result


def _ensure_scheme(url: str) -> str:
    """Add https:// if no scheme present."""
    if not url.startswith(('http://', 'https://')):
        return f'https://{url}'
    return url


def _url_to_signal(url: str) -> URLSignal:
    """Convert a raw URL string to a URLSignal with initial analysis."""
    full_url = _ensure_scheme(url)
    try:
        parsed = urlparse(full_url)
        domain = parsed.hostname or ''
    except Exception:
        domain = url.split('/')[0]

    signals = []
    is_shortened = domain.lower() in _SHORTENER_DOMAINS
    if is_shortened:
        signals.append('shortened_url')

    return URLSignal(
        url=full_url,
        domain=domain.lower(),
        signals=signals,
        is_shortened=is_shortened,
    )


def extract_iocs(evidence: IncidentEvidence, additional_urls: list[str] | None = None) -> IncidentEvidence:
    """
    Main ingestion entry point.
    Normalizes text, extracts URLs, emails, phones, IPs, UPI IDs.
    Populates evidence.urls, evidence.iocs, and adds IOC evidence items.
    """
    # Normalize
    normalized = _normalize_text(evidence.message)
    evidence.message = normalized

    # Extract URLs from message
    found_urls = _extract_urls(normalized)

    # Add any additional user-supplied URLs
    if additional_urls:
        for url in additional_urls:
            if url and url not in found_urls:
                found_urls.append(url)

    # Build URL signals
    evidence.urls = [_url_to_signal(u) for u in found_urls]

    # Extract other IOCs
    emails = _EMAIL_PATTERN.findall(normalized)
    phones = [p.strip() for p in _PHONE_PATTERN.findall(normalized) if len(p.strip()) >= 7]
    ips = _IP_PATTERN.findall(normalized)
    upi_ids = _UPI_PATTERN.findall(normalized)

    all_iocs = []
    for email in emails:
        all_iocs.append(f"email:{email}")
    for phone in phones:
        all_iocs.append(f"phone:{phone}")
    for ip in ips:
        all_iocs.append(f"ip:{ip}")
    for upi in upi_ids:
        all_iocs.append(f"upi:{upi}")
    for url_signal in evidence.urls:
        all_iocs.append(f"url:{url_signal.url}")

    evidence.iocs = all_iocs

    # Create evidence items for extracted IOCs
    if evidence.urls:
        evidence.evidence.append(EvidenceItem(
            type=EvidenceType.IOC_EXTRACTED,
            source="ingestion",
            description=f"Extracted {len(evidence.urls)} URL(s) from message",
            confidence=1.0,
            raw_data={"urls": [u.url for u in evidence.urls]},
        ))

    if emails:
        evidence.evidence.append(EvidenceItem(
            type=EvidenceType.IOC_EXTRACTED,
            source="ingestion",
            description=f"Extracted {len(emails)} email address(es): {', '.join(emails)}",
            confidence=1.0,
            raw_data={"emails": emails},
        ))

    if upi_ids:
        evidence.evidence.append(EvidenceItem(
            type=EvidenceType.IOC_EXTRACTED,
            source="ingestion",
            description=f"Extracted {len(upi_ids)} UPI ID(s): {', '.join(upi_ids)}",
            confidence=1.0,
            raw_data={"upi_ids": upi_ids},
        ))

    if phones:
        evidence.evidence.append(EvidenceItem(
            type=EvidenceType.IOC_EXTRACTED,
            source="ingestion",
            description=f"Extracted {len(phones)} phone number(s)",
            confidence=0.8,
            raw_data={"phones": phones},
        ))

    return evidence
