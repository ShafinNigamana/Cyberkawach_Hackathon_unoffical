"""
URL & domain analyzer — punycode, TLD, lexical, redirects.

URL-01: Deterministic URL analysis without external API calls.
Checks for suspicious characteristics that phishing URLs commonly exhibit.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, unquote

from backend.models.evidence import (
    EvidenceItem,
    EvidenceType,
    IncidentEvidence,
    URLSignal,
)


# ─── Suspicious TLDs (commonly abused, free registration) ───

_SUSPICIOUS_TLDS = frozenset({
    '.tk', '.ml', '.ga', '.cf', '.gq',  # Freenom
    '.top', '.xyz', '.click', '.link', '.online', '.site',
    '.club', '.live', '.store', '.shop', '.buzz', '.icu',
    '.rest', '.fit', '.surf', '.monster', '.work',
})

# ─── Trusted TLDs (legitimate domains frequently impersonated) ───

_TRUSTED_TLDS = frozenset({
    '.gov.in', '.nic.in', '.ac.in', '.edu', '.gov', '.mil',
})

# ─── Known legitimate shortener domains (not suspicious per se, but noteworthy) ───

_SHORTENERS = frozenset({
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy',
    'tiny.cc', 'lnkd.in', 'surl.li', 'short.io',
})

# ─── IP address pattern ───
_IP_DOMAIN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

# ─── Excessive subdomain pattern ───
_MANY_SUBDOMAINS = 3  # 3+ dots = suspicious

# ─── Suspicious path keywords ───
_SUSPICIOUS_PATH_WORDS = frozenset({
    'login', 'signin', 'sign-in', 'secure', 'verify', 'update',
    'confirm', 'account', 'banking', 'password', 'credential',
    'authenticate', 'validation', 'suspension', 'reactivate',
    'unlock', 'restore', 'wallet', 'payment',
})


def _has_punycode(domain: str) -> bool:
    """Check for punycode encoding (IDN homograph attacks)."""
    return 'xn--' in domain.lower()


def _get_tld(domain: str) -> str:
    """Extract TLD from domain. Handles compound TLDs like .co.in, .gov.in."""
    parts = domain.lower().rsplit('.', 2)
    if len(parts) >= 3 and parts[-2] in ('co', 'gov', 'ac', 'org', 'net', 'nic', 'gen', 'res', 'edu'):
        return f'.{parts[-2]}.{parts[-1]}'
    if len(parts) >= 2:
        return f'.{parts[-1]}'
    return ''


def _analyze_single_url(url_signal: URLSignal) -> tuple[URLSignal, list[EvidenceItem]]:
    """Analyze a single URL for suspicious characteristics."""
    signals = list(url_signal.signals)
    evidence_items = []
    url = url_signal.url
    domain = url_signal.domain

    try:
        parsed = urlparse(url)
    except Exception:
        signals.append('malformed_url')
        url_signal.signals = signals
        evidence_items.append(EvidenceItem(
            type=EvidenceType.URL_ANALYSIS,
            source="url_analyzer",
            description=f"Malformed URL detected: {url[:100]}",
            confidence=0.7,
            raw_data={"url": url, "signal": "malformed_url"},
        ))
        return url_signal, evidence_items

    # ─── Punycode / IDN ───
    if _has_punycode(domain):
        signals.append('punycode')
        evidence_items.append(EvidenceItem(
            type=EvidenceType.URL_ANALYSIS,
            source="url_analyzer",
            description=f"Punycode/IDN domain detected (potential homograph attack): {domain}",
            confidence=0.75,
            raw_data={"url": url, "domain": domain, "signal": "punycode"},
        ))

    # ─── Suspicious TLD ───
    tld = _get_tld(domain)
    if tld in _SUSPICIOUS_TLDS:
        signals.append('suspicious_tld')
        evidence_items.append(EvidenceItem(
            type=EvidenceType.URL_ANALYSIS,
            source="url_analyzer",
            description=f"Suspicious TLD '{tld}' — commonly used in phishing: {domain}",
            confidence=0.5,
            raw_data={"url": url, "domain": domain, "tld": tld, "signal": "suspicious_tld"},
        ))

    # ─── IP-based domain ───
    if _IP_DOMAIN.match(domain):
        signals.append('ip_domain')
        evidence_items.append(EvidenceItem(
            type=EvidenceType.URL_ANALYSIS,
            source="url_analyzer",
            description=f"URL uses raw IP address instead of domain: {domain}",
            confidence=0.65,
            raw_data={"url": url, "domain": domain, "signal": "ip_domain"},
        ))

    # ─── Excessive subdomains ───
    dot_count = domain.count('.')
    if dot_count >= _MANY_SUBDOMAINS:
        signals.append('excessive_subdomains')
        evidence_items.append(EvidenceItem(
            type=EvidenceType.URL_ANALYSIS,
            source="url_analyzer",
            description=f"Excessive subdomains ({dot_count} dots): {domain}",
            confidence=0.45,
            raw_data={"url": url, "domain": domain, "dot_count": dot_count, "signal": "excessive_subdomains"},
        ))

    # ─── Long domain name ───
    if len(domain) > 40:
        signals.append('long_domain')
        evidence_items.append(EvidenceItem(
            type=EvidenceType.URL_ANALYSIS,
            source="url_analyzer",
            description=f"Unusually long domain name ({len(domain)} chars): {domain[:50]}...",
            confidence=0.4,
            raw_data={"url": url, "domain": domain, "length": len(domain), "signal": "long_domain"},
        ))

    # ─── Suspicious path keywords ───
    path = unquote(parsed.path).lower()
    found_path_words = [w for w in _SUSPICIOUS_PATH_WORDS if w in path]
    if found_path_words:
        signals.append('suspicious_path')
        evidence_items.append(EvidenceItem(
            type=EvidenceType.URL_ANALYSIS,
            source="url_analyzer",
            description=f"Suspicious keywords in URL path: {', '.join(found_path_words)}",
            confidence=0.35,
            raw_data={"url": url, "path": parsed.path, "keywords": found_path_words, "signal": "suspicious_path"},
        ))

    # ─── Long path ───
    if len(parsed.path) > 100:
        signals.append('long_path')

    # ─── Has @ symbol (credential stuffing in URL) ───
    if '@' in url.split('//')[1] if '//' in url else False:
        signals.append('at_symbol')
        evidence_items.append(EvidenceItem(
            type=EvidenceType.URL_ANALYSIS,
            source="url_analyzer",
            description=f"URL contains @ symbol (potential credential injection): {url[:80]}",
            confidence=0.8,
            raw_data={"url": url, "signal": "at_symbol"},
        ))

    # ─── HTTP (not HTTPS) ───
    if parsed.scheme == 'http':
        signals.append('no_https')

    # ─── URL shortener ───
    if domain in _SHORTENERS:
        signals.append('shortened_url')

    url_signal.signals = signals
    return url_signal, evidence_items


async def analyze_urls(evidence: IncidentEvidence) -> IncidentEvidence:
    """
    Analyze all URLs in the evidence for suspicious characteristics.
    Purely deterministic — no external API calls.
    """
    if not evidence.urls:
        return evidence

    updated_urls = []
    for url_signal in evidence.urls:
        analyzed_signal, new_evidence = _analyze_single_url(url_signal)
        updated_urls.append(analyzed_signal)
        evidence.evidence.extend(new_evidence)

    evidence.urls = updated_urls
    return evidence
