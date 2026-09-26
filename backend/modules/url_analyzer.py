"""
URL & domain analyzer — punycode, TLD, lexical, IP classification, and structure.

URL-01: Deterministic URL analysis without external API calls.
Checks for suspicious characteristics that phishing URLs exhibit, while strictly
protecting against false positives:
- IPv4 literals (e.g. 127.0.0.1) are NEVER treated as subdomains.
- Differentiates loopback, private, cloud-metadata, and public IP literals.
- Distinguishes weak lexical heuristics from high-confidence indicators.
- Emits structured EvidenceItems with epistemic status and correlation grouping.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlparse

from backend.models.evidence import (
    EvidenceItem,
    EvidenceReliability,
    EvidenceSeverity,
    EvidenceStatus,
    EvidenceType,
    IncidentEvidence,
    RiskDirection,
    URLSignal,
)


# ─── Suspicious TLDs (commonly abused, cheap/free registration) ───
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

# ─── Known legitimate multi-level cloud/hosting platforms (many dots is normal) ───
_LEGITIMATE_MULTI_LEVEL = frozenset({
    'amazonaws.com', 'azurewebsites.net', 'blob.core.windows.net',
    'cloudfront.net', 'googleusercontent.com', 'github.io',
    'gitlab.io', 'vercel.app', 'web.app', 'firebaseapp.com',
})

# ─── Suspicious path keywords ───
_SUSPICIOUS_PATH_WORDS = frozenset({
    'login', 'signin', 'sign-in', 'secure', 'verify', 'update',
    'confirm', 'account', 'banking', 'password', 'credential',
    'authenticate', 'validation', 'suspension', 'reactivate',
    'unlock', 'restore', 'wallet', 'payment', 'kyc', 'otp',
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


def _clean_host(raw_host: str) -> str:
    """Extract clean hostname or IP, stripping port and IPv6 brackets."""
    host = raw_host.strip().lower()
    if not host:
        return ""
    # Strip port if present
    if host.startswith('[') and ']' in host:
        # IPv6 [::1]:8080
        host = host.split(']')[0].lstrip('[')
    elif ':' in host and not host.count(':') > 1:
        # IPv4 or hostname with port (e.g. localhost:8000, 1.2.3.4:80)
        host = host.split(':')[0]
    return host


def _classify_ip_address(host: str) -> tuple[bool, str, str]:
    """
    Check if host is an IP address literal and classify its scope.
    Returns: (is_ip: bool, ip_type: str, details: str)
    """
    if host == "localhost":
        return True, "loopback_ip", "Local loopback hostname (localhost)"

    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:
            return True, "loopback_ip", f"Local loopback address ({ip})"
        elif str(ip) == "169.254.169.254" or ip.is_link_local:
            return True, "cloud_metadata_ip", f"Link-local / cloud metadata address ({ip})"
        elif ip.is_private:
            return True, "private_ip", f"Private RFC1918 / local network address ({ip})"
        else:
            return True, "public_ip_literal", f"Public raw IP literal used instead of domain ({ip})"
    except ValueError:
        return False, "domain", ""


def _analyze_single_url(url_signal: URLSignal) -> tuple[URLSignal, list[EvidenceItem]]:
    """
    Analyze a single URL for suspicious characteristics.
    Emits enriched EvidenceItems with epistemic status and correlation grouping.
    """
    signals = list(url_signal.signals)
    evidence_items = []
    url = url_signal.url
    raw_domain = url_signal.domain

    try:
        parsed = urlparse(url)
    except Exception:
        signals.append('malformed_url')
        url_signal.signals = signals
        evidence_items.append(EvidenceItem(
            type=EvidenceType.URL_ANALYSIS,
            source="url_analyzer",
            description=f"Malformed URL syntax could not be safely parsed: {url[:80]}",
            observed_value=url[:80],
            interpretation="Malformed URL syntax",
            status=EvidenceStatus.SUSPICIOUS,
            reliability=EvidenceReliability.DETERMINISTIC_FACT,
            risk_direction=RiskDirection.INCREASES_RISK,
            severity=EvidenceSeverity.MEDIUM,
            correlation_group="url_structure",
            raw_data={"url": url, "signal": "malformed_url"},
        ))
        return url_signal, evidence_items

    host = _clean_host(parsed.netloc or raw_domain)
    is_ip, ip_type, ip_details = _classify_ip_address(host)

    # ─── 1. IP Address Literal Handling (CRITICAL: Never treat IP dots as subdomains) ───
    if is_ip:
        signals.append(ip_type)
        if ip_type in ("loopback_ip", "private_ip"):
            # Local/private destinations are security/operational concerns, not external phishing
            evidence_items.append(EvidenceItem(
                type=EvidenceType.URL_ANALYSIS,
                source="url_analyzer",
                description=f"URL targets internal/local network destination ({host}): {ip_details}",
                observed_value=host,
                interpretation=f"Non-routable local/private infrastructure ({ip_type})",
                status=EvidenceStatus.OBSERVED,
                reliability=EvidenceReliability.DETERMINISTIC_FACT,
                risk_direction=RiskDirection.NEUTRAL,
                severity=EvidenceSeverity.LOW,
                correlation_group="url_network_identity",
                raw_data={"url": url, "host": host, "ip_type": ip_type},
            ))
        elif ip_type == "cloud_metadata_ip":
            evidence_items.append(EvidenceItem(
                type=EvidenceType.URL_ANALYSIS,
                source="url_analyzer",
                description=f"URL explicitly targets cloud metadata service: {host}",
                observed_value=host,
                interpretation="Cloud metadata extraction vector (SSRF candidate)",
                status=EvidenceStatus.SUSPICIOUS,
                reliability=EvidenceReliability.DETERMINISTIC_FACT,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.HIGH,
                correlation_group="url_network_identity",
                raw_data={"url": url, "host": host, "ip_type": ip_type},
            ))
        else:
            # Public IP literal — suspicious because legitimate organizations rarely host customer portals on raw IPs
            evidence_items.append(EvidenceItem(
                type=EvidenceType.URL_ANALYSIS,
                source="url_analyzer",
                description=f"URL uses raw public IP address instead of domain name: {host}",
                observed_value=host,
                interpretation="Public IP address bypasses standard DNS reputation",
                status=EvidenceStatus.SUSPICIOUS,
                reliability=EvidenceReliability.DETERMINISTIC_FACT,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.MEDIUM,
                correlation_group="url_network_identity",
                raw_data={"url": url, "host": host, "ip_type": ip_type},
            ))
    else:
        # ─── 2. Standard Domain Analysis (Only run on genuine hostnames) ───

        # Punycode / IDN Homograph
        if _has_punycode(host):
            signals.append('punycode')
            evidence_items.append(EvidenceItem(
                type=EvidenceType.URL_ANALYSIS,
                source="url_analyzer",
                description=f"Punycode / IDN homograph domain detected: {host}",
                observed_value=host,
                interpretation="Punycode encoding commonly used for visual domain impersonation",
                status=EvidenceStatus.SUSPICIOUS,
                reliability=EvidenceReliability.DETERMINISTIC_FACT,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.HIGH,
                correlation_group="url_network_identity",
                raw_data={"url": url, "domain": host, "signal": "punycode"},
            ))

        # Suspicious TLD
        tld = _get_tld(host)
        if tld in _SUSPICIOUS_TLDS:
            signals.append('suspicious_tld')
            evidence_items.append(EvidenceItem(
                type=EvidenceType.URL_ANALYSIS,
                source="url_analyzer",
                description=f"Suspicious top-level domain '{tld}' observed on: {host}",
                observed_value=tld,
                interpretation=f"TLD {tld} is frequently abused due to low-cost or disposable registration",
                status=EvidenceStatus.SUSPICIOUS,
                reliability=EvidenceReliability.HEURISTIC,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.MEDIUM,
                correlation_group="url_tld",
                raw_data={"url": url, "domain": host, "tld": tld, "signal": "suspicious_tld"},
            ))

        # Subdomain Counting (Only for actual domains, taking compound TLDs and legitimate CDNs into account)
        is_cloud_multi = any(host.endswith(cloud) for cloud in _LEGITIMATE_MULTI_LEVEL)
        if not is_cloud_multi:
            # Strip recognized TLD to count actual subdomain segments
            domain_without_tld = host[:-len(tld)] if tld and host.endswith(tld) else host
            subdomain_dots = domain_without_tld.count('.')
            # If domain has 2 or more dots before the TLD (e.g. a.b.c.target.com), that is excessive
            if subdomain_dots >= 2:
                signals.append('excessive_subdomains')
                evidence_items.append(EvidenceItem(
                    type=EvidenceType.URL_ANALYSIS,
                    source="url_analyzer",
                    description=f"Excessive subdomain depth ({subdomain_dots + 1} levels) in hostname: {host}",
                    observed_value=host,
                    interpretation="Multiple subdomain tiers frequently used to disguise the true root domain",
                    status=EvidenceStatus.SUSPICIOUS,
                    reliability=EvidenceReliability.HEURISTIC,
                    risk_direction=RiskDirection.INCREASES_RISK,
                    severity=EvidenceSeverity.LOW,
                    correlation_group="url_structure",
                    raw_data={"url": url, "domain": host, "subdomain_dots": subdomain_dots},
                ))

        # Long Domain Name
        if len(host) > 40:
            signals.append('long_domain')
            evidence_items.append(EvidenceItem(
                type=EvidenceType.URL_ANALYSIS,
                source="url_analyzer",
                description=f"Unusually long hostname ({len(host)} characters): {host[:45]}...",
                observed_value=f"{len(host)} chars",
                interpretation="Lengthy hostname can obscure deceptive prefix on small mobile screens",
                status=EvidenceStatus.SUSPICIOUS,
                reliability=EvidenceReliability.HEURISTIC,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.LOW,
                correlation_group="url_structure",
                raw_data={"url": url, "domain": host, "length": len(host)},
            ))

    # ─── 3. Path & Query Heuristics (Applies to both IP and domains) ───

    # Suspicious Path Keywords
    path = unquote(parsed.path or "").lower()
    query = unquote(parsed.query or "").lower()
    full_path_context = f"{path}?{query}"
    found_keywords = [w for w in _SUSPICIOUS_PATH_WORDS if w in full_path_context]

    if found_keywords:
        signals.append('suspicious_path')
        evidence_items.append(EvidenceItem(
            type=EvidenceType.URL_ANALYSIS,
            source="url_analyzer",
            description=f"Sensitive authentication/verification keywords in URL path: {', '.join(found_keywords[:4])}",
            observed_value=", ".join(found_keywords[:4]),
            interpretation="URL directs to login/verification endpoints; benign on official sites, suspicious when paired with unknown domains",
            status=EvidenceStatus.SUSPICIOUS,
            reliability=EvidenceReliability.HEURISTIC,
            risk_direction=RiskDirection.INCREASES_RISK,
            severity=EvidenceSeverity.LOW,
            correlation_group="url_lexical",
            raw_data={"url": url, "path": parsed.path, "keywords": found_keywords},
        ))

    # Credential stuffing / Deceptive @ in URL authority
    netloc_raw = parsed.netloc or ""
    if '@' in netloc_raw:
        signals.append('at_symbol')
        evidence_items.append(EvidenceItem(
            type=EvidenceType.URL_ANALYSIS,
            source="url_analyzer",
            description=f"URL contains '@' in authority section: browser navigates to host after '@'",
            observed_value=netloc_raw[:60],
            interpretation="Deceptive URL trick: text before '@' is ignored by browsers while misleading users",
            status=EvidenceStatus.SUSPICIOUS,
            reliability=EvidenceReliability.DETERMINISTIC_FACT,
            risk_direction=RiskDirection.INCREASES_RISK,
            severity=EvidenceSeverity.HIGH,
            correlation_group="url_structure",
            raw_data={"url": url, "authority": netloc_raw},
        ))

    # Plain HTTP (Unencrypted protocol)
    if parsed.scheme == 'http':
        signals.append('no_https')
        evidence_items.append(EvidenceItem(
            type=EvidenceType.URL_ANALYSIS,
            source="url_analyzer",
            description="URL uses unencrypted HTTP protocol without transport security (TLS)",
            observed_value="http://",
            interpretation="Unencrypted connection allows eavesdropping; legitimate financial portals require HTTPS",
            status=EvidenceStatus.OBSERVED,
            reliability=EvidenceReliability.DETERMINISTIC_FACT,
            risk_direction=RiskDirection.INCREASES_RISK,
            severity=EvidenceSeverity.LOW,
            correlation_group="url_structure",
            raw_data={"url": url, "scheme": "http"},
        ))

    # URL Shorteners (Not proof of maliciousness, but noted)
    if host in _SHORTENERS:
        signals.append('shortened_url')
        evidence_items.append(EvidenceItem(
            type=EvidenceType.URL_ANALYSIS,
            source="url_analyzer",
            description=f"URL uses known shortening service ({host}) which conceals the destination",
            observed_value=host,
            interpretation="Shortened link masks final destination; not inherently malicious but widely used in SMS lures",
            status=EvidenceStatus.OBSERVED,
            reliability=EvidenceReliability.DETERMINISTIC_FACT,
            risk_direction=RiskDirection.NEUTRAL,
            severity=EvidenceSeverity.INFORMATIONAL,
            correlation_group="url_structure",
            raw_data={"url": url, "shortener": host},
        ))

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
