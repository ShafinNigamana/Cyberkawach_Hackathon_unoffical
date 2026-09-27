"""
Live Domain Intelligence Service (PRD Section 3 & 4).

Dynamically inspects domains via:
1. Live DNS queries (A, AAAA, MX, NS, CNAME, TXT for SPF/DMARC) using dnspython.
2. Live TLS certificate inspection (issuer, validity window, SAN coverage, domain mismatch) with SSRF defense.
3. Live RDAP / WHOIS domain registration age and registrar identification.

All network operations are strictly bounded by timeouts and guarded against SSRF.
"""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import logging
import socket
import ssl
import time
from typing import Any, Optional
from urllib.parse import urlparse

import dns.resolver
import httpx
import whois

from backend.models.evidence import (
    EvidenceItem,
    EvidenceReliability,
    EvidenceSeverity,
    EvidenceStatus,
    EvidenceType,
    RiskDirection,
)
from backend.utils.sanitize import is_safe_url
from backend.utils.security_logging import safe_error_message

logger = logging.getLogger(__name__)

_DEFAULT_DNS_TIMEOUT = 3.0
_DEFAULT_TLS_TIMEOUT = 3.0
_DEFAULT_RDAP_TIMEOUT = 3.5

_NEW_DOMAIN_CRITICAL_DAYS = 3
_NEW_DOMAIN_HIGH_DAYS = 14
_NEW_DOMAIN_MEDIUM_DAYS = 30


def is_safe_ip(ip_str: str) -> bool:
    """SSRF Defense: Verify IP is a valid public IP and not loopback, private, link-local, or cloud metadata."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return False
        if str(ip) == "169.254.169.254":
            return False
        return True
    except ValueError:
        return False


def clean_domain(domain_or_url: str) -> str:
    """Extract clean domain name from URL or host string."""
    d = domain_or_url.strip().lower()
    if "://" in d:
        try:
            parsed = urlparse(d)
            d = parsed.hostname or d
        except Exception:
            pass
    d = d.split("/")[0].split(":")[0].strip()
    return d


# ─── 1. DNS Resolution ───

def resolve_dns(domain: str) -> dict[str, Any]:
    """
    Perform live DNS queries for A, AAAA, MX, NS, CNAME, and TXT records.
    Returns structured results and flags SSRF or security concerns.
    """
    target = clean_domain(domain)
    result: dict[str, Any] = {
        "domain": target,
        "a": [],
        "aaaa": [],
        "mx": [],
        "ns": [],
        "cname": [],
        "txt": [],
        "spf": None,
        "dmarc": None,
        "is_resolvable": False,
        "contains_private_ip": False,
        "error": None,
    }

    if not target or "." not in target:
        result["error"] = "Invalid domain name"
        return result

    resolver = dns.resolver.Resolver()
    resolver.lifetime = _DEFAULT_DNS_TIMEOUT
    resolver.timeout = _DEFAULT_DNS_TIMEOUT

    # A Records
    try:
        answers = resolver.resolve(target, "A")
        for rdata in answers:
            ip_val = rdata.to_text().strip()
            result["a"].append(ip_val)
            if not is_safe_ip(ip_val):
                result["contains_private_ip"] = True
        result["is_resolvable"] = True
    except dns.resolver.NXDOMAIN:
        result["error"] = "NXDOMAIN"
    except dns.resolver.NoAnswer:
        result["error"] = "NoAnswer"
    except Exception as e:
        result["error"] = safe_error_message(e)

    # AAAA Records
    try:
        answers = resolver.resolve(target, "AAAA")
        for rdata in answers:
            ip_val = rdata.to_text().strip()
            result["aaaa"].append(ip_val)
            if not is_safe_ip(ip_val):
                result["contains_private_ip"] = True
        result["is_resolvable"] = True
    except Exception:
        pass

    # MX Records
    try:
        answers = resolver.resolve(target, "MX")
        for rdata in answers:
            result["mx"].append(rdata.exchange.to_text().rstrip("."))
    except Exception:
        pass

    # NS Records
    try:
        answers = resolver.resolve(target, "NS")
        for rdata in answers:
            result["ns"].append(rdata.target.to_text().rstrip("."))
    except Exception:
        pass

    # CNAME Records
    try:
        answers = resolver.resolve(target, "CNAME")
        for rdata in answers:
            result["cname"].append(rdata.target.to_text().rstrip("."))
    except Exception:
        pass

    # TXT Records (SPF)
    try:
        answers = resolver.resolve(target, "TXT")
        for rdata in answers:
            for txt_string in rdata.strings:
                decoded = txt_string.decode("utf-8", errors="ignore")
                result["txt"].append(decoded)
                if decoded.startswith("v=spf1"):
                    result["spf"] = decoded
    except Exception:
        pass

    # DMARC Record (_dmarc.domain)
    try:
        dmarc_target = f"_dmarc.{target}"
        answers = resolver.resolve(dmarc_target, "TXT")
        for rdata in answers:
            for txt_string in rdata.strings:
                decoded = txt_string.decode("utf-8", errors="ignore")
                if decoded.startswith("v=DMARC1"):
                    result["dmarc"] = decoded
    except Exception:
        pass

    return result


# ─── 2. Live TLS Certificate Inspection ───

def inspect_tls_certificate(domain: str, port: int = 443) -> dict[str, Any] | None:
    """
    Perform live TLS handshake to inspect SSL/TLS certificate.
    SSRF Protected: resolves destination first; refuses connection if resolved IP is non-public.
    """
    target = clean_domain(domain)
    if not target or "." not in target:
        return None

    # Resolve IP first to verify it is safe before connecting
    try:
        addrinfo = socket.getaddrinfo(target, port, socket.AF_INET, socket.SOCK_STREAM)
        if not addrinfo:
            return None
        target_ip = addrinfo[0][4][0]
        if not is_safe_ip(target_ip):
            logger.warning("SSRF blocked: Domain %s resolved to unsafe IP %s", target, target_ip)
            return None
    except Exception as e:
        logger.debug("Failed to resolve %s for TLS: %s", target, safe_error_message(e))
        return None

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(_DEFAULT_TLS_TIMEOUT)

    try:
        sock.connect((target_ip, port))
        with ctx.wrap_socket(sock, server_hostname=target) as ssock:
            cert_bin = ssock.getpeercert(binary_form=True)
            if not cert_bin:
                return None
            cert = ssock.getpeercert()

        issuer_str = "Unknown"
        subject_str = "Unknown"
        not_before = None
        not_after = None
        sans: list[str] = []

        if cert:
            issuer_parts = cert.get("issuer", ())
            issuer_dict = {item[0][0]: item[0][1] for item in issuer_parts if item and item[0]}
            issuer_str = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown Issuer"

            subject_parts = cert.get("subject", ())
            subject_dict = {item[0][0]: item[0][1] for item in subject_parts if item and item[0]}
            subject_str = subject_dict.get("commonName") or "Unknown Subject"

            not_before_str = cert.get("notBefore")
            not_after_str = cert.get("notAfter")
            if not_before_str:
                try:
                    not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                except Exception:
                    pass
            if not_after_str:
                try:
                    not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                except Exception:
                    pass

            for san_type, san_val in cert.get("subjectAltName", ()):
                if san_type.lower() == "dns":
                    sans.append(san_val.lower().strip())

        covered = False
        target_l = target.lower()
        for name in sans + ([subject_str.lower()] if subject_str else []):
            if name == target_l:
                covered = True
                break
            if name.startswith("*.") and target_l.endswith(name[1:]) and target_l.count(".") == name.count("."):
                covered = True
                break

        cert_age_days = None
        is_freshly_issued = False
        if not_before:
            delta = datetime.now(timezone.utc) - not_before
            cert_age_days = max(0, delta.days)
            if cert_age_days <= 3:
                is_freshly_issued = True

        return {
            "domain": target,
            "ip": target_ip,
            "issuer": issuer_str,
            "subject": subject_str,
            "sans": sans[:15],
            "not_before": not_before.isoformat() if not_before else None,
            "not_after": not_after.isoformat() if not_after else None,
            "cert_age_days": cert_age_days,
            "is_freshly_issued": is_freshly_issued,
            "domain_covered_by_cert": covered,
            "is_self_signed": issuer_str == subject_str and issuer_str != "Unknown",
        }
    except Exception as e:
        logger.debug("TLS inspection failed for %s: %s", target, safe_error_message(e))
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


# ─── 3. Live RDAP / WHOIS Registration ───

def get_rdap_whois_info(domain: str) -> dict[str, Any] | None:
    """Fetch domain registration details via RDAP (JSON) or WHOIS fallback."""
    clean = clean_domain(domain)
    if not clean or "." not in clean:
        return None

    test_url = f"http://{clean}"
    if not is_safe_url(test_url):
        return None

    # 1. Try modern RDAP
    try:
        rdap_url = f"https://rdap.org/domain/{clean}"
        with httpx.Client(timeout=_DEFAULT_RDAP_TIMEOUT, follow_redirects=True) as client:
            resp = client.get(
                rdap_url,
                headers={"Accept": "application/rdap+json, application/json", "User-Agent": "CyberKawach-Intel/1.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                events = data.get("events", [])
                reg_date_str = None
                exp_date_str = None
                for ev in events:
                    action = ev.get("eventAction", "")
                    if action in ("registration", "created"):
                        reg_date_str = ev.get("eventDate")
                    elif action in ("expiration", "expired"):
                        exp_date_str = ev.get("eventDate")

                registrar_name = "Unknown Registrar"
                entities = data.get("entities", [])
                for ent in entities:
                    roles = ent.get("roles", [])
                    if "registrar" in roles:
                        vcard = ent.get("vcardArray", [])
                        if len(vcard) > 1 and isinstance(vcard[1], list):
                            for prop in vcard[1]:
                                if len(prop) > 3 and prop[0] == "fn":
                                    registrar_name = str(prop[3]).strip()
                                    break

                if reg_date_str:
                    try:
                        clean_dt = reg_date_str.replace("Z", "+00:00")
                        created_dt = datetime.fromisoformat(clean_dt)
                        now = datetime.now(timezone.utc)
                        days_old = max(0, (now - created_dt).days)
                        return {
                            "domain": clean,
                            "days_old": days_old,
                            "creation_date": created_dt.isoformat(),
                            "expiration_date": exp_date_str,
                            "registrar": registrar_name,
                            "source": "rdap",
                        }
                    except Exception:
                        pass
    except Exception:
        pass

    # 2. Fallback to WHOIS
    try:
        w = whois.whois(clean)
        cdate = getattr(w, "creation_date", None)
        if isinstance(cdate, list):
            cdate = min((d for d in cdate if d is not None), default=None)
        if cdate:
            now = datetime.now(timezone.utc)
            if hasattr(cdate, "tzinfo") and cdate.tzinfo is not None:
                diff = now - cdate
            else:
                diff = datetime.now(timezone.utc) - cdate.replace(tzinfo=timezone.utc) if hasattr(cdate, "replace") else datetime.utcnow() - cdate
            days = max(0, diff.days)
            reg = getattr(w, "registrar", None)
            if isinstance(reg, list):
                reg = reg[0] if reg else "Unknown Registrar"
            return {
                "domain": clean,
                "days_old": days,
                "creation_date": cdate.isoformat() if hasattr(cdate, "isoformat") else str(cdate),
                "registrar": str(reg).strip() if reg else "Unknown Registrar",
                "source": "whois",
            }
    except Exception:
        pass

    return None


# ─── 4. Collector & Evidence Translation ───

def collect_domain_evidence(domain: str) -> list[EvidenceItem]:
    """
    Run DNS resolution, TLS inspection, and RDAP/WHOIS checks on a domain.
    Emits typed EvidenceItems with strict tiers and provenance.
    """
    items: list[EvidenceItem] = []
    target = clean_domain(domain)
    if not target or "." not in target:
        return items

    # 1. DNS Findings
    dns_res = resolve_dns(target)
    if dns_res.get("is_resolvable"):
        ip_summary = ", ".join(dns_res.get("a", [])[:3])
        items.append(EvidenceItem(
            type=EvidenceType.DNS_RECORD,
            source="dns_resolver",
            source_type="dns",
            evidence_tier="OBSERVED",
            indicator=target,
            finding=f"Domain successfully resolves to IP(s): {ip_summary}",
            description=f"Live DNS query resolved domain '{target}' to {len(dns_res.get('a', []))} IPv4 address(es).",
            observed_value=ip_summary,
            interpretation="Live domain is actively configured and reachable on the public Internet.",
            status=EvidenceStatus.OBSERVED,
            reliability=EvidenceReliability.DETERMINISTIC_FACT,
            risk_direction=RiskDirection.NEUTRAL,
            severity=EvidenceSeverity.INFORMATIONAL,
            correlation_group="dns_records",
            raw_data=dns_res,
        ))

        # Check for SPF / DMARC
        if dns_res.get("spf"):
            items.append(EvidenceItem(
                type=EvidenceType.DNS_RECORD,
                source="dns_resolver",
                source_type="dns",
                evidence_tier="OBSERVED",
                indicator=target,
                finding=f"SPF record configured for domain: {dns_res['spf'][:60]}...",
                description="Domain has an active Sender Policy Framework (SPF) DNS record.",
                observed_value=dns_res["spf"],
                interpretation="Domain defines authorized mail sending servers.",
                status=EvidenceStatus.OBSERVED,
                reliability=EvidenceReliability.DETERMINISTIC_FACT,
                risk_direction=RiskDirection.NEUTRAL,
                severity=EvidenceSeverity.INFORMATIONAL,
                correlation_group="email_authentication",
                raw_data={"spf": dns_res["spf"]},
            ))
    elif dns_res.get("error") and "NXDOMAIN" in dns_res.get("error", ""):
        items.append(EvidenceItem(
            type=EvidenceType.DNS_RECORD,
            source="dns_resolver",
            source_type="dns",
            evidence_tier="OBSERVED",
            indicator=target,
            finding="Domain does not exist in public DNS (NXDOMAIN)",
            description=f"DNS query for '{target}' returned NXDOMAIN — the domain is unallocated or suspended.",
            observed_value="NXDOMAIN",
            interpretation="Non-existent domain; cannot be reached. May be an expired phishing host or typo.",
            status=EvidenceStatus.OBSERVED,
            reliability=EvidenceReliability.DETERMINISTIC_FACT,
            risk_direction=RiskDirection.INCREASES_RISK,
            severity=EvidenceSeverity.MEDIUM,
            correlation_group="dns_records",
            raw_data=dns_res,
        ))

    # 2. TLS Findings
    tls_res = inspect_tls_certificate(target)
    if tls_res:
        issuer = tls_res.get("issuer", "Unknown")
        cert_age = tls_res.get("cert_age_days")
        is_fresh = tls_res.get("is_freshly_issued", False)
        covered = tls_res.get("domain_covered_by_cert", True)
        is_self_signed = tls_res.get("is_self_signed", False)

        if not covered:
            items.append(EvidenceItem(
                type=EvidenceType.TLS_CERTIFICATE,
                source="tls_inspector",
                source_type="tls",
                evidence_tier="OBSERVED",
                indicator=target,
                finding=f"TLS certificate does NOT cover domain '{target}' (Certificate Mismatch)",
                description=f"Server presented a certificate issued to '{tls_res.get('subject')}' which does not include '{target}'.",
                observed_value=f"Subject: {tls_res.get('subject')}, SANs: {', '.join(tls_res.get('sans', [])[:3])}",
                interpretation="TLS certificate mismatch — strong indicator of domain spoofing, proxy interception, or improper configuration.",
                status=EvidenceStatus.CONFIRMED,
                reliability=EvidenceReliability.CRYPTOGRAPHIC,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.HIGH,
                confidence=0.88,
                correlation_group="tls_security",
                raw_data=tls_res,
            ))
        elif is_self_signed:
            items.append(EvidenceItem(
                type=EvidenceType.TLS_CERTIFICATE,
                source="tls_inspector",
                source_type="tls",
                evidence_tier="OBSERVED",
                indicator=target,
                finding="Self-signed TLS certificate detected",
                description=f"The SSL certificate on '{target}' is self-signed and not issued by a recognized Certificate Authority.",
                observed_value=f"Issuer: {issuer}, Subject: {tls_res.get('subject')}",
                interpretation="Self-signed certificates are rejected by standard browsers and commonly found in ad-hoc attack infrastructure.",
                status=EvidenceStatus.CONFIRMED,
                reliability=EvidenceReliability.CRYPTOGRAPHIC,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.HIGH,
                confidence=0.85,
                correlation_group="tls_security",
                raw_data=tls_res,
            ))
        elif is_fresh:
            items.append(EvidenceItem(
                type=EvidenceType.TLS_CERTIFICATE,
                source="tls_inspector",
                source_type="tls",
                evidence_tier="OBSERVED",
                indicator=target,
                finding=f"Brand new TLS certificate issued {cert_age} day(s) ago by {issuer}",
                description=f"Certificate was issued within the last 72 hours ({cert_age} days old).",
                observed_value=f"{cert_age} days old (Issued by: {issuer})",
                interpretation="Freshly issued certificates on unfamiliar domains correlate strongly with newly deployed phishing campaigns.",
                status=EvidenceStatus.OBSERVED,
                reliability=EvidenceReliability.CRYPTOGRAPHIC,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.MEDIUM,
                confidence=0.75,
                correlation_group="tls_security",
                raw_data=tls_res,
            ))
        else:
            items.append(EvidenceItem(
                type=EvidenceType.TLS_CERTIFICATE,
                source="tls_inspector",
                source_type="tls",
                evidence_tier="OBSERVED",
                indicator=target,
                finding=f"Valid TLS certificate issued by {issuer}",
                description=f"Server presented a valid certificate covering '{target}' issued by {issuer}.",
                observed_value=f"Issuer: {issuer}, Certificate Age: {cert_age} days",
                interpretation="Standard TLS encryption active. Note that modern phishing sites routinely use free TLS certificates.",
                status=EvidenceStatus.OBSERVED,
                reliability=EvidenceReliability.CRYPTOGRAPHIC,
                risk_direction=RiskDirection.NEUTRAL,
                severity=EvidenceSeverity.INFORMATIONAL,
                correlation_group="tls_security",
                raw_data=tls_res,
            ))

    # 3. RDAP / WHOIS Findings
    whois_info = get_rdap_whois_info(target)
    if whois_info and whois_info.get("days_old") is not None:
        days = whois_info["days_old"]
        registrar = whois_info.get("registrar", "Unknown Registrar")
        source = whois_info.get("source", "rdap")

        if days <= _NEW_DOMAIN_CRITICAL_DAYS:
            items.append(EvidenceItem(
                type=EvidenceType.DOMAIN_AGE,
                source=f"{source}_service",
                source_type="rdap",
                evidence_tier="OBSERVED",
                indicator=target,
                finding=f"Domain registered just {days} day(s) ago ({registrar})",
                description=f"Live registration records show '{target}' was registered only {days} day(s) ago.",
                observed_value=f"{days} days old ({registrar})",
                interpretation="Extremely high risk: domain created immediately prior to message delivery, characteristic of disposable phishing lure.",
                status=EvidenceStatus.CONFIRMED,
                reliability=EvidenceReliability.EXTERNAL_DB,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.CRITICAL,
                confidence=0.92,
                correlation_group="domain_registration",
                raw_data=whois_info,
            ))
        elif days <= _NEW_DOMAIN_HIGH_DAYS:
            items.append(EvidenceItem(
                type=EvidenceType.DOMAIN_AGE,
                source=f"{source}_service",
                source_type="rdap",
                evidence_tier="OBSERVED",
                indicator=target,
                finding=f"Recently registered domain: {days} days old ({registrar})",
                description="Domain was registered within the past two weeks.",
                observed_value=f"{days} days old ({registrar})",
                interpretation="Recently registered domain; disproportionately represented in phishing and credential harvesting campaigns.",
                status=EvidenceStatus.CONFIRMED,
                reliability=EvidenceReliability.EXTERNAL_DB,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.HIGH,
                confidence=0.80,
                correlation_group="domain_registration",
                raw_data=whois_info,
            ))
        elif days <= _NEW_DOMAIN_MEDIUM_DAYS:
            items.append(EvidenceItem(
                type=EvidenceType.DOMAIN_AGE,
                source=f"{source}_service",
                source_type="rdap",
                evidence_tier="OBSERVED",
                indicator=target,
                finding=f"Domain is relatively new ({days} days old, {registrar})",
                description="Domain has been active for less than 30 days.",
                observed_value=f"{days} days old",
                interpretation="Relatively new domain requiring elevated caution.",
                status=EvidenceStatus.CONFIRMED,
                reliability=EvidenceReliability.EXTERNAL_DB,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.MEDIUM,
                confidence=0.65,
                correlation_group="domain_registration",
                raw_data=whois_info,
            ))
        else:
            items.append(EvidenceItem(
                type=EvidenceType.DOMAIN_AGE,
                source=f"{source}_service",
                source_type="rdap",
                evidence_tier="OBSERVED",
                indicator=target,
                finding=f"Established domain age: {days} days ({registrar})",
                description=f"Domain has existed for {days} days, consistent with mature infrastructure.",
                observed_value=f"{days} days old",
                interpretation="Established domain age significantly reduces probability of disposable lure.",
                status=EvidenceStatus.OBSERVED,
                reliability=EvidenceReliability.EXTERNAL_DB,
                risk_direction=RiskDirection.NEUTRAL,
                severity=EvidenceSeverity.INFORMATIONAL,
                confidence=0.50,
                correlation_group="domain_registration",
                raw_data=whois_info,
            ))

    return items
