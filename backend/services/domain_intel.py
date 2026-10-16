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

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtensionOID
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

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


# ─── Homoglyph & Infrastructure Intelligence Constants ───

CYRILLIC_LOOKALIKES: dict[str, str] = {
    "\u0430": "a", "\u0441": "c", "\u0435": "e", "\u043e": "o",
    "\u0440": "p", "\u0455": "s", "\u0445": "x", "\u0443": "y",
    "\u0456": "i", "\u0458": "j", "\u0410": "A", "\u0412": "B",
    "\u0421": "C", "\u0415": "E", "\u041d": "H", "\u041e": "O",
    "\u0420": "P", "\u0422": "T", "\u0425": "X",
}

KNOWN_HIGH_RISK_HOSTERS: set[str] = {
    "alexhost", "bulletproof", "stark industries", "free range cloud",
    "flokinet", "hostwinds", "hostinger", "namecheap", "contabo",
    "hetzner", "ovh", "vultr", "digitalocean", "linode", "choopa",
}


def detect_homoglyphs(domain: str) -> dict[str, Any]:
    """
    Detect Cyrillic / Greek lookalike characters or Punycode spoofing in domains.
    """
    clean = clean_domain(domain)
    has_punycode = clean.startswith("xn--") or ".xn--" in clean

    found_homoglyphs = []
    normalized_chars = []
    is_spoofed = False

    for ch in clean:
        if ch in CYRILLIC_LOOKALIKES:
            found_homoglyphs.append({
                "char": ch,
                "looks_like": CYRILLIC_LOOKALIKES[ch],
                "hex": f"U+{ord(ch):04X}",
            })
            normalized_chars.append(CYRILLIC_LOOKALIKES[ch])
            is_spoofed = True
        else:
            normalized_chars.append(ch)

    normalized_domain = "".join(normalized_chars)

    return {
        "domain": clean,
        "is_spoofed": is_spoofed or has_punycode,
        "has_punycode": has_punycode,
        "homoglyph_count": len(found_homoglyphs),
        "found_homoglyphs": found_homoglyphs,
        "normalized_domain": normalized_domain if is_spoofed else clean,
    }


def lookup_asn_and_infrastructure(ip_str: str, timeout: float = 2.5) -> dict[str, Any]:
    """
    Resolve IP to Autonomous System Number (ASN), BGP Prefix, Country, Org Name, and Reverse DNS (PTR).
    Uses DNS-based Team Cymru mapping for high-speed deterministic resolution without external API tokens.
    """
    ip = ip_str.strip()
    if not is_safe_ip(ip):
        return {"ip": ip, "valid": False, "error": "Non-public IP or SSRF restricted"}

    result: dict[str, Any] = {
        "ip": ip,
        "valid": True,
        "asn": None,
        "bgp_prefix": None,
        "country": None,
        "org_name": None,
        "ptr": None,
        "is_high_risk_hosting": False,
        "error": None,
    }

    # 1. Reverse DNS (PTR)
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        result["ptr"] = host
    except Exception:
        pass

    # 2. Team Cymru DNS IP-to-ASN
    try:
        octets = ip.split(".")
        if len(octets) == 4:
            reversed_ip = ".".join(reversed(octets))
            query_name = f"{reversed_ip}.origin.asn.cymru.com"
            resolver = dns.resolver.Resolver()
            resolver.lifetime = timeout
            resolver.timeout = timeout
            answers = resolver.resolve(query_name, "TXT")
            for rdata in answers:
                for s in rdata.strings:
                    raw = s.decode("utf-8", errors="ignore").strip('"')
                    parts = [p.strip() for p in raw.split("|")]
                    if len(parts) >= 3:
                        result["asn"] = f"AS{parts[0]}" if not parts[0].startswith("AS") else parts[0]
                        result["bgp_prefix"] = parts[1]
                        result["country"] = parts[2]
                        break

            # Query AS Name if ASN is found
            if result["asn"]:
                asn_num = result["asn"].replace("AS", "").strip()
                as_query = f"AS{asn_num}.asn.cymru.com"
                as_answers = resolver.resolve(as_query, "TXT")
                for rdata in as_answers:
                    for s in rdata.strings:
                        raw = s.decode("utf-8", errors="ignore").strip('"')
                        parts = [p.strip() for p in raw.split("|")]
                        if len(parts) >= 5:
                            result["org_name"] = parts[4].strip()
                            break
    except Exception as e:
        logger.debug("Cymru DNS ASN lookup notice for %s: %s", ip, safe_error_message(e))

    # Check if hosting organization or PTR matches known offshore / disposable hosting
    org_l = (result.get("org_name") or "").lower()
    ptr_l = (result.get("ptr") or "").lower()
    for high_risk in KNOWN_HIGH_RISK_HOSTERS:
        if high_risk in org_l or high_risk in ptr_l:
            result["is_high_risk_hosting"] = True
            break

    return result


# ─── 1. DNS Resolution ───

def resolve_dns(domain: str) -> dict[str, Any]:
    """
    Perform live DNS queries for A, AAAA, MX, NS, CNAME, and TXT records.
    Returns structured results and flags SSRF or security concerns.
    """
    target = clean_domain(domain)
    # IDNA encode non-ascii domains (e.g. Cyrillic homoglyphs) for standard DNS resolution
    try:
        query_target = target.encode("idna").decode("ascii")
    except Exception:
        query_target = target

    result: dict[str, Any] = {
        "domain": target,
        "query_target": query_target,
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
        answers = resolver.resolve(query_target, "A")
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
        answers = resolver.resolve(query_target, "AAAA")
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
        answers = resolver.resolve(query_target, "MX")
        for rdata in answers:
            result["mx"].append(rdata.exchange.to_text().rstrip("."))
    except Exception:
        pass

    # NS Records
    try:
        answers = resolver.resolve(query_target, "NS")
        for rdata in answers:
            result["ns"].append(rdata.target.to_text().rstrip("."))
    except Exception:
        pass

    # CNAME Records
    try:
        answers = resolver.resolve(query_target, "CNAME")
        for rdata in answers:
            result["cname"].append(rdata.target.to_text().rstrip("."))
    except Exception:
        pass

    # TXT Records (SPF)
    try:
        answers = resolver.resolve(query_target, "TXT")
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
        dmarc_target = f"_dmarc.{query_target}"
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

    # Check standard CA trust first
    is_trusted_ca = False
    try:
        verify_ctx = ssl.create_default_context()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as vsock:
            vsock.settimeout(_DEFAULT_TLS_TIMEOUT)
            vsock.connect((target_ip, port))
            with verify_ctx.wrap_socket(vsock, server_hostname=target) as vssock:
                is_trusted_ca = True
    except ssl.SSLCertVerificationError:
        is_trusted_ca = False
    except Exception:
        pass

    cert_bin = None
    cert_dict = {}

    # 1. Attempt standard verified connection to get full peer cert dictionary
    try:
        ctx_v = ssl.create_default_context()
        ctx_v.check_hostname = False
        with socket.create_connection((target_ip, port), timeout=_DEFAULT_TLS_TIMEOUT) as sock:
            with ctx_v.wrap_socket(sock, server_hostname=target) as ssock:
                cert_dict = ssock.getpeercert() or {}
                cert_bin = ssock.getpeercert(binary_form=True)
    except Exception:
        pass

    # 2. Fallback to unverified connection to retrieve binary DER certificate
    if not cert_bin:
        try:
            ctx_u = ssl.create_default_context()
            ctx_u.check_hostname = False
            ctx_u.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target_ip, port), timeout=_DEFAULT_TLS_TIMEOUT) as sock:
                with ctx_u.wrap_socket(sock, server_hostname=target) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    if not cert_dict:
                        cert_dict = ssock.getpeercert() or {}
        except Exception:
            pass

    if not cert_bin and not cert_dict:
        return None

    try:
        issuer_str = "Unknown Issuer"
        subject_str = "Unknown Subject"
        not_before = None
        not_after = None
        sans: list[str] = []
        is_self_signed = False

        if _HAS_CRYPTOGRAPHY and cert_bin:
            try:
                x_cert = x509.load_der_x509_certificate(cert_bin)
                # Issuer
                i_orgs = x_cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                i_cns = x_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                if i_orgs and i_orgs[0].value:
                    issuer_str = str(i_orgs[0].value)
                elif i_cns and i_cns[0].value:
                    issuer_str = str(i_cns[0].value)

                # Subject
                s_cns = x_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if s_cns and s_cns[0].value:
                    subject_str = str(s_cns[0].value)

                # Validity dates
                try:
                    not_before = x_cert.not_valid_before_utc
                    not_after = x_cert.not_valid_after_utc
                except AttributeError:
                    not_before = x_cert.not_valid_before.replace(tzinfo=timezone.utc)
                    not_after = x_cert.not_valid_after.replace(tzinfo=timezone.utc)

                # SANs
                try:
                    san_ext = x_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    sans = [s.lower().strip() for s in san_ext.value.get_values_for_type(x509.DNSName)]
                except Exception:
                    sans = []

                # Self-signed
                is_self_signed = (x_cert.issuer == x_cert.subject)
            except Exception as ex:
                logger.debug("x509 DER parse notice: %s", safe_error_message(ex))

        # Fallback to ssl dict if cryptography failed or unavailable
        if issuer_str == "Unknown Issuer" and cert_dict:
            issuer_parts = cert_dict.get("issuer", ())
            idict = {item[0][0]: item[0][1] for item in issuer_parts if item and item[0]}
            issuer_str = idict.get("organizationName") or idict.get("commonName") or "Unknown Issuer"

            subject_parts = cert_dict.get("subject", ())
            sdict = {item[0][0]: item[0][1] for item in subject_parts if item and item[0]}
            subject_str = sdict.get("commonName") or "Unknown Subject"

            if not not_before and cert_dict.get("notBefore"):
                try:
                    not_before = datetime.strptime(cert_dict["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                except Exception:
                    pass
            if not not_after and cert_dict.get("notAfter"):
                try:
                    not_after = datetime.strptime(cert_dict["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                except Exception:
                    pass

            if not sans:
                for san_type, san_val in cert_dict.get("subjectAltName", ()):
                    if san_type.lower() == "dns":
                        sans.append(san_val.lower().strip())

            is_self_signed = issuer_str == subject_str and issuer_str != "Unknown Issuer"

        # Check coverage
        covered = False
        target_l = target.lower()
        candidate_names = [n.lower() for n in sans]
        if subject_str and subject_str.lower() != "unknown subject":
            candidate_names.append(subject_str.lower())

        for name in candidate_names:
            if name == target_l:
                covered = True
                break
            if name.startswith("*."):
                suffix = name[2:]
                if target_l == suffix or (target_l.endswith("." + suffix) and target_l.count(".") == suffix.count(".") + 1):
                    covered = True
                    break

        now = datetime.now(timezone.utc)
        is_expired = False
        if not_after and now > not_after:
            is_expired = True
        if not_before and now < not_before:
            is_expired = True

        cert_age_days = None
        is_freshly_issued = False
        if not_before:
            delta = now - not_before
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
            "is_expired": is_expired,
            "domain_covered_by_cert": covered,
            "is_self_signed": is_self_signed,
            "is_trusted_ca": is_trusted_ca,
        }
    except Exception as e:
        logger.debug("TLS parsing failed for %s: %s", target, safe_error_message(e))
        return None


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

    # 0. Homoglyph & Punycode Spoofing Check
    homo_res = detect_homoglyphs(target)
    if homo_res.get("is_spoofed"):
        items.append(EvidenceItem(
            type=EvidenceType.URL_ANALYSIS,
            source="homoglyph_detector",
            source_type="content",
            evidence_tier="OBSERVED",
            indicator=target,
            finding=f"Homoglyph Unicode / Punycode visual spoofing detected: '{target}' masquerades as '{homo_res['normalized_domain']}'",
            description=(
                f"Domain contains {homo_res['homoglyph_count']} lookalike character(s) from a foreign script (e.g. Cyrillic) "
                f"or Punycode prefix (xn--) to deceive human visual inspection into believing it is '{homo_res['normalized_domain']}'."
            ),
            observed_value=f"Target: {target} -> Visual clone of: {homo_res['normalized_domain']}",
            interpretation="Homoglyph visual deception is a deliberate technique to forge known organizational brands.",
            status=EvidenceStatus.CONFIRMED,
            reliability=EvidenceReliability.DETERMINISTIC_FACT,
            risk_direction=RiskDirection.INCREASES_RISK,
            severity=EvidenceSeverity.CRITICAL,
            confidence=0.95,
            correlation_group="domain_homoglyph_spoofing",
            raw_data=homo_res,
        ))

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

        # Autonomous System (ASN) & BGP Infrastructure Forensics
        for ip in dns_res.get("a", [])[:2]:
            asn_info = lookup_asn_and_infrastructure(ip)
            if asn_info.get("valid") and (asn_info.get("asn") or asn_info.get("ptr")):
                asn_str = asn_info.get("asn") or "Unknown ASN"
                org_str = asn_info.get("org_name") or "Hosting Provider"
                country_str = asn_info.get("country") or "Global"
                ptr_str = asn_info.get("ptr") or "No PTR"
                is_high_risk = asn_info.get("is_high_risk_hosting", False)

                items.append(EvidenceItem(
                    type=EvidenceType.INFRASTRUCTURE_ANALYSIS,
                    source="asn_infrastructure_inspector",
                    source_type="dns",
                    evidence_tier="OBSERVED",
                    indicator=ip,
                    finding=f"BGP Autonomous System: {asn_str} ({org_str}) in {country_str}",
                    description=(
                        f"Resolved IP {ip} is hosted under {asn_str} [{org_str}], Prefix: {asn_info.get('bgp_prefix', 'N/A')}, "
                        f"Country: {country_str}, Reverse DNS PTR: '{ptr_str}'. "
                        + ("Identified with known bulletproof / disposable hosting provider patterns." if is_high_risk else "Public internet routing verified.")
                    ),
                    observed_value=f"{ip} -> {asn_str} ({org_str}), Country: {country_str}, PTR: {ptr_str}",
                    interpretation="Hosting infrastructure and network autonomous routing characteristics identified via live BGP/DNS telemetry.",
                    status=EvidenceStatus.CONFIRMED,
                    reliability=EvidenceReliability.DETERMINISTIC_FACT,
                    risk_direction=RiskDirection.INCREASES_RISK if is_high_risk else RiskDirection.NEUTRAL,
                    severity=EvidenceSeverity.HIGH if is_high_risk else EvidenceSeverity.INFORMATIONAL,
                    confidence=0.90,
                    correlation_group="bgp_infrastructure",
                    raw_data=asn_info,
                ))

        # Check SPF Policy
        spf_rec = dns_res.get("spf")
        if spf_rec:
            spf_l = spf_rec.lower()
            if "+all" in spf_l:
                items.append(EvidenceItem(
                    type=EvidenceType.DNS_RECORD,
                    source="email_security_auditor",
                    source_type="dns",
                    evidence_tier="OBSERVED",
                    indicator=target,
                    finding=f"Critical email security vulnerability: SPF policy '+all' permits ANY server to spoof '{target}'",
                    description=f"SPF record '{spf_rec}' includes '+all', explicitly authorizing any computer worldwide to send emails as this domain.",
                    observed_value=spf_rec,
                    interpretation="Permissive SPF (+all) enables threat actors to send forged phishing emails without authentication failure.",
                    status=EvidenceStatus.CONFIRMED,
                    reliability=EvidenceReliability.DETERMINISTIC_FACT,
                    risk_direction=RiskDirection.INCREASES_RISK,
                    severity=EvidenceSeverity.CRITICAL,
                    confidence=0.95,
                    correlation_group="email_authentication",
                    raw_data={"spf": spf_rec, "vulnerability": "permissive_plus_all"},
                ))
            elif "?all" in spf_l:
                items.append(EvidenceItem(
                    type=EvidenceType.DNS_RECORD,
                    source="email_security_auditor",
                    source_type="dns",
                    evidence_tier="OBSERVED",
                    indicator=target,
                    finding=f"Neutral SPF policy '?all' on '{target}' provides zero spoofing protection",
                    description="Domain explicitly declares a neutral SPF policy (?all), meaning recipient mail servers will not reject unauthorized senders.",
                    observed_value=spf_rec,
                    interpretation="Neutral SPF fails to protect email recipients from fraudulent sender impersonation.",
                    status=EvidenceStatus.CONFIRMED,
                    reliability=EvidenceReliability.DETERMINISTIC_FACT,
                    risk_direction=RiskDirection.INCREASES_RISK,
                    severity=EvidenceSeverity.HIGH,
                    confidence=0.88,
                    correlation_group="email_authentication",
                    raw_data={"spf": spf_rec, "vulnerability": "neutral_policy"},
                ))
            elif "-all" in spf_l:
                items.append(EvidenceItem(
                    type=EvidenceType.DNS_RECORD,
                    source="email_security_auditor",
                    source_type="dns",
                    evidence_tier="OBSERVED",
                    indicator=target,
                    finding=f"Hardfail SPF policy (-all) enforced for domain '{target}'",
                    description="Domain defines a strict hardfail SPF record (-all) instructing recipient servers to reject unlisted senders.",
                    observed_value=spf_rec,
                    interpretation="Legitimate email authentication policy enforced.",
                    status=EvidenceStatus.CONFIRMED,
                    reliability=EvidenceReliability.DETERMINISTIC_FACT,
                    risk_direction=RiskDirection.DECREASES_RISK,
                    severity=EvidenceSeverity.INFORMATIONAL,
                    correlation_group="email_authentication",
                    raw_data={"spf": spf_rec},
                ))
            else:
                items.append(EvidenceItem(
                    type=EvidenceType.DNS_RECORD,
                    source="email_security_auditor",
                    source_type="dns",
                    evidence_tier="OBSERVED",
                    indicator=target,
                    finding=f"Active SPF record configured: {spf_rec[:60]}...",
                    description="Domain has an active Sender Policy Framework (SPF) record.",
                    observed_value=spf_rec,
                    interpretation="Domain defines authorized mail sending servers.",
                    status=EvidenceStatus.OBSERVED,
                    reliability=EvidenceReliability.DETERMINISTIC_FACT,
                    risk_direction=RiskDirection.NEUTRAL,
                    severity=EvidenceSeverity.INFORMATIONAL,
                    correlation_group="email_authentication",
                    raw_data={"spf": spf_rec},
                ))

        # Check DMARC Policy
        dmarc_rec = dns_res.get("dmarc")
        if dmarc_rec:
            dmarc_l = dmarc_rec.lower()
            if "p=none" in dmarc_l:
                items.append(EvidenceItem(
                    type=EvidenceType.DNS_RECORD,
                    source="email_security_auditor",
                    source_type="dns",
                    evidence_tier="OBSERVED",
                    indicator=target,
                    finding=f"Permissive DMARC policy (p=none) on '{target}' — monitoring only, no rejection",
                    description=f"DMARC record '{dmarc_rec}' specifies 'p=none'. Spoofed emails sent by impostors will NOT be rejected by receiving mail gateways.",
                    observed_value=dmarc_rec,
                    interpretation="DMARC monitoring-only mode allows spoofed emails to land in citizen inboxes.",
                    status=EvidenceStatus.CONFIRMED,
                    reliability=EvidenceReliability.DETERMINISTIC_FACT,
                    risk_direction=RiskDirection.INCREASES_RISK,
                    severity=EvidenceSeverity.MEDIUM,
                    confidence=0.85,
                    correlation_group="email_authentication",
                    raw_data={"dmarc": dmarc_rec},
                ))
            elif "p=reject" in dmarc_l or "p=quarantine" in dmarc_l:
                policy_type = "reject" if "p=reject" in dmarc_l else "quarantine"
                items.append(EvidenceItem(
                    type=EvidenceType.DNS_RECORD,
                    source="email_security_auditor",
                    source_type="dns",
                    evidence_tier="OBSERVED",
                    indicator=target,
                    finding=f"Strict DMARC policy (p={policy_type}) enforced on '{target}'",
                    description=f"Domain strictly enforces DMARC p={policy_type}. Unauthorized emails will be rejected or placed in quarantine.",
                    observed_value=dmarc_rec,
                    interpretation="Domain owner actively protects reputation against unauthorized email forgery.",
                    status=EvidenceStatus.CONFIRMED,
                    reliability=EvidenceReliability.DETERMINISTIC_FACT,
                    risk_direction=RiskDirection.DECREASES_RISK,
                    severity=EvidenceSeverity.INFORMATIONAL,
                    correlation_group="email_authentication",
                    raw_data={"dmarc": dmarc_rec},
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
        is_expired = tls_res.get("is_expired", False)
        covered = tls_res.get("domain_covered_by_cert", True)
        is_self_signed = tls_res.get("is_self_signed", False)

        if is_expired:
            items.append(EvidenceItem(
                type=EvidenceType.TLS_CERTIFICATE,
                source="tls_inspector",
                source_type="tls",
                evidence_tier="OBSERVED",
                indicator=target,
                finding=f"Expired TLS certificate detected on '{target}'",
                description=f"Server presented an expired TLS certificate (Expired on: {tls_res.get('not_after')}).",
                observed_value=f"Expired: {tls_res.get('not_after')}, Issuer: {issuer}",
                interpretation="Expired certificates indicate abandoned infrastructure, compromised host, or security neglect.",
                status=EvidenceStatus.CONFIRMED,
                reliability=EvidenceReliability.CRYPTOGRAPHIC,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.HIGH,
                confidence=0.90,
                correlation_group="tls_security",
                raw_data=tls_res,
            ))
        elif not covered:
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
