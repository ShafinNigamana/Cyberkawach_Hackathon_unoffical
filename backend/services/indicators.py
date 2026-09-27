"""
Reusable Indicator Extraction & Normalization Layer (PRD Section 2).

Extracts and normalizes:
- URLs (with decomposition: scheme, hostname, root domain, subdomain, port, path, query, fragment)
- Domains and IP addresses (differentiating public vs private/loopback/cloud metadata)
- Phone numbers (Indian mobile, toll-free 1800, international)
- Email addresses
- Sender IDs (TRAI 6-character alphanumeric headers vs personal numbers)
- Mentioned brands and institutions
- Financial, credential, urgency, and threat keywords
- Deceptive hyperlink anchor mismatches (<a href="dest">display_text</a>)
Preserves original submitted input alongside all normalized forms.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional
from urllib.parse import parse_qs, unquote, urlparse

from pydantic import BaseModel, Field

# ─── Regex Patterns ───
_URL_REGEX = re.compile(
    r"""(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,63}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))""",
    re.VERBOSE,
)

_HTML_ANCHOR_REGEX = re.compile(
    r'<a\s+(?:[^>]*?\s+)?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)

_EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")

_INDIAN_PHONE_REGEX = re.compile(
    r"(?:(?:\+?91[\-\s]?)?[6-9]\d{9}|1800[\-\s]?\d{3}[\-\s]?\d{3,4})\b"
)

_SMS_HEADER_REGEX = re.compile(r"\b([A-Za-z]{2}[-\s]?[A-Za-z0-9]{6})\b")

# Well-known brands to track
_KNOWN_BRANDS = {
    "sbi": "State Bank of India",
    "yono": "State Bank of India",
    "hdfc": "HDFC Bank",
    "icici": "ICICI Bank",
    "axis": "Axis Bank",
    "pnb": "Punjab National Bank",
    "bob": "Bank of Baroda",
    "paytm": "Paytm",
    "phonepe": "PhonePe",
    "gpay": "Google Pay",
    "amazon": "Amazon India",
    "flipkart": "Flipkart",
    "delhivery": "Delhivery",
    "indiapost": "India Post",
    "india post": "India Post",
    "bluedart": "Blue Dart",
    "mahavitaran": "Mahavitaran (MSEDCL)",
    "msedcl": "Mahavitaran (MSEDCL)",
    "bescom": "BESCOM",
    "bses": "BSES Delhi",
    "income tax": "Income Tax Department",
    "incometax": "Income Tax Department",
    "cbi": "Central Bureau of Investigation (CBI)",
    "police": "Police Authority",
    "mumbai police": "Mumbai Police",
    "cyber crime": "Cyber Crime Department",
    "telegram": "Telegram",
    "whatsapp": "WhatsApp",
    "google": "Google",
    "microsoft": "Microsoft",
    "netflix": "Netflix",
}

_URGENCY_KEYWORDS = [
    "immediately", "urgent", "urgently", "blocked", "suspended", "disconnected",
    "tonight", "expire", "expires", "warning", "final notice", "terminated",
    "deactivated", "cut off", "arrest warrant", "detention", "24 hours", "12 hours",
]

_CREDENTIAL_KEYWORDS = [
    "otp", "pin", "password", "cvv", "pan", "aadhaar", "kyc", "netbanking",
    "login", "verify", "update kyc", "re-kyc", "card number", "debit card",
]

_FINANCIAL_KEYWORDS = [
    "refund", "unauthorized transaction", "lottery", "prize", "cashback",
    "customs charge", "processing fee", "security deposit", "recharge", "upi",
    "payment", "won rs", "earn daily", "part time job", "bill due",
]


class NormalizedURL(BaseModel):
    """Structured decomposition of an extracted URL."""
    original: str
    normalized: str
    scheme: str
    hostname: str
    registered_domain: str
    subdomain: str
    port: Optional[int] = None
    path: str = "/"
    query: str = ""
    query_params: dict[str, list[str]] = Field(default_factory=dict)
    fragment: str = ""
    is_ip: bool = False
    ip_classification: Optional[str] = None  # "public", "private", "loopback", "cloud_metadata"


class ExtractedIndicators(BaseModel):
    """Reusable indicator container holding both raw and normalized indicators."""
    original_text: str
    urls: list[NormalizedURL] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    ips: list[dict] = Field(default_factory=list)
    sender_ids: list[str] = Field(default_factory=list)
    phone_numbers: list[str] = Field(default_factory=list)
    email_addresses: list[str] = Field(default_factory=list)
    mentioned_brands: list[str] = Field(default_factory=list)
    urgency_keywords: list[str] = Field(default_factory=list)
    credential_keywords: list[str] = Field(default_factory=list)
    financial_keywords: list[str] = Field(default_factory=list)
    anchor_mismatches: list[dict] = Field(default_factory=list)


def _split_domain_parts(hostname: str) -> tuple[str, str]:
    """Split hostname into (subdomain, registered_domain)."""
    parts = hostname.split(".")
    if len(parts) <= 2:
        return "", hostname

    # Handle common two-level TLDs (.co.in, .gov.in, .ac.uk, .com.br)
    two_level_tlds = {"co.in", "gov.in", "nic.in", "ac.in", "org.in", "net.in", "co.uk", "com.au"}
    last_two = f"{parts[-2]}.{parts[-1]}".lower()

    if last_two in two_level_tlds and len(parts) >= 3:
        registered = f"{parts[-3]}.{last_two}"
        subdomain = ".".join(parts[:-3])
    else:
        registered = f"{parts[-2]}.{parts[-1]}"
        subdomain = ".".join(parts[:-2])

    return subdomain, registered


def normalize_url(raw_url: str) -> Optional[NormalizedURL]:
    """Parse and normalize a raw URL into structured components without loss of original."""
    clean = raw_url.strip().strip("<>()[]\"'")
    if not clean:
        return None

    # Prepend scheme if missing for parsing
    has_scheme = "://" in clean
    parse_target = clean if has_scheme else f"http://{clean}"

    try:
        parsed = urlparse(parse_target)
        hostname = (parsed.hostname or "").lower().strip()
        if not hostname:
            return None

        # Check IP
        is_ip = False
        ip_classification = None
        try:
            ip_obj = ipaddress.ip_address(hostname)
            is_ip = True
            if ip_obj.is_loopback:
                ip_classification = "loopback"
            elif ip_obj.is_private:
                ip_classification = "private"
            elif str(ip_obj) == "169.254.169.254":
                ip_classification = "cloud_metadata"
            else:
                ip_classification = "public"
            subdomain = ""
            registered_domain = hostname
        except ValueError:
            subdomain, registered_domain = _split_domain_parts(hostname)

        scheme = parsed.scheme.lower() if has_scheme else "http"
        port = parsed.port
        path = parsed.path or "/"
        query = parsed.query or ""
        fragment = parsed.fragment or ""
        params = parse_qs(query)

        # Reconstructed normalized URL
        norm_url = f"{scheme}://{hostname}"
        if port and port not in (80, 443):
            norm_url += f":{port}"
        norm_url += path
        if query:
            norm_url += f"?{query}"
        if fragment:
            norm_url += f"#{fragment}"

        return NormalizedURL(
            original=clean,
            normalized=norm_url,
            scheme=scheme,
            hostname=hostname,
            registered_domain=registered_domain,
            subdomain=subdomain,
            port=port,
            path=path,
            query=query,
            query_params=params,
            fragment=fragment,
            is_ip=is_ip,
            ip_classification=ip_classification,
        )
    except Exception:
        return None


def extract_indicators(text: str, additional_urls: list[str] | None = None) -> ExtractedIndicators:
    """
    Extract all observable indicators from raw message text or email.
    Detects anchor text mismatches, normalized URLs, domains, phones, emails, and brand entities.
    """
    if not text:
        text = ""

    norm_urls: list[NormalizedURL] = []
    seen_urls: set[str] = set()

    # 1. Check for HTML Anchor Mismatches (<a href="dest">display</a>)
    anchor_mismatches: list[dict] = []
    for match in _HTML_ANCHOR_REGEX.finditer(text):
        dest_url = match.group(1).strip()
        disp_text = re.sub(r"<[^>]+>", "", match.group(2)).strip()

        # If display text looks like a URL but points to a different domain
        if ("." in disp_text or "://" in disp_text) and dest_url:
            disp_norm = normalize_url(disp_text)
            dest_norm = normalize_url(dest_url)
            if disp_norm and dest_norm:
                if disp_norm.hostname != dest_norm.hostname:
                    anchor_mismatches.append({
                        "display_text": disp_text,
                        "display_host": disp_norm.hostname,
                        "actual_destination": dest_url,
                        "actual_host": dest_norm.hostname,
                    })

    # 2. Extract URLs from text
    raw_found_urls = [m[0] for m in _URL_REGEX.findall(text)]
    if additional_urls:
        raw_found_urls.extend(additional_urls)

    for r_url in raw_found_urls:
        nu = normalize_url(r_url)
        if nu and nu.normalized not in seen_urls:
            seen_urls.add(nu.normalized)
            norm_urls.append(nu)

    # 3. Extract unique domains & IPs
    domains: list[str] = []
    ips: list[dict] = []
    seen_domains: set[str] = set()

    for nu in norm_urls:
        if nu.is_ip:
            ips.append({
                "ip": nu.hostname,
                "classification": nu.ip_classification,
            })
        elif nu.registered_domain and nu.registered_domain not in seen_domains:
            seen_domains.add(nu.registered_domain)
            domains.append(nu.registered_domain)

    # 4. Extract Emails
    emails = list(set(_EMAIL_REGEX.findall(text)))

    # 5. Extract Phone Numbers
    phones = list(set(_INDIAN_PHONE_REGEX.findall(text)))

    # 6. Extract SMS DLT Headers
    sms_headers = list(set(_SMS_HEADER_REGEX.findall(text)))

    # 7. Extract Brands
    lower_text = text.lower()
    mentioned_brands: list[str] = []
    for token, official_name in _KNOWN_BRANDS.items():
        if re.search(rf"\b{re.escape(token)}\b", lower_text):
            if official_name not in mentioned_brands:
                mentioned_brands.append(official_name)

    # 8. Extract Keywords
    urgency = [w for w in _URGENCY_KEYWORDS if w in lower_text]
    credentials = [w for w in _CREDENTIAL_KEYWORDS if w in lower_text]
    financial = [w for w in _FINANCIAL_KEYWORDS if w in lower_text]

    return ExtractedIndicators(
        original_text=text,
        urls=norm_urls,
        domains=domains,
        ips=ips,
        sender_ids=sms_headers,
        phone_numbers=phones,
        email_addresses=emails,
        mentioned_brands=mentioned_brands,
        urgency_keywords=urgency,
        credential_keywords=credentials,
        financial_keywords=financial,
        anchor_mismatches=anchor_mismatches,
    )
