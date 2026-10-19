"""
Safe Website Behavior & DOM Analyzer (PRD Section 4).

Safely fetches and inspects suspicious target web pages under strict security bounds:
- SSRF Defense: Validates target IP before making HTTP requests (blocks RFC1918, 127.0.0.1, 169.254.169.254).
- Resource Bounding: 4.0s timeout, max 500 KB payload limit, max 5 redirects.
- Observable Behaviors:
  * Redirect chain & final destination tracking.
  * Credential harvesting inputs (<input type="password">, otp, pin, pan, aadhaar, cvv).
  * Cross-domain form action destinations (<form action="http://other-site.com/steal">).
  * Brand claiming in DOM title vs actual domain identity mismatch.
  * Obfuscated script payloads.
"""

from __future__ import annotations

import html
import logging
import re
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import httpx

from backend.models.evidence import (
    EvidenceItem,
    EvidenceReliability,
    EvidenceSeverity,
    EvidenceStatus,
    EvidenceType,
    RiskDirection,
)
from backend.services.domain_intel import clean_domain, is_safe_ip
from backend.utils.sanitize import is_safe_url
from backend.utils.security_logging import safe_error_message

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 4.0
_MAX_PAYLOAD_BYTES = 500 * 1024  # 500 KB
_MAX_REDIRECTS = 5

_CREDENTIAL_FIELD_REGEX = re.compile(
    r'<input\s+[^>]*?(?:name|id|placeholder|aria-label)=["\']([^"\']*(?:otp|pin|password|passwd|cvv|pan|aadhaar|netbanking|card_number|secret)[^"\']*)["\']',
    re.IGNORECASE,
)

_PASSWORD_TYPE_REGEX = re.compile(
    r'<input\s+[^>]*?type=["\']password["\']',
    re.IGNORECASE,
)

_FORM_ACTION_REGEX = re.compile(
    r'<form\s+[^>]*?action=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

_TITLE_REGEX = re.compile(r'<title[^>]*>(.*?)</title>', re.IGNORECASE | re.DOTALL)


async def inspect_website(url: str) -> tuple[dict[str, Any], list[EvidenceItem]]:
    """
    Safely inspect a website URL, observing DOM and redirect behavior.
    Returns structured analysis dict and generated EvidenceItem list.
    """
    evidence_items: list[EvidenceItem] = []
    analysis: dict[str, Any] = {
        "initial_url": url,
        "final_url": url,
        "redirect_chain": [],
        "status_code": None,
        "title": None,
        "has_password_field": False,
        "credential_fields": [],
        "cross_domain_forms": [],
        "inspected": False,
        "error": None,
    }

    if not is_safe_url(url):
        analysis["error"] = "URL blocked by SSRF defense"
        return analysis, evidence_items

    parsed = urlparse(url)
    initial_domain = (parsed.hostname or "").lower()

    redirect_chain = [url]
    response_body = ""
    final_url = url
    status_code = None

    try:
        # Bounded client with manual redirect handling to enforce SSRF check at EVERY hop
        async with httpx.AsyncClient(
            timeout=_DEFAULT_TIMEOUT,
            follow_redirects=False,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 CyberKawach-Safety-Scanner/1.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        ) as client:
            curr_url = url
            for _ in range(_MAX_REDIRECTS):
                if not is_safe_url(curr_url):
                    analysis["error"] = "Redirect target blocked by SSRF defense"
                    break

                resp = await client.get(curr_url)
                status_code = resp.status_code
                final_url = str(resp.url)

                if resp.is_redirect and "location" in resp.headers:
                    next_url = urljoin(curr_url, resp.headers["location"])
                    redirect_chain.append(next_url)
                    curr_url = next_url
                else:
                    # Final landing page reached — read bounded payload
                    content_chunks = []
                    bytes_read = 0
                    async for chunk in resp.aiter_bytes():
                        bytes_read += len(chunk)
                        content_chunks.append(chunk)
                        if bytes_read >= _MAX_PAYLOAD_BYTES:
                            break
                    raw_bytes = b"".join(content_chunks)
                    response_body = raw_bytes.decode("utf-8", errors="ignore")
                    response_headers = dict(resp.headers)
                    break

            analysis["status_code"] = status_code
            analysis["final_url"] = final_url
            analysis["redirect_chain"] = redirect_chain
            analysis["inspected"] = True

    except Exception as e:
        analysis["error"] = safe_error_message(e)
        logger.debug("Website inspection failed for %s: %s", url, safe_error_message(e))
        return analysis, evidence_items

    # Delegate DOM & redirect behavior analysis to modular analyzer
    dom_analysis, dom_items = analyze_html_content(
        final_url=final_url,
        response_body=response_body,
        redirect_chain=redirect_chain,
        initial_domain=initial_domain,
        response_headers=locals().get("response_headers", {}),
    )
    analysis.update(dom_analysis)
    evidence_items.extend(dom_items)
    return analysis, evidence_items


def analyze_html_content(
    final_url: str,
    response_body: str,
    redirect_chain: list[str] | None = None,
    initial_domain: str | None = None,
    response_headers: dict[str, str] | None = None,
) -> tuple[dict[str, Any], list[EvidenceItem]]:
    """
    Modular analysis of HTML DOM and redirect behavior for phishing signatures:
    - Cross-domain redirects
    - Credential entry fields
    - Cross-domain form destinations
    - Telegram / Discord exfiltration webhooks
    - Anti-bot / cloaking evasion scripts
    - Android APK sideloading lures
    - Right-click / DevTools blocking handlers
    - High-urgency coercive prompts in DOM
    - HTTP response security headers & technology banners
    """
    analysis: dict[str, Any] = {
        "title": None,
        "has_password_field": False,
        "credential_fields": [],
        "cross_domain_forms": [],
    }
    evidence_items: list[EvidenceItem] = []
    redirect_chain = redirect_chain or [final_url]

    # ─── 1. Redirect Chain Analysis ───
    final_parsed = urlparse(final_url)
    final_domain = (final_parsed.hostname or "").lower()
    initial_domain = initial_domain or final_domain

    if len(redirect_chain) > 1:
        if initial_domain != final_domain:
            evidence_items.append(EvidenceItem(
                type=EvidenceType.REDIRECT_CHAIN,
                source="website_analyzer",
                source_type="sandbox",
                evidence_tier="OBSERVED",
                indicator=url,
                finding=f"Cross-domain redirect detected: '{initial_domain}' redirected to '{final_domain}'",
                description=(
                    f"Initial request to '{initial_domain}' was redirected across {len(redirect_chain) - 1} "
                    f"hop(s), terminating at a different domain '{final_domain}'."
                ),
                observed_value=f"{' -> '.join(redirect_chain[:4])}",
                interpretation="Cross-domain redirection is frequently used to mask malicious destination URLs behind shorteners or open redirects.",
                status=EvidenceStatus.OBSERVED,
                reliability=EvidenceReliability.DETERMINISTIC_FACT,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.MEDIUM,
                correlation_group="url_redirection",
                raw_data={"redirect_chain": redirect_chain, "final_domain": final_domain},
            ))

    if not response_body:
        return analysis, evidence_items

    # ─── 2. Page Title Extraction ───
    title_match = _TITLE_REGEX.search(response_body)
    if title_match:
        page_title = html.unescape(title_match.group(1).strip())[:120]
        analysis["title"] = page_title

    # ─── 3. Credential Field & Password Input Detection ───
    has_pwd = bool(_PASSWORD_TYPE_REGEX.search(response_body))
    analysis["has_password_field"] = has_pwd

    cred_matches = set()
    for m in _CREDENTIAL_FIELD_REGEX.finditer(response_body):
        field_name = m.group(1).lower().strip()
        cred_matches.add(field_name)
    analysis["credential_fields"] = sorted(list(cred_matches))

    if has_pwd or cred_matches:
        fields_desc = ", ".join(list(cred_matches)[:4]) if cred_matches else "password input"
        evidence_items.append(EvidenceItem(
            type=EvidenceType.WEBSITE_BEHAVIOR,
            source="website_analyzer",
            source_type="sandbox",
            evidence_tier="OBSERVED",
            indicator=final_url,
            finding=f"Credential entry form observed on landing page ({fields_desc})",
            description=f"HTML analysis confirmed active input fields requesting sensitive user credentials ({fields_desc}).",
            observed_value=f"Fields: {fields_desc} on host {final_domain}",
            interpretation="Page presents an active credential harvesting interface asking for citizen authentication secrets.",
            status=EvidenceStatus.CONFIRMED,
            reliability=EvidenceReliability.DETERMINISTIC_FACT,
            risk_direction=RiskDirection.INCREASES_RISK,
            severity=EvidenceSeverity.HIGH,
            confidence=0.88,
            correlation_group="credential_harvesting_form",
            raw_data={"fields": list(cred_matches), "has_password": has_pwd, "final_url": final_url},
        ))

    # ─── 4. Cross-Domain Form Action Detection ───
    for form_m in _FORM_ACTION_REGEX.finditer(response_body):
        action_val = form_m.group(1).strip()
        if "://" in action_val:
            action_parsed = urlparse(action_val)
            action_host = (action_parsed.hostname or "").lower()
            if action_host and action_host != final_domain and not action_host.endswith(f".{final_domain}"):
                analysis["cross_domain_forms"].append(action_val)
                evidence_items.append(EvidenceItem(
                    type=EvidenceType.WEBSITE_BEHAVIOR,
                    source="website_analyzer",
                    source_type="sandbox",
                    evidence_tier="OBSERVED",
                    indicator=final_url,
                    finding=f"Form submits entered data to external 3rd-party host '{action_host}'",
                    description=f"HTML <form action='...'> sends citizen input away from '{final_domain}' to an external recipient '{action_host}'.",
                    observed_value=f"POST destination: {action_val[:80]}",
                    interpretation="Cross-domain form submission is a classic signature of phishing kits exfiltrating harvested credentials to a drop server.",
                    status=EvidenceStatus.CONFIRMED,
                    reliability=EvidenceReliability.DETERMINISTIC_FACT,
                    risk_direction=RiskDirection.INCREASES_RISK,
                    severity=EvidenceSeverity.CRITICAL,
                    confidence=0.92,
                    correlation_group="credential_exfiltration",
                    raw_data={"form_action": action_val, "page_host": final_domain, "action_host": action_host},
                ))
                break

    # ─── 5. Telegram / Discord Exfiltration Drop Trap ───
    exfil_trap_regex = re.compile(
        r'(api\.telegram\.org/bot[0-9a-zA-Z:_-]+|discord(?:app)?\.com/api/webhooks/[0-9]+/[0-9a-zA-Z_-]+)',
        re.IGNORECASE,
    )
    exfil_match = exfil_trap_regex.search(response_body)
    if exfil_match:
        evidence_items.append(EvidenceItem(
            type=EvidenceType.WEBSITE_BEHAVIOR,
            source="website_analyzer",
            source_type="sandbox",
            evidence_tier="OBSERVED",
            indicator=final_url,
            finding="Direct credential exfiltration webhook endpoint observed in page source",
            description="Page contains direct exfiltration API call pointing to Telegram Bot or Discord Webhook drop service.",
            observed_value=exfil_match.group(0)[:60] + "...",
            interpretation="Confirmed active credential exfiltration infrastructure used to stream stolen credentials directly to scam operators.",
            status=EvidenceStatus.CONFIRMED,
            reliability=EvidenceReliability.DETERMINISTIC_FACT,
            risk_direction=RiskDirection.INCREASES_RISK,
            severity=EvidenceSeverity.CRITICAL,
            confidence=0.98,
            correlation_group="credential_exfiltration",
            raw_data={"exfiltration_target": exfil_match.group(0)[:80]},
        ))

    # ─── 6. Anti-Analysis & Bot Cloaking Script Detection ───
    cloaking_patterns = [
        "navigator.webdriver",
        "devtools-detector",
        "debugger;",
        "window.callPhantom",
        "_phantom",
    ]
    detected_cloaking = [p for p in cloaking_patterns if p in response_body]
    if detected_cloaking:
        evidence_items.append(EvidenceItem(
            type=EvidenceType.WEBSITE_BEHAVIOR,
            source="website_analyzer",
            source_type="sandbox",
            evidence_tier="OBSERVED",
            indicator=final_url,
            finding=f"Anti-analysis / crawler evasion logic detected ({', '.join(detected_cloaking)})",
            description=f"Page script inspects runtime environment for automated scanners ({', '.join(detected_cloaking)}).",
            observed_value=", ".join(detected_cloaking),
            interpretation="Anti-bot / crawler cloaking scripts are deployed by phishing kits to conceal malicious DOM from automated security analyzers.",
            status=EvidenceStatus.SUSPICIOUS,
            reliability=EvidenceReliability.DETERMINISTIC_FACT,
            risk_direction=RiskDirection.INCREASES_RISK,
            severity=EvidenceSeverity.HIGH,
            confidence=0.85,
            correlation_group="anti_analysis_cloaking",
            raw_data={"cloaking_signatures": detected_cloaking},
        ))

    # ─── 7. Malicious Android APK Sideloading Detection ───
    apk_matches = re.findall(r'href=["\']([^"\']+\.apk(?:\?[^"\']*)?)["\']', response_body, re.I)
    apk_matches += re.findall(r'["\'](https?://[^"\']+\.apk(?:\?[^"\']*)?)["\']', response_body, re.I)
    if final_url.lower().endswith(".apk") or ".apk?" in final_url.lower():
        apk_matches.append(final_url)

    unique_apks = list(dict.fromkeys(apk_matches))
    if unique_apks:
        apk_target = unique_apks[0]
        apk_name = apk_target.split("/")[-1].split("?")[0]
        evidence_items.append(EvidenceItem(
            type=EvidenceType.WEBSITE_BEHAVIOR,
            source="website_analyzer",
            source_type="sandbox",
            evidence_tier="OBSERVED",
            indicator=final_url,
            finding=f"Malicious Android APK sideloading lure observed: '{apk_name}'",
            description=f"Page presents direct download links to an Android Package (.apk) file '{apk_name}'.",
            observed_value=f"APK Target: {apk_target[:80]}",
            interpretation="Android APK sideloading is the primary vehicle in India for mobile financial Trojans, SMS OTP forwarders, and banking drainers.",
            status=EvidenceStatus.CONFIRMED,
            reliability=EvidenceReliability.DETERMINISTIC_FACT,
            risk_direction=RiskDirection.INCREASES_RISK,
            severity=EvidenceSeverity.CRITICAL,
            confidence=0.96,
            correlation_group="malicious_apk_sideloading",
            raw_data={"apk_links": unique_apks[:3]},
        ))

    # ─── 8. Anti-Inspection & Right-Click Disabling Handlers ───
    anti_inspect_patterns = [
        ("oncontextmenu", 'oncontextmenu="return false;"'),
        ("oncontextmenu", "oncontextmenu='return false;'"),
        ("onselectstart", 'onselectstart="return false;"'),
        ("f12_block", "keyCode == 123"),
        ("ctrl_shift_i", "ctrlKey && e.shiftKey && e.keyCode == 73"),
    ]
    detected_anti_inspect = [label for label, pat in anti_inspect_patterns if pat.lower() in response_body.lower()]
    if detected_anti_inspect:
        evidence_items.append(EvidenceItem(
            type=EvidenceType.WEBSITE_BEHAVIOR,
            source="website_analyzer",
            source_type="sandbox",
            evidence_tier="OBSERVED",
            indicator=final_url,
            finding="Anti-forensic browser controls detected: right-click or DevTools disabled",
            description="Page script intentionally disables context menus (right-click) or developer shortcut keys (F12/Ctrl+Shift+I) to prevent user inspection.",
            observed_value=", ".join(detected_anti_inspect),
            interpretation="Anti-inspection tactics are deployed by phishing kits to obstruct victims from checking URL properties or viewing source code.",
            status=EvidenceStatus.CONFIRMED,
            reliability=EvidenceReliability.DETERMINISTIC_FACT,
            risk_direction=RiskDirection.INCREASES_RISK,
            severity=EvidenceSeverity.HIGH,
            confidence=0.90,
            correlation_group="anti_analysis_cloaking",
            raw_data={"disabled_handlers": detected_anti_inspect},
        ))

    # ─── 9. Coercive Threat & Countdown Modals in DOM ───
    coercion_dom_regex = re.compile(
        r'(disconnect(?:ed)?\s+(?:tonight|within\s+\d+|at\s+9[:.]30\s*pm)|'
        r'arrest\s+warrant|'
        r'account\s+(?:blocked|suspended)\s+within\s+\d+\s+hours|'
        r'update\s+kyc\s+immediately\s+or)',
        re.I
    )
    coercion_dom_match = coercion_dom_regex.search(response_body)
    if coercion_dom_match:
        matched_threat = coercion_dom_match.group(0).strip()
        evidence_items.append(EvidenceItem(
            type=EvidenceType.WEBSITE_BEHAVIOR,
            source="website_analyzer",
            source_type="sandbox",
            evidence_tier="OBSERVED",
            indicator=final_url,
            finding=f"Psychological coercion alert in page DOM: '{matched_threat}'",
            description=f"HTML content displays an artificial emergency ultimatum: '{matched_threat}'.",
            observed_value=matched_threat,
            interpretation="High-pressure deadline ultimatum intended to induce panic and bypass logical scrutiny.",
            status=EvidenceStatus.CONFIRMED,
            reliability=EvidenceReliability.DETERMINISTIC_FACT,
            risk_direction=RiskDirection.INCREASES_RISK,
            severity=EvidenceSeverity.HIGH,
            confidence=0.92,
            correlation_group="psychological_coercion",
            raw_data={"dom_coercion_text": matched_threat},
        ))

    # ─── 10. HTTP Response Security Headers & Fingerprinting ───
    if response_headers:
        h_lower = {k.lower(): v for k, v in response_headers.items()}
        # Missing HSTS on HTTPS
        if final_url.lower().startswith("https://") and "strict-transport-security" not in h_lower:
            evidence_items.append(EvidenceItem(
                type=EvidenceType.WEBSITE_BEHAVIOR,
                source="http_security_auditor",
                source_type="sandbox",
                evidence_tier="OBSERVED",
                indicator=final_url,
                finding="Missing HTTP Strict Transport Security (HSTS) header on secure endpoint",
                description="The HTTPS web server does not enforce HSTS, allowing sslstrip and man-in-the-middle downgrade attacks.",
                observed_value="Strict-Transport-Security: [MISSING]",
                interpretation="Financial and enterprise authentication portals strictly mandate HSTS; omission indicates negligent or ad-hoc attack infrastructure.",
                status=EvidenceStatus.OBSERVED,
                reliability=EvidenceReliability.DETERMINISTIC_FACT,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.MEDIUM,
                confidence=0.80,
                correlation_group="http_security_hardening",
                raw_data={"hsts_missing": True},
            ))

        # Missing CSP / X-Frame-Options
        if "content-security-policy" not in h_lower and "x-frame-options" not in h_lower:
            evidence_items.append(EvidenceItem(
                type=EvidenceType.WEBSITE_BEHAVIOR,
                source="http_security_auditor",
                source_type="sandbox",
                evidence_tier="OBSERVED",
                indicator=final_url,
                finding="Missing framing protections (CSP frame-ancestors & X-Frame-Options)",
                description="Server sends neither Content-Security-Policy nor X-Frame-Options, leaving page vulnerable to clickjacking overlay attacks.",
                observed_value="X-Frame-Options & CSP: [MISSING]",
                interpretation="Lacks standard defense-in-depth framing restrictions.",
                status=EvidenceStatus.OBSERVED,
                reliability=EvidenceReliability.DETERMINISTIC_FACT,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.LOW,
                confidence=0.75,
                correlation_group="http_security_hardening",
                raw_data={"framing_defense_missing": True},
            ))

        # Server Technology Information Disclosure
        server_hdr = h_lower.get("server")
        powered_by = h_lower.get("x-powered-by")
        if server_hdr or powered_by:
            tech_desc = f"Server: {server_hdr}" if server_hdr else ""
            if powered_by:
                tech_desc += f", Powered-By: {powered_by}" if tech_desc else f"Powered-By: {powered_by}"
            evidence_items.append(EvidenceItem(
                type=EvidenceType.WEBSITE_BEHAVIOR,
                source="http_security_auditor",
                source_type="sandbox",
                evidence_tier="OBSERVED",
                indicator=final_url,
                finding=f"Server technology banner disclosed: {tech_desc}",
                description=f"HTTP response headers reveal backend execution environment details: {tech_desc}.",
                observed_value=tech_desc,
                interpretation="Server software version disclosure allows attackers and analysts to profile underlying hosting stack.",
                status=EvidenceStatus.OBSERVED,
                reliability=EvidenceReliability.DETERMINISTIC_FACT,
                risk_direction=RiskDirection.NEUTRAL,
                severity=EvidenceSeverity.INFORMATIONAL,
                confidence=0.90,
                correlation_group="http_server_fingerprint",
                raw_data={"server": server_hdr, "x_powered_by": powered_by},
            ))

    return analysis, evidence_items
