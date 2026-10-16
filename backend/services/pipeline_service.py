"""
Pipeline Service for Cyber Fraud Guardian.
Extracts and coordinates the 10-stage forensic fraud analysis pipeline:
1. Ingestion & IOC Extraction
2. Rule-based Detection
3. ML Statistical Baseline
4. URL & Domain OSINT (DNS, TLS, RDAP) + Safe DOM Inspection
5. Brand Check + Sender Analysis + Financial/UPI OSINT
6. Multi-Source Threat Intelligence
7. Laya Fast Typed-Decision Triage
8. ML Classifier Triage
9. Evidence Fusion & Risk Scoring
10. Epistemic Explanation + Adaptive Response + Fraud DNA Syndicate Correlation + Persistence
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any, Optional

from backend.config import get_settings
from backend.models.evidence import (
    EvidenceItem,
    EvidenceReliability,
    EvidenceSeverity,
    EvidenceStatus,
    EvidenceType,
    IncidentEvidence,
    InputType,
    RiskDirection,
)
from backend.services.google_translator import translate_text_async
from backend.services.neo4j_repository import neo4j_repo
from backend.utils.sanitize import (
    detect_input_language,
    sanitize_message,
    sanitize_url,
    validate_language,
)
from backend.utils.security_logging import safe_error_message

logger = logging.getLogger("cyber_guardian.pipeline_service")
settings = get_settings()



async def _emit_event(callback: Optional[Any], event: str, data: dict[str, Any]) -> None:
    """Helper to emit structured forensic telemetry events to an async callback."""
    if callback:
        try:
            res = callback(event, data)
            if asyncio.iscoroutine(res):
                await res
        except Exception as e:
            logger.debug("Event callback error for %s: %s", event, safe_error_message(e))


async def execute_analysis_pipeline(
    message: str,
    urls: list[str],
    user_state: str = "received",
    response_language: Optional[str] = None,
    language: Optional[str] = None,
    input_type: InputType = InputType.SMS,
    sender: Optional[Any] = None,
    message_context: Optional[dict] = None,
    user_id: Optional[str] = None,
    event_callback: Optional[Any] = None,
) -> IncidentEvidence:
    """
    Execute the complete 10-stage forensic fraud triage pipeline with concurrent enrichment.
    Returns the enriched IncidentEvidence data contract.
    """
    start_time = time.time()

    # Sanitize inputs at boundary
    cleaned_message = sanitize_message(message, settings.max_message_length)
    cleaned_urls = [sanitize_url(u) for u in urls if sanitize_url(u)]
    requested_lang = response_language or language or "en"
    cleaned_response_lang = validate_language(requested_lang)
    detected_input_lang = detect_input_language(cleaned_message)

    # Normalize input type
    normalized_input_type = (
        InputType.SCREENSHOT
        if input_type in (InputType.IMAGE, InputType.PHOTO, InputType.SCREENSHOT)
        else input_type
    )

    # Normalize sender if passed as string, dict, or SenderContext
    from backend.models.evidence import SenderContext
    normalized_sender = None
    if isinstance(sender, SenderContext):
        normalized_sender = sender
    elif isinstance(sender, dict):
        normalized_sender = SenderContext(**sender)
    elif isinstance(sender, str) and sender.strip():
        s_val = sender.strip()
        if "@" in s_val:
            normalized_sender = SenderContext(email=s_val)
        elif any(c.isdigit() for c in s_val):
            normalized_sender = SenderContext(phone=s_val)
        else:
            normalized_sender = SenderContext(sender_id=s_val)

    evidence = IncidentEvidence(
        input_type=normalized_input_type,
        message=cleaned_message,
        original_input=cleaned_message,
        language=cleaned_response_lang,
        response_language=cleaned_response_lang,
        input_language=detected_input_lang,
        sender=normalized_sender,
        message_context=message_context,
    )

    modules_executed = []
    modules_failed = []

    # ─── Stage 1: Ingestion & IOC Extraction ───
    try:
        from backend.modules.ingestion import extract_iocs
        from backend.services.indicators import extract_indicators

        evidence = extract_iocs(evidence, cleaned_urls)
        extracted_ind = extract_indicators(evidence.message)
        for mismatch in extracted_ind.anchor_mismatches:
            evidence.evidence.append(
                EvidenceItem(
                    type=EvidenceType.URL_ANALYSIS,
                    source="indicator_extractor",
                    source_type="content",
                    evidence_tier="OBSERVED",
                    indicator=mismatch.get("display_text"),
                    finding=f"Deceptive hyperlink detected: text displays '{mismatch.get('display_text')}' but links to '{mismatch.get('actual_destination')}'",
                    description="HTML anchor mismatch: visible link text misrepresents destination URL.",
                    observed_value=f"Display: {mismatch.get('display_text')} -> Dest: {mismatch.get('actual_destination')}",
                    interpretation="Deceptive anchor mismatch intentionally tricks victims into trusting the destination URL.",
                    status=EvidenceStatus.CONFIRMED,
                    reliability=EvidenceReliability.DETERMINISTIC_FACT,
                    risk_direction=RiskDirection.INCREASES_RISK,
                    severity=EvidenceSeverity.HIGH,
                    confidence=0.95,
                    correlation_group="deceptive_link",
                    raw_data=mismatch,
                )
            )

        for zw in getattr(extracted_ind, "zero_width_characters", []):
            evidence.evidence.append(
                EvidenceItem(
                    type=EvidenceType.LINGUISTIC_ANALYSIS,
                    source="obfuscation_detector",
                    source_type="content",
                    evidence_tier="OBSERVED",
                    indicator=zw.get("char_hex"),
                    finding=f"Zero-width character smuggling detected: {zw.get('count')} hidden {zw.get('name')} ({zw.get('char_hex')})",
                    description=f"Message embeds {zw.get('count')} invisible zero-width unicode character(s) ({zw.get('name')}) inside text tokens to evade automated fraud keyword filters.",
                    observed_value=f"{zw.get('count')}x {zw.get('char_hex')} ({zw.get('name')})",
                    interpretation="Deliberate anti-detection obfuscation attempting to evade security keyword filters.",
                    status=EvidenceStatus.CONFIRMED,
                    reliability=EvidenceReliability.DETERMINISTIC_FACT,
                    risk_direction=RiskDirection.INCREASES_RISK,
                    severity=EvidenceSeverity.HIGH,
                    confidence=0.95,
                    correlation_group="unicode_obfuscation",
                    raw_data=zw,
                )
            )
        modules_executed.append("ingestion")
    except Exception as e:
        modules_failed.append("ingestion")
        evidence.errors.append(f"ingestion: {safe_error_message(e)}")

    # ─── Stage 2: Rule-Based Detection ───
    try:
        from backend.modules.rules import apply_rules

        evidence = apply_rules(evidence)
        modules_executed.append("rules")
    except Exception as e:
        modules_failed.append("rules")
        evidence.errors.append(f"rules: {safe_error_message(e)}")

    # ─── Stage 2b: ML Statistical Baseline ───
    try:
        from backend.modules.ml_baseline import run_ml_baseline

        evidence = run_ml_baseline(evidence)
        modules_executed.append("ml_baseline")
    except Exception as e:
        modules_failed.append("ml_baseline")
        evidence.errors.append(f"ml_baseline: {safe_error_message(e)}")

    # ─── Stage 4: Brand Impersonation Check (Fast CPU matching) ───
    try:
        from backend.modules.brand_check import check_brands

        evidence = check_brands(evidence)
        modules_executed.append("brand_check")
    except Exception as e:
        modules_failed.append("brand_check")
        evidence.errors.append(f"brand_check: {safe_error_message(e)}")

    claimed_brand = (
        getattr(evidence.brands[0], "brand_name", None)
        or getattr(evidence.brands[0], "brand", None)
    ) if evidence.brands else None

    # Emit IOC discovery milestone
    await _emit_event(
        event_callback,
        "ioc_discovered",
        {
            "incident_id": evidence.incident_id,
            "urls": [u.url for u in evidence.urls],
            "domains": [u.domain for u in evidence.urls if u.domain],
            "extracted_evidence_count": len(evidence.evidence),
        },
    )

    # ─── Concurrent Forensic Enrichment (Stages 3, 3b, 4b, 4c, 5) ───
    # Run URL/DNS/RDAP, website DOM, sender DLT, financial OSINT, and threat intel in parallel
    async def _enrich_urls_and_websites() -> tuple[list[EvidenceItem], list[str], list[str]]:
        items: list[EvidenceItem] = []
        exec_mods: list[str] = []
        fail_mods: list[str] = []

        try:
            from backend.modules.url_analyzer import analyze_urls
            from backend.services.domain_intel import collect_domain_evidence

            nonlocal evidence
            evidence = await analyze_urls(evidence)
            exec_mods.append("url_analyzer")

            seen_domains = set()
            domain_list = []
            for u in evidence.urls:
                d = (u.domain or "").lower().strip()
                if d and d not in seen_domains and "." in d:
                    seen_domains.add(d)
                    domain_list.append(d)

            if domain_list:
                domain_res = await asyncio.gather(
                    *[asyncio.to_thread(collect_domain_evidence, d) for d in domain_list[:3]],
                    return_exceptions=True,
                )
                for r in domain_res:
                    if isinstance(r, list):
                        items.extend(r)
        except Exception as err:
            fail_mods.append("url_analyzer")
            evidence.errors.append(f"url_analyzer: {safe_error_message(err)}")

        try:
            from backend.services.website_analyzer import inspect_website

            urls_to_inspect = [u.url for u in evidence.urls[:3] if u.url]
            if urls_to_inspect:
                site_res = await asyncio.gather(
                    *[inspect_website(target) for target in urls_to_inspect],
                    return_exceptions=True,
                )
                for r in site_res:
                    if isinstance(r, tuple) and len(r) == 2 and isinstance(r[1], list):
                        items.extend(r[1])
            exec_mods.append("website_analyzer")
        except Exception as err:
            fail_mods.append("website_analyzer")
            evidence.errors.append(f"website_analyzer: {safe_error_message(err)}")

        return items, exec_mods, fail_mods

    async def _enrich_senders() -> tuple[list[EvidenceItem], list[str], list[str]]:
        items: list[EvidenceItem] = []
        exec_mods: list[str] = []
        fail_mods: list[str] = []

        try:
            from backend.services.sender_analyzer import (
                analyze_email_sender,
                analyze_sms_sender,
            )

            target_senders = []
            if sender:
                if getattr(sender, "phone", None):
                    target_senders.append(sender.phone)
                if getattr(sender, "sender_id", None):
                    target_senders.append(sender.sender_id)

            header_prefix_match = re.search(
                r"(?:^|\n)\s*(?:from|sender|sent by|msg from)\s*[:\-]\s*([A-Za-z0-9\+\-\s]{3,20})\b",
                evidence.message,
                re.IGNORECASE,
            )
            if header_prefix_match:
                cand = header_prefix_match.group(1).strip()
                if cand and not any(
                    cand.lower().startswith(x)
                    for x in ("upi", "ref", "acc", "txn", "order", "dr")
                ):
                    target_senders.append(cand)

            sms_dlt_match = re.search(
                r"\b([A-Za-z]{2}[-\s][A-Za-z0-9]{6}(?:-[A-Za-z0-9]{1,2})?)\b",
                evidence.message,
            )
            if sms_dlt_match:
                target_senders.append(sms_dlt_match.group(1))

            lead_phone_match = re.search(
                r"^\s*(?:\+?91[\-\s]?)?([6-9]\d{9})\s*[:\-]", evidence.message
            )
            if lead_phone_match:
                target_senders.append(lead_phone_match.group(1))

            seen_senders = set()
            for s in target_senders:
                clean_s = s.strip()
                if clean_s and clean_s not in seen_senders:
                    seen_senders.add(clean_s)
                    _, sms_items = analyze_sms_sender(clean_s, evidence.message)
                    items.extend(sms_items)

            if "from:" in evidence.message.lower():
                from_m = re.search(r"from:\s*([^\r\n]+)", evidence.message, re.IGNORECASE)
                reply_m = re.search(r"reply-to:\s*([^\r\n]+)", evidence.message, re.IGNORECASE)
                auth_m = re.search(r"authentication-results:\s*([^\r\n]+)", evidence.message, re.IGNORECASE)
                if from_m:
                    _, email_items = analyze_email_sender(
                        from_header=from_m.group(1),
                        reply_to_header=reply_m.group(1) if reply_m else "",
                        auth_results=auth_m.group(1) if auth_m else "",
                    )
                    items.extend(email_items)

            exec_mods.append("sender_analyzer")
        except Exception as err:
            fail_mods.append("sender_analyzer")
            evidence.errors.append(f"sender_analyzer: {safe_error_message(err)}")

        return items, exec_mods, fail_mods

    async def _enrich_financial() -> tuple[list[EvidenceItem], list[str], list[str]]:
        items: list[EvidenceItem] = []
        exec_mods: list[str] = []
        fail_mods: list[str] = []

        try:
            from backend.services.financial_osint import (
                analyze_upi_vpa,
                extract_crypto_addresses,
                extract_ifsc_codes,
                extract_upi_vpas,
                lookup_ifsc_razorpay,
            )

            found_ifscs = extract_ifsc_codes(evidence.message)
            if found_ifscs:
                ifsc_results = await asyncio.gather(
                    *[lookup_ifsc_razorpay(code) for code in found_ifscs[:3]],
                    return_exceptions=True,
                )
                for code, ifsc_data in zip(found_ifscs[:3], ifsc_results):
                    if isinstance(ifsc_data, dict) and ifsc_data.get("valid"):
                        bank = ifsc_data.get("bank", "Unknown Bank")
                        branch = ifsc_data.get("branch", "Main Branch")
                        district = ifsc_data.get("district", "")
                        state = ifsc_data.get("state", "")
                        location = f"{branch}, {district}" if district else branch

                        mismatch_finding = ""
                        if (
                            claimed_brand
                            and claimed_brand.lower() not in bank.lower()
                            and bank.lower() not in claimed_brand.lower()
                        ):
                            mismatch_finding = f" [ROUTING MISMATCH: message claimed '{claimed_brand}' but payment routes to '{bank}']"

                        items.append(
                            EvidenceItem(
                                type=EvidenceType.FINANCIAL_ANALYSIS,
                                source="financial_osint",
                                source_type="content",
                                evidence_tier="OBSERVED",
                                indicator=code,
                                finding=f"Verified Indian Bank IFSC Code: {bank} ({location}){mismatch_finding}",
                                description=f"Payment routing code '{code}' verified as {bank} ({location}). State: {state}.",
                                observed_value=f"IFSC: {code} -> {bank} ({branch})",
                                interpretation=f"Direct banking payment routing destination identified via RBI / Razorpay registry.{mismatch_finding}",
                                status=EvidenceStatus.SUSPICIOUS if mismatch_finding else EvidenceStatus.CONFIRMED,
                                reliability=EvidenceReliability.DETERMINISTIC_FACT,
                                risk_direction=RiskDirection.INCREASES_RISK if mismatch_finding else RiskDirection.NEUTRAL,
                                severity=EvidenceSeverity.HIGH if mismatch_finding else EvidenceSeverity.INFO,
                                confidence=0.95,
                                correlation_group="financial_routing",
                                raw_data=ifsc_data,
                            )
                        )

            found_vpas = extract_upi_vpas(evidence.message)
            for vpa in found_vpas[:3]:
                vpa_analysis = analyze_upi_vpa(vpa)
                if vpa_analysis.get("deceptive"):
                    items.append(
                        EvidenceItem(
                            type=EvidenceType.FINANCIAL_ANALYSIS,
                            source="financial_osint",
                            source_type="content",
                            evidence_tier="OBSERVED",
                            indicator=vpa,
                            finding=f"Deceptive consumer UPI VPA handle ({vpa}) posing as official authority/service",
                            description=(
                                f"The payment handle '{vpa}' incorporates institutional keywords "
                                f"('{vpa_analysis.get('username')}') on a consumer payment provider ('@{vpa_analysis.get('handle')}'). "
                                "Legitimate statutory bodies and major utility providers never collect official fees or penalties "
                                "on personal Google Pay, PhonePe, or consumer UPI handles."
                            ),
                            observed_value=vpa,
                            interpretation="Consumer UPI account deceptively named to trick citizens into transferring funds.",
                            status=EvidenceStatus.CONFIRMED,
                            reliability=EvidenceReliability.DETERMINISTIC_FACT,
                            risk_direction=RiskDirection.INCREASES_RISK,
                            severity=EvidenceSeverity.CRITICAL,
                            confidence=0.92,
                            correlation_group="payment_diversion",
                            raw_data=vpa_analysis,
                        )
                    )
                elif vpa_analysis.get("is_mule_risk"):
                    reason = vpa_analysis.get("reason", "High-risk disposable or neo-bank mule account vector")
                    items.append(
                        EvidenceItem(
                            type=EvidenceType.FINANCIAL_ANALYSIS,
                            source="financial_osint",
                            source_type="content",
                            evidence_tier="OBSERVED",
                            indicator=vpa,
                            finding=f"High-risk mule account pattern on UPI handle ({vpa})",
                            description=(
                                f"Payment handle '{vpa}' is hosted on {vpa_analysis.get('provider')} "
                                f"(Sponsor: {vpa_analysis.get('sponsor_bank')}). {reason}."
                            ),
                            observed_value=f"{vpa} [{vpa_analysis.get('provider')}]",
                            interpretation="Disposable or neo-bank handle pattern characteristic of rented cybercrime mule accounts.",
                            status=EvidenceStatus.SUSPICIOUS,
                            reliability=EvidenceReliability.DETERMINISTIC_FACT,
                            risk_direction=RiskDirection.INCREASES_RISK,
                            severity=EvidenceSeverity.HIGH,
                            confidence=0.86,
                            correlation_group="payment_mule_vector",
                            raw_data=vpa_analysis,
                        )
                    )

            crypto_addrs = extract_crypto_addresses(evidence.message)
            for crypto in crypto_addrs[:3]:
                items.append(
                    EvidenceItem(
                        type=EvidenceType.FINANCIAL_ANALYSIS,
                        source="crypto_osint",
                        source_type="content",
                        evidence_tier="OBSERVED",
                        indicator=crypto["address"],
                        finding=f"Cryptocurrency settlement address detected: {crypto['asset']} ({crypto['chain']})",
                        description=f"Message solicits payment or settlement to cryptocurrency address '{crypto['address']}'. {crypto['risk_note']}",
                        observed_value=f"{crypto['chain']} -> {crypto['address']}",
                        interpretation="Unregulated pseudo-anonymous cryptocurrency settlement rail used to bypass statutory banking AML controls.",
                        status=EvidenceStatus.CONFIRMED,
                        reliability=EvidenceReliability.DETERMINISTIC_FACT,
                        risk_direction=RiskDirection.INCREASES_RISK,
                        severity=EvidenceSeverity.CRITICAL,
                        confidence=0.95,
                        correlation_group="crypto_settlement",
                        raw_data=crypto,
                    )
                )

            exec_mods.append("financial_osint")
        except Exception as err:
            fail_mods.append("financial_osint")
            evidence.errors.append(f"financial_osint: {safe_error_message(err)}")

        return items, exec_mods, fail_mods

    async def _enrich_threat_intel() -> tuple[list[ThreatIntelResult], list[EvidenceItem], list[str], list[str]]:
        ti_results: list[ThreatIntelResult] = []
        items: list[EvidenceItem] = []
        exec_mods: list[str] = []
        fail_mods: list[str] = []

        try:
            from backend.services.threat_intel_providers import threat_intel_manager

            target_urls = [u.url for u in evidence.urls if u.url]
            if target_urls:
                ti_outcomes = await asyncio.gather(
                    *[threat_intel_manager.query_all(u) for u in target_urls],
                    return_exceptions=True,
                )
                for out in ti_outcomes:
                    if isinstance(out, tuple) and len(out) == 2:
                        res_list, ev_list = out
                        if isinstance(res_list, list):
                            ti_results.extend(res_list)
                        if isinstance(ev_list, list):
                            items.extend(ev_list)
            exec_mods.append("threat_intel")
        except Exception as err:
            fail_mods.append("threat_intel")
            evidence.errors.append(f"threat_intel: {safe_error_message(err)}")

        return ti_results, items, exec_mods, fail_mods

    # Dispatch enrichment coroutines concurrently
    enrichment_outcomes = await asyncio.gather(
        _enrich_urls_and_websites(),
        _enrich_senders(),
        _enrich_financial(),
        _enrich_threat_intel(),
        return_exceptions=True,
    )

    # 1. Unpack URL & Website results
    url_site_out = enrichment_outcomes[0]
    if isinstance(url_site_out, tuple):
        items, execs, fails = url_site_out
        evidence.evidence.extend(items)
        modules_executed.extend(execs)
        modules_failed.extend(fails)
    elif isinstance(url_site_out, Exception):
        modules_failed.append("url_analyzer")
        evidence.errors.append(f"url_analyzer: {safe_error_message(url_site_out)}")

    # 2. Unpack Sender results
    sender_out = enrichment_outcomes[1]
    if isinstance(sender_out, tuple):
        items, execs, fails = sender_out
        evidence.evidence.extend(items)
        modules_executed.extend(execs)
        modules_failed.extend(fails)
    elif isinstance(sender_out, Exception):
        modules_failed.append("sender_analyzer")
        evidence.errors.append(f"sender_analyzer: {safe_error_message(sender_out)}")

    # 3. Unpack Financial results
    fin_out = enrichment_outcomes[2]
    if isinstance(fin_out, tuple):
        items, execs, fails = fin_out
        evidence.evidence.extend(items)
        modules_executed.extend(execs)
        modules_failed.extend(fails)
    elif isinstance(fin_out, Exception):
        modules_failed.append("financial_osint")
        evidence.errors.append(f"financial_osint: {safe_error_message(fin_out)}")

    # 4. Unpack Threat Intel results
    ti_out = enrichment_outcomes[3]
    if isinstance(ti_out, tuple):
        ti_results, items, execs, fails = ti_out
        evidence.threat_intel.extend(ti_results)
        evidence.evidence.extend(items)
        modules_executed.extend(execs)
        modules_failed.extend(fails)

        # Merge malicious threat intelligence signals into analyzed URLs
        for ti in evidence.threat_intel:
            status_val = getattr(
                getattr(ti, "intel_status", None),
                "value",
                str(getattr(ti, "intel_status", "")),
            ).lower()
            is_mal = (
                status_val in ("confirmed_malicious", "match", "match (malicious)")
                or getattr(ti, "is_match", False)
            )
            if is_mal:
                ti_target = (
                    getattr(ti, "url", "")
                    or getattr(ti, "raw_reference", "")
                    or ""
                ).lower()
                for u in evidence.urls:
                    if not ti_target or (
                        ti_target in u.url.lower()
                        or u.url.lower() in ti_target
                        or (u.domain and u.domain.lower() in ti_target)
                    ):
                        u.is_suspicious = True
                        u.risk_score = max(u.risk_score, 0.95)
                        provider_label = (
                            "Google Safe Browsing"
                            if "safe_browsing" in ti.source.lower()
                            else ti.source.capitalize()
                        )
                        sig_label = f"{provider_label}: {ti.threat_type or 'Confirmed Phishing / Social Engineering'}"
                        if sig_label not in u.signals:
                            u.signals.insert(0, sig_label)
    elif isinstance(ti_out, Exception):
        modules_failed.append("threat_intel")
        evidence.errors.append(f"threat_intel: {safe_error_message(ti_out)}")

    # Emit Infrastructure & Threat Intel milestones
    await _emit_event(
        event_callback,
        "infrastructure_resolved",
        {
            "incident_id": evidence.incident_id,
            "domains_analyzed": [u.domain for u in evidence.urls if u.domain],
            "evidence_count": len(evidence.evidence),
        },
    )
    await _emit_event(
        event_callback,
        "threat_intel_hits",
        {
            "incident_id": evidence.incident_id,
            "threat_intel_count": len(evidence.threat_intel),
            "malicious_matches": sum(
                1 for ti in evidence.threat_intel if getattr(ti, "is_match", False)
            ),
        },
    )

    # ─── Stage 5b: Laya Fast Typed-Decision Triage ───
    try:
        from backend.modules.laya import run_laya_triage

        evidence = await run_laya_triage(evidence)
        modules_executed.append("laya")
    except Exception as e:
        modules_failed.append("laya")
        evidence.errors.append(f"laya: {safe_error_message(e)}")

    # ─── Stage 5c: ML Classifier Triage ───
    try:
        from backend.modules.ml_classifier import run_ml_classification

        evidence = await run_ml_classification(evidence)
        modules_executed.append("ml_classifier")
    except Exception as e:
        modules_failed.append("ml_classifier")
        evidence.errors.append(f"ml_classifier: {safe_error_message(e)}")

    # ─── Stage 6: Evidence Fusion + Risk Scoring ───
    try:
        from backend.modules.fusion import fuse_evidence

        evidence = fuse_evidence(evidence)
        modules_executed.append("fusion")
    except Exception as e:
        modules_failed.append("fusion")
        evidence.errors.append(f"fusion: {safe_error_message(e)}")

    # ─── Stage 7: Explanation (Gemini with Deterministic Fallback) ───
    try:
        from backend.modules.gemini import explain_with_gemini

        evidence = await explain_with_gemini(evidence)
        modules_executed.append("gemini")
    except Exception as e:
        modules_failed.append("gemini")
        evidence.errors.append(f"gemini: {safe_error_message(e)}")

    if evidence.explanation is None:
        try:
            from backend.modules.fallback_explanation import (
                generate_fallback_explanation,
            )

            evidence = generate_fallback_explanation(evidence)
            modules_executed.append("fallback_explanation")
        except Exception as e:
            modules_failed.append("fallback_explanation")
            evidence.errors.append(f"fallback_explanation: {safe_error_message(e)}")

    # ─── Stage 8: Adaptive Response ───
    try:
        from backend.modules.response import generate_response

        evidence = generate_response(evidence, user_state)
        modules_executed.append("response")
    except Exception as e:
        modules_failed.append("response")
        evidence.errors.append(f"response: {safe_error_message(e)}")

    # ─── Stage 9: Fraud DNA & Campaign Syndicate Correlation ───
    try:
        from backend.modules.fraud_dna import compute_fraud_dna

        evidence.fraud_dna = compute_fraud_dna(evidence)
        modules_executed.append("fraud_dna")
    except Exception as e:
        modules_failed.append("fraud_dna")
        evidence.errors.append(f"fraud_dna: {safe_error_message(e)}")

    # ─── Stage 10: Persistent Storage ───
    try:
        from backend.services.evidence_store import save_investigation

        save_investigation(evidence)
    except Exception as e:
        logger.debug(
            "Failed to persist investigation %s: %s",
            evidence.incident_id,
            safe_error_message(e),
        )

    # Telemetry and Timing
    elapsed_ms = (time.time() - start_time) * 1000
    evidence.processing_time_ms = elapsed_ms
    evidence.modules_executed = modules_executed
    evidence.modules_failed = modules_failed

    # Neo4j Aura Persistence
    if settings.neo4j_enabled:
        try:
            persisted = neo4j_repo.save_full_incident(evidence, user_id=user_id)
            if persisted:
                if evidence.fraud_dna:
                    evidence.fraud_dna.graph_persisted = True
                neo4j_repo.log_audit_event(
                    "INCIDENT_CREATED", user_id, "Incident", evidence.incident_id
                )
        except Exception as e:
            logger.warning("Neo4j persistence degraded gracefully: %s", safe_error_message(e))

    # Emit Final Verdict Milestone
    await _emit_event(
        event_callback,
        "final_verdict",
        {
            "incident_id": evidence.incident_id,
            "risk_score": evidence.risk.score if evidence.risk else 0.0,
            "risk_level": evidence.risk.level.value if evidence.risk else "UNKNOWN",
            "evidence_count": len(evidence.evidence),
            "processing_time_ms": evidence.processing_time_ms,
        },
    )

    # Record Prometheus Observability Metrics (Phase 6)
    try:
        from backend.utils.telemetry import record_stage_latency, record_verdict

        record_stage_latency("pipeline_total", evidence.processing_time_ms / 1000.0)
        risk_str = evidence.risk.level.value if evidence.risk and hasattr(evidence.risk.level, "value") else str(getattr(evidence.risk, "level", "UNKNOWN"))
        record_verdict(risk_str)
    except Exception as e:
        logger.debug("Failed to record pipeline telemetry: %s", safe_error_message(e))

    return evidence
