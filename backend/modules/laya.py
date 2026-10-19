"""
Laya fast typed-decision engine (Phase 3).

Non-autoregressive System-1 decision layer:
Returns structured typed decisions in a single forward pass:
- fraud: float [0.0, 1.0]
- fraud_category: choice (banking, courier, electricity, government, lottery_prize, job_offer, investment, tech_support, upi_fraud, loan_fraud, extortion_legal, none)
- brand_impersonation: float [0.0, 1.0]
- credential_request: float [0.0, 1.0]
- payment_request: float [0.0, 1.0]
- deep_analysis_required: float [0.0, 1.0]

Preserves strict fallback: if Laya fails, times out, or is disabled,
the pipeline functions identically without it.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Optional

import httpx

from backend.config import get_settings
from backend.models.evidence import (
    EvidenceItem,
    EvidenceReliability,
    EvidenceSeverity,
    EvidenceStatus,
    EvidenceType,
    IncidentEvidence,
    LayaResult,
    RiskDirection,
)
from backend.modules.brand_check import is_official_brand_domain

logger = logging.getLogger("cyber_guardian.laya")

# ─── Local Multi-head Typed Decision Model ───
# Calibrated fast multi-task classifier for zero-dependency local execution
_is_calibrated = False
_vectorizer = None
_heads = {}


# Training representations for the multi-head typed decision tasks
_CALIBRATION_DATA = [
    # (text, fraud, category, brand_imp, cred_req, pay_req, deep_analysis)
    # ─── Phishing & Fraud Patterns ───
    (
        "Dear Customer Your SBI account has been BLOCKED due to incomplete KYC verification. Click here: http://sbi-kyc.xyz",
        0.94, "banking", 0.95, 0.90, 0.20, 0.40
    ),
    (
        "SBI YONO Alert: Your netbanking is temporarily suspended due to pending KYC update. Click http://sbi-yono-update.icu to submit PAN details within 24 hours.",
        0.95, "banking", 0.95, 0.92, 0.20, 0.45
    ),
    (
        "URGENT: Your SBI YONO account has been suspended due to pending PAN-Aadhaar KYC. Click here immediately to update: http://192.168.1.105/sbi/kyc-update",
        0.96, "banking", 0.95, 0.94, 0.25, 0.50
    ),
    (
        "Your HDFC debit card has been suspended. Verify your PAN and Aadhaar now to reactivate online",
        0.92, "banking", 0.90, 0.92, 0.20, 0.45
    ),
    (
        "Dear HDFC Customer, your NetBanking access is temporarily disabled due to suspicious login attempt. Reactivate your netbanking profile now at https://hdfc-bank-netbanking-verify.com/login before 24 hrs.",
        0.95, "banking", 0.92, 0.95, 0.20, 0.45
    ),
    (
        "Important Notice from ICICI Bank: Your debit card will be blocked within 12 hours due to unverified KYC. Click http://bit.ly/icici-kyc-verify to verify details now.",
        0.94, "banking", 0.90, 0.90, 0.20, 0.45
    ),
    (
        "Dear consumer your electricity power will be disconnected tonight at 9:30 pm from electricity office because your previous month bill was not updated. Please immediately contact our electricity officer at 9821839201. -Electricity Department",
        0.92, "electricity", 0.70, 0.20, 0.90, 0.60
    ),
    (
        "Dear consumer electricity power will be disconnected tonight at 9.30pm from electricity office because your previous month bill was not updated please contact our electricity officer 9821049210 http://vidhyut-bill.apk",
        0.95, "electricity", 0.75, 0.30, 0.92, 0.65
    ),
    (
        "Your parcel from Amazon could not be delivered due to incorrect address. Pay Rs 25 customs charge: http://amaz0n-delivery.top",
        0.91, "courier", 0.88, 0.30, 0.85, 0.35
    ),
    (
        "India Post: Your package could not be delivered due to incomplete address. Please update your address and pay re-delivery fee Rs 25 at http://indiapost-parcel.top",
        0.93, "courier", 0.88, 0.35, 0.88, 0.40
    ),
    (
        "India Post: Your package IN9827381 could not be delivered due to incomplete street address. Please update your address within 24 hours at https://indiapost-parcel-update.top/address to avoid return to sender.",
        0.94, "courier", 0.88, 0.40, 0.85, 0.40
    ),
    (
        "Delhivery package delivery failed. Reschedule delivery date and pay processing fee Rs 15",
        0.88, "courier", 0.85, 0.25, 0.80, 0.40
    ),
    (
        "Income Tax Refund of Rs 18,500 has been approved. Update bank account details within 48 hours to receive refund http://incometax-refund.link",
        0.93, "government", 0.80, 0.85, 0.15, 0.50
    ),
    (
        "Income Tax Department Notice: Your tax refund of Rs 24,850 is waiting. Submit your bank account and PAN details at http://incometax-efiling-refund.info/login to process.",
        0.95, "government", 0.85, 0.90, 0.15, 0.50
    ),
    (
        "CBI Official Notice: An arrest warrant has been issued against your Aadhaar card for money laundering. Join police Skype video investigation immediately to avoid physical arrest.",
        0.95, "extortion_legal", 0.80, 0.70, 0.85, 0.75
    ),
    (
        "E-challan pending traffic police fine. Arrest warrant will be issued if payment not made today",
        0.89, "government", 0.70, 0.20, 0.90, 0.55
    ),
    (
        "CONGRATULATIONS! You have WON Rs 25,00,000 in Google Annual Lottery. Pay processing fee Rs 4,999 to claim",
        0.96, "lottery_prize", 0.85, 0.40, 0.95, 0.30
    ),
    (
        "CONGRATULATIONS! You have won Rs 25,00,000 from KBC Kaun Banega Crorepati Lottery Lucky Draw 2026. Send your name and bank account on WhatsApp +91-9123456789 to claim prize money. Cheque number: KBC-9821.",
        0.96, "lottery_prize", 0.75, 0.50, 0.90, 0.40
    ),
    (
        "KBC Lucky Draw winner 25 Lakhs. Send WhatsApp message to manager to transfer prize money",
        0.95, "lottery_prize", 0.70, 0.30, 0.85, 0.35
    ),
    (
        "Earn Rs 3,000 to Rs 8,000 daily from home! Part time online job: simply like YouTube videos and write hotel reviews. No investment needed. Contact manager on Telegram: @amazon_review_job2026 to start now.",
        0.92, "job_offer", 0.70, 0.25, 0.88, 0.45
    ),
    (
        "Work from home part time data entry job. Earn Rs 15,000-45,000 monthly. Registration fee Rs 999 only",
        0.87, "job_offer", 0.20, 0.30, 0.88, 0.45
    ),
    (
        "Urgent hiring Amazon telegram product review task earn Rs 3000 daily pay security deposit to start",
        0.90, "job_offer", 0.75, 0.25, 0.90, 0.40
    ),
    (
        "Dear customer, your refund of Rs 4,500 for order #89281 has been initiated. Open PhonePe or Google Pay and approve the collect request sent to your UPI ID to receive money in your account.",
        0.94, "upi_fraud", 0.65, 0.85, 0.95, 0.65
    ),
    (
        "Personal loan pre-approved Rs 10 Lakhs at zero interest. Transfer processing fee Rs 1,999 to download loan sanction letter: http://instant-cash-india.xyz/loan.apk",
        0.93, "loan_fraud", 0.30, 0.40, 0.92, 0.60
    ),
    (
        "Guaranteed 10x return in stock market and crypto trading. Join VIP WhatsApp group deposit 10,000",
        0.92, "investment", 0.20, 0.30, 0.92, 0.60
    ),
    (
        "Microsoft Security Alert: Computer infected with trojan virus. Call toll-free helpline for remote support",
        0.89, "tech_support", 0.88, 0.65, 0.40, 0.50
    ),
    (
        "Your SIM card KYC is expired. Services will be stopped tonight. Recharge and submit Aadhaar http://airtel-sim-kyc.top",
        0.92, "telecom", 0.85, 0.88, 0.40, 0.50
    ),

    # ─── Legitimate / Benign Patterns ───
    (
        "Dear SBI Customer, your A/C ending in 4921 has been debited by Rs 1,450.00 on 26-Sep-2026. Ref: UPI/626918291048. Avail Bal: Rs 34,820.00. For disputes, visit https://www.onlinesbi.sbi or call 18001234. -State Bank of India",
        0.03, "banking", 0.02, 0.01, 0.02, 0.05
    ),
    (
        "Your SBI account XX1234 has been debited with Rs 2,500.00 on 25-Sep-2026. Available balance Rs 45,230.50. Call 1800111111 if not you",
        0.04, "banking", 0.03, 0.02, 0.02, 0.08
    ),
    (
        "481920 is your secret OTP for transaction of Rs 3,200.00 at AMAZON INDIA with HDFC Bank Card ending 1042. OTP valid for 10 mins. Never share OTP or password with anyone, including bank officials.",
        0.05, "banking", 0.03, 0.02, 0.02, 0.05
    ),
    (
        "Your OTP for Amazon shopping transaction is 482910. Valid for 10 mins. Do not share with anyone",
        0.05, "none", 0.02, 0.02, 0.02, 0.05
    ),
    (
        "Your India Post consignment EK928371928IN has reached Bangalore NSH. Expected delivery by 27-Sep-2026. Track your consignment at https://www.indiapost.gov.in/_layouts/15/dpt/track.aspx",
        0.02, "courier", 0.02, 0.01, 0.01, 0.04
    ),
    (
        "Your package from Flipkart has been delivered to your doorstep. Thank you for shopping with us",
        0.03, "courier", 0.03, 0.01, 0.01, 0.05
    ),
    (
        "Dear Consumer, payment of Rs 1,840 for BESCOM Account ID 8920192810 received successfully on 25-Sep-2026 via BBPS. Download official receipt from https://bescom.karnataka.gov.in -BESCOM",
        0.02, "electricity", 0.02, 0.01, 0.01, 0.04
    ),
    (
        "Dear Customer, your electricity bill of Rs 1,240 for August is due on 15-Sep. Pay via official BESCOM portal",
        0.04, "electricity", 0.03, 0.02, 0.04, 0.08
    ),
    (
        "Paid Rs 450 to Chai Point successfully from your UPI Linked Account. UPI Ref No: 426819283910. Check passbook in Paytm app.",
        0.03, "none", 0.02, 0.01, 0.02, 0.05
    ),
    (
        "Hi, please call me back when free.",
        0.02, "none", 0.01, 0.01, 0.01, 0.03
    ),
    (
        "Hi John, can we reschedule our meeting to 3 PM this afternoon? Let me know if that works",
        0.02, "none", 0.01, 0.01, 0.01, 0.05
    ),
    (
        "Reminder: Doctor appointment confirmed at Apollo Hospital for tomorrow 10:30 AM with Dr. Gupta",
        0.03, "none", 0.02, 0.02, 0.02, 0.05
    ),
    (
        "Your account XX5678 was credited with INR 65,000.00 on 28-Aug-2026 towards monthly salary. Available balance INR 89,200.00",
        0.02, "banking", 0.02, 0.01, 0.02, 0.05
    ),
    (
        "Dear Customer, your HDFC bank credit card ending 4410 payment of Rs 4,120 has been received. Thank you",
        0.03, "banking", 0.03, 0.01, 0.02, 0.08
    ),
    (
        "ICICI Bank: Rs 150.00 spent on your Debit Card ending in 9812 at Starbucks on 24-Sep-2026. Avail Bal: INR 32,100",
        0.03, "banking", 0.02, 0.01, 0.02, 0.06
    ),
]


def _init_local_laya():
    """Calibrate local fast multi-head decision heads."""
    global _is_calibrated, _vectorizer, _heads
    if _is_calibrated:
        return

    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import Ridge, LogisticRegression

        texts = [row[0] for row in _CALIBRATION_DATA]

        _vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=800,
            lowercase=True,
            stop_words="english",
        )
        x = _vectorizer.fit_transform(texts)

        # Head 1: Fraud score (calibrated logistic probability [0, 1])
        fraud_labels = [1 if row[1] >= 0.5 else 0 for row in _CALIBRATION_DATA]
        h_fraud = LogisticRegression(C=2.0, max_iter=300, class_weight="balanced")
        h_fraud.fit(x, fraud_labels)
        _heads["fraud"] = h_fraud

        # Head 2: Category choice (multi-class classification)
        h_cat = LogisticRegression(C=2.0, max_iter=300)
        h_cat.fit(x, [row[2] for row in _CALIBRATION_DATA])
        _heads["category"] = h_cat

        # Head 3: Brand impersonation score
        h_brand = Ridge(alpha=1.0)
        h_brand.fit(x, [row[3] for row in _CALIBRATION_DATA])
        _heads["brand"] = h_brand

        # Head 4: Credential request score
        h_cred = Ridge(alpha=1.0)
        h_cred.fit(x, [row[4] for row in _CALIBRATION_DATA])
        _heads["credential"] = h_cred

        # Head 5: Payment request score
        h_pay = Ridge(alpha=1.0)
        h_pay.fit(x, [row[5] for row in _CALIBRATION_DATA])
        _heads["payment"] = h_pay

        # Head 6: Deep analysis required (escalation score)
        h_deep = Ridge(alpha=1.0)
        h_deep.fit(x, [row[6] for row in _CALIBRATION_DATA])
        _heads["deep_analysis"] = h_deep

        _is_calibrated = True
        logger.info("Local Laya typed-decision heads calibrated successfully with %d samples.", len(_CALIBRATION_DATA))
    except Exception as e:
        logger.warning("Failed to calibrate local Laya heads: %s", e)
        _is_calibrated = False


def _clamp(val: float) -> float:
    """Clamp float to [0.0, 1.0] with 3 decimals."""
    return round(max(0.0, min(1.0, float(val))), 3)


async def _query_external_laya(text: str, endpoint: str) -> Optional[dict]:
    """Query external Laya service with strict timeout (150ms)."""
    try:
        async with httpx.AsyncClient(timeout=0.15) as client:
            resp = await client.post(endpoint, json={"text": text})
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        logger.debug("External Laya endpoint unavailable: %s", e)
    return None


def _predict_local_laya(text: str, context: Optional[dict] = None) -> Optional[dict]:
    """Execute local non-autoregressive multi-head typed decision pass with optional context."""
    if not _is_calibrated:
        _init_local_laya()

    if not _is_calibrated or _vectorizer is None:
        return None

    try:
        x = _vectorizer.transform([text])

        fraud_score = _clamp(_heads["fraud"].predict_proba(x)[0][1])
        category = str(_heads["category"].predict(x)[0])
        brand_score = _clamp(_heads["brand"].predict(x)[0])
        cred_score = _clamp(_heads["credential"].predict(x)[0])
        pay_score = _clamp(_heads["payment"].predict(x)[0])
        deep_score = _clamp(_heads["deep_analysis"].predict(x)[0])

        if context:
            is_official = context.get("is_official_domain", False)
            has_ti = context.get("has_threat_intel_hit", False)
            has_ip = context.get("has_ip_literal", False)
            has_apk = context.get("has_apk", False)
            has_tld = context.get("has_suspicious_tld", False)
            has_mismatch = context.get("has_brand_mismatch", False)
            has_upi = context.get("has_upi_collect_fraud", False)

            if is_official and not has_ti and not has_apk:
                fraud_score = min(fraud_score, 0.05)
                brand_score = min(brand_score, 0.05)
                cred_score = min(cred_score, 0.05)
                deep_score = min(deep_score, 0.10)

            if has_ip or has_apk:
                fraud_score = max(fraud_score, 0.92)
                deep_score = max(deep_score, 0.75)

            if has_tld or has_mismatch:
                fraud_score = max(fraud_score, 0.88)
                brand_score = max(brand_score, 0.85)

            if has_upi:
                fraud_score = max(fraud_score, 0.85)
                pay_score = max(pay_score, 0.85)
                category = "upi_fraud"

        return {
            "fraud": _clamp(fraud_score),
            "fraud_category": category,
            "brand_impersonation": _clamp(brand_score),
            "credential_request": _clamp(cred_score),
            "payment_request": _clamp(pay_score),
            "deep_analysis_required": _clamp(deep_score),
        }
    except Exception as e:
        logger.warning("Local Laya forward pass error: %s", e)
        return None


async def run_laya_triage(evidence: IncidentEvidence) -> IncidentEvidence:
    """
    Run Laya typed-decision System-1 triage with workflow context.
    Preserves strict fallback: on any failure, evidence.laya stays with available=False.
    """
    text = evidence.message
    if not text or len(text.strip()) < 5:
        return evidence

    start_time = time.perf_counter()
    decisions = None

    # Step A: Check for external self-hosted Laya endpoint if configured
    settings = get_settings()
    endpoint = getattr(settings, "laya_endpoint", None)
    if endpoint:
        decisions = await _query_external_laya(text, endpoint)

    # Step B: Local fast typed decision pass with workflow context
    if decisions is None:
        urls = evidence.urls or []
        items = evidence.evidence or []
        msg_lower = (evidence.message or "").lower()

        context = {
            "is_official_domain": any(is_official_brand_domain(u.domain) for u in urls if u.domain),
            "has_suspicious_tld": any(
                getattr(u, "is_suspicious_tld", False)
                or (u.domain and u.domain.split(".")[-1].lower() in ("top", "xyz", "icu", "site", "live", "link", "apk"))
                for u in urls
            ),
            "has_ip_literal": any(
                getattr(u, "is_ip_literal", False) or bool(re.search(r'https?://(?:\d{1,3}\.){3}\d{1,3}', u.url))
                for u in urls
            ),
            "has_apk": any(u.url.lower().endswith(".apk") or ".apk?" in u.url.lower() for u in urls) or ".apk" in msg_lower,
            "has_brand_mismatch": any(item.type == EvidenceType.BRAND_MISMATCH and (item.confidence or 0) >= 0.70 for item in items),
            "has_threat_intel_hit": any(item.type == EvidenceType.THREAT_INTEL_HIT and getattr(item, "status", None) == EvidenceStatus.CONFIRMED for item in items),
            "has_upi_collect_fraud": "approve the collect" in msg_lower or "approve collect request" in msg_lower or ("collect request" in msg_lower and "pin" in msg_lower),
        }
        decisions = _predict_local_laya(text, context=context)

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    # If Laya produced typed decisions
    if decisions:
        fraud_val = decisions.get("fraud", 0.0)
        cat_val = decisions.get("fraud_category", "none")
        brand_val = decisions.get("brand_impersonation", 0.0)
        cred_val = decisions.get("credential_request", 0.0)
        pay_val = decisions.get("payment_request", 0.0)
        deep_val = decisions.get("deep_analysis_required", 0.0)

        evidence.laya = LayaResult(
            fraud=fraud_val,
            fraud_category=cat_val,
            brand_impersonation=brand_val,
            credential_request=cred_val,
            payment_request=pay_val,
            deep_analysis_required=deep_val,
            available=True,
            latency_ms=elapsed_ms,
        )

        # Determine epistemic status and risk direction for model signal
        if fraud_val >= 0.65:
            laya_status = EvidenceStatus.SUSPICIOUS
            laya_severity = EvidenceSeverity.HIGH if fraud_val >= 0.80 else EvidenceSeverity.MEDIUM
            laya_direction = RiskDirection.INCREASES_RISK
        elif fraud_val >= 0.35:
            laya_status = EvidenceStatus.POSSIBLE
            laya_severity = EvidenceSeverity.LOW
            laya_direction = RiskDirection.NEUTRAL
        else:
            laya_status = EvidenceStatus.OBSERVED
            laya_severity = EvidenceSeverity.INFORMATIONAL
            laya_direction = RiskDirection.NEUTRAL

        # Attach Laya typed decision to evidence list with provenance
        evidence.evidence.append(
            EvidenceItem(
                type=EvidenceType.LAYA_SIGNAL,
                source="laya",
                description=(
                    f"Laya fast typed decision: scam likelihood {fraud_val:.0%}, "
                    f"category: {cat_val}, credential risk: {cred_val:.0%}, payment risk: {pay_val:.0%}"
                ),
                confidence=fraud_val,
                status=laya_status,
                reliability=EvidenceReliability.MODEL_SIGNAL,
                severity=laya_severity,
                risk_direction=laya_direction,
                observed_value=f"Laya output: fraud={fraud_val:.2f}, category={cat_val}, latency={elapsed_ms}ms",
                interpretation=f"Non-autoregressive model estimates {fraud_val:.0%} statistical likelihood of {cat_val} pattern",
                correlation_group="ml_decision",
                raw_data={
                    "laya_typed_decisions": decisions,
                    "latency_ms": elapsed_ms,
                },
            )
        )
    else:
        evidence.laya.available = False

    return evidence
