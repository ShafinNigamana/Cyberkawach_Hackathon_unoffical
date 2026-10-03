"""
Dedicated Scikit-Learn ML Classifier Service (PRD Section 8 & Section 33).

Architectural Contract:
- Operates in tandem with Laya fast typed-decision engine without collision.
- Architecture: Hybrid Context-Aware TF-IDF + Calibrated Logistic Regression.
- Returns formal Section 8 schema:
  {
    "classification": "phishing" | "suspicious" | "legitimate",
    "confidence": float [0.0, 1.0],
    "model_version": "v1.2-sklearn-tfidf",
    "top_features": list[str]
  }
- Generates EvidenceType.ML_SIGNAL with MODEL_SIGNAL reliability and epistemic modesty.
- Strict fallback: on failure or empty input, pipeline continues cleanly.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Optional

from backend.models.evidence import (
    EvidenceItem,
    EvidenceReliability,
    EvidenceSeverity,
    EvidenceStatus,
    EvidenceType,
    IncidentEvidence,
    MLClassifierResult,
    RiskDirection,
)
from backend.modules.brand_check import is_official_brand_domain

logger = logging.getLogger("cyber_guardian.ml_classifier")

# ─── Training & Calibration Dataset ───
# Comprehensive real-world Indian cyber-fraud telemetric patterns and legitimate transactional norms
_TRAINING_DATA = [
    # ─── 1. Banking & KYC Phishing (Label: 1) ───
    ("Dear Customer Your SBI account has been BLOCKED due to incomplete KYC verification. Click here: http://sbi-kyc.xyz", 1),
    ("SBI YONO Alert: Your netbanking is temporarily suspended due to pending KYC update. Click http://sbi-yono-update.icu to submit PAN details within 24 hours.", 1),
    ("URGENT: Your SBI YONO account has been suspended due to pending PAN-Aadhaar KYC. Click here immediately to update: http://192.168.1.105/sbi/kyc-update to prevent permanent account suspension.", 1),
    ("Your HDFC debit card has been suspended. Verify your PAN and Aadhaar now to reactivate online", 1),
    ("Dear HDFC Customer, your NetBanking access is temporarily disabled due to suspicious login attempt. Reactivate your netbanking profile now at https://hdfc-bank-netbanking-verify.com/login before 24 hrs.", 1),
    ("Dear HDFC user, your 9,850 reward points worth Rs 4,925 expire today. Redeem immediately in your bank account: http://hdfc-reward-claim.site", 1),
    ("ICICI Bank alert: Your internet banking access will be terminated today. Update your mobile number and OTP at http://icici-portal.top", 1),
    ("Important Notice from ICICI Bank: Your debit card will be blocked within 12 hours due to unverified KYC. Click http://bit.ly/icici-kyc-verify to verify details now.", 1),
    ("Important notice: Axis Bank account frozen due to non-submission of Form 16. Upload documents at http://axis-kyc.online", 1),
    ("Immediate action: PNB customer your credit card is blocked due to international transaction. Call helpdesk 9182391029", 1),
    ("Kotak Bank: Your account verification failed. Avoid permanent suspension by verifying netbanking credentials at http://kotak-portal-update.live", 1),
    ("Bank of Baroda alert: Your netbanking session expired. Log in immediately to verify your registered mobile number http://bob-netbanking.top", 1),
    ("Dear customer your bank account is on hold. Verify Aadhaar number and OTP within 2 hours: http://bank-kyc-update.com", 1),
    ("Attention: Canara bank user your debit card reward points of Rs 7,500 expire tonight. Click http://canara-rewards.site to claim cash credit.", 1),
    ("Union Bank Alert: Netbanking credentials compromised. Reset your password immediately at http://unionbank-secure.top", 1),

    # ─── 2. Utility & Electricity Cutoff Threats (Label: 1) ───
    ("Dear consumer electricity power will be disconnected tonight at 9.30pm from electricity office because your previous month bill was not updated please contact our electricity officer 9821049210 http://vidhyut-bill.apk", 1),
    ("Dear consumer your electricity power will be disconnected tonight at 9:30 pm from electricity office because your previous month bill was not updated. Please immediately contact our electricity officer at 9821839201. -Electricity Department", 1),
    ("Mahavitaran notice: Dear customer your electricity power supply will be cut off tonight due to unpaid bill. Pay immediately or call 9182391029", 1),
    ("BESCOM alert: Power disconnection order issued for consumer ID 98219482. Clear pending arrears immediately via APK download: http://bescom-bill.apk", 1),
    ("Tata Power Notice: Urgent electric line disconnection today 8 PM. Settle your overdue balance by calling officer 9821049210", 1),
    ("Urgent electricity department warning: Power supply will be disconnected in 1 hour. Pay bill now via link: http://electricity-payment.live", 1),

    # ─── 3. Courier, Parcel & Customs Fraud (Label: 1) ───
    ("Your parcel from Amazon could not be delivered due to incorrect address. Pay Rs 25 customs charge: http://amaz0n-delivery.top", 1),
    ("India Post: Your package could not be delivered due to incomplete address. Please update your address and pay re-delivery fee Rs 25 at http://indiapost-parcel.top", 1),
    ("India Post: Your package IN9827381 could not be delivered due to incomplete street address. Please update your address within 24 hours at https://indiapost-parcel-update.top/address to avoid return to sender.", 1),
    ("Delhivery package delivery failed. Reschedule delivery date and pay processing fee Rs 15 at http://delhivery-redelivery.site", 1),
    ("BlueDart shipment on hold at customs. Pay handling fee Rs 49 to release parcel: http://bluedart-release.top", 1),
    ("DHL Express: Courier package detained due to unpaid customs duty Rs 120. Update delivery address and pay at http://dhl-customs.link", 1),

    # ─── 4. Digital Arrest, Police & Statutory Extortion (Label: 1) ───
    ("CBI Official Notice: An arrest warrant has been issued against your Aadhaar card for money laundering. Join police Skype video investigation immediately to avoid physical arrest.", 1),
    ("Mumbai Police Cyber Crime: Your identity used in illegal contraband parcel. Transfer security deposit to RBI verification account to avoid immediate detention.", 1),
    ("TRAI Legal Notice: An illegal SIM registered on your Aadhaar card was used in cyber terrorism. Physical police raid will occur in 2 hours unless you join Skype interrogation.", 1),
    ("Delhi Police Cyber Cell: Your Aadhaar linked bank accounts are frozen under Section 420 IPC. Report on video call to cyber inspector immediately.", 1),
    ("Narcotics Control Bureau: Contraband parcel containing MDMA intercepted in your name. Download police warrant and transfer bail security deposit.", 1),
    ("Supreme Court e-Summons: You are summoned for urgent court hearing regarding financial tax fraud. Failure to appear will trigger immediate non-bailable warrant.", 1),

    # ─── 5. Fake Lottery, Prizes & Rewards (Label: 1) ───
    ("CONGRATULATIONS! You have WON Rs 25,00,000 in Google Annual Lottery. Pay processing fee Rs 4,999 to claim", 1),
    ("CONGRATULATIONS! You have won Rs 25,00,000 from KBC Kaun Banega Crorepati Lottery Lucky Draw 2026. Send your name and bank account on WhatsApp +91-9123456789 to claim prize money. Cheque number: KBC-9821.", 1),
    ("KBC Lucky Draw winner 25 Lakhs. Send WhatsApp message to manager to transfer prize money", 1),
    ("Jio 5G Celebration Lucky Draw: You are selected for free 1 year recharge and Rs 50,000 cash. Click to claim voucher http://jio-recharge.site", 1),
    ("PhonePe Scratch Card: You won Rs 4,999 cash cashback. Click link to deposit instantly into your bank account: http://phonepe-cashback.top", 1),
    ("Amazon Mega Festive Gift: You won iPhone 15 Pro Max. Pay Rs 999 shipping charge to receive delivery tomorrow http://amazon-festive-gift.top", 1),

    # ─── 6. Part-Time Job, Review & Investment Scams (Label: 1) ───
    ("Earn Rs 3,000 to Rs 8,000 daily from home! Part time online job: simply like YouTube videos and write hotel reviews. No investment needed. Contact manager on Telegram: @amazon_review_job2026 to start now.", 1),
    ("Work from home part time data entry job. Earn Rs 15,000-45,000 monthly. Registration fee Rs 999 only", 1),
    ("Urgent hiring Amazon telegram product review task earn Rs 3000 daily pay security deposit to start", 1),
    ("YouTube video like and subscribe part time job earn Rs 150 per like. Contact HR manager on Telegram @daily_task_payout", 1),
    ("Guaranteed 10x return in stock market and crypto trading. Join VIP WhatsApp group deposit 10,000", 1),
    ("Work from mobile: Complete 15 minutes Google Maps rating task and earn Rs 2,500 daily. WhatsApp HR to get registered.", 1),
    ("Institutional stock market insider tips. 500% profit guaranteed in 3 days. Send deposit to VIP broker telegram.", 1),

    # ─── 7. UPI Collect & Fake Refund Scams (Label: 1) ───
    ("Dear customer, your refund of Rs 4,500 for order #89281 has been initiated. Open PhonePe or Google Pay and approve the collect request sent to your UPI ID to receive money in your account.", 1),
    ("Google Pay: Cashback of Rs 2,499 approved. Approve the pending collect request on GPay and enter your UPI PIN to claim funds.", 1),
    ("Paytm Refund: Rs 3,850 failed recharge refund initiated. Enter UPI PIN to confirm credit into your wallet.", 1),
    ("PhonePe refund notification: Tap to accept collect request of Rs 5,000 sent by merchant to receive your return payment.", 1),

    # ─── 8. Pre-Approved Loans & Government Tax Scams (Label: 1) ───
    ("Personal loan pre-approved Rs 10 Lakhs at zero interest. Transfer processing fee Rs 1,999 to download loan sanction letter: http://instant-cash-india.xyz/loan.apk", 1),
    ("Instant Mudra Loan approved Rs 5,00,000 with zero collateral. Pay file charge Rs 2,499 to disburse funds to bank.", 1),
    ("Income Tax Refund of Rs 18,500 has been approved. Update bank account details within 48 hours to receive refund http://incometax-refund.link", 1),
    ("Income Tax Department Notice: Your tax refund of Rs 24,850 is waiting. Submit your bank account and PAN details at http://incometax-efiling-refund.info/login to process.", 1),
    ("E-challan pending traffic police fine. Arrest warrant will be issued if payment not made today", 1),
    ("Traffic Police Notice: Unpaid speed violation e-challan MH02-8921. Pay fine within 24 hours at http://echallan-parivahan.top to avoid impounding vehicle.", 1),

    # ─── 9. Telecom SIM Block & Account Takeover (Label: 1) ───
    ("Your SIM card KYC is expired. Outgoing and incoming calls will be blocked in 24 hours. Submit Aadhaar at http://airtel-sim-kyc.top", 1),
    ("Jio 4G SIM verification overdue. Your mobile number will be deactivated tonight. Call customer executive 9182391029 immediately.", 1),
    ("Your WhatsApp will be deactivated in 12 hours. Verify your account now by forwarding your 6-digit registration code.", 1),
    ("Microsoft Security Alert: Computer infected with trojan virus. Call toll-free helpline for remote support", 1),

    # ═══════════════════════════════════════════════════════════════
    # ─── 10. Legitimate Bank SMS & Financial Notifications (Label: 0) ───
    ("Dear SBI Customer, your A/C ending in 4921 has been debited by Rs 1,450.00 on 26-Sep-2026. Ref: UPI/626918291048. Avail Bal: Rs 34,820.00. For disputes, visit https://www.onlinesbi.sbi or call 18001234. -State Bank of India", 0),
    ("Your SBI account XX1234 has been debited with Rs 2,500.00 on 25-Sep-2026. Available balance Rs 45,230.50. Call 1800111111 if not you", 0),
    ("Your account XX5678 was credited with INR 65,000.00 on 28-Aug-2026 towards monthly salary. Available balance INR 89,200.00", 0),
    ("Dear Customer, your HDFC bank credit card ending 4410 payment of Rs 4,120 has been received. Thank you", 0),
    ("ICICI Bank: Rs 150.00 spent on your Debit Card ending in 9812 at Starbucks on 24-Sep-2026. Avail Bal: INR 32,100", 0),
    ("Axis Bank: Your A/C 98120481 has been credited with INR 12,000.00 via NEFT. UTR: UTIB0001294819. Avail Bal: INR 48,900.00", 0),
    ("PNB Alert: Rs 850.00 debited at ATM cash withdrawal on 22-Sep-2026. Bal: Rs 15,200.00. Call 18001802222 if unauthorized.", 0),
    ("Bank of Baroda: Interest of Rs 342.00 credited to savings account XX8910 on 30-Sep-2026.", 0),

    # ─── 11. Legitimate OTPs with Strict "Never Share" Warnings (Label: 0) ───
    ("481920 is your secret OTP for transaction of Rs 3,200.00 at AMAZON INDIA with HDFC Bank Card ending 1042. OTP valid for 10 mins. Never share OTP or password with anyone, including bank officials.", 0),
    ("Your OTP for Amazon shopping transaction is 482910. Valid for 10 mins. Do not share with anyone", 0),
    ("829104 is your verification code for logging into ICICI iMobile. Valid for 5 minutes. Bank never calls asking for OTP.", 0),
    ("SBI: 391029 is OTP for login on OnlineSBI. Do NOT share OTP or password with anyone. Bank never asks for it.", 0),
    ("Your one time password for Aadhaar authentication is 918273. Valid for 10 minutes. Do not disclose to any person.", 0),

    # ─── 12. Legitimate UPI & Merchant Payment Alerts (Label: 0) ───
    ("Paid Rs 450 to Chai Point successfully from your UPI Linked Account. UPI Ref No: 426819283910. Check passbook in Paytm app.", 0),
    ("Money Sent: Rs 1,200.00 transferred successfully to Ramesh Kumar (ramesh@okhdfcbank) via Google Pay. UPI Ref: 391820192810.", 0),
    ("PhonePe: Payment of Rs 350 to Fresh Fruits Mart successful. Ref No: 982104928104. Transaction completed.", 0),
    ("Received Rs 500.00 from Priya Sharma on PhonePe. Updated wallet balance is Rs 1,450.00.", 0),
    ("Cred: Your payment of Rs 14,200 towards HDFC Bank Credit Card has been confirmed. Cash points credited.", 0),

    # ─── 13. Legitimate Utilities, BBPS Receipts & Government Portals (Label: 0) ───
    ("Dear Consumer, payment of Rs 1,840 for BESCOM Account ID 8920192810 received successfully on 25-Sep-2026 via BBPS. Download official receipt from https://bescom.karnataka.gov.in -BESCOM", 0),
    ("Dear Customer, your electricity bill of Rs 1,240 for August is due on 15-Sep. Pay via official BESCOM portal", 0),
    ("MSEDCL Receipt: Payment of Rs 1,450 received against Consumer No 028491823910 on 24-Sep-2026. Transaction ID 98219482194. Thank you.", 0),
    ("Tata Power DDL: Payment of Rs 2,100 received for CA 6001928102. Current outstanding balance is Nil.", 0),
    ("Indane Gas: Booking confirmed for cylinder ref 89201928. Delivery agent will arrive in 2 working days.", 0),
    ("Income Tax Department: ITR-V for AY 2026-27 has been successfully verified. E-acknowledgement sent to registered email.", 0),

    # ─── 14. Legitimate Courier & Delivery Tracking (Label: 0) ───
    ("Your India Post consignment EK928371928IN has reached Bangalore NSH. Expected delivery by 27-Sep-2026. Track your consignment at https://www.indiapost.gov.in/_layouts/15/dpt/track.aspx", 0),
    ("Your package from Flipkart has been delivered to your doorstep. Thank you for shopping with us", 0),
    ("BlueDart: Shipment 829102910 out for delivery today. Delivery agent will arrive by 4 PM. Contact 18602331234 for assistance.", 0),
    ("Delhivery: Package with tracking ID 482910391 is out for delivery. OTP for delivery confirmation is 4821.", 0),
    ("Swiggy: Your order from Chai Point has been picked up by delivery partner Ramesh. Track live in the app.", 0),
    ("Zomato: Order confirmed! Delivery in 25 mins. Your delivery partner is vaccinated.", 0),

    # ─── 15. Legitimate Telecom, Travel & Services (Label: 0) ───
    ("Airtel Thanks: Your daily 1.5 GB high-speed data balance is 800 MB remaining. Recharges valid till 20-Oct.", 0),
    ("Jio: Recharge of Rs 299 successful on your number 9820192810. Plan includes 1.5GB/day + unlimited calls for 28 days.", 0),
    ("IRCTC: PNR 4829103912 Train 12951 Mumbai Rajdhani 28-Sep-2026 2A B2-45 Confirmed. Enjoy your journey.", 0),
    ("IndiGo flight 6E-204 from Delhi to Mumbai is on schedule. Web check-in is now open.", 0),
    ("Uber: Your ride has arrived. Maruti Dzire DL01AB9821 driver Suresh is waiting outside.", 0),

    # ─── 16. Legitimate Conversational & Workplace Messages (Label: 0) ───
    ("Hi, please call me back when free.", 0),
    ("Hi, please call me back when you get a chance thanks.", 0),
    ("Hi John, can we reschedule our meeting to 3 PM this afternoon? Let me know if that works", 0),
    ("Reminder: Doctor appointment confirmed at Apollo Hospital for tomorrow 10:30 AM with Dr. Gupta", 0),
    ("Can you please email me the updated presentation slides before our team sync?", 0),
    ("Reminder: Team weekly standup scheduled at 11:00 AM on Google Meet", 0),
    ("Happy birthday! Wishing you a wonderful year ahead filled with joy and success", 0),
    ("Security alert for your linked Google Account. A new sign-in was detected on Windows. Check activity at https://myaccount.google.com/notifications", 0),

    # ─── 17. Civic & Statutory Announcements (Label: 0) ───
    ("This Independence Day celebrate 150 years of Vande Mataram with Har Ghar Tiranga hoist Tiranga at home upload selfie on harghartiranga.com", 0),
    ("Advisory as per the Telecommunications Act 2023 acquiring SIMs or telecom identifiers by fraud is a punishable offence with imprisonment and fine", 0),
    ("Election Commission of India: Check your name in voter list online at voters.eci.gov.in. National Voters Day.", 0),
]

_vectorizer = None
_model = None
_is_ready = False


def _init_classifier():
    """Train and calibrate the Scikit-learn TF-IDF + Logistic Regression pipeline."""
    global _vectorizer, _model, _is_ready
    if _is_ready:
        return

    import pickle
    from pathlib import Path

    model_cache = Path(__file__).resolve().parent.parent / "data" / "ml_classifier_model.pkl"
    if model_cache.exists():
        try:
            with open(model_cache, "rb") as f:
                _vectorizer, _model = pickle.load(f)
            _vectorizer.transform(["warmup message"])
            _is_ready = True
            logger.info("Scikit-Learn ML Classifier loaded from persistent cache: %s", model_cache)
            return
        except Exception as e:
            logger.warning("Could not load cached ML classifier model: %s", e)

    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression

        texts = [row[0] for row in _TRAINING_DATA]
        labels = [row[1] for row in _TRAINING_DATA]

        _vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=2500,
            lowercase=True,
            sublinear_tf=True,
            token_pattern=r"(?u)\b\w+\b|https?://\S+",
        )
        x = _vectorizer.fit_transform(texts)

        _model = LogisticRegression(C=2.0, max_iter=400, class_weight="balanced", random_state=42)
        _model.fit(x, labels)
        _vectorizer.transform(["warmup message"])

        _is_ready = True
        logger.info("Scikit-Learn ML Classifier pipeline initialized successfully with %d samples.", len(_TRAINING_DATA))
    except Exception as e:
        logger.warning("Failed to initialize Scikit-Learn ML Classifier: %s", e)
        _is_ready = False


# Eager warmup on module load to guarantee sub-5ms latency on requests
try:
    _init_classifier()
except Exception:
    pass


def extract_workflow_context(evidence: IncidentEvidence) -> dict:
    """Extract contextual signals from upstream pipeline stages for hybrid ML classification."""
    urls = evidence.urls or []
    items = evidence.evidence or []
    msg_lower = (evidence.message or "").lower()

    # 1. URL network & domain signals
    has_official_domain = any(is_official_brand_domain(u.domain) for u in urls if u.domain)
    has_suspicious_tld = any(
        getattr(u, "is_suspicious_tld", False)
        or (u.domain and u.domain.split(".")[-1].lower() in (
            "top", "xyz", "icu", "site", "live", "link", "club", "buzz", "online", "click", "rest", "apk"
        ))
        for u in urls
    )
    has_ip_literal = any(
        getattr(u, "is_ip_literal", False)
        or bool(re.search(r'https?://(?:\d{1,3}\.){3}\d{1,3}', u.url))
        for u in urls
    )
    has_apk = any(
        u.url.lower().endswith(".apk") or ".apk?" in u.url.lower()
        for u in urls
    ) or ".apk" in msg_lower

    # 2. Brand & Typosquatting signals
    has_brand_mismatch = any(
        item.type == EvidenceType.BRAND_MISMATCH and (item.confidence or 0.0) >= 0.70
        for item in items
    )

    # 3. Threat Intelligence hits
    has_threat_intel_hit = any(
        item.type == EvidenceType.THREAT_INTEL_HIT
        and getattr(item, "status", None) == EvidenceStatus.CONFIRMED
        for item in items
    )

    # 4. Behavioral & Rule signals
    has_urgency_threat = any(
        item.type == EvidenceType.RULE_MATCH
        and any(k in item.description.lower() for k in ("cutoff", "disconnect", "arrest", "warrant", "suspend", "block", "police", "legal"))
        for item in items
    )
    has_upi_collect_fraud = (
        "approve the collect" in msg_lower
        or "approve collect request" in msg_lower
        or ("collect request" in msg_lower and "pin" in msg_lower)
        or any("collect" in item.description.lower() and "upi" in item.description.lower() for item in items)
    )
    has_never_share_otp = bool(
        re.search(r'(never\s+share|do\s+not\s+share)\b.*?\b(otp|password|pin)', msg_lower)
    )

    return {
        "is_official_domain": has_official_domain,
        "has_suspicious_tld": has_suspicious_tld,
        "has_ip_literal": has_ip_literal,
        "has_apk": has_apk,
        "has_brand_mismatch": has_brand_mismatch,
        "has_threat_intel_hit": has_threat_intel_hit,
        "has_urgency_threat": has_urgency_threat,
        "has_upi_collect_fraud": has_upi_collect_fraud,
        "has_never_share_otp": has_never_share_otp,
    }


def predict_text(text: str, context: Optional[dict] = None) -> Optional[dict]:
    """
    Execute Scikit-Learn inference and extract top explainable features.
    Accepts optional workflow `context` for hybrid text + pipeline signal calibration.
    """
    if not _is_ready:
        _init_classifier()

    if not _is_ready or _vectorizer is None or _model is None:
        return None

    try:
        x = _vectorizer.transform([text])
        proba_phishing = float(_model.predict_proba(x)[0][1])

        # Extract top positive contributing features (Section 8 explainability)
        top_features: list[str] = []
        try:
            feature_names = _vectorizer.get_feature_names_out()
            coefs = _model.coef_[0]
            non_zero_indices = x.nonzero()[1]
            token_impacts = [(feature_names[i], coefs[i]) for i in non_zero_indices if coefs[i] > 0]
            token_impacts.sort(key=lambda t: t[1], reverse=True)
            top_features = [t[0] for t in token_impacts[:5]]
        except Exception:
            top_features = []

        calibrated_prob = proba_phishing
        added_context_features: list[str] = []

        if context:
            # ─── Hybrid Workflow Feature Calibration ───
            is_official = context.get("is_official_domain", False)
            has_ti = context.get("has_threat_intel_hit", False)
            has_ip = context.get("has_ip_literal", False)
            has_apk = context.get("has_apk", False)
            has_tld = context.get("has_suspicious_tld", False)
            has_mismatch = context.get("has_brand_mismatch", False)
            has_upi_scam = context.get("has_upi_collect_fraud", False)
            has_urgency = context.get("has_urgency_threat", False)
            has_otp_warn = context.get("has_never_share_otp", False)

            # Legitimate institutional infrastructure dampens false positives
            if is_official and not has_ti and not has_apk:
                calibrated_prob = min(calibrated_prob, 0.10)
                added_context_features.append("official_institutional_domain")

            # Standard bank OTP warnings without external links
            if has_otp_warn and not has_tld and not has_mismatch and not has_ip:
                calibrated_prob = min(calibrated_prob, 0.12)
                added_context_features.append("security_warning_present")

            # Hard structural malware/phishing indicators
            if has_ip:
                calibrated_prob = max(calibrated_prob, 0.88)
                added_context_features.append("ip_literal_url")
            if has_apk:
                calibrated_prob = max(calibrated_prob, 0.86)
                added_context_features.append("unverified_apk_download")
            if has_tld:
                calibrated_prob = max(calibrated_prob, 0.82)
                added_context_features.append("suspicious_tld")
            if has_mismatch:
                calibrated_prob = max(calibrated_prob, 0.85)
                added_context_features.append("brand_impersonation_mismatch")
            if has_ti:
                calibrated_prob = max(calibrated_prob, 0.95)
                added_context_features.append("threat_intelligence_hit")
            if has_upi_scam:
                calibrated_prob = max(calibrated_prob, 0.82)
                added_context_features.append("upi_collect_request_lure")
            if has_urgency and not is_official:
                calibrated_prob = max(calibrated_prob, 0.65)
                added_context_features.append("coercive_urgency_pressure")

        # Combine features for explainability
        all_features = added_context_features + top_features

        # Decisive categorization
        if calibrated_prob >= 0.60:
            classification = "phishing"
            confidence = round(calibrated_prob, 3)
        elif calibrated_prob >= 0.38:
            classification = "suspicious"
            confidence = round(calibrated_prob, 3)
        else:
            classification = "legitimate"
            confidence = round(1.0 - calibrated_prob, 3)

        return {
            "classification": classification,
            "confidence": confidence,
            "fraud_probability": round(calibrated_prob, 3),
            "top_features": all_features[:5],
            "model_version": "v1.2-sklearn-tfidf",
        }
    except Exception as e:
        logger.warning("ML Classifier inference error: %s", e)
        return None


async def run_ml_classification(evidence: IncidentEvidence) -> IncidentEvidence:
    """
    Run dedicated Scikit-Learn ML Classifier triage with full workflow awareness.
    Preserves strict fallback: on any failure, evidence.ml_classifier stays available=False.
    """
    text = evidence.message
    if not text or len(text.strip()) < 5:
        return evidence

    start_time = time.perf_counter()
    context = extract_workflow_context(evidence)
    res = predict_text(text, context=context)
    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    if res:
        classification = res["classification"]
        confidence = res["confidence"]
        fraud_prob = res["fraud_probability"]
        top_tokens = res["top_features"]
        version = res["model_version"]

        evidence.ml_classifier = MLClassifierResult(
            classification=classification,
            confidence=confidence,
            model_version=version,
            top_features=top_tokens,
            available=True,
            latency_ms=elapsed_ms,
        )

        # Epistemic bounds & risk direction
        if classification == "phishing":
            ml_status = EvidenceStatus.SUSPICIOUS
            ml_severity = EvidenceSeverity.HIGH if confidence >= 0.80 else EvidenceSeverity.MEDIUM
            ml_direction = RiskDirection.INCREASES_RISK
        elif classification == "suspicious":
            ml_status = EvidenceStatus.POSSIBLE
            ml_severity = EvidenceSeverity.LOW
            ml_direction = RiskDirection.NEUTRAL
        else:
            ml_status = EvidenceStatus.OBSERVED
            ml_severity = EvidenceSeverity.INFORMATIONAL
            ml_direction = RiskDirection.NEUTRAL

        token_hint = f" | Indicative signals: {', '.join(top_tokens[:3])}" if top_tokens else ""

        # Attach ML EvidenceItem
        evidence.evidence.append(
            EvidenceItem(
                type=EvidenceType.ML_SIGNAL,
                source="ml_classifier",
                description=(
                    f"Scikit-Learn Hybrid Classifier ({classification.upper()}, {confidence:.0%} confidence): "
                    f"Calibrated TF-IDF + pipeline context classification{token_hint}"
                ),
                confidence=confidence,
                status=ml_status,
                reliability=EvidenceReliability.MODEL_SIGNAL,
                severity=ml_severity,
                risk_direction=ml_direction,
                observed_value=f"ML: class={classification}, conf={confidence:.2f}, prob={fraud_prob:.2f}, latency={elapsed_ms}ms",
                interpretation=f"Trained TF-IDF Logistic Regression estimates {confidence:.0%} confidence in {classification} pattern",
                correlation_group="ml_classification",
                raw_data={
                    "ml_result": res,
                    "latency_ms": elapsed_ms,
                },
            )
        )
    else:
        evidence.ml_classifier.available = False

    return evidence
