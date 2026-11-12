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
# Balanced multi-class dataset covering all 12 threat archetypes + benign samples
_CALIBRATION_DATA = [
    # (text, fraud, category, brand_imp, cred_req, pay_req, deep_analysis)
    # ─── 1. Banking Phishing (fraud ~ 0.94, cat: banking) ───
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
        "Axis Bank Alert: Account suspended due to non-submission of mandatory PAN KYC documents. Update at http://axis-kyc-portal.top immediately.",
        0.93, "banking", 0.90, 0.91, 0.20, 0.45
    ),
    (
        "Kotak Mahindra Bank: Netbanking profile locked due to unauthorized login. Reactivate credentials at http://kotak-secure-login.site",
        0.94, "banking", 0.90, 0.93, 0.20, 0.45
    ),

    # ─── 2. Electricity & Utility Cutoff (fraud ~ 0.93, cat: electricity) ───
    (
        "Dear consumer your electricity power will be disconnected tonight at 9:30 pm from electricity office because your previous month bill was not updated. Please immediately contact our electricity officer at 9821839201. -Electricity Department",
        0.92, "electricity", 0.70, 0.20, 0.90, 0.60
    ),
    (
        "Dear consumer electricity power will be disconnected tonight at 9.30pm from electricity office because your previous month bill was not updated please contact our electricity officer 9821049210 http://vidhyut-bill.apk",
        0.95, "electricity", 0.75, 0.30, 0.92, 0.65
    ),
    (
        "Mahavitaran notice: Dear customer your electricity power supply will be cut off tonight due to unpaid bill. Pay immediately or call 9182391029",
        0.93, "electricity", 0.75, 0.25, 0.90, 0.60
    ),
    (
        "BESCOM alert: Power disconnection order issued for consumer ID 98219482. Clear pending arrears immediately via APK download: http://bescom-bill.apk",
        0.95, "electricity", 0.75, 0.30, 0.92, 0.65
    ),
    (
        "Tata Power Notice: Urgent electric line disconnection today 8 PM. Settle your overdue balance by calling officer 9821049210",
        0.92, "electricity", 0.70, 0.20, 0.90, 0.60
    ),
    (
        "Urgent electricity department warning: Power supply will be disconnected in 1 hour. Pay overdue bill now via link: http://electricity-payment.live",
        0.93, "electricity", 0.70, 0.25, 0.91, 0.60
    ),

    # ─── 3. Courier & Customs Fraud (fraud ~ 0.92, cat: courier) ───
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
        "Delhivery package delivery failed. Reschedule delivery date and pay processing fee Rs 15 at http://delhivery-redelivery.site",
        0.90, "courier", 0.85, 0.25, 0.82, 0.40
    ),
    (
        "BlueDart shipment on hold at customs. Pay handling fee Rs 49 to release parcel: http://bluedart-release.top",
        0.91, "courier", 0.85, 0.25, 0.85, 0.40
    ),
    (
        "DHL Express: Courier package detained due to unpaid customs duty Rs 120. Update delivery address and pay at http://dhl-customs.link",
        0.92, "courier", 0.85, 0.30, 0.85, 0.40
    ),

    # ─── 4. Digital Arrest & Legal Extortion (fraud ~ 0.95, cat: extortion_legal) ───
    (
        "CBI Official Notice: An arrest warrant has been issued against your Aadhaar card for money laundering. Join police Skype video investigation immediately to avoid physical arrest.",
        0.95, "extortion_legal", 0.80, 0.70, 0.85, 0.75
    ),
    (
        "Mumbai Police Cyber Crime: Your identity used in illegal contraband parcel. Transfer security deposit to RBI verification account to avoid immediate detention.",
        0.96, "extortion_legal", 0.80, 0.70, 0.92, 0.80
    ),
    (
        "TRAI Legal Notice: An illegal SIM registered on your Aadhaar card was used in cyber terrorism. Physical police raid will occur in 2 hours unless you join Skype interrogation.",
        0.95, "extortion_legal", 0.75, 0.70, 0.85, 0.75
    ),
    (
        "Delhi Police Cyber Cell: Your Aadhaar linked bank accounts are frozen under Section 420 IPC. Report on video call to cyber inspector immediately.",
        0.94, "extortion_legal", 0.80, 0.65, 0.85, 0.70
    ),
    (
        "Narcotics Control Bureau: Contraband parcel containing MDMA intercepted in your name. Download police warrant and transfer bail security deposit to avoid arrest.",
        0.96, "extortion_legal", 0.80, 0.70, 0.92, 0.80
    ),
    (
        "Supreme Court e-Summons: You are summoned for urgent court hearing regarding financial tax fraud. Failure to appear will trigger immediate non-bailable warrant.",
        0.93, "extortion_legal", 0.75, 0.60, 0.80, 0.70
    ),

    # ─── 5. Fake Lottery & Rewards (fraud ~ 0.95, cat: lottery_prize) ───
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
        "Jio 5G Celebration Lucky Draw: You are selected for free 1 year recharge and Rs 50,000 cash. Click to claim voucher http://jio-recharge.site",
        0.94, "lottery_prize", 0.80, 0.35, 0.85, 0.35
    ),
    (
        "PhonePe Scratch Card: You won Rs 4,999 cash cashback. Click link to deposit instantly into your bank account: http://phonepe-cashback.top",
        0.94, "lottery_prize", 0.80, 0.40, 0.90, 0.35
    ),
    (
        "Amazon Mega Festive Gift: You won iPhone 15 Pro Max. Pay Rs 999 shipping charge to receive delivery tomorrow http://amazon-festive-gift.top",
        0.93, "lottery_prize", 0.85, 0.30, 0.90, 0.35
    ),

    # ─── 6. Part-Time Job & Task Scams (fraud ~ 0.91, cat: job_offer) ───
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
        "YouTube video like and subscribe part time job earn Rs 150 per like. Contact HR manager on Telegram @daily_task_payout",
        0.91, "job_offer", 0.65, 0.20, 0.85, 0.40
    ),
    (
        "Work from mobile: Complete 15 minutes Google Maps rating task and earn Rs 2,500 daily. WhatsApp HR to get registered with deposit.",
        0.90, "job_offer", 0.65, 0.25, 0.88, 0.40
    ),
    (
        "Freelance online typing job: Earn Rs 2,000 per assignment. Transfer refundable security deposit of Rs 1,499 to receive project files.",
        0.89, "job_offer", 0.20, 0.30, 0.90, 0.45
    ),

    # ─── 7. UPI Collect & Refund Fraud (fraud ~ 0.94, cat: upi_fraud) ───
    (
        "Dear customer, your refund of Rs 4,500 for order #89281 has been initiated. Open PhonePe or Google Pay and approve the collect request sent to your UPI ID to receive money in your account.",
        0.94, "upi_fraud", 0.65, 0.85, 0.95, 0.65
    ),
    (
        "Google Pay: Cashback of Rs 2,499 approved. Approve the pending collect request on GPay and enter your UPI PIN to claim funds.",
        0.95, "upi_fraud", 0.70, 0.85, 0.95, 0.65
    ),
    (
        "Paytm Refund: Rs 3,850 failed recharge refund initiated. Enter UPI PIN to confirm credit into your wallet.",
        0.95, "upi_fraud", 0.70, 0.85, 0.95, 0.65
    ),
    (
        "PhonePe refund notification: Tap to accept collect request of Rs 5,000 sent by merchant to receive your return payment.",
        0.94, "upi_fraud", 0.70, 0.85, 0.95, 0.65
    ),
    (
        "Flipkart order cancellation refund Rs 1,999 waiting. Accept UPI mandate request in your banking app to receive money.",
        0.93, "upi_fraud", 0.75, 0.80, 0.92, 0.60
    ),

    # ─── 8. Fake Loan Scams (fraud ~ 0.93, cat: loan_fraud) ───
    (
        "Personal loan pre-approved Rs 10 Lakhs at zero interest. Transfer processing fee Rs 1,999 to download loan sanction letter: http://instant-cash-india.xyz/loan.apk",
        0.93, "loan_fraud", 0.30, 0.40, 0.92, 0.60
    ),
    (
        "Instant Mudra Loan approved Rs 5,00,000 with zero collateral. Pay file charge Rs 2,499 to disburse funds to bank.",
        0.94, "loan_fraud", 0.50, 0.35, 0.92, 0.60
    ),
    (
        "SBI Instant Loan approved for Rs 3,50,000. Transfer insurance verification fee Rs 3,200 to manager account to release funds immediately.",
        0.95, "loan_fraud", 0.80, 0.40, 0.94, 0.65
    ),
    (
        "Bajaj Finance instant paperless loan Rs 8,00,000 pre-approved. Pay processing fee Rs 1,850 via UPI to generate agreement.",
        0.93, "loan_fraud", 0.85, 0.35, 0.92, 0.60
    ),
    (
        "Emergency quick cash loan approved within 15 minutes. Install loan app from http://quick-cash-loan.apk and pay verification fee.",
        0.94, "loan_fraud", 0.30, 0.45, 0.94, 0.65
    ),

    # ─── 9. Investment & Crypto Scams (fraud ~ 0.93, cat: investment) ───
    (
        "Guaranteed 10x return in stock market and crypto trading. Join VIP WhatsApp group deposit 10,000",
        0.92, "investment", 0.20, 0.30, 0.92, 0.60
    ),
    (
        "Institutional stock market insider tips. 500% profit guaranteed in 3 days. Send deposit to VIP broker telegram.",
        0.93, "investment", 0.20, 0.30, 0.94, 0.65
    ),
    (
        "Forex trading automated AI bot: Earn Rs 25,000 daily passive income. Deposit minimum Rs 5,000 to activate bot in Telegram @forex_bot_india",
        0.92, "investment", 0.25, 0.30, 0.93, 0.60
    ),
    (
        "Crypto arbitrage pool: 20% daily compounding returns guaranteed by smart contracts. Transfer USDT to join private syndicate.",
        0.93, "investment", 0.20, 0.30, 0.95, 0.65
    ),
    (
        "Tata Mutual Fund private pre-IPO allocation: Buy shares at 80% discount before market listing. Deposit to designated trustee bank account.",
        0.94, "investment", 0.80, 0.40, 0.94, 0.65
    ),

    # ─── 10. Tech Support Scams (fraud ~ 0.90, cat: tech_support) ───
    (
        "Microsoft Security Alert: Computer infected with trojan virus. Call toll-free helpline for remote support",
        0.89, "tech_support", 0.88, 0.65, 0.40, 0.50
    ),
    (
        "Windows Defender detected suspicious spyware on your device. Call Microsoft certified support 1800-891-2910 immediately.",
        0.90, "tech_support", 0.88, 0.65, 0.40, 0.50
    ),
    (
        "Apple Security Warning: Your iCloud account is locked due to unauthorized access from Moscow. Call Apple executive 1800-291-9201",
        0.91, "tech_support", 0.88, 0.70, 0.35, 0.50
    ),
    (
        "Your PC is locked due to Trojan virus infection. Do not restart computer. Contact support helpline 9821049210 to unlock device.",
        0.90, "tech_support", 0.80, 0.60, 0.50, 0.55
    ),
    (
        "Google Account Alert: Critical security vulnerability found on your Android device. Download antivirus fix from http://google-security-fix.top",
        0.92, "tech_support", 0.88, 0.75, 0.30, 0.50
    ),

    # ─── 11. Telecom & SIM Swap Scams (fraud ~ 0.93, cat: telecom) ───
    (
        "Your SIM card KYC is expired. Outgoing and incoming calls will be blocked in 24 hours. Submit Aadhaar at http://airtel-sim-kyc.top",
        0.93, "telecom", 0.85, 0.88, 0.40, 0.50
    ),
    (
        "Your SIM card KYC is expired. Services will be stopped tonight. Recharge and submit Aadhaar http://airtel-sim-kyc.top",
        0.92, "telecom", 0.85, 0.88, 0.40, 0.50
    ),
    (
        "Jio 4G SIM verification overdue. Your mobile number will be deactivated tonight. Call customer executive 9182391029 immediately.",
        0.93, "telecom", 0.85, 0.85, 0.40, 0.50
    ),
    (
        "Your WhatsApp will be deactivated in 12 hours. Verify your account now by forwarding your 6-digit registration code.",
        0.92, "telecom", 0.80, 0.92, 0.20, 0.50
    ),
    (
        "BSNL SIM upgrade alert: Your 3G SIM will be disconnected today. Send SMS to port number to convert to 5G instantly.",
        0.91, "telecom", 0.85, 0.80, 0.35, 0.50
    ),

    # ─── 12. Government & Tax Scams (fraud ~ 0.93, cat: government) ───
    (
        "Income Tax Refund of Rs 18,500 has been approved. Update bank account details within 48 hours to receive refund http://incometax-refund.link",
        0.93, "government", 0.80, 0.85, 0.15, 0.50
    ),
    (
        "Income Tax Department Notice: Your tax refund of Rs 24,850 is waiting. Submit your bank account and PAN details at http://incometax-efiling-refund.info/login to process.",
        0.95, "government", 0.85, 0.90, 0.15, 0.50
    ),
    (
        "E-challan pending traffic police fine. Arrest warrant will be issued if payment not made today",
        0.89, "government", 0.70, 0.20, 0.90, 0.55
    ),
    (
        "Traffic Police Notice: Unpaid speed violation e-challan MH02-8921. Pay fine within 24 hours at http://echallan-parivahan.top to avoid impounding vehicle.",
        0.92, "government", 0.80, 0.30, 0.90, 0.55
    ),
    (
        "PM Kisan Yojana subsidy of Rs 6,000 approved for your Aadhaar card. Update your bank account details at http://pm-kisan-subsidy.site to disburse funds.",
        0.94, "government", 0.80, 0.85, 0.20, 0.50
    ),

    # ─── 13. Legitimate / Benign (fraud ~ 0.03, cat: none) ───
    (
        "Dear SBI Customer, your A/C ending in 4921 has been debited by Rs 1,450.00 on 26-Sep-2026. Ref: UPI/626918291048. Avail Bal: Rs 34,820.00. For disputes, visit https://www.onlinesbi.sbi or call 18001234. -State Bank of India",
        0.03, "none", 0.02, 0.01, 0.02, 0.05
    ),
    (
        "Your SBI account XX1234 has been debited with Rs 2,500.00 on 25-Sep-2026. Available balance Rs 45,230.50. Call 1800111111 if not you",
        0.04, "none", 0.03, 0.02, 0.02, 0.08
    ),
    (
        "481920 is your secret OTP for transaction of Rs 3,200.00 at AMAZON INDIA with HDFC Bank Card ending 1042. OTP valid for 10 mins. Never share OTP or password with anyone, including bank officials.",
        0.05, "none", 0.03, 0.02, 0.02, 0.05
    ),
    (
        "Your OTP for Amazon shopping transaction is 482910. Valid for 10 mins. Do not share with anyone",
        0.05, "none", 0.02, 0.02, 0.02, 0.05
    ),
    (
        "829104 is your verification code for logging into ICICI iMobile. Valid for 5 minutes. Bank never calls asking for OTP.",
        0.04, "none", 0.03, 0.02, 0.02, 0.05
    ),
    (
        "SBI: 391029 is OTP for login on OnlineSBI. Do NOT share OTP or password with anyone. Bank never asks for it.",
        0.04, "none", 0.03, 0.02, 0.02, 0.05
    ),
    (
        "Your India Post consignment EK928371928IN has reached Bangalore NSH. Expected delivery by 27-Sep-2026. Track your consignment at https://www.indiapost.gov.in/_layouts/15/dpt/track.aspx",
        0.02, "none", 0.02, 0.01, 0.01, 0.04
    ),
    (
        "Your package from Flipkart has been delivered to your doorstep. Thank you for shopping with us",
        0.03, "none", 0.03, 0.01, 0.01, 0.05
    ),
    (
        "Dear Consumer, payment of Rs 1,840 for BESCOM Account ID 8920192810 received successfully on 25-Sep-2026 via BBPS. Download official receipt from https://bescom.karnataka.gov.in -BESCOM",
        0.02, "none", 0.02, 0.01, 0.01, 0.04
    ),
    (
        "Dear Customer, your electricity bill of Rs 1,240 for August is due on 15-Sep. Pay via official BESCOM portal",
        0.04, "none", 0.03, 0.02, 0.04, 0.08
    ),
    (
        "MSEDCL Receipt: Payment of Rs 1,450 received against Consumer No 028491823910 on 24-Sep-2026. Transaction ID 98219482194. Thank you.",
        0.02, "none", 0.02, 0.01, 0.01, 0.04
    ),
    (
        "Paid Rs 450 to Chai Point successfully from your UPI Linked Account. UPI Ref No: 426819283910. Check passbook in Paytm app.",
        0.03, "none", 0.02, 0.01, 0.02, 0.05
    ),
    (
        "Money Sent: Rs 1,200.00 transferred successfully to Ramesh Kumar (ramesh@okhdfcbank) via Google Pay. UPI Ref: 391820192810.",
        0.03, "none", 0.02, 0.01, 0.02, 0.05
    ),
    (
        "Received Rs 500.00 from Priya Sharma on PhonePe. Updated wallet balance is Rs 1,450.00.",
        0.02, "none", 0.01, 0.01, 0.01, 0.04
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
        0.02, "none", 0.02, 0.01, 0.02, 0.05
    ),
    (
        "Dear Customer, your HDFC bank credit card ending 4410 payment of Rs 4,120 has been received. Thank you",
        0.03, "none", 0.03, 0.01, 0.02, 0.08
    ),
    (
        "ICICI Bank: Rs 150.00 spent on your Debit Card ending in 9812 at Starbucks on 24-Sep-2026. Avail Bal: INR 32,100",
        0.03, "none", 0.02, 0.01, 0.02, 0.06
    ),
]


def _load_calibration_corpus() -> list:
    """Load extended calibration corpus from backend/data/laya_training_corpus.json if available."""
    try:
        import os
        import json
        corpus_path = os.path.join(os.path.dirname(__file__), "..", "data", "laya_training_corpus.json")
        if os.path.exists(corpus_path):
            with open(corpus_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if data and isinstance(data, list):
                return [
                    (
                        item["text"],
                        float(item["fraud"]),
                        str(item["category"]),
                        float(item["brand_imp"]),
                        float(item["cred_req"]),
                        float(item["pay_req"]),
                        float(item["deep_analysis"]),
                    )
                    for item in data
                ]
    except Exception as e:
        logger.debug("Failed loading external corpus: %s", e)
    return _CALIBRATION_DATA


def _init_local_laya():
    """Calibrate local fast multi-head decision heads with low-variance regularized estimators."""
    global _is_calibrated, _vectorizer, _heads
    if _is_calibrated:
        return

    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import Ridge, LogisticRegression

        corpus = _load_calibration_corpus()
        texts = [row[0] for row in corpus]

        # Regularized feature extraction: limit dimension to prevent memorization / high-variance overfitting
        _vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=350,
            min_df=2,
            sublinear_tf=True,
            lowercase=True,
            stop_words="english",
        )
        x = _vectorizer.fit_transform(texts)

        # Head 1: Fraud score (regularized balanced logistic regression C=2.0, max_iter=500)
        fraud_labels = [1 if row[1] >= 0.5 else 0 for row in corpus]
        h_fraud = LogisticRegression(C=2.0, max_iter=500, class_weight="balanced")
        h_fraud.fit(x, fraud_labels)
        _heads["fraud"] = h_fraud

        # Head 2: Category choice (balanced multi-class logistic regression C=2.0)
        h_cat = LogisticRegression(C=2.0, max_iter=500, class_weight="balanced")
        h_cat.fit(x, [row[2] for row in corpus])
        _heads["category"] = h_cat

        # Head 3: Brand impersonation score (regularized L2 Ridge alpha=3.0)
        h_brand = Ridge(alpha=3.0)
        h_brand.fit(x, [row[3] for row in corpus])
        _heads["brand"] = h_brand

        # Head 4: Credential request score (regularized L2 Ridge alpha=3.0)
        h_cred = Ridge(alpha=3.0)
        h_cred.fit(x, [row[4] for row in corpus])
        _heads["credential"] = h_cred

        # Head 5: Payment request score (regularized L2 Ridge alpha=3.0)
        h_pay = Ridge(alpha=3.0)
        h_pay.fit(x, [row[5] for row in corpus])
        _heads["payment"] = h_pay

        # Head 6: Deep analysis required (regularized L2 Ridge alpha=3.0)
        h_deep = Ridge(alpha=3.0)
        h_deep.fit(x, [row[6] for row in corpus])
        _heads["deep_analysis"] = h_deep

        _is_calibrated = True
        logger.info("Local Laya typed-decision heads calibrated successfully with %d samples.", len(corpus))
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
        elif fraud_val >= 0.40:
            laya_status = EvidenceStatus.SUSPICIOUS
            laya_severity = EvidenceSeverity.LOW
            laya_direction = RiskDirection.INCREASES_RISK
        else:
            laya_status = EvidenceStatus.OBSERVED
            laya_severity = EvidenceSeverity.INFORMATIONAL
            laya_direction = RiskDirection.NEUTRAL

        # Attach Laya typed decision to evidence list with provenance
        desc = (
            f"Laya fast typed decision: scam likelihood {fraud_val:.0%}, "
            f"category: {cat_val}, credential risk: {cred_val:.0%}, payment risk: {pay_val:.0%}"
        )
        evidence.evidence.append(
            EvidenceItem(
                type=EvidenceType.LAYA_SIGNAL,
                source="laya",
                finding=desc,
                description=desc,
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
