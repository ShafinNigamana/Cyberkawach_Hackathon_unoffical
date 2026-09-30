"""
ML Baseline — TF-IDF + Logistic Regression classification.

DET-02: Optional TF-IDF/Logistic Regression baseline.
Separate from rule-based detection — provides an empirical statistical score
trained on phishing/fraud vs legitimate message patterns.
"""

from __future__ import annotations

import logging
from typing import Optional

from backend.models.evidence import (
    EvidenceItem,
    EvidenceReliability,
    EvidenceSeverity,
    EvidenceStatus,
    EvidenceType,
    IncidentEvidence,
    RiskDirection,
)

logger = logging.getLogger("cyber_guardian.ml_baseline")

# In-memory pipeline cache
_vectorizer = None
_classifier = None
_is_initialized = False


# Curated training data: realistic scam and legitimate text patterns
_TRAINING_CORPUS: list[tuple[str, int]] = [
    # ─── Fraud / Phishing (Label 1) ───
    ("Dear customer your SBI account is blocked due to incomplete KYC click here to update immediately", 1),
    ("Your HDFC debit card has been suspended. Verify your PAN and Aadhaar now to reactivate", 1),
    ("Important notice: Your bank account will be deactivated within 24 hours. Submit OTP to prevent", 1),
    ("Congratulations! You won Rs 25,00,000 in KBC lottery lucky draw. Contact manager to claim prize", 1),
    ("Your parcel delivery failed due to wrong address. Pay Rs 25 redelivery charge to reschedule", 1),
    ("Income tax department approved your refund of Rs 15,400. Click link to deposit to bank account", 1),
    ("Work from home earn Rs 5000 daily part time simple tasks telegram rating job pay registration fee", 1),
    ("Electricity power will be disconnected tonight 9:30 PM due to unpaid bill. Call officer immediately", 1),
    ("Guaranteed stock market trading tips 10x returns join VIP WhatsApp group invest crypto bitcoin", 1),
    ("Security alert: Unauthorized login attempt on your device. Call Microsoft support helpline now", 1),
    ("Urgent: Your SIM card KYC is expired. Services will be stopped. Recharge and submit Aadhaar", 1),
    ("Claim your cash reward of Rs 4,999 on PhonePe / Google Pay. Scratch card waiting click link", 1),
    ("Your credit card reward points worth Rs 8,500 expiring today. Redeem for cash directly", 1),
    ("E-challan traffic violation fine unpaid. Arrest warrant issued by police click to pay fine", 1),
    ("Personal loan pre-approved Rs 10 Lakhs at zero interest. Transfer processing fee Rs 1,999", 1),
    # ─── Legitimate / Normal (Label 0) ───
    ("Your account was debited with INR 500.00 on 24-Sep-2026. Available balance INR 12,450.00", 0),
    ("OTP for your transaction at Amazon is 492810. Do not share OTP with anyone including bank staff", 0),
    ("Your package from Flipkart has been delivered. Thank you for shopping with us", 0),
    ("Your appointment with Dr. Sharma is confirmed for tomorrow 4:00 PM at Apollo Clinic", 0),
    ("Dear user, your monthly statement for August 2026 has been generated and sent to email", 0),
    ("Flight 6E-204 from Delhi to Mumbai is on schedule. Web check-in is now open", 0),
    ("Your mobile recharge of Rs 299 was successful. Data balance 1.5GB/day valid for 28 days", 0),
    ("Salary of INR 65,000 credited to your savings account by your employer", 0),
    ("Electricity bill for consumer no 849201 is Rs 1,420 due on 15th October. Pay via official app", 0),
    ("Your ride with Uber has arrived. Vehicle number MH02AB1234 driver Suresh is waiting", 0),
    ("Hi Rahul, let's meet for lunch at 1 PM today near the office cafeteria", 0),
    ("Can you please share the project presentation slides when you get a chance thanks", 0),
    ("Reminder: Team weekly standup scheduled at 11:00 AM on Google Meet", 0),
    ("Your order #8291 has been shipped via BlueDart. Track delivery on our official website", 0),
    ("Happy birthday! Wishing you a wonderful year ahead filled with joy and success", 0),
    ("This Independence Day celebrate 150 years of Vande Mataram with Har Ghar Tiranga hoist Tiranga at home upload selfie on harghartiranga.com", 0),
    ("Advisory as per the Telecommunications Act 2023 acquiring SIMs or telecom identifiers by fraud is a punishable offence with imprisonment and fine", 0),
]


def _init_model():
    """Train the lightweight TF-IDF + Logistic Regression model on startup."""
    global _vectorizer, _classifier, _is_initialized
    if _is_initialized:
        return

    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression

        texts = [item[0] for item in _TRAINING_CORPUS]
        labels = [item[1] for item in _TRAINING_CORPUS]

        _vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=500,
            lowercase=True,
            stop_words="english",
        )
        x_train = _vectorizer.fit_transform(texts)

        _classifier = LogisticRegression(C=1.0, max_iter=200, random_state=42)
        _classifier.fit(x_train, labels)
        _is_initialized = True
        logger.info("ML Baseline model successfully initialized and calibrated.")
    except Exception as e:
        logger.warning("Could not initialize ML baseline model: %s", e)
        _is_initialized = False


def predict_scam_probability(text: str) -> Optional[float]:
    """
    Predict probability that text is a scam message.
    Returns float in [0.0, 1.0], or None if ML model is unavailable.
    """
    if not _is_initialized:
        _init_model()

    if not _is_initialized or _vectorizer is None or _classifier is None:
        return None

    try:
        features = _vectorizer.transform([text])
        probabilities = _classifier.predict_proba(features)[0]
        # Label 1 is scam
        scam_prob = float(probabilities[1])
        return round(scam_prob, 4)
    except Exception as e:
        logger.warning("ML prediction failed: %s", e)
        return None


def run_ml_baseline(evidence: IncidentEvidence) -> IncidentEvidence:
    """
    Run the ML baseline classifier and attach an evidence item.
    Non-critical: gracefully returns unchanged evidence on any failure.
    """
    text = evidence.message
    if not text or len(text.strip()) < 5:
        return evidence

    prob = predict_scam_probability(text)
    if prob is None:
        return evidence

    # Only add evidence item if there is a meaningful statistical signal
    if prob >= 0.50:
        evidence.evidence.append(
            EvidenceItem(
                type=EvidenceType.PATTERN_MATCH,
                source="ml_baseline",
                source_type="content",
                evidence_tier="DERIVED",
                finding=f"ML baseline classifier: elevated scam likelihood ({prob:.0%})",
                description=f"ML baseline (TF-IDF + Logistic Regression): scam likelihood {prob:.0%}",
                confidence=prob,
                status=EvidenceStatus.OBSERVED,
                reliability=EvidenceReliability.MODEL_SIGNAL,
                risk_direction=RiskDirection.INCREASES_RISK,
                severity=EvidenceSeverity.MEDIUM,
                correlation_group="ml_baseline_signal",
                raw_data={"model": "tfidf_logistic_regression", "scam_probability": prob},
            )
        )
    elif prob < 0.50:
        evidence.evidence.append(
            EvidenceItem(
                type=EvidenceType.PATTERN_MATCH,
                source="ml_baseline",
                source_type="content",
                evidence_tier="DERIVED",
                finding=f"ML baseline classifier: low scam likelihood ({prob:.0%})",
                description=f"ML baseline (TF-IDF + Logistic Regression): low scam likelihood ({prob:.0%})",
                confidence=round(1.0 - prob, 4),
                status=EvidenceStatus.OBSERVED,
                reliability=EvidenceReliability.MODEL_SIGNAL,
                risk_direction=RiskDirection.NEUTRAL,
                severity=EvidenceSeverity.INFORMATIONAL,
                correlation_group="ml_baseline_signal",
                raw_data={"model": "tfidf_logistic_regression", "scam_probability": prob},
            )
        )

    return evidence
