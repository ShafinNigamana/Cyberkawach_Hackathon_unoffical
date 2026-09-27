"""
Evidence Contract — the internal API between all pipeline modules.

Phase 1 Accuracy Update:
Enriches EvidenceItem with:
- Epistemic status: CONFIRMED, OBSERVED, SUSPICIOUS, POSSIBLE, UNKNOWN, UNAVAILABLE
- Factual observation vs. interpretation separation
- Source reliability and risk direction
- Correlation grouping to prevent double-counting
- Uncertainty and negative finding bounding
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ─── Enums ───

class RiskLevel(str, Enum):
    """Internal risk levels — used identically across every screen and API contract."""
    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class UserCategory(str, Enum):
    """
    Citizen-facing categorical risk assessment.
    Avoids equating low risk with a false guarantee of safety.
    """
    CONFIRMED_HIGH_RISK = "CONFIRMED HIGH RISK"
    HIGH_RISK = "HIGH RISK"
    SUSPICIOUS = "SUSPICIOUS"
    LOW_CONCERN = "LOW CONCERN"
    UNKNOWN = "UNKNOWN"


class InputType(str, Enum):
    """Supported input types."""
    TEXT = "text"
    URL = "url"
    SMS = "sms"
    EMAIL = "email"
    CHAT = "chat"
    SCREENSHOT = "screenshot"
    IMAGE = "image"
    PHOTO = "photo"


class UserState(str, Enum):
    """Adaptive response state machine states."""
    RECEIVED = "received"
    CLICKED = "clicked"
    ENTERED_CREDENTIALS = "entered_credentials"
    PAID = "paid"


class EvidenceType(str, Enum):
    """Types of evidence items — each renders as its own labeled item in the UI."""
    RULE_MATCH = "rule_match"
    URL_ANALYSIS = "url_analysis"
    BRAND_MISMATCH = "brand_mismatch"
    THREAT_INTEL_HIT = "threat_intel_hit"
    THREAT_INTEL_MISS = "threat_intel_miss"
    LAYA_SIGNAL = "laya_signal"
    ML_SIGNAL = "ml_signal"
    IOC_EXTRACTED = "ioc_extracted"
    PATTERN_MATCH = "pattern_match"
    DOMAIN_AGE = "domain_age"
    DNS_RECORD = "dns_record"
    TLS_CERTIFICATE = "tls_certificate"
    HTTP_REDIRECT = "http_redirect"
    WEBSITE_BEHAVIOR = "website_behavior"
    SENDER_ANALYSIS = "sender_analysis"
    REDIRECT_CHAIN = "redirect_chain"
    CAMPAIGN_LINK = "campaign_link"


class EvidenceStatus(str, Enum):
    """
    Epistemic status of a single piece of evidence.
    Distinguishes verified external hits from empirical facts, heuristics, and inferences.
    """
    CONFIRMED = "CONFIRMED"      # Verified by a trusted external source or ground truth
    OBSERVED = "OBSERVED"        # Directly measured or extracted objective fact
    SUSPICIOUS = "SUSPICIOUS"    # Evidence indicates elevated concern without proven malice
    POSSIBLE = "POSSIBLE"        # Plausible interpretation with insufficient support
    UNKNOWN = "UNKNOWN"          # Insufficient information to make a determination
    UNAVAILABLE = "UNAVAILABLE"  # Check could not be performed (e.g. source down or unconfigured)


class EvidenceReliability(str, Enum):
    """Reliability tier of the source producing the evidence."""
    CRYPTOGRAPHIC = "CRYPTOGRAPHIC"            # E.g. TLS certificates, cryptographic proofs
    EXTERNAL_DB = "EXTERNAL_DB"                # E.g. Google Safe Browsing, PhishTank, PhishStats
    DETERMINISTIC_FACT = "DETERMINISTIC_FACT"  # E.g. raw IP literal, port, length, exact regex
    HEURISTIC = "HEURISTIC"                    # E.g. keyword searches, lexical patterns, TLD checks
    MODEL_SIGNAL = "MODEL_SIGNAL"              # E.g. statistical classifier, Laya inference
    UNVERIFIED = "UNVERIFIED"                  # E.g. uncorroborated user inference


class RiskDirection(str, Enum):
    """Directional influence of this evidence on fraud assessment."""
    INCREASES_RISK = "INCREASES_RISK"
    NEUTRAL = "NEUTRAL"
    DECREASES_RISK = "DECREASES_RISK"


class EvidenceSeverity(str, Enum):
    """Severity magnitude of the finding."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class ThreatIntelStatus(str, Enum):
    """State classification for threat intelligence lookups."""
    KNOWN_MALICIOUS = "KNOWN MALICIOUS"
    NO_KNOWN_MATCH = "NO KNOWN MATCH"
    SOURCE_UNAVAILABLE = "SOURCE UNAVAILABLE"
    SOURCE_ERROR = "SOURCE ERROR"


# ─── Sub-models ───

class URLSignal(BaseModel):
    """Signals extracted from a single URL."""
    url: str
    domain: str
    signals: list[str] = Field(default_factory=list)
    is_shortened: bool = False
    redirect_chain: list[str] = Field(default_factory=list)
    final_url: Optional[str] = None


class BrandMatch(BaseModel):
    """Brand impersonation detection result."""
    brand_name: str
    confidence: float = Field(ge=0.0, le=1.0)
    match_type: str = ""  # "exact", "similarity", "domain_mismatch"
    legitimate_domain: Optional[str] = None


class LayaResult(BaseModel):
    """
    Laya typed-decision output. Populated with nulls/defaults when Laya
    is not active — fusion reads this without special-casing.
    """
    fraud: Optional[float] = None
    fraud_category: Optional[str] = None
    brand_impersonation: Optional[float] = None
    credential_request: Optional[float] = None
    payment_request: Optional[float] = None
    deep_analysis_required: Optional[float] = None
    available: bool = False  # False when Laya is not wired up
    latency_ms: Optional[float] = None


class MLClassifierResult(BaseModel):
    """
    Dedicated Scikit-Learn TF-IDF + Logistic Regression ML Classifier (PRD Section 8).
    Runs alongside Laya as a dedicated statistical classification layer.
    """
    classification: str = "unknown"  # "phishing", "suspicious", "legitimate"
    confidence: float = 0.0
    model_version: str = "v1.2-sklearn-tfidf"
    top_features: list[str] = Field(default_factory=list)
    available: bool = False
    latency_ms: Optional[float] = None


class ThreatIntelResult(BaseModel):
    """Single threat-intelligence source result."""
    source: str  # "safe_browsing", "phishtank", "phishstats"
    match: Optional[bool] = None  # None = lookup failed / unavailable
    details: Optional[str] = None
    lookup_url: Optional[str] = None
    error: Optional[str] = None  # Non-null when API call failed
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    intel_status: ThreatIntelStatus = ThreatIntelStatus.NO_KNOWN_MATCH


class RiskAssessment(BaseModel):
    """Fused risk assessment with separate confidence, sufficiency, and limits."""
    level: RiskLevel = RiskLevel.UNKNOWN
    category: UserCategory = UserCategory.UNKNOWN
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    calibrated: bool = False
    evidence_sufficiency: str = "INSUFFICIENT"  # "SUFFICIENT", "PARTIAL", "INSUFFICIENT"
    uncertainty_reasons: list[str] = Field(default_factory=list)
    what_cannot_be_concluded: list[str] = Field(default_factory=list)
    contributing_factors: list[str] = Field(default_factory=list)


class EvidenceItem(BaseModel):
    """
    Standardized Evidence Item with strict provenance and tiering (PRD Section 9 & 10).
    Answers: WHAT was found, HOW it was found, WHERE it came from, and WHEN it was observed.
    Never collapsed into an opaque verdict.
    """
    id: str = Field(default_factory=lambda: f"EVD-{uuid.uuid4().hex[:8].upper()}")
    indicator: Optional[str] = None  # What was analyzed (domain, URL, phone, sender, text)
    type: EvidenceType
    source: str  # Which module/provider produced this evidence
    source_type: str = "rule"  # "api" | "rdap" | "dns" | "tls" | "sandbox" | "content" | "ocr" | "rule"
    evidence_tier: str = "OBSERVED"  # "DIRECT" | "OBSERVED" | "DERIVED" | "WEAK_SIGNAL"
    description: str
    finding: Optional[str] = None  # Human-readable finding statement
    observed_value: Optional[str] = None  # Factual measured or extracted data
    interpretation: Optional[str] = None   # What the observation signifies
    status: EvidenceStatus = EvidenceStatus.OBSERVED  # Epistemic status (CONFIRMED, OBSERVED, UNAVAILABLE, etc.)
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    reliability: EvidenceReliability = EvidenceReliability.DETERMINISTIC_FACT
    risk_direction: RiskDirection = RiskDirection.INCREASES_RISK
    severity: EvidenceSeverity = EvidenceSeverity.MEDIUM
    correlation_group: Optional[str] = None  # Prevents double-counting correlated signals
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_reference: Optional[str] = None  # Reference link or raw identifier
    is_cached: bool = False  # Distinguishes LIVE vs CACHED
    raw_data: Optional[dict] = None  # Preserved raw technical payload for auditability


class AttackStep(BaseModel):
    """
    A traceable step in an attack causal chain linking observed evidence to harm.
    Enforces the causal graph: Evidence Item -> Attack Step -> Consequence.
    """
    step_number: int
    description: str
    causal_stage: str = "lure"  # "lure", "redirection", "exploitation", "monetization", "execution"
    evidence_indices: list[int] = Field(default_factory=list)  # 1-indexed references to evidence items
    observed_basis: Optional[str] = None  # Specific observed value or signal
    intended_consequence: Optional[str] = None  # Downstream threat if victim complies


class GeminiExplanation(BaseModel):
    """
    Explanation output — structured, never freeform.
    Can be produced by Gemini or deterministic template fallback.
    """
    summary: str = ""
    reasons: list[str] = Field(default_factory=list)
    attack_path: list[str] = Field(default_factory=list)
    structured_attack_path: list[AttackStep] = Field(default_factory=list)
    user_action: list[str] = Field(default_factory=list)
    uncertainty: str = ""
    what_cannot_be_concluded: list[str] = Field(default_factory=list)
    model_used: str = ""  # "gemini-flash-latest", "deterministic-fallback", etc.
    evidence_cited: list[str] = Field(default_factory=list)  # IDs of evidence items used
    is_fallback: bool = False  # True when generated by deterministic template


class AdaptiveResponse(BaseModel):
    """State-dependent guidance based on user's interaction level."""
    user_state: UserState = UserState.RECEIVED
    immediate_actions: list[str] = Field(default_factory=list)
    recovery_steps: list[str] = Field(default_factory=list)
    reporting_info: list[str] = Field(default_factory=list)
    urgency: str = "normal"  # "normal", "urgent", "critical"


class SenderContext(BaseModel):
    """Optional sender information (email, phone, claimed org, etc.)."""
    display_name: Optional[str] = None
    email_address: Optional[str] = None
    phone_number: Optional[str] = None
    sender_id: Optional[str] = None
    username: Optional[str] = None
    claimed_organization: Optional[str] = None
    sender_domain: Optional[str] = None
    reply_to: Optional[str] = None


class MessageContext(BaseModel):
    """Optional message envelope metadata."""
    channel: Optional[str] = None
    subject: Optional[str] = None
    timestamp: Optional[str] = None
    attachments: list[str] = Field(default_factory=list)
    original_source: Optional[str] = None


class FraudDNA(BaseModel):
    """Fraud DNA fingerprint for campaign correlation (P2)."""
    fingerprint: Optional[str] = None
    campaign_id: Optional[str] = None
    related_incidents: list[str] = Field(default_factory=list)
    available: bool = False  # False until Fraud DNA module is wired up
    graph_persisted: bool = False  # True when synced to Neo4j graph


# ─── Main Evidence Contract ───

class IncidentEvidence(BaseModel):
    """
    THE Evidence Contract.

    Every module downstream of ingestion reads and writes this object.
    All fields have sane defaults so the pipeline works regardless of
    which optional modules are active.

    Invariants:
    - `incident_id` is set once at creation, never changed.
    - `laya` is always present (with `available=False` when Laya isn't wired).
    - `fraud_dna` is always present (with `available=False` when DNA isn't wired).
    - `evidence` is append-only — modules add items, never remove them.
    - `threat_intel` entries include `error` when a lookup failed.
    """
    # Identity
    incident_id: str = Field(default_factory=lambda: f"INC-{datetime.now(timezone.utc).strftime('%Y')}-{uuid.uuid4().hex[:8].upper()}")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Input
    input_type: InputType = InputType.TEXT
    language: str = "en"
    response_language: Optional[str] = None
    input_language: Optional[str] = None
    message: str = ""
    original_input: Optional[str] = None  # Preserved before normalization

    # Sender & Context (Optional)
    sender: Optional[SenderContext] = None
    message_context: Optional[MessageContext] = None

    # Extraction
    urls: list[URLSignal] = Field(default_factory=list)
    brands: list[BrandMatch] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)  # Indicators of compromise

    # Analysis
    laya: LayaResult = Field(default_factory=LayaResult)
    ml_classifier: MLClassifierResult = Field(default_factory=MLClassifierResult)
    threat_intel: list[ThreatIntelResult] = Field(default_factory=list)
    rule_matches: list[str] = Field(default_factory=list)
    fraud_category: Optional[str] = None  # "banking", "courier", "government", "lottery", etc.

    # Fusion
    risk: RiskAssessment = Field(default_factory=RiskAssessment)
    evidence: list[EvidenceItem] = Field(default_factory=list)

    # Explanation
    explanation: Optional[GeminiExplanation] = None

    # Response
    response: Optional[AdaptiveResponse] = None

    # Campaign (P2)
    fraud_dna: FraudDNA = Field(default_factory=FraudDNA)

    # Processing metadata
    processing_time_ms: Optional[float] = None
    modules_executed: list[str] = Field(default_factory=list)
    modules_failed: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
