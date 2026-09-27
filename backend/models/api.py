"""
API request/response schemas — the contract between frontend and backend.

Hardened against injection, unexpected field pollution, and unbounded payloads.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from backend.models.evidence import (
    AdaptiveResponse,
    BrandMatch,
    EvidenceItem,
    FraudDNA,
    GeminiExplanation,
    InputType,
    LayaResult,
    MLClassifierResult,
    RiskAssessment,
    ThreatIntelResult,
    URLSignal,
    UserState,
)


# ─── Request Models ───

class AnalyzeRequest(BaseModel):
    """
    POST /api/analyze — primary endpoint.
    Accepts text, URL, or both. Rejects unknown fields.
    """
    model_config = ConfigDict(extra="forbid")

    message: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="The suspicious message text to analyze",
    )
    input_type: InputType = Field(
        default=InputType.TEXT,
        description="Type of input being submitted",
    )
    user_state: UserState = Field(
        default=UserState.RECEIVED,
        description="How far the user has interacted with the scam",
    )
    urls: list[str] = Field(
        default_factory=list,
        max_length=20,
        description="Additional URLs to analyze (max 20, auto-extracted from message too)",
    )
    language: str = Field(
        default="en",
        max_length=10,
        pattern=r"^[a-zA-Z]{2}(-[a-zA-Z0-9]{2,4})?$",
        description="ISO language code (e.g. 'en', 'hi', 'gu', 'ta')",
    )
    response_language: Optional[str] = Field(
        default=None,
        max_length=10,
        pattern=r"^[a-zA-Z]{2}(-[a-zA-Z0-9]{2,4})?$",
        description="Explicit user-preferred response language ('en', 'hi', 'gu', 'ta')",
    )


class UpdateUserStateRequest(BaseModel):
    """
    POST /api/incidents/{incident_id}/state — update user state for adaptive response.
    Rejects unknown fields.
    """
    model_config = ConfigDict(extra="forbid")

    user_state: UserState
    language: Optional[str] = Field(
        default=None,
        max_length=10,
        pattern=r"^[a-zA-Z]{2}(-[a-zA-Z0-9]{2,4})?$",
        description="Optional language code",
    )
    response_language: Optional[str] = Field(
        default=None,
        max_length=10,
        pattern=r"^[a-zA-Z]{2}(-[a-zA-Z0-9]{2,4})?$",
        description="Optional updated response language",
    )
    language: Optional[str] = Field(
        default=None,
        max_length=10,
        pattern=r"^[a-zA-Z]{2}(-[a-zA-Z0-9]{2,4})?$",
        description="Optional alias for response_language",
    )


class TranslateRequest(BaseModel):
    """
    POST /api/translate — Translate text dynamically via Google Cloud Translation API.
    """
    model_config = ConfigDict(extra="forbid")

    text: Optional[str] = Field(default=None, max_length=10000, description="Single text string to translate")
    texts: Optional[list[str]] = Field(default=None, max_length=100, description="List of text strings to translate")
    target_lang: str = Field(..., max_length=10, description="Target ISO language code (e.g. 'hi', 'gu', 'ta', 'te', 'bn', 'en')")
    source_lang: Optional[str] = Field(default="en", max_length=10, description="Source language code (defaults to 'en')")


class TranslateResponse(BaseModel):
    """
    Response model for POST /api/translate.
    """
    translated_text: Optional[str] = None
    translated_texts: list[str] = Field(default_factory=list)
    source_lang: str = "en"
    target_lang: str
    cached: bool = False


# ─── Response Models ───

class AnalyzeResponse(BaseModel):
    """
    Response from POST /api/analyze.
    Evidence-dense: every threat-intel result is its own sourced item.
    """
    incident_id: str
    input_type: InputType
    message_preview: str = Field(description="First 200 chars of analyzed message")

    # Risk assessment
    risk: RiskAssessment

    # Evidence items — each rendered separately in the UI
    evidence: list[EvidenceItem] = Field(default_factory=list)

    # URL analysis details
    urls: list[URLSignal] = Field(default_factory=list)

    # Brand impersonation
    brands: list[BrandMatch] = Field(default_factory=list)

    # Individual threat-intel results (never collapsed)
    threat_intel: list[ThreatIntelResult] = Field(default_factory=list)

    # Gemini explanation
    explanation: Optional[GeminiExplanation] = None

    # Adaptive response
    response: Optional[AdaptiveResponse] = None

    # Laya fast decision output (Phase 3)
    laya: Optional[LayaResult] = None

    # Dedicated Scikit-Learn ML Classifier output (PRD Section 8)
    ml_classifier: Optional[MLClassifierResult] = None

    # ML Classifier output (PRD Section 8 & Section 33)
    classification: Optional[str] = None
    model_confidence: Optional[float] = None

    # Campaign (when available)
    fraud_dna: Optional[FraudDNA] = None

    # Metadata
    fraud_category: Optional[str] = None
    language: str = "en"
    response_language: str = "en"
    input_language: Optional[str] = None
    processing_time_ms: Optional[float] = None
    modules_executed: list[str] = Field(default_factory=list)
    modules_failed: list[str] = Field(default_factory=list)


class HealthResponse(BaseModel):
    """GET /api/health — system health check."""
    status: str = "ok"
    version: str = "0.1.0"
    modules: dict[str, bool] = Field(
        default_factory=dict,
        description="Module availability: name → is_available",
    )
    api_keys_configured: dict[str, bool] = Field(
        default_factory=dict,
        description="Which external APIs have keys configured",
    )


class FileUploadResponse(BaseModel):
    """Response model for uploaded screenshots/files."""
    status: str
    filename: str
    size_bytes: int
    content_type: str
    incident_id: Optional[str] = None
    extracted_text: Optional[str] = None


class OSINTResponse(BaseModel):
    """Response model for asynchronous OSINT enrichment."""
    status: str
    evidence: list[EvidenceItem] = Field(default_factory=list)
    raw: dict = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str
    detail: Optional[str] = None
    incident_id: Optional[str] = None
