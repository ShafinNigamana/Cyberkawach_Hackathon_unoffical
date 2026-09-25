"""
API request/response schemas — the contract between frontend and backend.

These are the HTTP-facing models. Internally, the pipeline uses IncidentEvidence.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from backend.models.evidence import (
    AdaptiveResponse,
    EvidenceItem,
    FraudDNA,
    GeminiExplanation,
    InputType,
    RiskAssessment,
    ThreatIntelResult,
    URLSignal,
    BrandMatch,
    UserState,
)


# ─── Request Models ───

class AnalyzeRequest(BaseModel):
    """
    POST /api/analyze — primary endpoint.
    Accepts text, URL, or both. Screenshot upload is a separate endpoint.
    """
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
        description="Additional URLs to analyze (auto-extracted from message too)",
    )
    language: str = Field(
        default="en",
        description="ISO language code or 'hi-en' for code-mixed",
    )


class UpdateUserStateRequest(BaseModel):
    """
    POST /api/incidents/{incident_id}/state — update user state for adaptive response.
    """
    user_state: UserState


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

    # Campaign (when available)
    fraud_dna: Optional[FraudDNA] = None

    # Metadata
    fraud_category: Optional[str] = None
    language: str = "en"
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


class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str
    detail: Optional[str] = None
    incident_id: Optional[str] = None
