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
    MessageContext,
    RiskAssessment,
    SenderContext,
    ThreatIntelResult,
    URLSignal,
    UserState,
)


# ─── Auth Request & Response Models ───

class RegisterRequest(BaseModel):
    """POST /api/auth/register — citizen registration."""
    model_config = ConfigDict(extra="forbid")

    email: str = Field(..., min_length=3, max_length=254, description="User email address")
    password: str = Field(..., min_length=8, max_length=128, description="User password (min 8 chars)")
    phone: Optional[str] = Field(default=None, max_length=20, description="Optional phone number")
    display_name: Optional[str] = Field(default=None, max_length=100, description="Optional display name")
    preferred_language: Optional[str] = Field(default="en", max_length=10, description="Preferred language code")


class LoginRequest(BaseModel):
    """POST /api/auth/login — authenticate citizen."""
    model_config = ConfigDict(extra="forbid")

    email: str = Field(..., min_length=3, max_length=254, description="User email address")
    password: str = Field(..., min_length=1, max_length=128, description="User password")


class UserResponse(BaseModel):
    """Citizen user profile (no secrets or password hashes)."""
    user_id: str
    email: str
    display_name: str
    phone_masked: Optional[str] = None
    preferred_language: str = "en"
    is_active: bool = True
    created_at: str
    last_login_at: Optional[str] = None


class AuthResponse(BaseModel):
    """Authentication token and user details response."""
    status: str = "success"
    session_token: str
    user: UserResponse


class UserPreferencesRequest(BaseModel):
    """PUT /api/auth/preferences — update user accessibility & language preferences."""
    model_config = ConfigDict(extra="forbid")

    language: Optional[str] = Field(default=None, max_length=10)
    font_size: Optional[str] = Field(default=None, max_length=20)
    accessibility_mode: Optional[bool] = None
    notification_preferences: Optional[str] = Field(default=None, max_length=100)
    theme: Optional[str] = Field(default=None, max_length=20)


class UserPreferencesResponse(BaseModel):
    """Citizen user preferences response."""
    status: str = "success"
    preferences: dict = Field(default_factory=dict)


# ─── Incident History & Graph Response Models ───

class IncidentHistoryItem(BaseModel):
    """Compact incident summary for 'My Checks' list view."""
    incident_id: str
    created_at: str
    input_type: str
    title: str
    message_preview: str
    risk_level: str
    risk_score: float
    fraud_category: str
    current_user_state: str = "received"
    campaign_id: Optional[str] = None


class IncidentHistoryResponse(BaseModel):
    """GET /api/incidents — list of citizen's past incidents."""
    incidents: list[IncidentHistoryItem] = Field(default_factory=list)
    total: int = 0


class GraphNode(BaseModel):
    """Graph node for frontend relationship visualization."""
    id: str
    label: str
    type: Optional[str] = None
    title: Optional[str] = None
    properties: dict = Field(default_factory=dict)


class GraphEdge(BaseModel):
    """Graph relationship edge for frontend visualization."""
    source: str
    target: str
    relationship: str
    properties: dict = Field(default_factory=dict)


class IncidentGraphResponse(BaseModel):
    """GET /api/incidents/{incident_id}/graph — full contextual relationship graph."""
    incident_id: str
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    node_count: int = 0
    edge_count: int = 0
    summary: Optional[str] = None


# ─── Primary Analysis Request Models ───

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
    sender: Optional[SenderContext] = Field(
        default=None,
        description="Optional sender context (phone, email, claimed organization, channel)",
    )
    message_context: Optional[MessageContext] = Field(
        default=None,
        description="Optional message metadata (channel, timestamp, reply-to)",
    )


class UpdateUserStateRequest(BaseModel):
    """
    POST /api/incidents/{incident_id}/state — update user state for adaptive response.
    Rejects unknown fields.
    """
    model_config = ConfigDict(extra="forbid")

    user_state: UserState
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
