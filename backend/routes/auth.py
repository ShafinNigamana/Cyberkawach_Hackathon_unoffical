"""
Authentication & Citizen Account Management Router.
Provides session tokens, PBKDF2 password hashing, and preference persistence via Neo4j / SQLite.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Request

from backend.config import get_settings
from backend.models.api import (
    AuthResponse,
    LoginRequest,
    RegisterRequest,
    UserPreferencesRequest,
    UserPreferencesResponse,
    UserResponse,
)
from backend.services.neo4j_repository import neo4j_repo
from backend.utils.rate_limiter import check_rate_limit
from backend.utils.security_logging import safe_error_message

logger = logging.getLogger("cyber_guardian.auth")
settings = get_settings()

auth_router = APIRouter(prefix="/api/auth", tags=["auth"])


def get_current_user_optional(raw_request: Request) -> Optional[dict]:
    """Extract authenticated citizen if valid session token provided; otherwise None."""
    auth_header = raw_request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif "X-Session-Token" in raw_request.headers:
        token = raw_request.headers["X-Session-Token"].strip()
    elif "session_token" in raw_request.cookies:
        token = raw_request.cookies["session_token"].strip()

    if not token:
        return None

    try:
        session_info = neo4j_repo.validate_session(token)
        if session_info:
            return session_info["user"]
    except Exception as e:
        logger.warning("Session validation error: %s", safe_error_message(e))
    return None


def get_current_user(raw_request: Request) -> dict:
    """Enforce authentication requirement for protected endpoints, raising 401."""
    user = get_current_user_optional(raw_request)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Please log in or provide a valid session token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


@auth_router.post("/register", response_model=AuthResponse)
async def register_citizen(request: RegisterRequest, raw_request: Request):
    """Register citizen account into datastore with PBKDF2 password hashing."""
    check_rate_limit(raw_request)

    existing = neo4j_repo.get_user_by_email(request.email)
    if existing:
        raise HTTPException(status_code=400, detail="An account with this email already exists.")

    user = neo4j_repo.create_user(
        email=request.email,
        password=request.password,
        phone=request.phone,
        display_name=request.display_name,
        preferred_language=request.preferred_language or "en",
    )
    if not user:
        raise HTTPException(status_code=500, detail="Failed to create citizen account.")

    raw_token, session_record = neo4j_repo.create_session(user["user_id"])
    neo4j_repo.log_audit_event("USER_REGISTERED", user["user_id"], "User", user["user_id"])

    return AuthResponse(
        status="success",
        session_token=raw_token,
        user=UserResponse(
            user_id=user["user_id"],
            email=user["email"],
            display_name=user.get("display_name") or user["email"].split("@")[0],
            phone_masked=user.get("phone_masked"),
            preferred_language=user.get("preferred_language", "en"),
            is_active=user.get("is_active", True),
            created_at=user.get("created_at", ""),
            last_login_at=user.get("last_login_at"),
        ),
    )


@auth_router.post("/login", response_model=AuthResponse)
async def login_citizen(request: LoginRequest, raw_request: Request):
    """Authenticate citizen and issue a hashed session token."""
    check_rate_limit(raw_request)

    user = neo4j_repo.authenticate_user(request.email, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    raw_token, session_record = neo4j_repo.create_session(user["user_id"])
    neo4j_repo.log_audit_event("LOGIN", user["user_id"], "Session", session_record.get("session_id", ""))

    return AuthResponse(
        status="success",
        session_token=raw_token,
        user=UserResponse(
            user_id=user["user_id"],
            email=user["email"],
            display_name=user.get("display_name") or user["email"].split("@")[0],
            phone_masked=user.get("phone_masked"),
            preferred_language=user.get("preferred_language", "en"),
            is_active=user.get("is_active", True),
            created_at=user.get("created_at", ""),
            last_login_at=user.get("last_login_at"),
        ),
    )


@auth_router.post("/logout")
async def logout_citizen(raw_request: Request):
    """Revoke citizen session token."""
    auth_header = raw_request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif "X-Session-Token" in raw_request.headers:
        token = raw_request.headers["X-Session-Token"].strip()
    elif "session_token" in raw_request.cookies:
        token = raw_request.cookies["session_token"].strip()

    if token:
        sess_info = neo4j_repo.validate_session(token)
        if sess_info:
            session_id = sess_info["session"]["session_id"]
            user_id = sess_info["user"]["user_id"]
            neo4j_repo.revoke_session(session_id)
            neo4j_repo.log_audit_event("LOGOUT", user_id, "Session", session_id)

    return {"status": "success", "message": "Logged out successfully."}


@auth_router.get("/me", response_model=UserResponse)
async def get_my_profile(raw_request: Request):
    """Get authenticated citizen profile."""
    user = get_current_user(raw_request)
    return UserResponse(
        user_id=user["user_id"],
        email=user["email"],
        display_name=user.get("display_name") or user["email"].split("@")[0],
        phone_masked=user.get("phone_masked"),
        preferred_language=user.get("preferred_language", "en"),
        is_active=user.get("is_active", True),
        created_at=user.get("created_at", ""),
        last_login_at=user.get("last_login_at"),
    )


@auth_router.get("/preferences", response_model=UserPreferencesResponse)
async def get_user_preferences(raw_request: Request):
    """Fetch user UI and accessibility preferences."""
    user = get_current_user(raw_request)
    prefs = neo4j_repo.get_user_preferences(user["user_id"])
    return UserPreferencesResponse(status="success", preferences=prefs)


@auth_router.put("/preferences", response_model=UserPreferencesResponse)
async def update_user_preferences(request: UserPreferencesRequest, raw_request: Request):
    """Persist updated user preferences."""
    user = get_current_user(raw_request)
    updated = neo4j_repo.update_user_preferences(
        user_id=user["user_id"],
        language=request.language,
        font_size=request.font_size,
        accessibility_mode=request.accessibility_mode,
        notification_preferences=request.notification_preferences,
        theme=request.theme,
    )
    return UserPreferencesResponse(status="success", preferences=updated)
