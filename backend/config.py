"""
Application configuration — loads from environment with sane defaults.
Every API key is optional; modules degrade gracefully when keys are missing.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    All settings from .env. Every external API key defaults to None —
    modules check availability before calling.
    """

    # ─── Gemini ───
    gemini_api_key: Optional[str] = None
    gemini_model: str = "gemini-2.0-flash-lite"

    # ─── Threat Intel APIs (P0) ───
    safe_browsing_api_key: Optional[str] = None
    phishtank_api_key: Optional[str] = None

    # ─── Threat Intel APIs (P2 optional) ───
    abuseipdb_api_key: Optional[str] = None
    # URLhaus: no key needed, wired in Phase 4 if time allows

    # ─── Application ───
    app_env: str = "development"
    app_port: int = 8000
    app_host: str = "0.0.0.0"
    log_level: str = "INFO"

    # ─── Rate Limiting ───
    rate_limit_per_minute: int = 30

    # ─── File Upload ───
    max_upload_size_mb: int = 10
    allowed_upload_types: str = "image/png,image/jpeg,image/webp"

    # ─── Security ───
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    max_message_length: int = 10000
    max_urls_per_message: int = 20

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def allowed_upload_type_list(self) -> list[str]:
        return [t.strip() for t in self.allowed_upload_types.split(",") if t.strip()]

    def api_availability(self) -> dict[str, bool]:
        """Check which external APIs have keys configured."""
        return {
            "gemini": self.gemini_api_key is not None,
            # P0 threat-intel
            "safe_browsing": self.safe_browsing_api_key is not None,
            "phishtank": self.phishtank_api_key is not None,
            # P2 optional threat-intel
            "abuseipdb": self.abuseipdb_api_key is not None,
            "urlhaus": True,  # No key needed, but P2 optional
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()
