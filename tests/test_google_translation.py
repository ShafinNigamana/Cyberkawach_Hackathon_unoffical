"""
Tests for Google Cloud Translation API (v2 Basic) Integration.
Validates service resilience, in-memory caching, API endpoints, and fallback behavior.
"""

from __future__ import annotations

import asyncio
import pytest
from starlette.testclient import TestClient

from backend.main import app
from backend.services.google_translator import (
    _translation_cache,
    translate_batch_async,
    translate_text,
    translate_text_async,
)


@pytest.fixture(autouse=True)
def clean_cache():
    _translation_cache.clear()
    yield
    _translation_cache.clear()


def test_translate_same_language_returns_original():
    result = asyncio.run(translate_text_async("Hello world", target_lang="en", source_lang="en"))
    assert result == "Hello world"


def test_translate_empty_string_returns_original():
    assert asyncio.run(translate_text_async("", target_lang="hi")) == ""
    assert asyncio.run(translate_text_async("   ", target_lang="hi")) == "   "


def test_translation_caching():
    _translation_cache.set("en", "hi", "Security Alert", "सुरक्षा चेतावनी")
    
    # Should resolve directly from cache without hitting external API
    result = asyncio.run(translate_text_async("Security Alert", target_lang="hi", source_lang="en"))
    assert result == "सुरक्षा चेतावनी"


def test_batch_translation_cached_and_uncached():
    _translation_cache.set("en", "gu", "Police", "પોલીસ")

    texts = ["Police", "Bank"]
    # With Police in cache, it will use the cached value
    results = asyncio.run(translate_batch_async(texts, target_lang="gu", source_lang="en"))
    assert len(results) == 2
    assert results[0] == "પોલીસ"


def test_translate_text_sync():
    _translation_cache.set("en", "ta", "Urgent", "அவசரம்")
    result = translate_text("Urgent", target_lang="ta", source_lang="en")
    assert result == "அவசரம்"


def test_translate_api_endpoint():
    client = TestClient(app)
    
    _translation_cache.set("en", "hi", "Verify Account", "खाता सत्यापित करें")
    
    response = client.post(
        "/api/translate",
        json={
            "text": "Verify Account",
            "target_lang": "hi",
            "source_lang": "en",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["target_lang"] == "hi"
    assert data["translated_text"] == "खाता सत्यापित करें"


def test_translate_api_v1_endpoint_batch():
    client = TestClient(app)
    
    _translation_cache.set("en", "bn", "Warning", "সতর্কতা")
    _translation_cache.set("en", "bn", "Danger", "বিপদ")
    
    response = client.post(
        "/api/v1/translate",
        json={
            "texts": ["Warning", "Danger"],
            "target_lang": "bn",
            "source_lang": "en",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["target_lang"] == "bn"
    assert data["translated_texts"] == ["সতর্কতা", "বিপদ"]


def test_translate_api_validation_error():
    client = TestClient(app)
    
    # Missing required target_lang
    response = client.post(
        "/api/translate",
        json={"text": "Hello"},
    )
    assert response.status_code == 422
