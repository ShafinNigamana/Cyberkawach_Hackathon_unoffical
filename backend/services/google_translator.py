"""
Google Cloud Translation API (v2 Basic) Integration Service.

Provides secure, cached, resilient translation capabilities for global multilingual triage.
API key is strictly read from environment (GOOGLE_TRANSLATE_API_KEY) and never exposed to the client.
"""

from __future__ import annotations

import html
import logging
from collections import OrderedDict
from threading import Lock
from typing import Optional

import httpx

from backend.config import get_settings
from backend.utils.security_logging import safe_error_message

logger = logging.getLogger("cyber_guardian.translator")

_GOOGLE_TRANSLATE_URL = "https://translation.googleapis.com/language/translate/v2"


class TranslationMemoryCache:
    """Thread-safe bounded in-memory LRU cache for translations."""

    def __init__(self, max_capacity: int = 5000):
        self.max_capacity = max_capacity
        self._cache: OrderedDict[tuple[str, str, str], str] = OrderedDict()
        self._lock = Lock()

    def get(self, source_lang: str, target_lang: str, text: str) -> Optional[str]:
        key = (source_lang.lower(), target_lang.lower(), text)
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
            return None

    def set(self, source_lang: str, target_lang: str, text: str, translated: str) -> None:
        key = (source_lang.lower(), target_lang.lower(), text)
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = translated
            if len(self._cache) > self.max_capacity:
                self._cache.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


# Global in-memory translation cache instance
_translation_cache = TranslationMemoryCache()


async def translate_text_async(
    text: str,
    target_lang: str,
    source_lang: str = "en",
) -> str:
    """
    Translate a single text string asynchronously using Google Cloud Translation API (v2).
    Falls back gracefully to original text if API key is not configured, API errors, or network fails.
    """
    if not text or not text.strip():
        return text

    # Normalization & short-circuit if source == target
    s_lang = (source_lang or "en").lower().split("-")[0]
    t_lang = (target_lang or "en").lower().split("-")[0]

    if s_lang == t_lang:
        return text

    # Check cache first
    cached_val = _translation_cache.get(s_lang, t_lang, text)
    if cached_val is not None:
        return cached_val

    settings = get_settings()
    api_key = settings.google_translate_api_key

    if not api_key or not api_key.strip():
        logger.debug("Google Translate API key not set; falling back to original text.")
        return text

    payload = {
        "q": text,
        "target": t_lang,
        "source": s_lang,
        "format": "text",
    }

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(
                _GOOGLE_TRANSLATE_URL,
                params={"key": api_key},
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()

            translations = data.get("data", {}).get("translations", [])
            if translations and "translatedText" in translations[0]:
                raw_translated = translations[0]["translatedText"]
                # Google Translate v2 may HTML-entity-encode special characters
                translated = html.unescape(raw_translated)
                _translation_cache.set(s_lang, t_lang, text, translated)
                return translated

    except httpx.TimeoutException:
        logger.warning(f"Google Translate API timeout when translating to {t_lang}.")
    except Exception as e:
        logger.warning(f"Google Translate error: {safe_error_message(e)}")

    # Fallback to original text on any failure
    return text


async def translate_batch_async(
    texts: list[str],
    target_lang: str,
    source_lang: str = "en",
) -> list[str]:
    """
    Translate multiple texts in a single batch request via Google Cloud Translation API.
    Caches each item and only queries un-cached items.
    """
    if not texts:
        return []

    s_lang = (source_lang or "en").lower().split("-")[0]
    t_lang = (target_lang or "en").lower().split("-")[0]

    if s_lang == t_lang:
        return list(texts)

    results: list[Optional[str]] = [None] * len(texts)
    uncached_indices: list[int] = []
    uncached_texts: list[str] = []

    # Check cache for each text
    for idx, text in enumerate(texts):
        if not text or not text.strip():
            results[idx] = text
            continue

        cached_val = _translation_cache.get(s_lang, t_lang, text)
        if cached_val is not None:
            results[idx] = cached_val
        else:
            uncached_indices.append(idx)
            uncached_texts.append(text)

    # If all items were cached, return immediately
    if not uncached_texts:
        return [r if r is not None else "" for r in results]

    settings = get_settings()
    api_key = settings.google_translate_api_key

    if not api_key or not api_key.strip():
        # Fallback all uncached to original text
        for idx, text in zip(uncached_indices, uncached_texts):
            results[idx] = text
        return [r if r is not None else "" for r in results]

    payload = {
        "q": uncached_texts,
        "target": t_lang,
        "source": s_lang,
        "format": "text",
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                _GOOGLE_TRANSLATE_URL,
                params={"key": api_key},
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()

            translations = data.get("data", {}).get("translations", [])
            for i, item in enumerate(translations):
                idx = uncached_indices[i]
                raw_translated = item.get("translatedText", uncached_texts[i])
                translated = html.unescape(raw_translated)
                _translation_cache.set(s_lang, t_lang, uncached_texts[i], translated)
                results[idx] = translated

    except Exception as e:
        logger.warning(f"Google Translate batch error: {safe_error_message(e)}")
        # Fill remaining with original text
        for idx, text in zip(uncached_indices, uncached_texts):
            if results[idx] is None:
                results[idx] = text

    return [r if r is not None else "" for r in results]


def translate_text(
    text: str,
    target_lang: str,
    source_lang: str = "en",
) -> str:
    """
    Synchronous wrapper for translate_text_async using httpx.Client.
    """
    if not text or not text.strip():
        return text

    s_lang = (source_lang or "en").lower().split("-")[0]
    t_lang = (target_lang or "en").lower().split("-")[0]

    if s_lang == t_lang:
        return text

    cached_val = _translation_cache.get(s_lang, t_lang, text)
    if cached_val is not None:
        return cached_val

    settings = get_settings()
    api_key = settings.google_translate_api_key

    if not api_key or not api_key.strip():
        return text

    payload = {
        "q": text,
        "target": t_lang,
        "source": s_lang,
        "format": "text",
    }

    try:
        with httpx.Client(timeout=8.0) as client:
            resp = client.post(
                _GOOGLE_TRANSLATE_URL,
                params={"key": api_key},
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()

            translations = data.get("data", {}).get("translations", [])
            if translations and "translatedText" in translations[0]:
                raw_translated = translations[0]["translatedText"]
                translated = html.unescape(raw_translated)
                _translation_cache.set(s_lang, t_lang, text, translated)
                return translated
    except Exception as e:
        logger.warning(f"Google Translate sync error: {safe_error_message(e)}")

    return text
