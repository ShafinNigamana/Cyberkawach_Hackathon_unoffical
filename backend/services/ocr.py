"""
OCR and Screenshot Ingestion Service.

Extracts text, phone numbers, and URLs from uploaded scam screenshots
via local OCR engine (pytesseract if present) or multimodal Gemini Flash Vision.
"""

from __future__ import annotations

import base64
import logging
from io import BytesIO
from typing import Optional

from PIL import Image

from backend.config import get_settings
from backend.utils.security_logging import safe_error_message

logger = logging.getLogger(__name__)


def extract_text_from_image(image_bytes: bytes, filename: str = "screenshot.png") -> str:
    """
    Extract text content from image bytes.
    Tries:
    1. Local pytesseract if installed and binary available.
    2. Gemini Flash Vision API if API key is configured.
    3. Graceful fallback returning empty string.
    """
    if not image_bytes:
        return ""

    # Verify image integrity with PIL
    try:
        image = Image.open(BytesIO(image_bytes))
        image.verify()
        # Reopen because verify() consumes file
        image = Image.open(BytesIO(image_bytes))
    except Exception as e:
        logger.warning(f"Invalid image format for OCR: {safe_error_message(e)}")
        return ""

    # Strategy 1: Local pytesseract (if installed)
    try:
        import pytesseract
        text = pytesseract.image_to_string(image)
        if text and text.strip():
            logger.info("OCR successfully extracted text using local pytesseract")
            return text.strip()
    except Exception:
        # pytesseract not installed or tesseract binary not found on PATH
        pass

    # Strategy 2: Gemini Flash Vision API (if configured)
    settings = get_settings()
    if settings.gemini_api_key:
        try:
            import httpx

            # Convert to base64
            b64_image = base64.b64encode(image_bytes).decode("utf-8")
            mime_type = "image/png"
            if filename.lower().endswith((".jpg", ".jpeg")):
                mime_type = "image/jpeg"
            elif filename.lower().endswith(".webp"):
                mime_type = "image/webp"

            url = (
                f"https://generativelanguage.googleapis.com/v1beta/models/"
                f"{settings.gemini_model}:generateContent"
            )
            body = {
                "contents": [
                    {
                        "parts": [
                            {"text": "Extract and transcribe all text from this screenshot verbatim. Do not add explanations or formatting. Only output the exact text visible in the image."},
                            {
                                "inline_data": {
                                    "mime_type": mime_type,
                                    "data": b64_image,
                                }
                            },
                        ]
                    }
                ],
                "generationConfig": {
                    "temperature": 0.0,
                    "maxOutputTokens": 1024,
                },
            }

            with httpx.Client(timeout=10.0) as client:
                resp = client.post(url, params={"key": settings.gemini_api_key}, json=body)
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        extracted = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                        if extracted and extracted.strip():
                            logger.info("OCR successfully extracted text using Gemini Vision")
                            return extracted.strip()
        except Exception as e:
            logger.warning(f"Gemini Vision OCR error: {safe_error_message(e)}")

    # Strategy 3: Graceful fallback when no OCR engines are active
    return ""
