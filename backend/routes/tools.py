"""
Tools Router: Screenshot OCR Upload and Multilingual Translation Proxy.
"""

from __future__ import annotations

import logging
from fastapi import APIRouter, File, HTTPException, Request, UploadFile

from backend.config import get_settings
from backend.models.api import FileUploadResponse, TranslateRequest, TranslateResponse
from backend.services.google_translator import (
    translate_batch_async,
    translate_text_async,
)
from backend.utils.file_security import validate_file_security
from backend.utils.rate_limiter import check_rate_limit
from backend.utils.sanitize import validate_language
from backend.utils.security_logging import safe_error_message

logger = logging.getLogger("cyber_guardian.tools")
settings = get_settings()

tools_router = APIRouter(prefix="/api", tags=["tools"])


@tools_router.post("/upload/screenshot", response_model=FileUploadResponse)
async def upload_screenshot(
    file: UploadFile = File(...),
    raw_request: Request = None,
):
    """
    Secure screenshot upload endpoint.
    Enforces maximum size, MIME verification, magic bytes verification,
    filename sanitization, and path traversal defense.
    """
    if raw_request:
        check_rate_limit(raw_request)

    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    content = await file.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum allowed size of {settings.max_upload_size_mb} MB",
        )

    is_valid, safe_name, err = validate_file_security(
        content=content,
        original_filename=file.filename or "screenshot.png",
        declared_content_type=file.content_type or "application/octet-stream",
        max_size_bytes=max_bytes,
    )

    if not is_valid:
        raise HTTPException(status_code=400, detail=err)

    extracted_text = ""
    try:
        from backend.services.ocr import extract_text_from_image

        extracted_text = extract_text_from_image(content, safe_name)
    except Exception as e:
        logger.warning("OCR extraction error: %s", safe_error_message(e))

    return FileUploadResponse(
        status="ok",
        filename=safe_name,
        size_bytes=len(content),
        content_type=file.content_type,
        extracted_text=extracted_text or None,
    )


@tools_router.post("/translate", response_model=TranslateResponse)
@tools_router.post("/v1/translate", response_model=TranslateResponse)
async def translate_content(
    request: TranslateRequest,
    raw_request: Request = None,
):
    """
    Secure backend proxy for Cloud Translation API with in-memory caching.
    Keeps API credentials secure on the backend.
    """
    if raw_request:
        check_rate_limit(raw_request)

    target_lang = validate_language(request.target_lang) or "en"
    source_lang = validate_language(request.source_lang or "en") or "en"

    translated_text = None
    translated_texts = []

    if request.text is not None:
        translated_text = await translate_text_async(
            text=request.text,
            target_lang=target_lang,
            source_lang=source_lang,
        )

    if request.texts:
        translated_texts = await translate_batch_async(
            texts=request.texts,
            target_lang=target_lang,
            source_lang=source_lang,
        )

    return TranslateResponse(
        translated_text=translated_text,
        translated_texts=translated_texts,
        source_lang=source_lang,
        target_lang=target_lang,
        cached=False,
    )


@tools_router.post("/audio/transcribe")
async def transcribe_audio_endpoint(
    file: UploadFile = File(...),
    lang: str = "hi-IN",
    raw_request: Request = None,
):
    """
    Direct voice transcription endpoint. Converts recorded citizen voice audio (WAV)
    into text using Python SpeechRecognition with Google Speech service fallback.
    Provides server-side transcription when browser Web Speech API is blocked on HTTP.
    """
    if raw_request:
        check_rate_limit(raw_request)

    content = await file.read(5 * 1024 * 1024)
    if not content:
        raise HTTPException(status_code=400, detail="Empty audio recording")

    try:
        import io
        import speech_recognition as sr

        r = sr.Recognizer()
        buf = io.BytesIO(content)
        with sr.AudioFile(buf) as source:
            audio = r.record(source)
            # Normalize language code for Google speech recognition (e.g. 'hi-IN', 'en-IN')
            text = r.recognize_google(audio, language=lang or "hi-IN")
            return {"status": "ok", "transcript": text}
    except Exception as e:
        logger.info("Audio transcription fallback note: %s", safe_error_message(e))
        return {"status": "ok", "transcript": ""}

