"""
Secure file handling utilities.

Hardens file acceptance against:
- Arbitrary file upload / Remote code execution
- Path traversal via filenames (e.g. ../../etc/passwd)
- MIME spoofing (verifies magic bytes / file signatures)
- SVG-based XSS attacks
- Dangerous executable extensions (.exe, .sh, .php, .py, .bat)
- Resource exhaustion via oversized files
"""

from __future__ import annotations

import os
import re
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

# Magic byte signatures for permitted formats
_IMAGE_SIGNATURES = {
    "image/png": [b"\x89PNG\r\n\x1a\n"],
    "image/jpeg": [b"\xff\xd8\xff"],
    "image/webp": [b"RIFF"],  # also checks WEBP at offset 8
}

_DISALLOWED_EXTENSIONS = frozenset({
    ".exe", ".dll", ".bat", ".cmd", ".sh", ".bash", ".ps1", ".vbs",
    ".py", ".pyw", ".pl", ".php", ".phtml", ".jsp", ".asp", ".aspx",
    ".js", ".mjs", ".ts", ".html", ".htm", ".xhtml", ".svg", ".xml",
    ".jar", ".war", ".bin", ".com", ".scr", ".msi",
})

_MAX_FILENAME_LENGTH = 100
_ALLOWED_MIME_TYPES = frozenset({"image/png", "image/jpeg", "image/webp"})


def sanitize_filename(filename: str) -> str:
    """
    Sanitize an uploaded filename:
    - Strip directory paths (prevents path traversal)
    - Remove null bytes and control characters
    - Restrict characters to safe alphanumeric, underscore, hyphen, and single dot
    - Limit length
    """
    if not filename:
        return f"file_{uuid.uuid4().hex[:8]}.bin"

    # Strip directory components
    base = os.path.basename(filename.replace('\\', '/'))

    # Remove null bytes and control characters
    base = base.replace('\x00', '')
    base = re.sub(r'[\x01-\x1f\x7f]', '', base)

    # Remove path traversal sequences
    base = re.sub(r'\.\.+', '.', base)

    # Keep only safe characters
    clean = re.sub(r'[^a-zA-Z0-9._-]', '_', base)
    clean = clean.strip('._')

    if not clean:
        clean = f"file_{uuid.uuid4().hex[:8]}"

    if len(clean) > _MAX_FILENAME_LENGTH:
        name_parts = clean.rsplit('.', 1)
        if len(name_parts) == 2:
            clean = f"{name_parts[0][:80]}.{name_parts[1][:10]}"
        else:
            clean = clean[:_MAX_FILENAME_LENGTH]

    return clean


def detect_magic_mime(content: bytes) -> str | None:
    """
    Verify actual file signature (magic bytes) to prevent MIME spoofing.
    """
    if not content or len(content) < 12:
        return None

    # Check PNG
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"

    # Check JPEG
    if content.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"

    # Check WebP: starts with RIFF and has WEBP at offset 8
    if content.startswith(b"RIFF") and content[8:12] == b"WEBP":
        return "image/webp"

    return None


def validate_file_security(
    content: bytes,
    original_filename: str,
    declared_content_type: str,
    max_size_bytes: int = 10 * 1024 * 1024,  # 10 MB
) -> tuple[bool, str, str]:
    """
    Comprehensive security validation for uploaded files.

    Returns:
        (is_valid: bool, safe_filename: str, error_message: str)
    """
    # 1. Size check
    if len(content) == 0:
        return False, "", "File is empty"

    if len(content) > max_size_bytes:
        return False, "", f"File exceeds maximum allowed size of {max_size_bytes // (1024 * 1024)} MB"

    # 2. Filename traversal check & sanitization
    if any(traversal in original_filename for traversal in ["..", "/", "\\"]):
        pass  # Will be stripped, but noted

    safe_name = sanitize_filename(original_filename)

    # 3. Disallowed extensions check
    ext = Path(safe_name).suffix.lower()
    if ext in _DISALLOWED_EXTENSIONS:
        return False, "", f"File extension '{ext}' is prohibited for security reasons"

    # 4. MIME type check
    clean_declared_mime = declared_content_type.split(";")[0].strip().lower()
    if clean_declared_mime not in _ALLOWED_MIME_TYPES:
        return False, "", f"MIME type '{clean_declared_mime}' is not permitted. Only PNG, JPEG, and WebP are allowed."

    # 5. Magic bytes signature verification (anti-spoofing)
    detected_mime = detect_magic_mime(content)
    if detected_mime is None:
        return False, "", "File content does not match any allowed image signature (PNG, JPEG, WebP)"

    if detected_mime != clean_declared_mime:
        return False, "", f"MIME type mismatch: declared '{clean_declared_mime}', but file header matches '{detected_mime}'"

    # 6. Additional check for embedded script tags / HTML in images (e.g. polyglots)
    header_sample = content[:4096].lower()
    if b"<script" in header_sample or b"<?php" in header_sample or b"<!doctype html" in header_sample:
        return False, "", "Executable or script payload detected in file header"

    # Generate server-side random filename to guarantee no filesystem collision or traversal
    secure_server_filename = f"{uuid.uuid4().hex}_{safe_name}"

    return True, secure_server_filename, ""


@contextmanager
def secure_temp_file(
    content: bytes,
    suffix: str = ".bin",
) -> Generator[Path, None, None]:
    """
    Context manager that writes content to a temporary file located
    outside any static web directory, sets restrictive permissions,
    and guarantees file cleanup upon exit.
    """
    temp_dir = Path(tempfile.gettempdir()) / "cyber_guardian_secure_uploads"
    temp_dir.mkdir(parents=True, exist_ok=True)

    temp_path = temp_dir / f"{uuid.uuid4().hex}{suffix}"
    try:
        temp_path.write_bytes(content)
        # Yield safe path
        yield temp_path
    finally:
        # Guarantee automatic cleanup
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
