"""
Unit tests for Screenshot OCR extraction and upload integration.
"""

from io import BytesIO
import pytest
from PIL import Image
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.ocr import extract_text_from_image
from backend.utils.rate_limiter import get_rate_limiter


@pytest.fixture(autouse=True)
def reset_rate_limit():
    get_rate_limiter().reset()
    yield
    get_rate_limiter().reset()


@pytest.fixture
def client():
    return TestClient(app)


def create_test_image(text_color="red") -> bytes:
    """Create a minimal valid PNG image in memory."""
    img = Image.new("RGB", (100, 40), color="white")
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_extract_text_empty_bytes():
    assert extract_text_from_image(b"") == ""


def test_extract_text_corrupt_bytes():
    assert extract_text_from_image(b"not an image file content") == ""


def test_extract_text_valid_image():
    img_bytes = create_test_image()
    # Should not crash, returns string (empty or extracted)
    result = extract_text_from_image(img_bytes, "test.png")
    assert isinstance(result, str)


def test_upload_screenshot_endpoint_with_ocr(client):
    img_bytes = create_test_image()
    files = {"file": ("screenshot.png", img_bytes, "image/png")}

    resp = client.post("/api/upload/screenshot", files=files)
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "ok"
    assert "screenshot" in data["filename"]
    assert "extracted_text" in data
