"""
Unit and integration tests for Asynchronous Scan Job Queues and status polling.
"""

from __future__ import annotations

import io
import time
import pytest
from starlette.testclient import TestClient

from backend.main import app
from backend.services.scan_queue import scan_job_manager


@pytest.fixture
def test_client():
    return TestClient(app)


def test_async_file_scan_and_polling(test_client):
    headers = {"Authorization": "Bearer analyst_test_token"}
    file_content = b"Mock benign test file content for asynchronous scan verification."
    files = {"file": ("async_test.txt", io.BytesIO(file_content), "text/plain")}

    # 1. Enqueue scan with async_mode=true
    response = test_client.post("/api/scan/file?async_mode=true", files=files, headers=headers)
    assert response.status_code == 202

    job_data = response.json()
    assert "job_id" in job_data
    assert job_data["status"] in ("queued", "processing", "completed")
    job_id = job_data["job_id"]

    # 2. Poll until completed (timeout 5s)
    max_wait = 5.0
    start = time.time()
    completed = False
    final_data = None

    while time.time() - start < max_wait:
        time.sleep(0.2)
        poll_resp = test_client.get(f"/api/scan/jobs/{job_id}", headers=headers)
        assert poll_resp.status_code == 200
        poll_data = poll_resp.json()
        if poll_data["status"] == "completed":
            completed = True
            final_data = poll_data
            break

    assert completed is True
    assert final_data["progress_percent"] == 100
    assert final_data["stage"] == "completed"
    assert final_data["result"] is not None
    assert final_data["result"]["state"] == "CLEAN"


def test_job_not_found(test_client):
    response = test_client.get("/api/scan/jobs/JOB-NONEXISTENT")
    assert response.status_code == 404
