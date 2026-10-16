"""
Unit and integration tests for Phase 3: Server-Sent Events (SSE) Real-Time Triage Streaming.
"""

import json
import pytest
from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def test_analyze_stream_emits_genuine_milestones():
    payload = {
        "message": "Dear customer, your SBI account is suspended due to KYC. Update here: https://secure-sbi-update.top/login. Send verification fee to sbi.manager@ybl",
        "urls": ["https://secure-sbi-update.top/login"],
        "language": "en",
        "input_type": "sms",
    }

    # Request SSE stream
    with client.stream("POST", "/api/analyze/stream", json=payload) as response:
        assert response.status_code == 200
        assert "text/event-stream" in response.headers.get("content-type", "")

        events_received = []
        final_verdict_chunk = None
        current_event = None

        for line in response.iter_lines():
            if not line:
                continue
            if line.startswith("event:"):
                current_event = line.replace("event:", "", 1).strip()
                events_received.append(current_event)
            elif line.startswith("data:"):
                data_str = line.replace("data:", "", 1).strip()
                if current_event == "final_verdict":
                    final_verdict_chunk = json.loads(data_str)

        assert "pipeline_started" in events_received
        assert "ioc_discovered" in events_received
        assert "final_verdict" in events_received

        assert final_verdict_chunk is not None
        assert "incident_id" in final_verdict_chunk
        assert "risk" in final_verdict_chunk
        assert final_verdict_chunk["risk"]["level"] in ("HIGH", "CRITICAL")
