"""
Phase 10: 20-Case Accuracy Regression Matrix Test Suite.
Validates zero false positives on legitimate communications, 100% detection on high-confidence scams,
epistemic modesty on ambiguous texts, and proportional Golden Hour response on compromised states.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "accuracy_matrix_cases.json"

def load_matrix_cases():
    with open(FIXTURE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

CASES = load_matrix_cases()


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_accuracy_matrix_individual_case(case):
    """
    Execute each case through the full FastAPI pipeline and verify:
    1. Risk level is within expected range
    2. Score bounds are satisfied (max_score for benign, min_score for malicious)
    3. Sufficiency matches epistemic expectation
    4. Adaptive response contains required advisory text
    """
    user_state = case.get("user_state", "received")
    payload = {
        "message": case["message"],
        "user_state": user_state,
    }

    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200, f"API error on {case['id']}: {response.text}"
    data = response.json()

    risk_level = data["risk"]["level"]
    risk_score = data["risk"]["score"]
    sufficiency = data["risk"]["evidence_sufficiency"]

    # 1. Expected risk levels
    if "expected_risk" in case:
        assert risk_level in case["expected_risk"], (
            f"Case {case['id']} expected risk in {case['expected_risk']}, got {risk_level} (score: {risk_score:.3f})"
        )

    # 2. Score bounds
    if "max_score" in case:
        assert risk_score <= case["max_score"] + 0.05, (
            f"Case {case['id']} score {risk_score:.3f} exceeded max_score {case['max_score']}"
        )
    if "min_score" in case:
        assert risk_score >= case["min_score"] - 0.05, (
            f"Case {case['id']} score {risk_score:.3f} below min_score {case['min_score']}"
        )

    # 3. Expected sufficiency
    if "expected_sufficiency" in case:
        assert sufficiency in case["expected_sufficiency"], (
            f"Case {case['id']} expected sufficiency in {case['expected_sufficiency']}, got {sufficiency}"
        )

    # 4. Response check
    if "expected_urgency" in case:
        assert data["response"]["urgency"].lower() == case["expected_urgency"].lower(), (
            f"Case {case['id']} expected urgency {case['expected_urgency']}, got {data['response']['urgency']}"
        )

    if "must_contain_response" in case:
        all_actions = " ".join(
            data["response"].get("immediate_actions", [])
            + data["response"].get("recovery_steps", [])
            + data["response"].get("reporting_info", [])
        )
        for kw in case["must_contain_response"]:
            assert kw.lower() in all_actions.lower(), (
                f"Case {case['id']} response missing expected keyword '{kw}'. Immediate actions: {data['response'].get('immediate_actions')}"
            )


def test_zero_false_positives_on_legitimate_traffic():
    """
    Strict safety invariant: Legitimate communications (banking, courier, utilities, promotion)
    MUST NEVER be classified as HIGH or CRITICAL risk.
    """
    legit_cases = [c for c in CASES if c.get("is_legitimate")]
    assert len(legit_cases) >= 5, "Expected at least 5 legitimate test cases"

    for case in legit_cases:
        res = client.post("/api/analyze", json={"message": case["message"]})
        assert res.status_code == 200
        data = res.json()
        assert data["risk"]["level"] in ["LOW", "UNKNOWN"], (
            f"FALSE POSITIVE on legitimate case '{case['name']}': got {data['risk']['level']} (score: {data['risk']['score']:.3f})"
        )
        assert data["risk"]["score"] < 0.30, (
            f"FALSE POSITIVE score on legitimate case '{case['name']}': score {data['risk']['score']:.3f} >= 0.30 (threshold for MEDIUM)"
        )


def test_zero_false_negatives_on_critical_phishing():
    """
    Strict safety invariant: Clear phishing attacks with fake domains or IP literals
    MUST NEVER be classified as LOW or UNKNOWN.
    """
    phishing_cases = [c for c in CASES if c.get("is_phishing")]
    assert len(phishing_cases) >= 10, "Expected at least 10 phishing test cases"

    for case in phishing_cases:
        res = client.post("/api/analyze", json={"message": case["message"]})
        assert res.status_code == 200
        data = res.json()
        assert data["risk"]["level"] in ["MEDIUM", "HIGH", "CRITICAL"], (
            f"FALSE NEGATIVE on phishing case '{case['name']}': classified as {data['risk']['level']}"
        )
        assert data["risk"]["score"] >= 0.30, (
            f"FALSE NEGATIVE low score on phishing case '{case['name']}': score {data['risk']['score']:.3f} < 0.30 (threshold for MEDIUM)"
        )


def test_structured_attack_path_traceability_on_phishing():
    """
    Attack path traceability invariant:
    Phishing cases must generate causal steps with step numbers and stages.
    """
    phishing_cases = [c for c in CASES if c.get("is_phishing")]
    for case in phishing_cases:
        res = client.post("/api/analyze", json={"message": case["message"]})
        data = res.json()
        expl = data.get("explanation")
        assert expl is not None, f"No explanation for {case['id']}"

        attack_path = expl.get("attack_path", [])
        structured = expl.get("structured_attack_path", [])
        assert len(attack_path) > 0 or len(structured) > 0, (
            f"Phishing case {case['id']} did not generate any attack path steps"
        )

        if structured:
            stages = [s["causal_stage"] for s in structured]
            assert any(st in ["lure", "redirection", "exploitation", "monetization"] for st in stages), (
                f"Phishing case {case['id']} missing valid causal stage: {stages}"
            )


def test_golden_hour_protocol_enforced_on_paid_state():
    """
    State machine invariant:
    UserState.PAID must trigger immediate 1930 / Golden Hour protocol and CRITICAL urgency.
    """
    compromised_cases = [c for c in CASES if c.get("is_compromised")]
    for case in compromised_cases:
        res = client.post("/api/analyze", json={
            "message": case["message"],
            "user_state": "paid",
        })
        data = res.json()
        resp = data["response"]
        assert resp["urgency"].lower() == "critical", f"Expected CRITICAL urgency, got {resp['urgency']}"

        combined = " ".join(
            resp.get("immediate_actions", [])
            + resp.get("recovery_steps", [])
            + resp.get("reporting_info", [])
        )
        assert "1930" in combined, "Golden Hour 1930 helpline must be present in response"
        assert any(term in combined.lower() for term in ["freeze", "golden hour", "block", "dispute"]), (
            "Fund freeze / dispute action must be present in response"
        )


def test_har_ghar_tiranga_official_broadcast_scored_near_zero():
    """
    False-positive regression test:
    The official Har Ghar Tiranga campaign SMS with statutory advisory from JG-REGINF-G
    must score LOW / near 0 (score <= 0.05).
    - Verified official domain -> no brand mismatch
    - No credential or OTP request
    - No suspicious forms
    - Official campaign context + TRAI DLT Government header
    - Statutory legal notice wording does not override trusted-domain evidence
    """
    message = (
        "JG-REGINF-G\n"
        "This Independence Day, celebrate 150 years of Vande Mataram with Har Ghar Tiranga. "
        "Hoist Tiranga at home & upload your selfie on https://harghartiranga.com/\n"
        "Advisory as per the Telecommunications Act 2023. Acquiring SIMs or telecom identifiers by fraud, "
        "cheating or personation is a punishable offence under the Telecommunications Act, 2023 with imprisonment "
        "up to 3 years, a fine up to Rs. 50 lakhs or both. The same penalty applies to abetment, attempt, or conspiracy."
    )
    res = client.post("/api/analyze", json={"message": message})
    assert res.status_code == 200
    data = res.json()

    assert data["risk"]["level"] == "LOW"
    assert data["risk"]["score"] <= 0.05
    assert data["risk"]["category"] == "LOW CONCERN"
    assert data.get("fraud_category") is None

    # Check evidence items
    evidence_types = [e.get("type") for e in data.get("evidence", [])]
    # No brand mismatch should be generated
    assert "brand_mismatch" not in evidence_types

    # Verified official domain and government sender must be recognized
    findings = [e.get("finding") or e.get("description") or "" for e in data.get("evidence", [])]
    assert any("harghartiranga.com" in f for f in findings)
    assert any("TRAI DLT" in f for f in findings)

