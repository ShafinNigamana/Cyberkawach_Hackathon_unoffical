"""
Automated 20-Case Accuracy Regression Matrix Runner.
Executes all 20 benchmark test cases against the Cyber Fraud Guardian pipeline,
verifies epistemic bounds, prints a structured evaluation matrix, and computes accuracy metrics.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient
from backend.main import app

FIXTURE_PATH = PROJECT_ROOT / "fixtures" / "accuracy_matrix_cases.json"


def run_matrix():
    client = TestClient(app)

    with open(FIXTURE_PATH, "r", encoding="utf-8") as f:
        cases = json.load(f)

    print("=" * 105)
    print(" CYBER FRAUD GUARDIAN — 20-CASE ACCURACY REGRESSION MATRIX")
    print("=" * 105)
    print(f"{'Case ID':<32} | {'Category':<16} | {'Expected':<12} | {'Actual':<10} | {'Score':<6} | {'Sufficiency':<11} | {'Status':<6}")
    print("-" * 105)

    passed_count = 0
    false_positives = 0
    false_negatives = 0
    attack_path_hits = 0
    total_time = 0.0

    for case in cases:
        case_id = case["id"]
        cat = case.get("category", "unknown")[:16]
        user_state = case.get("user_state", "received")
        msg = case["message"]

        t0 = time.time()
        res = client.post("/api/analyze", json={"message": msg, "user_state": user_state})
        elapsed = time.time() - t0
        total_time += elapsed

        if res.status_code != 200:
            print(f"{case_id:<32} | {cat:<16} | {'HTTP 200':<12} | {f'ERR {res.status_code}':<10} | {'N/A':<6} | {'N/A':<11} | FAIL")
            continue

        data = res.json()
        risk_level = data["risk"]["level"]
        risk_score = data["risk"]["score"]
        sufficiency = data["risk"]["evidence_sufficiency"]
        is_legit = case.get("is_legitimate", False)
        is_phish = case.get("is_phishing", False)

        # Verification checks
        case_passed = True

        # Check risk level
        expected_risk = case.get("expected_risk", [])
        if expected_risk and risk_level not in expected_risk:
            case_passed = False

        # Check score bounds
        if "max_score" in case and risk_score > case["max_score"] + 0.05:
            case_passed = False
        if "min_score" in case and risk_score < case["min_score"] - 0.05:
            case_passed = False

        # False positive / negative tracking
        if is_legit and risk_level in ["HIGH", "CRITICAL"]:
            false_positives += 1
            case_passed = False

        if is_phish and risk_level in ["LOW", "UNKNOWN"]:
            false_negatives += 1
            case_passed = False

        # Attack path coverage
        expl = data.get("explanation") or {}
        if is_phish and (expl.get("attack_path") or expl.get("structured_attack_path")):
            attack_path_hits += 1

        # Response urgency check
        if "expected_urgency" in case:
            actual_urgency = data.get("response", {}).get("urgency", "").lower()
            if actual_urgency != case["expected_urgency"].lower():
                case_passed = False

        # Response keywords check
        if "must_contain_response" in case:
            resp_texts = " ".join(
                data.get("response", {}).get("immediate_actions", [])
                + data.get("response", {}).get("recovery_steps", [])
                + data.get("response", {}).get("reporting_info", [])
            ).lower()
            for kw in case["must_contain_response"]:
                if kw.lower() not in resp_texts:
                    case_passed = False

        if case_passed:
            passed_count += 1
            status_str = "PASS"
        else:
            status_str = "FAIL"

        exp_str = ",".join(expected_risk)[:12] if expected_risk else case.get("expected_urgency", "N/A")
        print(f"{case_id:<32} | {cat:<16} | {exp_str:<12} | {risk_level:<10} | {risk_score:<6.3f} | {sufficiency:<11} | {status_str:<6}")

    print("=" * 105)
    print(" SUMMARY METRICS")
    print("=" * 105)
    total_cases = len(cases)
    phish_cases = sum(1 for c in cases if c.get("is_phishing"))
    accuracy = (passed_count / total_cases) * 100

    print(f"Total Cases Evaluated   : {total_cases}")
    print(f"Passed Assertions       : {passed_count} / {total_cases} ({accuracy:.1f}%)")
    print(f"False Positives         : {false_positives} (Target: 0)")
    print(f"False Negatives         : {false_negatives} (Target: 0)")
    print(f"Attack Path Coverage    : {attack_path_hits} / {phish_cases} phishing cases ({attack_path_hits/phish_cases*100:.1f}%)")
    print(f"Total Latency           : {total_time:.2f}s (Avg: {total_time/total_cases*1000:.1f}ms/case)")
    print("=" * 105)

    if passed_count == total_cases:
        print("[SUCCESS] All 20 accuracy regression test cases satisfied all epistemic and security contracts.")
        return 0
    else:
        print(f"[FAILURE] {total_cases - passed_count} test case(s) failed assertions.")
        return 1


if __name__ == "__main__":
    sys.exit(run_matrix())
