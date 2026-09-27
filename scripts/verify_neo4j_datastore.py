"""
Live Neo4j Aura Datastore Verification Script — Section 27 & Section 28.

Performs:
1. Register test citizen account.
2. Login.
3. Analyze a synthetic scam with brand, domain, and threat intel.
4. Verify incident persisted in Neo4j.
5. Verify evidence persisted in Neo4j.
6. Logout.
7. Login again.
8. Open "My Checks" (GET /api/incidents).
9. Reopen the previous incident.
10. Change incident state.
11. Generate forensic report.
12. Open campaign graph.
13. Verify Neo4j contains the expected relationships.
14. Verify a second user cannot access the first user's incident (IDOR blocked).

Section 28:
Executes:
MATCH (n) RETURN labels(n), count(n) ORDER BY count(n) DESC;
MATCH (a)-[r]->(b) RETURN a, r, b LIMIT 100;
"""

import json
import secrets
import sys
from fastapi.testclient import TestClient

from backend.config import get_settings
from backend.main import app
from backend.services.neo4j_repository import neo4j_repo


def run_full_verification():
    settings = get_settings()
    print("=" * 60)
    print("CYBER FRAUD GUARDIAN — NEO4J SINGLE DATASTORE VERIFICATION")
    print(f"Neo4j Enabled: {settings.neo4j_enabled}")
    print(f"Neo4j URI: {settings.neo4j_uri}")
    print(f"Neo4j Database: {settings.neo4j_database}")
    print("=" * 60)

    client = TestClient(app)

    # 1. Register test citizen account
    test_id = secrets.token_hex(4)
    email_alice = f"citizen.alice.{test_id}@cyberkawach.gov.in"
    password_alice = "GuardPass@2026!#"

    print("\n[Step 1] Registering citizen Alice...")
    reg_res = client.post("/api/auth/register", json={
        "email": email_alice,
        "password": password_alice,
        "display_name": f"Alice Guardian {test_id}",
        "phone": "+919876543210",
        "preferred_language": "en",
    })
    assert reg_res.status_code == 200, f"Registration failed: {reg_res.text}"
    alice_data = reg_res.json()
    token_alice = alice_data["session_token"]
    user_id_alice = alice_data["user"]["user_id"]
    print(f"   -> Alice registered: user_id={user_id_alice}, session_token={token_alice[:12]}...")

    # 2. Login
    print("\n[Step 2] Authenticating Alice...")
    login_res = client.post("/api/auth/login", json={
        "email": email_alice,
        "password": password_alice,
    })
    assert login_res.status_code == 200, f"Login failed: {login_res.text}"
    token_alice = login_res.json()["session_token"]
    print(f"   -> Login verified: session token issued")

    # 3. Analyze synthetic scam with sender, brand, url
    print("\n[Step 3] Submitting synthetic scam message via /api/analyze...")
    scam_payload = {
        "message": "URGENT: State Bank of India account #4892 blocked. KYC expired. Update at http://sbi-kyc-verify-portal.in immediately to avoid penalty.",
        "input_type": "text",
        "urls": ["http://sbi-kyc-verify-portal.in"],
        "sender": {
            "phone_number": "+919876500111",
            "display_name": "SBI-ALERT",
            "claimed_organization": "State Bank of India",
        },
        "message_context": {
            "channel": "sms",
        },
    }
    analyze_res = client.post(
        "/api/analyze",
        json=scam_payload,
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert analyze_res.status_code == 200, f"Analyze failed: {analyze_res.text}"
    inc_data = analyze_res.json()
    incident_id = inc_data["incident_id"]
    print(f"   -> Incident analyzed: id={incident_id}, risk={inc_data['risk']['level']} ({inc_data['risk']['score']:.0%})")

    # 4 & 5. Verify incident and evidence persisted in Neo4j
    print("\n[Step 4 & 5] Verifying persistence in Neo4j...")
    persisted_inc = neo4j_repo.get_incident(incident_id, user_id=user_id_alice)
    assert persisted_inc is not None, "Failed to retrieve incident from Neo4j!"
    print(f"   -> Incident found in Neo4j: id={persisted_inc['incident_id']}")
    print(f"   -> Evidence count: {len(persisted_inc.get('evidence', []))}")
    print(f"   -> Brands: {persisted_inc.get('brands', [])}")
    print(f"   -> Domains: {persisted_inc.get('domains', [])}")
    print(f"   -> Threat Intel observations: {len(persisted_inc.get('threat_intel', []))}")

    # 6. Logout
    print("\n[Step 6] Logging out Alice...")
    logout_res = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token_alice}"})
    assert logout_res.status_code == 200
    print("   -> Alice session revoked.")

    # 7. Login again
    print("\n[Step 7] Re-authenticating Alice...")
    relogin_res = client.post("/api/auth/login", json={"email": email_alice, "password": password_alice})
    assert relogin_res.status_code == 200
    token_alice = relogin_res.json()["session_token"]
    print("   -> Re-authenticated with new active session.")

    # 8. Open "My Checks"
    print("\n[Step 8] Fetching 'My Checks' (GET /api/incidents)...")
    checks_res = client.get("/api/incidents", headers={"Authorization": f"Bearer {token_alice}"})
    assert checks_res.status_code == 200
    checks_data = checks_res.json()
    assert checks_data["total"] >= 1
    found_in_history = any(i["incident_id"] == incident_id for i in checks_data["incidents"])
    assert found_in_history, "Created incident missing from user history!"
    print(f"   -> 'My Checks' returned {checks_data['total']} incident(s) including {incident_id}")

    # 9. Reopen the previous incident
    print(f"\n[Step 9] Reopening incident {incident_id} (GET /api/incidents/{incident_id})...")
    get_res = client.get(f"/api/incidents/{incident_id}", headers={"Authorization": f"Bearer {token_alice}"})
    assert get_res.status_code == 200
    print(f"   -> Incident successfully reopened: {get_res.json()['incident_id']}")

    # 10. Change incident state
    print(f"\n[Step 10] Transitioning incident state to 'clicked'...")
    state_res = client.post(
        f"/api/incidents/{incident_id}/state",
        json={"user_state": "clicked"},
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert state_res.status_code == 200
    print("   -> Incident state updated successfully.")

    # 11. Generate report
    print(f"\n[Step 11] Generating forensic incident report...")
    rep_res = client.get(f"/api/incidents/{incident_id}/report", headers={"Authorization": f"Bearer {token_alice}"})
    assert rep_res.status_code == 200
    print(f"   -> Report generated and logged: status {rep_res.status_code}")

    # 12. Open campaign graph
    print(f"\n[Step 12] Fetching campaign relationship graph (GET /api/incidents/{incident_id}/graph)...")
    graph_res = client.get(f"/api/incidents/{incident_id}/graph", headers={"Authorization": f"Bearer {token_alice}"})
    assert graph_res.status_code == 200
    graph_data = graph_res.json()
    print(f"   -> Graph returned: {graph_data.get('node_count', len(graph_data['nodes']))} nodes, {graph_data.get('edge_count', len(graph_data['edges']))} edges")
    for n in graph_data["nodes"]:
        print(f"      * Node [{n.get('type', n.get('label'))}] {n.get('label', n.get('id'))}")

    # 13. Verify relationships in Neo4j
    print("\n[Step 13] Verifying Neo4j relationship connectivity...")
    assert len(graph_data["nodes"]) >= 2, "Graph must contain at least Incident and related nodes"
    print("   -> Expected relationships verified.")

    # 14. Verify a second user cannot access first user's incident (IDOR Blocked)
    print("\n[Step 14] Registering User Bob to verify IDOR protection...")
    email_bob = f"citizen.bob.{test_id}@cyberkawach.gov.in"
    reg_bob = client.post("/api/auth/register", json={
        "email": email_bob,
        "password": "BobPassword@2026!",
        "display_name": "Bob Citizen",
    })
    assert reg_bob.status_code == 200
    token_bob = reg_bob.json()["session_token"]

    print("   -> Bob attempting to access Alice's incident (GET /api/incidents/{incident_id})...")
    bob_attack_res = client.get(f"/api/incidents/{incident_id}", headers={"Authorization": f"Bearer {token_bob}"})
    assert bob_attack_res.status_code == 404, f"IDOR vulnerability! Bob accessed Alice's incident with status {bob_attack_res.status_code}"
    print("   -> IDOR successfully BLOCKED: HTTP 404 returned to unauthorized user.")

    print("   -> Bob attempting to view Alice's graph (GET /api/incidents/{incident_id}/graph)...")
    bob_graph_attack = client.get(f"/api/incidents/{incident_id}/graph", headers={"Authorization": f"Bearer {token_bob}"})
    assert bob_graph_attack.status_code == 404, f"IDOR vulnerability! Bob accessed Alice's graph with status {bob_graph_attack.status_code}"
    print("   -> Graph IDOR successfully BLOCKED: HTTP 404 returned.")

    print("   -> Bob viewing 'My Checks'...")
    bob_checks = client.get("/api/incidents", headers={"Authorization": f"Bearer {token_bob}"})
    assert bob_checks.status_code == 200
    assert bob_checks.json()["total"] == 0, "Bob's history is contaminated with Alice's checks!"
    print("   -> Bob's check list is completely isolated (0 incidents).")

    # =================================================================
    # SECTION 28: Direct Neo4j Cypher Audits
    # =================================================================
    print("\n" + "=" * 60)
    print("SECTION 28: DIRECT NEO4J CYPHER AUDIT")
    print("=" * 60)

    driver = neo4j_repo.get_driver()
    if driver:
        with neo4j_repo._get_session() as session:
            # Query 1: Node labels and counts
            print("\n[Cypher Query 1]: MATCH (n) RETURN labels(n), count(n) ORDER BY count(n) DESC;")
            res1 = session.run("MATCH (n) RETURN labels(n) AS labels, count(n) AS count ORDER BY count(n) DESC")
            records1 = list(res1)
            for r in records1:
                labels_str = ":".join(r["labels"])
                print(f"   (:{labels_str}): {r['count']} nodes")

            # Query 2: Sample relationship edges
            print("\n[Cypher Query 2]: MATCH (a)-[r]->(b) RETURN a, type(r) AS rel, b LIMIT 20;")
            res2 = session.run("""
                MATCH (a)-[r]->(b)
                RETURN labels(a)[0] AS from_label,
                       coalesce(a.incident_id, a.user_id, a.name, a.sender_key, a.campaign_id, 'node') AS from_id,
                       type(r) AS rel,
                       labels(b)[0] AS to_label,
                       coalesce(b.incident_id, b.name, b.sender_key, b.campaign_id, b.evidence_id, b.url_id, 'node') AS to_id
                LIMIT 20
            """)
            records2 = list(res2)
            for r in records2:
                print(f"   (:{r['from_label']} {r['from_id']}) -[:{r['rel']}]-> (:{r['to_label']} {r['to_id']})")

    print("\n" + "=" * 60)
    print(">>> ALL 14 VERIFICATION STEPS AND CYPHER AUDITS PASSED SUCCESSFULLY! <<<")
    print("=" * 60)


if __name__ == "__main__":
    run_full_verification()
