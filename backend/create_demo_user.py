import sys
import os
sys.path.insert(0, os.path.abspath('.'))

from backend.services.neo4j_repository import neo4j_repo, hash_password

email = "demo@cyberkawach.gov.in"
raw_password = "Password@123"

pw_hash = hash_password(raw_password)

cypher = """
MERGE (u:User {email_normalized: $email_normalized})
SET u.user_id = coalesce(u.user_id, 'usr_demo_citizen_001'),
    u.email = $email,
    u.display_name = 'Citizen Demo',
    u.password_hash = $pw_hash,
    u.is_active = true,
    u.preferred_language = 'en'
RETURN u.email AS email, u.display_name AS name
"""

with neo4j_repo._get_session() as session:
    res = session.run(
        cypher,
        email_normalized=email.lower(),
        email=email,
        pw_hash=pw_hash,
    ).single()
    print("SUCCESS:", res["email"], res["name"])
