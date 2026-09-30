import sqlite3

con = sqlite3.connect('backend/data/investigations.db')
cur = con.cursor()

evs = cur.execute("SELECT type, source, finding, severity, risk_direction, confidence FROM evidence_records WHERE incident_id = 'INC-2026-A5DE10C0' AND risk_direction = 'INCREASES_RISK'").fetchall()
print("Items with INCREASES_RISK:")
for e in evs:
    print(e)
