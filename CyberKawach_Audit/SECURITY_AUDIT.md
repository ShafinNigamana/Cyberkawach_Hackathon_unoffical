# CyberKawach — Application Security Audit Report

**Scope:** Backend APIs, Authentication Mechanism, File Scanner, Database Queries, CORS, Rate Limiting, and Forensics Export.  
**Standard:** OWASP Top 10 API Security, ASVS Level 2, and CWE Top 25.

---

## Confirmed Vulnerabilities & Weaknesses

---

### Finding `CK-SEC-01`: CORS Policy Drops Custom Headers (`X-Incident-Claim-Token`, `X-Session-Token`)
- **Severity:** **HIGH**
- **CWE:** CWE-346 (Origin Validation Error) / CWE-942 (Overly Permissive or Incomplete CORS Policy)
- **Affected Component:** `backend/main.py` lines 90–96
- **Source Location:**
  ```python
  app.add_middleware(
      CORSMiddleware,
      allow_origins=settings.cors_origin_list,
      allow_credentials=True,
      allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
  )
  ```
- **Reproduction Steps:**
  1. Host the React SPA frontend on `http://localhost:3000`.
  2. Send an authenticated preflight request to `http://localhost:8000/api/incidents/{incident_id}`:
     ```http
     OPTIONS /api/incidents/INC-2026-A1B2C3D4 HTTP/1.1
     Host: localhost:8000
     Origin: http://localhost:3000
     Access-Control-Request-Method: GET
     Access-Control-Request-Headers: Content-Type, X-Incident-Claim-Token
     ```
  3. Observe that FastAPI CORSMiddleware does not return `Access-Control-Allow-Headers: X-Incident-Claim-Token`.
- **Expected Behavior:** `allow_headers` should explicitly include `X-Incident-Claim-Token` and `X-Session-Token` (or wildcard `["*"]` when permissible) so modern web browsers allow cross-origin requests.
- **Actual Behavior:** Modern browsers block the cross-origin request at the preflight stage, rendering anonymous dossier claiming and alternate token authentication completely inoperable in decoupled frontend architectures.
- **Potential Impact:** Denial of service for decoupled web applications; inability to export dossiers from React UI.
- **Recommended Fix:**
  Update `allow_headers` in `backend/main.py`:
  ```python
  allow_headers=[
      "Content-Type",
      "Authorization",
      "X-Requested-With",
      "X-Incident-Claim-Token",
      "X-Session-Token",
  ]
  ```

---

### Finding `CK-SEC-02`: Desynchronized Fallback Query & Missing Tenant Isolation in `list_user_incidents`
- **Severity:** **MEDIUM**
- **CWE:** CWE-284 (Improper Access Control) / CWE-404 (Improper Resource Shutdown or Release)
- **Affected Component:** `backend/services/neo4j_repository.py` lines 1112–1140
- **Source Location:**
  ```python
  # Fallback to local SQLite investigations table
  try:
      conn = self._get_sqlite_conn()
      rows = conn.execute(
          """
          SELECT incident_id, created_at, input_type, raw_input, risk_score, risk_level, fraud_category
          FROM investigations
          ORDER BY created_at DESC
          LIMIT ?
          """,
          (limit,),
      ).fetchall()
  ```
- **Reproduction Steps:**
  1. Run CyberKawach with `NEO4J_ENABLED=false`.
  2. Register and log in as Citizen A (`user_id = "usr_001"`).
  3. Submit a fraud analysis.
  4. Call `GET /api/incidents` to list past checks.
  5. The endpoint queries `investigations.db` for a table named `investigations`, which does not exist (`_get_sqlite_conn()` only initializes `citizen_users`, `citizen_sessions`, `citizen_preferences`, and `citizen_audit_events`).
  6. The query raises an `sqlite3.OperationalError: no such table: investigations`, which is caught by `except Exception: return []`.
- **Expected Behavior:** The offline fallback should query the `incidents` table in `backend/data/incidents.db` filtered strictly by `WHERE user_id = ?`.
- **Actual Behavior:** 
  1. The call silently fails and returns an empty list `[]`, giving citizens the false impression that their history was lost.
  2. If the `investigations` table had been present, the query lacked `WHERE user_id = ?`, which would have returned *every citizen's* incident records to any authenticated user (Severe IDOR / Data Breach).
- **Potential Impact:** Broken feature under offline mode; catastrophic data exposure if table were populated without the `WHERE user_id = ?` clause.
- **Recommended Fix:**
  Point `list_user_incidents` to `BoundedIncidentStore` or query `incidents.db` with `WHERE user_id = ?`:
  ```python
  conn = sqlite3.connect(str(_DEFAULT_DB_DIR / "incidents.db"))
  rows = conn.execute(
      "SELECT payload FROM incidents WHERE user_id = ? ORDER BY updated_at DESC LIMIT ?",
      (user_id, limit),
  ).fetchall()
  ```

---

### Finding `CK-SEC-03`: Incomplete Zero-Width Sanitization in Basic Sanitizer
- **Severity:** **MEDIUM**
- **CWE:** CWE-116 (Improper Encoding or Escaping of Output)
- **Affected Component:** `backend/utils/sanitize.py` line 37
- **Source Location:**
  ```python
  text = re.sub(r'[\u202A-\u202E\u2066-\u2069]', '', text)
  ```
- **Reproduction Steps:**
  1. Pass text containing zero-width spaces (`\u200B`, `\u200C`, `\uFEFF`) to `sanitize_message("s\u200Bb\u200Bi")`.
  2. The output retains `\u200B`.
- **Expected Behavior:** All non-printable zero-width evasion characters should be stripped at the perimeter sanitization boundary.
- **Actual Behavior:** While `adversarial_normalizer.py` cleans zero-width characters during the deep pipeline analysis, any lightweight route or utility calling only `sanitize_message()` leaves these obfuscation bytes intact.
- **Potential Impact:** Bypass of perimeter regex rules or keyword blacklists if not passed through the full normalizer module.
- **Recommended Fix:**
  Add `\u200B-\u200D\uFEFF\u00AD` to the character stripping regex in `backend/utils/sanitize.py`.

---

### Finding `CK-SEC-04`: Missing `__len__()` Protocol on `BoundedIncidentStore`
- **Severity:** **LOW**
- **CWE:** CWE-758 (Reliance on Undefined, Unspecified, or Implementation-Specific Behavior)
- **Affected Component:** `backend/services/incident_store.py`
- **Reproduction Steps:**
  1. Run Python interactive prompt or unit test.
  2. Call `len(incident_store)`.
  3. Observe exception:
     `TypeError: object of type 'BoundedIncidentStore' has no len()`
- **Expected Behavior:** Custom container stores implementing dictionary-like interfaces should implement `__len__()`.
- **Actual Behavior:** Unhandled `TypeError` is raised if any monitoring, metrics, or diagnostic code evaluates `len(incident_store)`.
- **Recommended Fix:**
  Add `__len__` method to `BoundedIncidentStore`:
  ```python
  def __len__(self) -> int:
      with self._lock:
          return len(self._store)
  ```

---

## Verified Security Controls (Defenses That Succeeded)

1. **SQL Injection Defense:** All database queries utilize parameterized queries (`?` in SQLite, `$param` in Cypher). No string concatenation vulnerabilities found.
2. **SSRF Defense:** `backend/utils/ssrf.py` blocks RFC 1918 private IPs, loopback, link-local metadata (`169.254.169.254`), and dangerous schemes (`file://`, `data://`).
3. **Zip-Slip & Path Traversal:** `backend/services/file_scanner.py` and `backend/utils/file_security.py` strictly sanitize filenames and reject archives containing `..` or absolute paths.
4. **Command Injection Defense:** Zero dynamic shell invocations (`os.system` / `subprocess.Popen`) exist in untrusted input processing paths.
5. **Memory Exhaustion (DoS) Defense:** `RequestSizeLimitMiddleware` strictly rejects request payloads exceeding `max_upload_size_mb`.

