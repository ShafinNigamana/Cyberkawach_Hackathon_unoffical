# CyberKawach — Reproducible Bug Report

This document records all confirmed bugs, implementation discrepancies, and runtime defects discovered during empirical test execution, along with their resolution status.

**Status Summary:** 5 of 5 Bugs **RESOLVED & VERIFIED**.

---

### Bug #1: CORS Missing Custom Header White-listing
- **Status:** **RESOLVED**
- **File:** `backend/main.py`
- **Lines:** 90–105
- **Type:** API Integration / Configuration Defect
- **Steps to Reproduce & Verify:**
  ```python
  from fastapi.testclient import TestClient
  from backend.main import app

  client = TestClient(app)
  response = client.options(
      "/api/incidents/claim",
      headers={
          "Origin": "http://localhost:3000",
          "Access-Control-Request-Method": "POST",
          "Access-Control-Request-Headers": "X-Incident-Claim-Token, X-Session-Token",
      },
  )
  assert response.status_code == 200
  assert "x-incident-claim-token" in response.headers.get("access-control-allow-headers", "").lower()
  assert "x-session-token" in response.headers.get("access-control-allow-headers", "").lower()
  ```
- **Resolution:** Added `X-Incident-Claim-Token`, `X-Session-Token`, `X-API-Key`, `Accept`, and `Origin` to `allow_headers` in `backend/main.py`.

---

### Bug #2: `BoundedIncidentStore` Lacks `__len__()` Protocol
- **Status:** **RESOLVED**
- **File:** `backend/services/incident_store.py`
- **Lines:** 154–158
- **Type:** Runtime TypeError / Incomplete Container Protocol
- **Steps to Reproduce & Verify:**
  ```python
  from backend.services.incident_store import incident_store
  count = len(incident_store)  # Returns int successfully
  assert isinstance(count, int)
  ```
- **Resolution:** Implemented `def __len__(self) -> int: with self._lock: return len(self._store)` on `BoundedIncidentStore`.

---

### Bug #3: Disconnected SQLite Fallback Table for User Incident History
- **Status:** **RESOLVED**
- **File:** `backend/services/neo4j_repository.py`
- **Lines:** 152–175, 1126–1175
- **Type:** Architectural Desynchronization & Potential IDOR
- **Steps to Reproduce & Verify:**
  ```python
  from backend.services.neo4j_repository import neo4j_repo
  res = neo4j_repo.list_user_incidents("usr_test", limit=10)
  assert isinstance(res, list)  # Runs without sqlite3.OperationalError
  ```
- **Resolution:** Added table definition in `_get_sqlite_conn()` and implemented two-tier fallback querying `incidents.db` first, then `investigations.db`, both parameterized with `WHERE user_id = ?` for strict tenant isolation.

---

### Bug #4: Perimeter Sanitizer Misses Zero-Width Character Evasion
- **Status:** **RESOLVED**
- **File:** `backend/utils/sanitize.py`
- **Lines:** 24–44
- **Type:** Input Sanitization Gap
- **Steps to Reproduce & Verify:**
  ```python
  from backend.utils.sanitize import sanitize_message
  output = sanitize_message("h\u200Bd\u200Bf\u200Bc")
  assert "\u200B" not in output
  ```
- **Resolution:** Added `_ZERO_WIDTH_CHARS = re.compile(r"[\u200B-\u200D\uFEFF\u2060\u180E]")` to `sanitize_message()`, stripping invisible smuggling characters before processing.

---

### Bug #5: File Scan Schema Field Discrepancy (`size_bytes` vs `filesize`)
- **Status:** **RESOLVED**
- **File:** `backend/services/file_scanner.py`
- **Lines:** 142–147
- **Type:** Schema Inconsistency
- **Steps to Reproduce & Verify:**
  ```python
  from backend.services.file_scanner import FileScanRecord
  rec = FileScanRecord(original_filename="a.txt", safe_filename="a.txt", size_bytes=100)
  assert rec.filesize == 100
  assert rec.model_dump()["filesize"] == 100
  ```
- **Resolution:** Added `@computed_field` `@property def filesize(self) -> int: return self.size_bytes` to `FileScanRecord`.

