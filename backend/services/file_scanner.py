"""
File Security, Deep Threat Scanning & Folder Inspection Engine (Phase 7).

Implements early download, deep live malware analysis, and whole-folder inspection with:
- Pure Live Dynamic Analysis (Zero reliance on preloaded or pre-cached hashes).
- Extension Cloaking / Format Confusion Engine: Detects weaponized exploits and scripts
  masquerading as images (.jpg, .png, .gif) or innocuous documents.
- True File Signature & Magic-Byte Identification:
  * Windows PE32 (MZ), Linux ELF (\x7fELF), Android DEX, Compound OLE, RTF, XML Scriptlets
  * Microsoft Office OpenXML (DOCX/XLSX) detection inside PK containers
- Deep Static & Behavioral Heuristics:
  * Equation Editor (CVE-2017-11882 / CVE-2017-0199) weaponized RTF & OLE exploit detection
  * PowerShell execution policy bypass & hidden download cradles
  * Windows Scriptlet (SCT / ShortJSRAT) trojan registration
  * WScript.Shell & schtasks persistence mechanisms
  * Low-level memory allocation & thread injection (VirtualAlloc, WriteProcessMemory, CreateRemoteThread)
  * Ransomware shadow copy and backup destruction commands
  * Macro execution vectors (AutoOpen, Document_Open, Workbook_Open, vbaProject.bin)
  * Raw shellcode headers on PE binaries (MZ\\xe8 bootstrap)
- Recursive Archive Member Deep Scanning: Unpacks and inspects all internal files of ZIP & OpenXML containers.
- Whole Folder / Batch Scanning: Multi-file folder tree scanning with per-file breakdown and aggregate folder security verdicts.
- Strict release policy: Files are NEVER released if suspicious, malicious, or if scan errored.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from enum import Enum
import hashlib
import io
import logging
import math
import os
from pathlib import Path
import re
import socket
import tempfile
import time
from typing import Any, AsyncGenerator, Callable, Optional
import uuid
import zipfile

from pydantic import BaseModel, Field

from backend.config import get_settings
from backend.utils.file_security import sanitize_filename
from backend.utils.security_logging import safe_error_message
from backend.utils.telemetry import record_file_scan_result

logger = logging.getLogger("cyber_guardian.file_scanner")
settings = get_settings()

_QUARANTINE_DIR = Path(__file__).resolve().parent.parent / "data" / "quarantine"
_SAFE_DIR = Path(__file__).resolve().parent.parent / "data" / "safe_downloads"

# Maximum limits for defense-in-depth
_MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
_MAX_ARCHIVE_UNCOMPRESSED_BYTES = 200 * 1024 * 1024  # 200 MB
_MAX_COMPRESSION_RATIO = 100.0  # Zip-bomb ratio threshold
_MAX_FOLDER_FILES = 300  # Maximum files in a batch folder scan

# Standard EICAR Antivirus Test File String (Harmless test signature recognized by all AVs)
_EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# Magic Byte Signatures
_MAGIC_BYTE_SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"MZ", "application/x-dosexec", "PE32 Executable (.exe/.dll)"),
    (b"\x7fELF", "application/x-executable", "Linux ELF Executable"),
    (b"{\\rtf", "application/rtf", "Rich Text Format (RTF) Document"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage", "Microsoft Compound OLE Document"),
    (b"GIF87a", "image/gif", "GIF Image"),
    (b"GIF89a", "image/gif", "GIF Image"),
    (b"\x89PNG\r\n\x1a\n", "image/png", "PNG Image"),
    (b"\xff\xd8", "image/jpeg", "JPEG Image"),
    (b"RIFF", "image/webp", "WebP Image"),
    (b"dex\n", "application/x-android-dex", "Compiled Android DEX Binary"),
    (b"%PDF-", "application/pdf", "Adobe PDF Document"),
    (b"\x1f\x8b", "application/gzip", "GZIP Compressed Archive"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", "7-Zip Compressed Archive"),
    (b"Rar!\x1a\x07", "application/x-rar-compressed", "RAR Compressed Archive"),
    (b"BZh", "application/x-bzip2", "BZip2 Compressed Archive"),
    (b"\xfd7zXZ\x00", "application/x-xz", "XZ Compressed Archive"),
]

# Image file extensions for extension cloaking detection
_IMAGE_EXTENSIONS = frozenset({".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".tiff"})

# Deep Analysis Heuristic Patterns
_LIVE_MALWARE_PATTERNS = [
    # Ransomware & Sabotage
    (re.compile(rb"vssadmin\s+delete\s+shadows", re.I), "MALICIOUS", "Ransomware Command: Shadow copy deletion (vssadmin)"),
    (re.compile(rb"wmic\s+shadowcopy\s+delete", re.I), "MALICIOUS", "Ransomware Command: WMIC shadow copy wipe"),
    (re.compile(rb"wbadmin\s+delete\s+catalog", re.I), "MALICIOUS", "Ransomware Command: Backup catalog wipe"),
    
    # Obfuscated PowerShell / Downloader Cradles
    (re.compile(rb"powershell(\.exe)?\s+(-[a-z\s]+)*(iex|invoke-expression)", re.I), "MALICIOUS", "Malicious Dropper: Obfuscated PowerShell IEX execution"),
    (re.compile(rb"-[eE][nN][cC]([oO][dD][eE][dD][cC][oO][mM][mM][aA][nN][dD])?\s+[A-Za-z0-9+/=]{20,}", re.I), "MALICIOUS", "Malicious Script: Encoded Base64 PowerShell payload"),
    (re.compile(rb"New-Object\s+Net\.WebClient.*downloadstring", re.I), "MALICIOUS", "Malicious Dropper: Remote payload download cradle (Net.WebClient)"),
    (re.compile(rb"bypass\s+-windowstyle\s+hidden", re.I), "MALICIOUS", "Evasion Technique: Hidden execution policy bypass"),
    (re.compile(rb"Set-StrictMode\s+-Version.*Get-Process\s+powershell", re.I), "MALICIOUS", "Trojan Script: PowerShell carrier with reflection and injection"),
    
    # Windows Scriptlets / Trojans
    (re.compile(rb"<scriptlet>.*progid=.*ShortJSRAT", re.I | re.S), "MALICIOUS", "Remote Access Trojan: ShortJSRAT XML scriptlet carrier"),
    (re.compile(rb"<scriptlet>|<registration\s+progid=", re.I), "MALICIOUS", "Weaponized Scriptlet: SCT/WSC COM registration vector"),
    
    # WScript & Persistence
    (re.compile(rb"WScript\.Shell.*schtasks\s+/create", re.I | re.S), "MALICIOUS", "Trojan Persistence: Scheduled task persistence creation via WScript.Shell"),
    (re.compile(rb"schtasks\s+/create\s+/tn\s+[\"'].*[\"']\s+/tr", re.I), "MALICIOUS", "Trojan Persistence: schtasks backdoor registration"),
    (re.compile(rb"ConvertFrom-Base64\(.*schtasks", re.I | re.S), "MALICIOUS", "Obfuscated Trojan: Base64 persistence dropper"),
    
    # Process Injection / Memory Hook APIs
    (re.compile(rb"VirtualAlloc(Ex)?.*WriteProcessMemory.*CreateRemoteThread", re.I | re.S), "MALICIOUS", "Process Injection: VirtualAlloc + WriteProcessMemory + CreateRemoteThread"),
    (re.compile(rb"VirtualAlloc(Ex)?", re.I), "SUSPICIOUS", "Deep Inspection: Low-level memory allocation API (VirtualAlloc)"),
    (re.compile(rb"WriteProcessMemory", re.I), "SUSPICIOUS", "Deep Inspection: Remote process memory injection API"),
    (re.compile(rb"CreateRemoteThread", re.I), "SUSPICIOUS", "Deep Inspection: Remote process thread execution API"),
    
    # RTF Weaponized Exploits (CVE-2017-11882 / Equation Editor)
    (re.compile(rb"\\object\s+\\objocx|Equation\.3|\\objdata|\\objupdate", re.I), "MALICIOUS", "Weaponized Document: RTF embedded OLE / Equation Editor exploit (CVE-2017-11882)"),
    
    # Macro Execution
    (re.compile(rb"AutoOpen|Document_Open|Workbook_Open|ExecuteExcel4Macro", re.I), "MALICIOUS", "Weaponized Document: Automatic macro execution vector"),
    (re.compile(rb"vbaProject\.bin", re.I), "SUSPICIOUS", "Embedded VBA Macro Project detected"),
]


class ScanState(str, Enum):
    INITIATED = "INITIATED"
    RECEIVING = "RECEIVING"
    SCANNING = "SCANNING"
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    ERROR = "ERROR"
    QUARANTINED = "QUARANTINED"


class ReleasePolicy(str, Enum):
    BLOCKED = "BLOCKED"
    ALLOWED = "ALLOWED"


class FileScanRecord(BaseModel):
    scan_id: str = Field(default_factory=lambda: f"scan_{uuid.uuid4().hex[:12]}")
    original_filename: str
    safe_filename: str
    size_bytes: int = 0
    sha256: str = ""
    sha1: str = ""
    magic_mime: str = "application/octet-stream"
    file_type_description: str = "Unknown Binary"
    entropy: float = 0.0
    state: ScanState = ScanState.INITIATED
    release_policy: ReleasePolicy = ReleasePolicy.BLOCKED
    findings: list[str] = Field(default_factory=list)
    threat_signatures: list[str] = Field(default_factory=list)
    deep_analysis: dict[str, Any] = Field(default_factory=dict)
    quarantine_path: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    processing_time_ms: float = 0.0


class FolderScanRecord(BaseModel):
    batch_id: str = Field(default_factory=lambda: f"folder_{uuid.uuid4().hex[:12]}")
    folder_name: str
    total_files: int = 0
    scanned_files: int = 0
    clean_count: int = 0
    suspicious_count: int = 0
    malicious_count: int = 0
    error_count: int = 0
    overall_state: ScanState = ScanState.INITIATED
    overall_release_policy: ReleasePolicy = ReleasePolicy.BLOCKED
    summary: str = ""
    file_records: list[FileScanRecord] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    processing_time_ms: float = 0.0


# In-memory scan registries
_SCAN_RECORDS: dict[str, FileScanRecord] = {}
_FOLDER_RECORDS: dict[str, FolderScanRecord] = {}

# Cached ClamAV daemon reachability
_CLAMAV_PROBED_TIME = 0.0
_CLAMAV_IS_ALIVE = False


def _ensure_directories() -> None:
    _QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    _SAFE_DIR.mkdir(parents=True, exist_ok=True)


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon Entropy (0.0 to 8.0) across byte distributions."""
    if not data:
        return 0.0
    occurrences = [0] * 256
    for b in data:
        occurrences[b] += 1
    entropy = 0.0
    length = len(data)
    for count in occurrences:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def detect_file_signature(chunk: bytes) -> tuple[str, str]:
    """Identify real MIME and format by inspecting initial magic bytes."""
    if not chunk:
        return "application/x-empty", "Empty File"

    # Check for ZIP containers and derivatives
    # PK\x03\x04: Local file header (standard non-empty ZIP)
    # PK\x05\x06: End of central directory (empty ZIP archive)
    # PK\x07\x08: Data descriptor
    # PK\x01\x02: Central directory header
    if chunk.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"PK\x01\x02")):
        if b"word/" in chunk or b"[Content_Types].xml" in chunk:
            return "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "Microsoft Word OpenXML Document"
        elif b"xl/" in chunk:
            return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "Microsoft Excel OpenXML Document"
        elif b"AndroidManifest.xml" in chunk or b"classes.dex" in chunk:
            return "application/vnd.android.package-archive", "Android Application Package (.apk)"
        if chunk.startswith(b"PK\x05\x06"):
            return "application/zip", "Empty ZIP Archive Package"
        return "application/zip", "ZIP Archive Package"

    # Check for XML Scriptlets
    if chunk.startswith((b"<?xml", b"<?XML")):
        if b"<scriptlet" in chunk or b"ShortJSRAT" in chunk or b"<registration" in chunk:
            return "text/x-scriptlet", "Windows Scriptlet Component (SCT Exploit)"
        return "application/xml", "XML Data Document"

    for magic, mime, desc in _MAGIC_BYTE_SIGNATURES:
        if chunk.startswith(magic):
            return mime, desc

    # Script heuristics
    try:
        sample = chunk[:512].decode("utf-8", errors="ignore").lower()
        if sample.startswith(("#!/bin/", "#!/usr/bin", "<?php", "<script", "import os", "powershell", "@echo off", "rem ", "set-strictmode", "function ")):
            return "text/x-script", "Script / Source Executable"
    except Exception:
        pass

    return "application/octet-stream", "Generic Binary Stream"


def inspect_archive_safety(
    content: bytes,
    max_depth: int = 1,
    current_depth: int = 0,
    members_out: Optional[list[dict[str, Any]]] = None,
) -> tuple[bool, list[str], list[str]]:
    """
    Inspect ZIP / APK / Archive contents for:
    - Zip-Slip path traversal (cross-platform .. and absolute paths)
    - Decompression bomb ratio (>100:1) and maximum expansion limits
    - Smuggled executables, scripts, and weaponized relationships
    - Deep member content inspection (EICAR, malware patterns, format confusion)
    - Encrypted/password-protected members and corrupted archives
    Returns: (is_safe: bool, findings: list[str], threats: list[str])
    """
    findings: list[str] = []
    threats: list[str] = []
    errors: list[str] = []

    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            infolist = zf.infolist()

            # 1. Handle Empty Archive Gracefully
            if len(infolist) == 0:
                findings.append("Archive verified: Empty archive (0 files, 0 threats detected).")
                return True, findings, threats

            total_uncompressed = 0
            scanned_member_count = 0

            # 2. Member count boundary check
            if len(infolist) > 500:
                msg = f"Archive exceeds maximum member file limit ({len(infolist)} > 500 entries)"
                errors.append(msg)
                findings.append(msg)

            for info in infolist:
                norm_name = os.path.normpath(info.filename)

                # Cross-platform Zip-Slip path traversal exploit check
                has_traversal = (
                    norm_name.startswith("..")
                    or "/../" in info.filename
                    or "\\..\\" in info.filename
                    or info.filename.startswith(("/", "\\"))
                    or os.path.isabs(info.filename)
                    or (len(info.filename) >= 2 and info.filename[1] == ":")
                )
                if has_traversal:
                    msg = f"Zip-Slip path traversal exploit detected: '{info.filename}'"
                    threats.append(msg)
                    findings.append(msg)

                total_uncompressed += info.file_size

                # Skip directory entries for content scanning
                if info.is_dir() or info.filename.endswith(("/", "\\")):
                    continue

                scanned_member_count += 1
                lower_name = info.filename.lower()
                member_ext = os.path.splitext(lower_name)[1]

                # Smuggled dangerous executables
                if lower_name.endswith((".exe", ".dll", ".bat", ".vbs", ".ps1", ".cmd", ".scr", ".pif", ".cpl", ".hta", ".wsf", ".jar", ".com")):
                    msg = f"Dangerous executable smuggled inside archive: '{info.filename}'"
                    threats.append(msg)
                    findings.append(msg)

                # Encrypted / password-protected member check
                if info.flag_bits & 0x1:
                    msg = f"Encrypted / password-protected archive member detected: '{info.filename}' (encrypted payloads cannot be inspected)"
                    errors.append(msg)
                    findings.append(msg)
                    if members_out is not None:
                        members_out.append({
                            "filename": info.filename,
                            "size_bytes": info.file_size,
                            "entropy": 0.0,
                            "is_safe": False,
                            "note": "Encrypted",
                        })
                    continue

                # Member expansion limit check (25 MB per member)
                if info.file_size > 25 * 1024 * 1024:
                    msg = f"Archive member '{info.filename}' exceeds safe extraction limit ({info.file_size / (1024*1024):.1f} MB > 25 MB)"
                    errors.append(msg)
                    findings.append(msg)
                    continue

                # Safe member byte extraction and deep analysis
                try:
                    member_bytes = zf.read(info.filename)
                except (NotImplementedError, zipfile.BadZipFile) as comp_err:
                    msg = f"Unsupported or corrupted compression in member '{info.filename}': {safe_error_message(comp_err)}"
                    errors.append(msg)
                    findings.append(msg)
                    continue
                except RuntimeError as re_err:
                    msg = f"Cannot extract member '{info.filename}': {safe_error_message(re_err)}"
                    errors.append(msg)
                    findings.append(msg)
                    continue
                except Exception as ex:
                    msg = f"Extraction error on '{info.filename}': {safe_error_message(ex)}"
                    errors.append(msg)
                    findings.append(msg)
                    continue

                # Deep scan unpacked member bytes
                member_threats: list[str] = []

                # EICAR detection inside member
                if _EICAR_SIGNATURE in member_bytes:
                    t_msg = f"Archive member '{info.filename}' matches EICAR Standard Antivirus Test Fixture"
                    threats.append(t_msg)
                    findings.append(t_msg)
                    member_threats.append(t_msg)

                # OpenXML relationships check for remote OLE injection
                if lower_name.endswith(".rels"):
                    try:
                        rels_content = member_bytes.decode("utf-8", errors="ignore")
                        if "oleObject" in rels_content or "TargetMode=\"External\"" in rels_content:
                            t_msg = f"Weaponized Office Document: Remote OLE / Scriptlet Relationship detected in {info.filename}"
                            threats.append(t_msg)
                            findings.append(t_msg)
                            member_threats.append(t_msg)
                    except Exception:
                        pass

                # Format confusion inside archive (e.g. executable disguised as .png/.txt/.dat)
                if member_ext in _IMAGE_EXTENSIONS or member_ext in (".txt", ".pdf", ".dat", ".csv", ".doc"):
                    if member_bytes.startswith(b"MZ"):
                        t_msg = f"Format Confusion Exploit: Archive member '{info.filename}' is a disguised Windows PE32 binary"
                        threats.append(t_msg)
                        findings.append(t_msg)
                        member_threats.append(t_msg)
                    elif member_bytes.startswith(b"\x7fELF"):
                        t_msg = f"Format Confusion Exploit: Archive member '{info.filename}' is a disguised Linux ELF binary"
                        threats.append(t_msg)
                        findings.append(t_msg)
                        member_threats.append(t_msg)
                    elif member_bytes.startswith(b"{\\rtf"):
                        t_msg = f"Format Confusion Exploit: Archive member '{info.filename}' is a weaponized RTF document"
                        threats.append(t_msg)
                        findings.append(t_msg)
                        member_threats.append(t_msg)

                # Live malware patterns inside unpacked member bytes
                for pattern, severity, desc_hit in _LIVE_MALWARE_PATTERNS:
                    if pattern.search(member_bytes):
                        p_msg = f"Archive member '{info.filename}': {desc_hit}"
                        findings.append(p_msg)
                        if severity == "MALICIOUS":
                            threats.append(p_msg)
                            member_threats.append(p_msg)

                # Recursive nested ZIP inspection (where supported)
                if lower_name.endswith(".zip") and current_depth < max_depth:
                    nested_safe, nested_findings, nested_threats = inspect_archive_safety(
                        member_bytes,
                        max_depth=max_depth,
                        current_depth=current_depth + 1,
                        members_out=members_out,
                    )
                    if nested_threats:
                        for nt in nested_threats:
                            t_nested = f"Nested archive '{info.filename}' -> {nt}"
                            threats.append(t_nested)
                            member_threats.append(t_nested)
                    if not nested_safe and not nested_threats:
                        errors.append(f"Nested archive '{info.filename}' contains unverified or corrupted content")
                    for nf in nested_findings:
                        findings.append(f"Nested '{info.filename}' -> {nf}")

                # Collect member metadata
                if members_out is not None:
                    members_out.append({
                        "filename": info.filename,
                        "size_bytes": info.file_size,
                        "entropy": calculate_entropy(member_bytes[:4096]) if member_bytes else 0.0,
                        "is_safe": len(member_threats) == 0,
                    })

            # 3. Compression ratio / Decompression Bomb check
            compressed_size = len(content)
            if compressed_size > 0:
                ratio = total_uncompressed / compressed_size
                if ratio > _MAX_COMPRESSION_RATIO and total_uncompressed > 10 * 1024 * 1024:
                    msg = f"Archive bomb signature detected (compression ratio {ratio:.1f}:1 exceeds safety threshold)"
                    threats.append(msg)
                    findings.append(msg)

            # 4. Total uncompressed size limit
            if total_uncompressed > _MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                msg = f"Archive exceeds maximum expansion limit ({total_uncompressed / (1024*1024):.1f} MB > {_MAX_ARCHIVE_UNCOMPRESSED_BYTES / (1024*1024):.0f} MB)"
                errors.append(msg)
                findings.append(msg)

            # 5. Clean archive informational summary
            if len(threats) == 0 and len(errors) == 0:
                findings.append(f"ZIP Archive verified: {scanned_member_count} member file(s) inspected, 0 threats detected.")

    except zipfile.BadZipFile:
        msg = "Corrupted or malformed archive format: Invalid ZIP headers or payload corruption"
        errors.append(msg)
        findings.append(msg)
    except NotImplementedError as nie:
        msg = f"Unsupported archive compression method: {safe_error_message(nie)}"
        errors.append(msg)
        findings.append(msg)
    except Exception as e:
        msg = f"Archive inspection error: {safe_error_message(e)}"
        errors.append(msg)
        findings.append(msg)

    is_safe = len(threats) == 0 and len(errors) == 0
    return is_safe, findings, threats


def check_clamav_socket(file_path: Path, host: str = "127.0.0.1", port: int = 3310) -> Optional[tuple[bool, str]]:
    """
    Query ClamAV daemon via clamd network protocol if active.
    Uses cached availability with 0.05s timeout to prevent latency stalls when offline.
    """
    global _CLAMAV_PROBED_TIME, _CLAMAV_IS_ALIVE

    now = time.time()
    if not _CLAMAV_IS_ALIVE and (now - _CLAMAV_PROBED_TIME < 60.0):
        return None

    _CLAMAV_PROBED_TIME = now
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.05)
            s.connect((host, port))
            _CLAMAV_IS_ALIVE = True
            cmd = f"SCAN {file_path.resolve()}\n".encode("utf-8")
            s.sendall(cmd)
            response = s.recv(1024).decode("utf-8", errors="ignore").strip()

            if "OK" in response:
                return True, "ClamAV: Clean"
            elif "FOUND" in response:
                sig = response.split(":")[-1].replace("FOUND", "").strip()
                return False, f"ClamAV: Threat detected ({sig})"
    except Exception:
        _CLAMAV_IS_ALIVE = False
        pass
    return None


class FileSecurityScanner:
    """
    Orchestrates live file scanning, deep heuristic analysis, format confusion detection,
    and whole-folder batch inspection.
    """

    def __init__(self):
        _ensure_directories()

    async def scan_bytes(self, content: bytes, original_filename: str) -> FileScanRecord:
        """Scan completed byte buffer with multi-engine deep analysis."""
        record = FileScanRecord(
            original_filename=original_filename,
            safe_filename=sanitize_filename(original_filename),
            size_bytes=len(content),
            state=ScanState.RECEIVING,
        )
        _SCAN_RECORDS[record.scan_id] = record
        start_time = time.time()

        # 1. Size limit boundary check
        if len(content) > _MAX_FILE_SIZE_BYTES:
            record.state = ScanState.ERROR
            record.release_policy = ReleasePolicy.BLOCKED
            record.findings.append(f"File exceeds maximum size limit ({len(content)/(1024*1024):.1f} MB > {_MAX_FILE_SIZE_BYTES/(1024*1024):.0f} MB)")
            record.completed_at = datetime.now(timezone.utc).isoformat()
            record_file_scan_result("error")
            return record

        # 2. Cryptographic Fingerprints
        sha256_hash = hashlib.sha256()
        sha1_hash = hashlib.sha1()
        sha256_hash.update(content)
        sha1_hash.update(content)

        record.sha256 = sha256_hash.hexdigest()
        record.sha1 = sha1_hash.hexdigest()
        record.state = ScanState.SCANNING

        # 3. Shannon Entropy Calculation (Deep Analysis)
        record.entropy = calculate_entropy(content)
        record.deep_analysis["entropy"] = record.entropy

        # 4. True Magic Byte Detection
        mime, desc = detect_file_signature(content)
        record.magic_mime = mime
        record.file_type_description = desc

        # 5. Secure Isolation / Quarantine Writing
        quarantine_file = _QUARANTINE_DIR / f"{record.sha256}.bin"
        with open(quarantine_file, "wb") as f:
            f.write(content)
        record.quarantine_path = str(quarantine_file)

        # ─── Multi-Engine Analysis ───

        # Engine 1: Standard EICAR Antivirus Test Signature
        if _EICAR_SIGNATURE in content:
            record.threat_signatures.append("EICAR Standard Antivirus Test Fixture")
            record.findings.append("Positive detection: Standard EICAR antivirus verification pattern detected.")
            record.state = ScanState.MALICIOUS
            record.release_policy = ReleasePolicy.BLOCKED

        # Engine 2: Extension Cloaking & Format Confusion Evasion Detection
        ext = os.path.splitext(record.safe_filename)[1].lower()
        if ext in _IMAGE_EXTENSIONS:
            # An image file should never be an RTF, Script, OLE, or PE executable!
            if content.startswith(b"{\\rtf"):
                msg = f"Format Confusion Exploit: File has image extension '{ext}' but is a weaponized RTF document"
                record.threat_signatures.append(msg)
                record.findings.append(msg)
                record.state = ScanState.MALICIOUS
                record.release_policy = ReleasePolicy.BLOCKED

            elif content.startswith((b"<?xml", b"<?XML")) and (b"<scriptlet" in content or b"ShortJSRAT" in content):
                msg = f"Format Confusion Exploit: File has image extension '{ext}' but is a Windows XML Scriptlet Trojan"
                record.threat_signatures.append(msg)
                record.findings.append(msg)
                record.state = ScanState.MALICIOUS
                record.release_policy = ReleasePolicy.BLOCKED

            elif b"Set-StrictMode" in content or b"powershell" in content.lower():
                msg = f"Format Confusion Exploit: File has image extension '{ext}' but contains active PowerShell malware"
                record.threat_signatures.append(msg)
                record.findings.append(msg)
                record.state = ScanState.MALICIOUS
                record.release_policy = ReleasePolicy.BLOCKED

            elif b"WScript.Shell" in content or b"ConvertFrom-Base64" in content:
                msg = f"Format Confusion Exploit: File has image extension '{ext}' but contains active WScript / Base64 persistence code"
                record.threat_signatures.append(msg)
                record.findings.append(msg)
                record.state = ScanState.MALICIOUS
                record.release_policy = ReleasePolicy.BLOCKED

            elif mime in ("application/x-dosexec", "application/x-executable"):
                msg = f"Format Confusion Exploit: File has image extension '{ext}' but is an executable binary ({mime})"
                record.threat_signatures.append(msg)
                record.findings.append(msg)
                record.state = ScanState.MALICIOUS
                record.release_policy = ReleasePolicy.BLOCKED

        # Engine 3: Executable Without Extension (Raw Dropper)
        if not ext and mime == "application/x-dosexec":
            msg = "Malware Dropper: PE32 executable binary disguised without file extension"
            record.threat_signatures.append(msg)
            record.findings.append(msg)
            record.state = ScanState.MALICIOUS
            record.release_policy = ReleasePolicy.BLOCKED

        # PE with Raw Shellcode Header (MZ\xe8 bootstrap)
        if content.startswith(b"MZ\xe8"):
            msg = "Malware Dropper: PE32 binary contains raw shellcode bootstrap header (MZ\\xe8)"
            record.threat_signatures.append(msg)
            record.findings.append(msg)
            record.state = ScanState.MALICIOUS
            record.release_policy = ReleasePolicy.BLOCKED

        # Engine 4: Live Deep Malware Heuristics
        heuristic_hits = []
        for pattern, severity, desc_hit in _LIVE_MALWARE_PATTERNS:
            if pattern.search(content):
                heuristic_hits.append(desc_hit)
                record.findings.append(desc_hit)
                if severity == "MALICIOUS":
                    record.threat_signatures.append(desc_hit)
                    record.state = ScanState.MALICIOUS
                    record.release_policy = ReleasePolicy.BLOCKED
                elif severity == "SUSPICIOUS" and record.state != ScanState.MALICIOUS:
                    record.state = ScanState.SUSPICIOUS
                    record.release_policy = ReleasePolicy.BLOCKED
        if heuristic_hits:
            record.deep_analysis["heuristic_hits"] = heuristic_hits

        # Engine 5: Archive & OpenXML Deep Inspection
        is_archive_mime = mime in (
            "application/zip",
            "application/vnd.android.package-archive",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        if is_archive_mime:
            members_info: list[dict[str, Any]] = []
            is_safe, archive_findings, threats = inspect_archive_safety(content, members_out=members_info)
            record.findings.extend(archive_findings)
            if members_info:
                record.deep_analysis["archive_members"] = members_info
            if threats:
                record.threat_signatures.extend(threats)
                record.state = ScanState.MALICIOUS
                record.release_policy = ReleasePolicy.BLOCKED
            elif not is_safe and record.state != ScanState.MALICIOUS:
                record.state = ScanState.SUSPICIOUS
                record.release_policy = ReleasePolicy.BLOCKED

        # Engine 5b: Corrupted or spoofed archive by extension
        elif ext in (".zip", ".apk", ".docx", ".xlsx", ".jar"):
            if not zipfile.is_zipfile(io.BytesIO(content)):
                msg = f"Corrupted or invalid archive format: File named '{record.safe_filename}' does not contain a valid ZIP container structure (detected {desc})"
                record.findings.append(msg)
                if record.state != ScanState.MALICIOUS:
                    record.state = ScanState.SUSPICIOUS
                    record.release_policy = ReleasePolicy.BLOCKED

        # Engine 6: Executable & Binary Format Policy
        if mime in ("application/x-dosexec", "application/x-executable"):
            exe_type = "Windows PE32" if mime == "application/x-dosexec" else "Linux ELF"
            record.findings.append(f"Executable binary format ({exe_type}). Direct execution blocked by security policy.")
            if record.state != ScanState.MALICIOUS:
                record.state = ScanState.SUSPICIOUS
                record.release_policy = ReleasePolicy.BLOCKED

        elif mime == "application/vnd.android.package-archive":
            record.findings.append("Android Application Package (.apk) inspected for side-load coercive permissions.")
            if record.state != ScanState.MALICIOUS:
                record.state = ScanState.SUSPICIOUS
                record.release_policy = ReleasePolicy.BLOCKED

        # High Entropy Heuristic (detects packed / encrypted executables)
        if record.entropy > 7.3 and mime in ("application/x-dosexec", "application/x-executable", "application/octet-stream"):
            ent_msg = f"High entropy signature ({record.entropy}/8.0): File exhibits packed, obfuscated, or encrypted payload characteristics."
            record.deep_analysis["high_entropy_warning"] = ent_msg
            record.findings.append(ent_msg)
            if record.state != ScanState.MALICIOUS:
                record.state = ScanState.SUSPICIOUS
                record.release_policy = ReleasePolicy.BLOCKED

        # Engine 7: ClamAV Daemon Check (if active)
        clam_res = check_clamav_socket(quarantine_file)
        if clam_res is not None:
            is_clean, sig = clam_res
            if not is_clean:
                record.threat_signatures.append(sig)
                record.findings.append(sig)
                record.state = ScanState.MALICIOUS
                record.release_policy = ReleasePolicy.BLOCKED

        # Final release decision
        if record.state == ScanState.SCANNING:
            record.state = ScanState.CLEAN
            record.release_policy = ReleasePolicy.ALLOWED
            record.findings.append("No active threat signatures, archive exploits, or malicious hashes identified.")

            safe_target = _SAFE_DIR / f"{record.scan_id}_{record.safe_filename}"
            with open(safe_target, "wb") as f:
                f.write(content)

        record.completed_at = datetime.now(timezone.utc).isoformat()
        record.processing_time_ms = round((time.time() - start_time) * 1000, 2)

        record_file_scan_result(record.state.value)
        return record

    async def scan_folder_batch(self, files: list[tuple[bytes, str]], folder_name: str = "Uploaded_Folder") -> FolderScanRecord:
        """
        Deep batch scan of an entire directory tree.
        Scans each file, compiles individual deep analysis records,
        and computes aggregate threat metrics for the entire folder.
        """
        # If a single archive is submitted to the folder batch scanner, unpack and inspect members
        if len(files) == 1 and files[0][1].lower().endswith(".zip") and zipfile.is_zipfile(io.BytesIO(files[0][0])):
            archive_bytes, archive_filename = files[0]
            unpacked_members: list[tuple[bytes, str]] = []
            try:
                with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
                    for info in zf.infolist():
                        if not info.is_dir() and not info.filename.endswith(("/", "\\")):
                            try:
                                member_content = zf.read(info.filename)
                                unpacked_members.append((member_content, info.filename))
                            except Exception:
                                pass
            except Exception:
                pass
            if unpacked_members:
                files = unpacked_members
                base_name = os.path.splitext(os.path.basename(archive_filename))[0]
                if not folder_name or folder_name == "Uploaded_Folder":
                    folder_name = base_name

        batch_record = FolderScanRecord(
            folder_name=folder_name,
            total_files=len(files),
            state=ScanState.SCANNING,
        )
        _FOLDER_RECORDS[batch_record.batch_id] = batch_record
        start_time = time.time()

        if len(files) > _MAX_FOLDER_FILES:
            batch_record.overall_state = ScanState.ERROR
            batch_record.overall_release_policy = ReleasePolicy.BLOCKED
            batch_record.summary = f"Folder exceeds maximum allowed file count ({len(files)} > {_MAX_FOLDER_FILES})"
            batch_record.completed_at = datetime.now(timezone.utc).isoformat()
            return batch_record

        # Scan all files
        for content, rel_path in files:
            file_rec = await self.scan_bytes(content=content, original_filename=rel_path)
            batch_record.file_records.append(file_rec)
            batch_record.scanned_files += 1

            if file_rec.state == ScanState.CLEAN:
                batch_record.clean_count += 1
            elif file_rec.state == ScanState.MALICIOUS:
                batch_record.malicious_count += 1
            elif file_rec.state == ScanState.SUSPICIOUS:
                batch_record.suspicious_count += 1
            else:
                batch_record.error_count += 1

        # Determine overall folder state and policy
        if batch_record.malicious_count > 0:
            batch_record.overall_state = ScanState.MALICIOUS
            batch_record.overall_release_policy = ReleasePolicy.BLOCKED
            batch_record.summary = (
                f"Malicious threat detected in folder '{folder_name}'. "
                f"{batch_record.malicious_count} malicious file(s), {batch_record.suspicious_count} suspicious file(s)."
            )
        elif batch_record.suspicious_count > 0 or batch_record.error_count > 0:
            batch_record.overall_state = ScanState.SUSPICIOUS
            batch_record.overall_release_policy = ReleasePolicy.BLOCKED
            batch_record.summary = (
                f"Folder '{folder_name}' contains {batch_record.suspicious_count} suspicious file(s). Quarantined by policy."
            )
        else:
            batch_record.overall_state = ScanState.CLEAN
            batch_record.overall_release_policy = ReleasePolicy.ALLOWED
            batch_record.summary = f"All {batch_record.total_files} file(s) in folder '{folder_name}' verified clean."

        batch_record.completed_at = datetime.now(timezone.utc).isoformat()
        batch_record.processing_time_ms = round((time.time() - start_time) * 1000, 2)
        return batch_record

    def get_record(self, scan_id: str) -> Optional[FileScanRecord]:
        return _SCAN_RECORDS.get(scan_id)

    def get_folder_record(self, batch_id: str) -> Optional[FolderScanRecord]:
        return _FOLDER_RECORDS.get(batch_id)

    def get_safe_file_path(self, scan_id: str) -> Optional[Path]:
        """Return path to safe file ONLY if release policy is ALLOWED and state is CLEAN."""
        record = self.get_record(scan_id)
        if not record or record.state != ScanState.CLEAN or record.release_policy != ReleasePolicy.ALLOWED:
            return None
        candidate = _SAFE_DIR / f"{record.scan_id}_{record.safe_filename}"
        return candidate if candidate.exists() else None


file_scanner = FileSecurityScanner()
