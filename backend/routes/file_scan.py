"""
File Security & Threat Inspection Router (Phase 7).

Endpoints:
- POST /api/scan/file: Ingest and inspect upload with streaming SHA-256 and multi-engine analysis.
- POST /api/scan/url: Platform-managed remote download inspector with quarantine streaming.
- GET /api/scan/{scan_id}: Retrieve scan report and threat signatures.
- GET /api/scan/{scan_id}/download: Secure release gate. Returns file ONLY if verdict is CLEAN.
"""

from __future__ import annotations

import logging
import os
from typing import Optional
from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, Query, Request, Response, UploadFile, status
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, HttpUrl

from backend.config import get_settings
from backend.services.file_scanner import (
    FileScanRecord,
    FolderScanRecord,
    ReleasePolicy,
    ScanState,
    file_scanner,
)
from backend.services.scan_queue import scan_job_manager
from backend.utils.rate_limiter import check_rate_limit
from backend.utils.security_logging import safe_error_message

logger = logging.getLogger("cyber_guardian.file_scan_router")
settings = get_settings()

file_scan_router = APIRouter(prefix="/api/scan", tags=["file_security"])


class UrlScanRequest(BaseModel):
    download_url: str
    custom_filename: str = ""


@file_scan_router.post("/file")
async def scan_uploaded_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    async_mode: bool = Query(False, description="When true, queues scan asynchronously and returns 202 Accepted"),
    raw_request: Request = None,
):
    """
    Ingest and inspect file upload or platform download.
    Streams contents into isolated quarantine, computes SHA-256 & SHA-1,
    detects magic-byte signatures, archive bombs, and malware signatures.
    Supports asynchronous execution via ?async_mode=true.
    """
    if raw_request:
        check_rate_limit(raw_request)

    max_bytes = 50 * 1024 * 1024
    content = await file.read(max_bytes + 1)
    filename = file.filename or "downloaded_file.bin"

    if async_mode:
        job = scan_job_manager.create_job(filename=filename, size_bytes=len(content))
        background_tasks.add_task(scan_job_manager.run_scan_job, job, content, filename)
        return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content=job.to_dict())

    record = await file_scanner.scan_bytes(content=content, original_filename=filename)
    return record


@file_scan_router.get("/jobs/{job_id}")
async def get_scan_job_status(job_id: str, raw_request: Request = None):
    """
    Poll status, real-time stage progress, and final results of an asynchronous scan job.
    """
    if raw_request:
        check_rate_limit(raw_request)

    job = scan_job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found or expired.")

    return job.to_dict()


@file_scan_router.post("/folder", response_model=FolderScanRecord)
async def scan_uploaded_folder(
    files: list[UploadFile] = File(...),
    folder_name: Optional[str] = Form(None),
    raw_request: Request = None,
):
    """
    Deep recursive inspection of an entire folder tree or file batch.
    Scans every file, extracts entropy, detects disguised malware binaries and archive bombs,
    and returns a comprehensive folder security audit.
    """
    if raw_request:
        check_rate_limit(raw_request)
        if not folder_name:
            folder_name = raw_request.query_params.get("folder_name")

    resolved_folder_name = folder_name or "Uploaded_Folder"

    file_payloads = []
    max_bytes = 50 * 1024 * 1024
    for f in files:
        content = await f.read(max_bytes + 1)
        filename = f.filename or "file.bin"
        file_payloads.append((content, filename))

    batch_record = await file_scanner.scan_folder_batch(file_payloads, folder_name=resolved_folder_name)
    return batch_record


@file_scan_router.get("/folder/{batch_id}", response_model=FolderScanRecord)
async def get_folder_scan_status(batch_id: str):
    """Retrieve folder batch inspection report by batch_id."""
    record = file_scanner.get_folder_record(batch_id)
    if not record:
        raise HTTPException(status_code=404, detail="Folder scan record not found.")
    return record


@file_scan_router.post("/url", response_model=FileScanRecord)
async def scan_remote_download_url(
    req: UrlScanRequest,
    raw_request: Request = None,
):
    """
    Platform-managed download monitoring:
    Streams remote URL directly into quarantine storage with size limits,
    computing hashes on the fly and evaluating threat signatures before release.
    """
    if raw_request:
        check_rate_limit(raw_request)

    import httpx
    from urllib.parse import urlparse

    from backend.utils.ssrf import validate_url_for_ssrf

    target_url = req.download_url.strip()
    if not target_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Invalid download URL protocol.")

    # Enforce strict SSRF pre-check
    is_safe, reason = validate_url_for_ssrf(target_url)
    if not is_safe:
        raise HTTPException(
            status_code=400,
            detail=f"Download URL blocked by SSRF defense: {reason}",
        )

    parsed = urlparse(target_url)
    inferred_filename = req.custom_filename.strip() or os.path.basename(parsed.path) or "download.bin"

    # Stream download with bounded size limit and redirect SSRF verification
    max_bytes = 50 * 1024 * 1024
    chunks = []
    total_received = 0

    try:
        current_url = target_url
        redirect_count = 0
        max_redirects = 3
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            while True:
                async with client.stream("GET", current_url) as resp:
                    if resp.is_redirect and "location" in resp.headers:
                        redirect_count += 1
                        if redirect_count > max_redirects:
                            raise HTTPException(status_code=400, detail="Exceeded maximum redirects for remote download.")
                        next_url = str(resp.headers["location"])
                        if next_url.startswith("/"):
                            parsed_curr = urlparse(current_url)
                            next_url = f"{parsed_curr.scheme}://{parsed_curr.netloc}{next_url}"
                        is_safe_redirect, redirect_reason = validate_url_for_ssrf(next_url)
                        if not is_safe_redirect:
                            raise HTTPException(
                                status_code=400,
                                detail=f"SSRF blocked on download redirect: {redirect_reason}",
                            )
                        current_url = next_url
                        continue

                    if resp.status_code >= 400:
                        raise HTTPException(
                            status_code=400,
                            detail=f"Remote server responded with HTTP {resp.status_code}",
                        )
                    async for chunk in resp.aiter_bytes():
                        total_received += len(chunk)
                        if total_received > max_bytes:
                            raise HTTPException(
                                status_code=413,
                                detail="Remote download exceeds maximum 50 MB safety limit",
                            )
                        chunks.append(chunk)
                    break
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch remote download: {safe_error_message(e)}")

    full_content = b"".join(chunks)
    record = await file_scanner.scan_bytes(content=full_content, original_filename=inferred_filename)
    return record


@file_scan_router.get("/{scan_id}", response_model=FileScanRecord)
async def get_scan_status(scan_id: str):
    """Retrieve file inspection report by scan_id."""
    record = file_scanner.get_record(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return record


@file_scan_router.get("/{scan_id}/download")
async def download_safe_file(scan_id: str):
    """
    Strict Release Gate:
    Releases inspected file to the citizen ONLY if verdict is CLEAN and policy is ALLOWED.
    Returns HTTP 403 Forbidden with security findings if quarantined.
    """
    record = file_scanner.get_record(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    if record.state != ScanState.CLEAN or record.release_policy != ReleasePolicy.ALLOWED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "Download Blocked by CyberKawach Quarantine Policy",
                "state": record.state.value,
                "release_policy": record.release_policy.value,
                "threat_signatures": record.threat_signatures,
                "findings": record.findings,
            },
        )

    safe_path = file_scanner.get_safe_file_path(scan_id)
    if not safe_path or not safe_path.exists():
        raise HTTPException(status_code=404, detail="Inspected file no longer available on disk.")

    return FileResponse(
        path=str(safe_path),
        filename=record.safe_filename,
        media_type=record.magic_mime,
    )
