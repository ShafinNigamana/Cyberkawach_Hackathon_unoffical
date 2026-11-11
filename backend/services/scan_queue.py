"""
Asynchronous Scan Job Queue & Concurrency Manager.

Prevents worker thread exhaustion and request timeouts during heavy forensic
archive unpacking and bytecode analysis by decoupling long-running scans into
non-blocking asynchronous tasks with progress tracking.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
from threading import Lock
import time
from typing import Any, Dict, Optional
import uuid

from backend.services.file_scanner import FileScanRecord, file_scanner

logger = logging.getLogger("cyber_guardian.scan_queue")


class ScanJobStatus:
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanJob:
    def __init__(self, job_id: str, filename: str, size_bytes: int):
        self.job_id = job_id
        self.filename = filename
        self.size_bytes = size_bytes
        self.status = ScanJobStatus.QUEUED
        self.progress_percent = 0
        self.stage = "enqueued"
        self.result: Optional[Dict[str, Any]] = None
        self.error: Optional[str] = None
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.completed_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "filename": self.filename,
            "size_bytes": self.size_bytes,
            "status": self.status,
            "progress_percent": self.progress_percent,
            "stage": self.stage,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }


class ScanJobManager:
    """Bounded asynchronous queue for deep file forensics."""

    def __init__(self, max_concurrent_jobs: int = 4, max_history: int = 500):
        self._semaphore = asyncio.Semaphore(max_concurrent_jobs)
        self._jobs: Dict[str, ScanJob] = {}
        self._lock = Lock()
        self.max_history = max_history

    def get_job(self, job_id: str) -> Optional[ScanJob]:
        with self._lock:
            return self._jobs.get(job_id)

    def create_job(self, filename: str, size_bytes: int) -> ScanJob:
        job_id = f"JOB-{uuid.uuid4().hex[:12].upper()}"
        job = ScanJob(job_id=job_id, filename=filename, size_bytes=size_bytes)
        with self._lock:
            self._jobs[job_id] = job
            if len(self._jobs) > self.max_history:
                oldest_id = next(iter(self._jobs))
                del self._jobs[oldest_id]
        return job

    async def run_scan_job(self, job: ScanJob, content: bytes, filename: str) -> None:
        await self._process_scan_job(job, content, filename)

    async def enqueue_scan(self, content: bytes, filename: str) -> ScanJob:
        job = self.create_job(filename, len(content))
        asyncio.create_task(self._process_scan_job(job, content, filename))
        return job

    async def _process_scan_job(self, job: ScanJob, content: bytes, filename: str) -> None:
        async with self._semaphore:
            job.status = ScanJobStatus.PROCESSING
            job.stage = "quarantine_hashing"
            job.progress_percent = 25

            try:
                # Yield control briefly so status updates propagate
                await asyncio.sleep(0.01)

                job.stage = "deep_bytecode_inspection"
                job.progress_percent = 60

                record: FileScanRecord = await file_scanner.scan_bytes(
                    content=content, original_filename=filename
                )

                job.stage = "completed"
                job.progress_percent = 100
                job.status = ScanJobStatus.COMPLETED
                job.result = record.model_dump(mode="json")
                job.completed_at = datetime.now(timezone.utc).isoformat()

            except Exception as e:
                logger.exception(f"Async scan job {job.job_id} failed: {e}")
                job.status = ScanJobStatus.FAILED
                job.stage = "failed"
                job.error = str(e)
                job.completed_at = datetime.now(timezone.utc).isoformat()


# Global scan queue instance
scan_job_manager = ScanJobManager(max_concurrent_jobs=4)
