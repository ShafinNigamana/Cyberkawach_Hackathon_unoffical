"""
In-memory rate limiter middleware for FastAPI.

SEC-03: Rate limiting on API endpoints to prevent brute-force attacks and abuse.
Ponytail principle: In-memory sliding window, no Redis required.
"""

from __future__ import annotations

import time
from collections import defaultdict
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Sliding-window in-memory rate limiter by client IP.
    Default: 60 requests per minute per IP.
    """

    def __init__(self, app, max_requests: int = 60, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.request_records: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        # Exclude static assets and health check from strict rate limits
        path = request.url.path
        if path.startswith(("/css", "/js", "/fixtures")) or path == "/api/health" or path == "/":
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window_start = now - self.window_seconds

        # Clean timestamps older than the sliding window
        timestamps = [t for t in self.request_records[client_ip] if t > window_start]
        self.request_records[client_ip] = timestamps

        if len(timestamps) >= self.max_requests:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate limit exceeded",
                    "detail": f"Maximum {self.max_requests} requests per minute allowed.",
                    "retry_after_seconds": int(self.window_seconds - (now - timestamps[0])),
                },
                headers={"Retry-After": str(self.window_seconds)},
            )

        self.request_records[client_ip].append(now)
        return await call_next(request)
