"""
Request size limit middleware — prevents DoS via oversized payloads.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Rejects requests whose Content-Length or body size exceeds max_bytes.
    Returns HTTP 413 Payload Too Large.
    """

    def __init__(self, app, max_bytes: int = 10 * 1024 * 1024):  # 10 MB default
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        # Check Content-Length header if present
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
                if length > self.max_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "error": "Payload Too Large",
                            "detail": f"Request size {length} bytes exceeds maximum permitted size of {self.max_bytes} bytes.",
                        },
                    )
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"error": "Bad Request", "detail": "Invalid Content-Length header"},
                )

        return await call_next(request)
