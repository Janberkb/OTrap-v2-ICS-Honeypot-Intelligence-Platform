"""
manager/security/csrf.py — Double-submit cookie CSRF protection.

Pattern:
1. GET /api/v1/auth/csrf-token  → sets HttpOnly cookie "csrf_token" + returns it in JSON
2. All state-mutating requests must include header X-CSRF-Token matching the cookie value
3. Middleware validates header == cookie before routing reaches handlers
"""

from __future__ import annotations

import secrets
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

SAFE_METHODS  = {"GET", "HEAD", "OPTIONS"}
CSRF_HEADER   = "x-csrf-token"
CSRF_COOKIE   = "csrf_token"
EXEMPT_PATHS  = {"/api/v1/auth/csrf-token", "/api/v1/health", "/api/v1/stream"}


class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.method in SAFE_METHODS:
            return await call_next(request)

        # Exempt certain paths
        if request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        # Validate CSRF
        header_token = request.headers.get(CSRF_HEADER)
        cookie_token = request.cookies.get(CSRF_COOKIE)

        if not header_token or not cookie_token:
            return JSONResponse(
                {"error": "CSRF_REQUIRED", "message": "CSRF token required"},
                status_code=403,
            )

        if not secrets.compare_digest(header_token, cookie_token):
            return JSONResponse(
                {"error": "CSRF_FAILED", "message": "CSRF token mismatch"},
                status_code=403,
            )

        return await call_next(request)


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)
