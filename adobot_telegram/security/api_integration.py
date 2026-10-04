"""Authenticated AdoBot API request integration.

This module contains the server-side authentication boundary for the
local AdoBot HTTP API. It is intentionally fail-closed.

The API secret is environment-only and is never returned, logged, or
written to the audit chain.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ..audit.config import AUDIT, AUDIT_PATH
from .api_auth import APIAuthenticationError, verify
from .rate_limit import RateLimitExceeded, RateLimiter
from .replay import ReplayCache

PROTECTED_PATHS = frozenset({
    "/api",
    "/info",
    "/diagnostics",
})

SECRET_ENV = "ADOBOT_API_HMAC_SECRET"

HEADER_TIMESTAMP = "X-AdoBot-Timestamp"
HEADER_NONCE = "X-AdoBot-Nonce"
HEADER_REQUEST_ID = "X-AdoBot-Request-ID"
HEADER_SIGNATURE = "X-AdoBot-Signature"

MAX_SECRET_BYTES = 4096
MAX_HEADER_BYTES = 256

API_RATE_LIMITER = RateLimiter(
    limit=30,
    window_seconds=60.0,
)

API_REPLAY_CACHE = ReplayCache(
    max_entries=4096,
    ttl_seconds=300,
)

API_AUDIT = AUDIT
@dataclass(frozen=True, slots=True)
class APIAuthDecision:
    allowed: bool
    reason: str
    request_id: str


def _secret_from_environment() -> bytes:
    value = os.environ.get(SECRET_ENV)

    if not value:
        raise APIAuthenticationError(
            "API authentication secret is not configured"
        )

    secret = value.encode("utf-8")

    if len(secret) < 32:
        raise APIAuthenticationError(
            "API authentication secret is too short"
        )

    if len(secret) > MAX_SECRET_BYTES:
        raise APIAuthenticationError(
            "API authentication secret is too long"
        )

    return secret


def _header(request: Request, name: str) -> str:
    value = request.headers.get(name, "").strip()

    if not value:
        raise APIAuthenticationError(
            f"missing required authentication header: {name}"
        )

    if len(value.encode("utf-8")) > MAX_HEADER_BYTES:
        raise APIAuthenticationError(
            f"authentication header is too long: {name}"
        )

    return value


def _request_id_for_audit(request: Request) -> str:
    value = request.headers.get(
        HEADER_REQUEST_ID,
        "",
    ).strip()

    if not value:
        return "unauthenticated"

    return value[:MAX_HEADER_BYTES]


async def authenticate_request(
    request: Request,
) -> APIAuthDecision:
    path = request.url.path

    if path not in PROTECTED_PATHS:
        return APIAuthDecision(
            True,
            "public",
            "public",
        )

    request_id = _request_id_for_audit(request)

    try:
        secret = _secret_from_environment()

        timestamp = _header(
            request,
            HEADER_TIMESTAMP,
        )

        nonce = _header(
            request,
            HEADER_NONCE,
        )

        request_id = _header(
            request,
            HEADER_REQUEST_ID,
        )

        signature = _header(
            request,
            HEADER_SIGNATURE,
        )

        body = await request.body()

        principal = "telegram-worker"

        # Authenticate first. An unauthenticated caller must not be able
        # to consume the authenticated principal's rate-limit bucket.
        verify(
            secret,
            signature,
            method=request.method,
            path=path,
            timestamp=timestamp,
            nonce=nonce,
            request_id=request_id,
            body=body,
        )

        API_RATE_LIMITER.check(principal)

        if not API_REPLAY_CACHE.check_and_record(
            principal=principal,
            command_id=request_id,
            nonce=nonce,
        ):
            raise APIAuthenticationError(
                "replayed API request"
            )

        API_AUDIT.append(
            event="api.authentication",
            actor=principal,
            outcome="accepted",
            request_id=request_id,
        )

        return APIAuthDecision(
            True,
            "authenticated",
            request_id,
        )

    except RateLimitExceeded:
        API_AUDIT.append(
            event="api.authentication",
            actor="telegram-worker",
            outcome="rate_limited",
            request_id=request_id,
        )

        return APIAuthDecision(
            False,
            "rate_limited",
            request_id,
        )

    except (APIAuthenticationError, ValueError):
        API_AUDIT.append(
            event="api.authentication",
            actor="unknown",
            outcome="denied",
            request_id=request_id,
        )

        return APIAuthDecision(
            False,
            "authentication_failed",
            request_id,
        )


class APIAuthenticationMiddleware(BaseHTTPMiddleware):
    """Fail-closed HTTP authentication boundary for protected routes."""

    async def dispatch(
        self,
        request: Request,
        call_next,
    ) -> Response:
        decision = await authenticate_request(request)

        if not decision.allowed:
            status = (
                429
                if decision.reason == "rate_limited"
                else 401
            )

            return JSONResponse(
                {
                    "error": (
                        "authentication_required"
                        if status == 401
                        else "rate_limit_exceeded"
                    ),
                },
                status_code=status,
            )

        return await call_next(request)
