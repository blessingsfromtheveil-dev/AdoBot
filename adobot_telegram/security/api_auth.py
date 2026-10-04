"""Fail-closed authentication primitives for the local AdoBot API.

This module does not expose secrets and does not execute commands.
Requests are authenticated with HMAC-SHA256 over a canonical envelope.
"""

from __future__ import annotations

import hashlib
import hmac
import time


MAX_CLOCK_SKEW_SECONDS = 300


class APIAuthenticationError(ValueError):
    """Raised when an API authentication envelope is invalid."""


def canonical_message(
    *,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    request_id: str,
    body_hash: str,
) -> bytes:
    values = (
        method.upper(),
        path,
        timestamp,
        nonce,
        request_id,
        body_hash,
    )

    if any(not value or "\n" in value or "\r" in value for value in values):
        raise APIAuthenticationError("invalid authentication envelope")

    return "\n".join(values).encode("utf-8")


def body_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def sign(
    secret: bytes,
    *,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    request_id: str,
    body: bytes = b"",
) -> str:
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise APIAuthenticationError("authentication secret is too short")

    message = canonical_message(
        method=method,
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        request_id=request_id,
        body_hash=body_digest(body),
    )

    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def verify(
    secret: bytes,
    signature: str,
    *,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    request_id: str,
    body: bytes = b"",
    now: float | None = None,
) -> None:
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise APIAuthenticationError("authentication secret is not configured")

    if not signature or len(signature) != 64:
        raise APIAuthenticationError("invalid signature")

    try:
        timestamp_value = int(timestamp)
    except (TypeError, ValueError) as exc:
        raise APIAuthenticationError("invalid timestamp") from exc

    current = time.time() if now is None else now

    if abs(current - timestamp_value) > MAX_CLOCK_SKEW_SECONDS:
        raise APIAuthenticationError("authentication timestamp expired")

    expected = sign(
        secret,
        method=method,
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        request_id=request_id,
        body=body,
    )

    if not hmac.compare_digest(expected, signature):
        raise APIAuthenticationError("authentication failed")
