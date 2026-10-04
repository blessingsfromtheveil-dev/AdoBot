"""Explicit command allowlist.

Arbitrary shell execution is intentionally absent.
"""

from __future__ import annotations

from enum import StrEnum


class Command(StrEnum):
    STATUS = "status"
    DIAGNOSTICS = "diagnostics"
    PERMISSIONS = "permissions"
    HEARTBEAT = "heartbeat"

    # These operations require explicit device-owner authorization
    # in the Android client.
    APPROVED_CAPTURE = "approved_capture"
    APPROVED_EXPORT = "approved_export"


READ_ONLY = {
    Command.STATUS,
    Command.DIAGNOSTICS,
    Command.PERMISSIONS,
    Command.HEARTBEAT,
}

CONSENT_REQUIRED = {
    Command.APPROVED_CAPTURE,
    Command.APPROVED_EXPORT,
}


def is_allowed(value: str) -> bool:
    try:
        Command(value)
        return True
    except ValueError:
        return False
