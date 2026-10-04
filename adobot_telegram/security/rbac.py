"""Minimal fail-closed role authorization."""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


PERMISSIONS = {
    Role.ADMIN: {
        "device.read",
        "device.diagnostics",
        "device.command",
        "device.schedule",
        "audit.read",
        "security.manage",
    },
    Role.OPERATOR: {
        "device.read",
        "device.diagnostics",
        "device.command",
        "device.schedule",
        "audit.read",
    },
    Role.VIEWER: {
        "device.read",
        "device.diagnostics",
        "audit.read",
    },
}


def authorize(role: str, permission: str) -> bool:
    try:
        parsed = Role(role)
    except ValueError:
        return False

    return permission in PERMISSIONS.get(parsed, set())
