from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from .rate_limit import RateLimiter, RateLimitExceeded
from .rbac import Role, authorize
from ..audit.config import AUDIT, AUDIT_PATH


ROOT = Path(__file__).resolve().parents[2]

# Public commands intentionally remain informational only.
PUBLIC_COMMANDS = frozenset({"start", "help"})

# Existing operational/API commands require an authenticated allowlisted
# Telegram identity. No arbitrary command execution is exposed.
PROTECTED_PERMISSIONS = {
    "status": "device.read",
    "diagnostics": "device.diagnostics",
    "api_root": "device.read",
    "api_status": "device.read",
    "api_ready": "device.read",
    "api_info": "device.read",
}

RATE_LIMITER = RateLimiter(limit=30, window_seconds=60.0)


def _configured_role_ids(env_name: str) -> frozenset[int]:
    raw = os.environ.get(env_name, "")
    if not raw.strip():
        return frozenset()

    values: set[int] = set()

    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue

        try:
            value = int(item)
        except ValueError as exc:
            raise RuntimeError(
                f"{env_name} contains a non-integer value"
            ) from exc

        if value <= 0:
            raise RuntimeError(
                f"{env_name} must contain positive integers"
            )

        values.add(value)

    return frozenset(values)


def _configured_roles() -> dict[int, Role]:
    role_groups = {
        Role.ADMIN: _configured_role_ids("ADOBOT_TELEGRAM_ADMIN_IDS"),
        Role.OPERATOR: _configured_role_ids("ADOBOT_TELEGRAM_OPERATOR_IDS"),
        Role.VIEWER: _configured_role_ids("ADOBOT_TELEGRAM_VIEWER_IDS"),
    }

    roles: dict[int, Role] = {}

    for role, user_ids in role_groups.items():
        for user_id in user_ids:
            existing = roles.get(user_id)

            if existing is not None and existing is not role:
                raise RuntimeError(
                    f"Telegram user ID assigned multiple roles: {user_id}"
                )

            roles[user_id] = role

    return roles


def principal_for_user(user_id: int | None) -> str:
    if user_id is None or user_id <= 0:
        return ""
    return f"telegram:{user_id}"


@dataclass(frozen=True)
class SecurityDecision:
    allowed: bool
    reason: str
    request_id: str


def authorize_telegram_command(
    *,
    command: str,
    user_id: int | None,
) -> SecurityDecision:
    normalized = command.strip().lower().lstrip("/")
    request_id = secrets.token_hex(16)

    if normalized in PUBLIC_COMMANDS:
        AUDIT.append(
            event=f"telegram.command.{normalized}",
            actor=principal_for_user(user_id) or "anonymous",
            outcome="accepted",
            request_id=request_id,
        )
        return SecurityDecision(True, "public", request_id)

    principal = principal_for_user(user_id)

    if not principal:
        AUDIT.append(
            event=f"telegram.command.{normalized}",
            actor="anonymous",
            outcome="denied",
            request_id=request_id,
        )
        return SecurityDecision(False, "missing_identity", request_id)

    try:
        RATE_LIMITER.check(principal)
    except RateLimitExceeded:
        AUDIT.append(
            event=f"telegram.command.{normalized}",
            actor=principal,
            outcome="denied",
            request_id=request_id,
        )
        return SecurityDecision(False, "rate_limited", request_id)

    permission = PROTECTED_PERMISSIONS.get(normalized)

    if permission is None:
        AUDIT.append(
            event=f"telegram.command.{normalized}",
            actor=principal,
            outcome="denied",
            request_id=request_id,
        )
        return SecurityDecision(False, "command_not_allowlisted", request_id)

    try:
        roles = _configured_roles()
    except RuntimeError:
        AUDIT.append(
            event=f"telegram.command.{normalized}",
            actor=principal,
            outcome="denied",
            request_id=request_id,
        )
        return SecurityDecision(
            False,
            "invalid_role_configuration",
            request_id,
        )

    role = roles.get(user_id)

    if role is None:
        AUDIT.append(
            event=f"telegram.command.{normalized}",
            actor=principal,
            outcome="denied",
            request_id=request_id,
        )
        return SecurityDecision(False, "identity_not_allowlisted", request_id)

    if not authorize(role.value, permission):
        AUDIT.append(
            event=f"telegram.command.{normalized}",
            actor=principal,
            outcome="denied",
            request_id=request_id,
        )
        return SecurityDecision(False, "permission_denied", request_id)

    AUDIT.append(
        event=f"telegram.command.{normalized}",
        actor=principal,
        outcome="accepted",
        request_id=request_id,
    )

    return SecurityDecision(True, "authorized", request_id)
