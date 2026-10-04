from __future__ import annotations

import os
from pathlib import Path

from .chain import AuditChain


ROOT = Path(__file__).resolve().parents[2]

# One canonical append-only security audit chain for all local security
# integrations. An explicit environment override is supported, but both
# integrations import the same singleton from this module.
DEFAULT_AUDIT_PATH = ROOT / "runtime" / "security-audit.jsonl"

AUDIT_PATH = Path(
    os.environ.get("ADOBOT_AUDIT_PATH", str(DEFAULT_AUDIT_PATH))
).expanduser()

AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
AUDIT = AuditChain(AUDIT_PATH)
