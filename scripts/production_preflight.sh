#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1

PASS=0
FAIL=0
WARN=0

pass() {
    printf 'PASS  %s\n' "$1"
    PASS=$((PASS + 1))
}

fail() {
    printf 'FAIL  %s\n' "$1"
    FAIL=$((FAIL + 1))
}

warn() {
    printf 'WARN  %s\n' "$1"
    WARN=$((WARN + 1))
}

section() {
    printf '\n===== %s =====\n' "$1"
}

# ---------------------------------------------------------------------------
# 0. Operational boundary
# ---------------------------------------------------------------------------

section "OPERATIONAL BOUNDARY"

printf '%s\n' \
    "NETWORK_REQUESTS=NOT_PERFORMED" \
    "SERVICE_START=NOT_PERFORMED" \
    "SERVICE_RESTART=NOT_PERFORMED" \
    "TELEGRAM_REQUESTS=NOT_PERFORMED" \
    "DEPLOY=NOT_PERFORMED" \
    "COMMIT=NOT_PERFORMED" \
    "PUSH=NOT_PERFORMED" \
    "SOURCE_RESET=NOT_PERFORMED"

pass "Read-only operational boundary"

# ---------------------------------------------------------------------------
# 1. Repository/runtime identity
# ---------------------------------------------------------------------------

section "REPOSITORY / RUNTIME"

if [ -d "$ROOT/.git" ]; then
    pass "Git repository present"
else
    fail "Git repository missing"
fi

if [ -x "$ROOT/.venv/bin/python" ]; then
    pass "Virtual environment present"
else
    fail "Expected .venv/bin/python missing"
fi

if "$ROOT/.venv/bin/python" --version >/dev/null 2>&1; then
    printf 'INFO  Python: '
    "$ROOT/.venv/bin/python" --version
    pass "Python executable usable"
else
    fail "Python executable unusable"
fi

if git -C "$ROOT" rev-parse HEAD >/dev/null 2>&1; then
    printf 'INFO  Git HEAD: %s\n' "$(git -C "$ROOT" rev-parse HEAD)"
    pass "Git HEAD readable"
else
    fail "Unable to read Git HEAD"
fi

# ---------------------------------------------------------------------------
# 2. Working-tree integrity
# ---------------------------------------------------------------------------

section "WORKING TREE"

if git -C "$ROOT" diff --check >/dev/null 2>&1; then
    pass "Git diff whitespace/error check"
else
    fail "Git diff --check reported errors"
fi

printf 'INFO  Working-tree status:\n'
git -C "$ROOT" status --short

# This is informational, not a failure: the security implementation is
# intentionally uncommitted in the current project state.
if [ -z "$(git -C "$ROOT" status --porcelain)" ]; then
    pass "Working tree clean"
else
    warn "Working tree contains changes; no changes were modified"
fi

# ---------------------------------------------------------------------------
# 3. Required production environment variables
# ---------------------------------------------------------------------------

section "PRODUCTION ENVIRONMENT"

required_env=(
    "ADOBOT_API_HMAC_SECRET"
    "TELEGRAM_BOT_TOKEN"
)

for name in "${required_env[@]}"; do
    value="${!name-}"

    if [ -z "$value" ]; then
        fail "$name is not configured"
        continue
    fi

    # Never print the value.
    pass "$name is present"
done

# ---------------------------------------------------------------------------
# 4. HMAC configuration
# ---------------------------------------------------------------------------

section "HMAC CONFIGURATION"

if "$ROOT/.venv/bin/python" - <<'PY'
import os
from adobot_telegram.security.api_integration import _secret_from_environment

name = "ADOBOT_API_HMAC_SECRET"
value = os.environ.get(name)

if value is None or value == "":
    raise SystemExit("missing")

secret = _secret_from_environment()

if not isinstance(secret, bytes):
    raise SystemExit("not-bytes")

if len(secret) < 32:
    raise SystemExit("too-short")

print("HMAC_SECRET_VALID=YES")
PY
then
    pass "ADOBOT_API_HMAC_SECRET satisfies production requirements"
else
    fail "ADOBOT_API_HMAC_SECRET failed production validation"
fi

# ---------------------------------------------------------------------------
# 5. Telegram token sanity check
# ---------------------------------------------------------------------------

section "TELEGRAM CONFIGURATION"

if [ -n "${TELEGRAM_BOT_TOKEN-}" ]; then
    # Telegram Bot API tokens conventionally have:
    #   numeric bot id : opaque token
    #
    # This checks shape only. It does NOT contact Telegram.
    if printf '%s' "$TELEGRAM_BOT_TOKEN" |
        grep -Eq '^[0-9]{6,12}:[A-Za-z0-9_-]{20,}$'
    then
        pass "TELEGRAM_BOT_TOKEN has valid-looking token shape"
    else
        fail "TELEGRAM_BOT_TOKEN has invalid-looking token shape"
    fi
else
    fail "TELEGRAM_BOT_TOKEN unavailable for validation"
fi

# ---------------------------------------------------------------------------
# 6. Telegram RBAC
# ---------------------------------------------------------------------------

section "RBAC CONFIGURATION"

if "$ROOT/.venv/bin/python" - <<'PY'
from adobot_telegram.security.integration import _configured_roles

roles = _configured_roles()

print(f"CONFIGURED_PRINCIPALS={len(roles)}")

for principal, role in sorted(roles.items()):
    print(f"PRINCIPAL={principal} ROLE={role.value}")

if not roles:
    raise SystemExit("no Telegram principals configured")
PY
then
    pass "Telegram RBAC configuration is valid"
else
    fail "Telegram RBAC configuration is invalid or empty"
fi

# ---------------------------------------------------------------------------
# 7. Audit architecture
# ---------------------------------------------------------------------------

section "AUDIT ARCHITECTURE"

if "$ROOT/.venv/bin/python" - <<'PY'
from adobot_telegram.audit.config import AUDIT, AUDIT_PATH
from adobot_telegram.security import integration, api_integration

assert integration.AUDIT is AUDIT
assert api_integration.API_AUDIT is AUDIT

assert integration.AUDIT.path == AUDIT_PATH
assert api_integration.API_AUDIT.path == AUDIT_PATH

print(f"AUDIT_PATH={AUDIT_PATH}")
print("TELEGRAM_AND_API_SHARE_AUDIT_OBJECT=YES")
PY
then
    pass "Telegram/API share canonical audit object"
else
    fail "Telegram/API audit wiring is not unified"
fi

# ---------------------------------------------------------------------------
# 8. Audit filesystem permissions
# ---------------------------------------------------------------------------

section "AUDIT FILE SECURITY"

AUDIT_PATH="$(
    "$ROOT/.venv/bin/python" - <<'PY'
from adobot_telegram.audit.config import AUDIT_PATH
print(AUDIT_PATH)
PY
)"

if [ -f "$AUDIT_PATH" ]; then
    audit_dir="$(dirname "$AUDIT_PATH")"
    dir_mode="$(stat -c '%a' "$audit_dir")"
    file_mode="$(stat -c '%a' "$AUDIT_PATH")"

    printf 'INFO  Audit directory: %s mode=%s\n' "$audit_dir" "$dir_mode"
    printf 'INFO  Audit file:      %s mode=%s\n' "$AUDIT_PATH" "$file_mode"

    if [ "$dir_mode" = "700" ]; then
        pass "Audit directory mode 0700"
    else
        fail "Audit directory mode is not 0700"
    fi

    if [ "$file_mode" = "600" ]; then
        pass "Audit file mode 0600"
    else
        fail "Audit file mode is not 0600"
    fi
else
    fail "Canonical audit file does not exist"
fi

# ---------------------------------------------------------------------------
# 9. Audit-chain integrity
# ---------------------------------------------------------------------------

section "AUDIT INTEGRITY"

if "$ROOT/.venv/bin/python" - <<'PY'
from adobot_telegram.audit.config import AUDIT

result = AUDIT.verify()
print(f"AUDIT_VERIFY_RESULT={result}")

if result is not True:
    raise SystemExit(1)
PY
then
    pass "Audit chain verifies"
else
    fail "Audit chain verification failed"
fi

# ---------------------------------------------------------------------------
# 10. Dangerous execution scan
# ---------------------------------------------------------------------------

section "EXECUTION SURFACE"

if grep -RniE \
    --exclude-dir=.git \
    --exclude-dir=.venv \
    --exclude-dir=__pycache__ \
    --exclude='*.pyc' \
    --include='*.py' \
    '(^|[^[:alnum:]_])(subprocess\.(run|Popen|call|check_call|check_output)|os\.system|os\.popen|pty\.spawn|commands\.getoutput|commands\.getstatusoutput|shell[[:space:]]*=[[:space:]]*True)([^[:alnum:]_]|$)' \
    adobot_telegram app
then
    fail "Dangerous process-execution reference detected"
else
    pass "No dangerous process-execution primitive detected"
fi

# ---------------------------------------------------------------------------
# 11. Sensitive collection primitive scan
# ---------------------------------------------------------------------------

section "SENSITIVE COLLECTION SURFACE"

if grep -RniE \
    --exclude-dir=.git \
    --exclude-dir=.venv \
    --exclude-dir=__pycache__ \
    --exclude='*.pyc' \
    --include='*.py' \
    '(^|[^[:alnum:]_])(pynput|keyboard\.read|keylogger|cv2\.VideoCapture|sounddevice|pyaudio|geopy|gpsd|android\.location|ACCESS_FINE_LOCATION|ACCESS_COARSE_LOCATION)([^[:alnum:]_]|$)' \
    adobot_telegram app
then
    fail "Sensitive collection primitive detected"
else
    pass "No sensitive collection primitive detected"
fi

# ---------------------------------------------------------------------------
# 12. Secret-value exposure scan
# ---------------------------------------------------------------------------

section "SECRET EXPOSURE"

# Search source and common project text files for assignments containing
# non-placeholder secret values. The environment itself is intentionally
# never printed.
if grep -RniE \
    --exclude-dir=.git \
    --exclude-dir=.venv \
    --exclude-dir=__pycache__ \
    --exclude='*.pyc' \
    --include='*.py' \
    --include='*.sh' \
    --include='*.env' \
    --include='*.md' \
    --include='*.txt' \
    'TELEGRAM_BOT_TOKEN[[:space:]]*=[[:space:]]*[^[:space:]$"{<]|ADOBOT_API_HMAC_SECRET[[:space:]]*=[[:space:]]*[^[:space:]$"{<]' \
    adobot_telegram app scripts .env 2>/dev/null
then
    fail "Potential hard-coded secret assignment detected"
else
    pass "No hard-coded Telegram/HMAC secret assignment detected"
fi

# ---------------------------------------------------------------------------
# 13. Python syntax/compile validation without writing bytecode
# ---------------------------------------------------------------------------

section "PYTHON SOURCE VALIDATION"

if "$ROOT/.venv/bin/python" - <<'PY'
from pathlib import Path
import ast

roots = (Path("adobot_telegram"), Path("app"))
files = sorted(
    p for root in roots if root.exists()
    for p in root.rglob("*.py")
)

if not files:
    raise SystemExit("no Python source files found")

for path in files:
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

print(f"AST_FILES_CHECKED={len(files)}")
PY
then
    pass "All Python sources parse successfully"
else
    fail "Python AST validation failed"
fi

# ---------------------------------------------------------------------------
# 14. Regression suite
# ---------------------------------------------------------------------------

section "REGRESSION"

if "$ROOT/.venv/bin/pytest" \
    -q \
    -p no:cacheprovider \
    --disable-warnings
then
    pass "Regression suite passed"
else
    fail "Regression suite failed"
fi

# ---------------------------------------------------------------------------
# 15. Requirements sanity
# ---------------------------------------------------------------------------

section "DEPENDENCY CONTRACT"

if [ -f "$ROOT/requirements.txt" ]; then
    for requirement in \
        "starlette==0.47.3" \
        "uvicorn==0.35.0" \
        "python-telegram-bot==22.8" \
        "cryptography==46.0.2"
    do
        if grep -Fxq "$requirement" "$ROOT/requirements.txt"; then
            pass "Required dependency pinned: $requirement"
        else
            fail "Required dependency pin missing: $requirement"
        fi
    done
else
    fail "requirements.txt missing"
fi

# ---------------------------------------------------------------------------
# 16. Final result
# ---------------------------------------------------------------------------

section "FINAL PREFLIGHT RESULT"

printf 'PASS_COUNT=%s\n' "$PASS"
printf 'FAIL_COUNT=%s\n' "$FAIL"
printf 'WARN_COUNT=%s\n' "$WARN"

if [ "$FAIL" -eq 0 ]; then
    printf '%s\n' "PRODUCTION_PREFLIGHT=PASS"
    printf '%s\n' "PRODUCTION_PREFLIGHT_NETWORK=NOT_PERFORMED"
    printf '%s\n' "PRODUCTION_PREFLIGHT_SERVICE_START=NOT_PERFORMED"
    exit 0
else
    printf '%s\n' "PRODUCTION_PREFLIGHT=FAIL"
    exit 1
fi
