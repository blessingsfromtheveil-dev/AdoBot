import time

import pytest

from adobot_telegram.security.commands import (
    Command,
    is_allowed,
)
from adobot_telegram.security.crypto import (
    decode_key,
    decrypt,
    encode_key,
    encrypt,
    generate_key,
)
from adobot_telegram.security.rbac import authorize
from adobot_telegram.security.replay import ReplayGuard


def test_aes_gcm_round_trip():
    key = generate_key()
    encrypted = encrypt(key, b"secret-value", b"device-01")

    assert decrypt(
        key,
        encrypted,
        b"device-01",
    ) == b"secret-value"


def test_aes_gcm_detects_tampering():
    key = generate_key()
    encrypted = encrypt(key, b"secret")

    tampered = type(encrypted)(
        nonce=encrypted.nonce,
        ciphertext=encrypted.ciphertext[:-2] + "AA",
    )

    with pytest.raises(Exception):
        decrypt(key, tampered)


def test_key_encoding_round_trip():
    key = generate_key()
    assert decode_key(encode_key(key)) == key


def test_rbac_fails_closed():
    assert authorize("admin", "device.read")
    assert authorize("viewer", "device.read")
    assert not authorize("viewer", "device.command")
    assert not authorize("unknown", "device.command")


def test_command_allowlist():
    assert is_allowed(Command.STATUS)
    assert is_allowed(Command.APPROVED_EXPORT)
    assert not is_allowed("shell")
    assert not is_allowed("exec")


def test_replay_timestamp_accepts_recent_command():
    guard = ReplayGuard(max_age=300)
    guard.validate_timestamp(int(time.time()))


def test_replay_timestamp_rejects_old_command():
    guard = ReplayGuard(max_age=300)

    with pytest.raises(ValueError):
        guard.validate_timestamp(int(time.time()) - 301)
