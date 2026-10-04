"""Authenticated encryption primitives for AdoBot.

Secrets are never logged or serialized in plaintext by this module.
AES-GCM is used for confidentiality + integrity.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as exc:
    raise RuntimeError(
        "cryptography is required for encrypted persistence"
    ) from exc


NONCE_SIZE = 12
KEY_SIZE = 32


@dataclass(frozen=True)
class EncryptedValue:
    nonce: str
    ciphertext: str


def generate_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def encode_key(key: bytes) -> str:
    if len(key) != KEY_SIZE:
        raise ValueError("invalid AES-256 key length")
    return base64.urlsafe_b64encode(key).decode("ascii")


def decode_key(value: str) -> bytes:
    key = base64.urlsafe_b64decode(value.encode("ascii"))
    if len(key) != KEY_SIZE:
        raise ValueError("invalid AES-256 key length")
    return key


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> EncryptedValue:
    if len(key) != KEY_SIZE:
        raise ValueError("invalid AES-256 key length")

    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(
        nonce,
        plaintext,
        associated_data or None,
    )

    return EncryptedValue(
        nonce=base64.urlsafe_b64encode(nonce).decode("ascii"),
        ciphertext=base64.urlsafe_b64encode(ciphertext).decode("ascii"),
    )


def decrypt(
    key: bytes,
    encrypted: EncryptedValue,
    associated_data: bytes = b"",
) -> bytes:
    if len(key) != KEY_SIZE:
        raise ValueError("invalid AES-256 key length")

    nonce = base64.urlsafe_b64decode(encrypted.nonce.encode("ascii"))
    ciphertext = base64.urlsafe_b64decode(encrypted.ciphertext.encode("ascii"))

    if len(nonce) != NONCE_SIZE:
        raise ValueError("invalid nonce")

    return AESGCM(key).decrypt(
        nonce,
        ciphertext,
        associated_data or None,
    )
