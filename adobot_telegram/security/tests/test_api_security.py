from __future__ import annotations

import pytest

from adobot_telegram.audit.chain import AuditChain
from adobot_telegram.security.api_auth import (
    APIAuthenticationError,
    sign,
    verify,
)
from adobot_telegram.security.rate_limit import (
    RateLimitExceeded,
    RateLimiter,
)


def test_api_signature_round_trip():
    secret = b"x" * 32

    signature = sign(
        secret,
        method="POST",
        path="/api/command",
        timestamp="1000",
        nonce="abc",
        request_id="req-1",
        body=b"{}",
    )

    verify(
        secret,
        signature,
        method="POST",
        path="/api/command",
        timestamp="1000",
        nonce="abc",
        request_id="req-1",
        body=b"{}",
        now=1000,
    )


def test_api_signature_rejects_modified_body():
    secret = b"x" * 32

    signature = sign(
        secret,
        method="POST",
        path="/api/command",
        timestamp="1000",
        nonce="abc",
        request_id="req-1",
        body=b"{}",
    )

    with pytest.raises(APIAuthenticationError):
        verify(
            secret,
            signature,
            method="POST",
            path="/api/command",
            timestamp="1000",
            nonce="abc",
            request_id="req-1",
            body=b'{"changed":true}',
            now=1000,
        )


def test_api_signature_rejects_old_timestamp():
    secret = b"x" * 32

    signature = sign(
        secret,
        method="GET",
        path="/health",
        timestamp="1000",
        nonce="abc",
        request_id="req-1",
    )

    with pytest.raises(APIAuthenticationError):
        verify(
            secret,
            signature,
            method="GET",
            path="/health",
            timestamp="1000",
            nonce="abc",
            request_id="req-1",
            now=2000,
        )


def test_rate_limiter():
    limiter = RateLimiter(limit=2, window_seconds=60)

    limiter.check("actor", now=100)
    limiter.check("actor", now=101)

    with pytest.raises(RateLimitExceeded):
        limiter.check("actor", now=102)


def test_audit_chain_integrity(tmp_path):
    path = tmp_path / "audit.jsonl"
    chain = AuditChain(path)

    chain.append(
        event="security.test",
        actor="test",
        outcome="success",
        request_id="req-1",
    )

    chain.append(
        event="security.test",
        actor="test",
        outcome="success",
        request_id="req-2",
    )

    assert chain.verify()


def test_audit_chain_detects_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    chain = AuditChain(path)

    chain.append(
        event="security.test",
        actor="test",
        outcome="success",
        request_id="req-1",
    )

    text = path.read_text()
    path.write_text(text.replace('"success"', '"tampered"', 1))

    assert not chain.verify()
