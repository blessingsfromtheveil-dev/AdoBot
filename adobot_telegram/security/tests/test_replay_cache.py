from adobot_telegram.security.replay import ReplayCache


def test_first_request_is_accepted():
    cache = ReplayCache()

    assert cache.check_and_record(
        principal="telegram:100",
        command_id="request-1",
        nonce="nonce-1",
        now=1000.0,
    )


def test_duplicate_request_is_rejected():
    cache = ReplayCache()

    assert cache.check_and_record(
        principal="telegram:100",
        command_id="request-1",
        nonce="nonce-1",
        now=1000.0,
    )

    assert not cache.check_and_record(
        principal="telegram:100",
        command_id="request-1",
        nonce="nonce-1",
        now=1001.0,
    )


def test_principal_is_part_of_replay_scope():
    cache = ReplayCache()

    assert cache.check_and_record(
        principal="telegram:100",
        command_id="request-1",
        nonce="nonce-1",
        now=1000.0,
    )

    assert cache.check_and_record(
        principal="telegram:200",
        command_id="request-1",
        nonce="nonce-1",
        now=1000.0,
    )


def test_expired_entry_can_be_used_again():
    cache = ReplayCache(ttl_seconds=5)

    assert cache.check_and_record(
        principal="telegram:100",
        command_id="request-1",
        nonce="nonce-1",
        now=1000.0,
    )

    assert cache.check_and_record(
        principal="telegram:100",
        command_id="request-1",
        nonce="nonce-1",
        now=1006.0,
    )


def test_empty_identity_fails_closed():
    cache = ReplayCache()

    try:
        cache.check_and_record(
            principal="",
            command_id="request-1",
            nonce="nonce-1",
            now=1000.0,
        )
    except ValueError:
        pass
    else:
        raise AssertionError("empty principal must fail closed")


def test_cache_is_bounded():
    cache = ReplayCache(max_entries=2, ttl_seconds=100)

    for value in ("1", "2", "3"):
        assert cache.check_and_record(
            principal=value,
            command_id=value,
            nonce=value,
            now=1000.0,
        )

    assert cache.size() <= 2
