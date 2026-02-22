from sfts.replay import NonceCache


def test_nonce_cache_detects_reuse():
    cache = NonceCache()
    cache.add("abc")
    assert cache.seen("abc") is True
    assert cache.seen("def") is False
