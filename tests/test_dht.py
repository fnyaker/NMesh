"""
DHT building blocks: content-addressed store and app packages.

The security property under test is content addressing: values are bound to
their hash, so poisoning is impossible and any tampering on the way is caught.
"""
import os
import random

import pytest

from src.app_package import (
    build, parse_manifest, reassemble, chunk_keys, content_key,
    AppPackageError, CHUNK_SIZE,
)
from src.dht import ContentStore, MAX_VALUE


# ---------------------------------------------------------------------------
# App packages
# ---------------------------------------------------------------------------

class TestAppPackage:
    def test_roundtrip(self):
        files = {
            "main.py": b"print('hello')\n" * 4000,   # spans several chunks
            "data.bin": bytes(range(256)) * 300,
            "empty": b"",
        }
        app_id, manifest, chunks = build("demo", "1.2.3", files)
        assert len(app_id) == 20
        store = dict(chunks)
        store[app_id] = manifest
        m = parse_manifest(store[app_id])
        assert m["name"] == "demo" and m["version"] == "1.2.3"
        got = reassemble(m, store.get)
        assert got == files

    def test_chunking(self):
        content = b"x" * (CHUNK_SIZE * 2 + 5)
        _, manifest, chunks = build("a", "1", {"f": content})
        m = parse_manifest(manifest)
        assert len(m["files"][0]["chunks"]) == 3
        # every chunk is content-addressed
        for k, v in chunks.items():
            assert content_key(v) == k

    def test_tampered_chunk_rejected(self):
        files = {"f": b"trustworthy content" * 100}
        app_id, manifest, chunks = build("a", "1", files)
        m = parse_manifest(manifest)
        # Serve a corrupted chunk under the right key.
        key = next(iter(chunks))
        bad = dict(chunks)
        bad[key] = b"evil" + chunks[key][4:]
        with pytest.raises(AppPackageError):
            reassemble(m, bad.get)

    def test_missing_chunk_rejected(self):
        _, manifest, _ = build("a", "1", {"f": b"data" * 100})
        m = parse_manifest(manifest)
        with pytest.raises(AppPackageError):
            reassemble(m, lambda k: None)

    def test_parse_fuzz(self):
        rng = random.Random(0xDEA1)
        for _ in range(3000):
            data = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 200)))
            try:
                parse_manifest(data)
            except AppPackageError:
                pass  # expected for garbage; must never raise anything else


# ---------------------------------------------------------------------------
# Content store
# ---------------------------------------------------------------------------

class TestContentStore:
    def test_put_get(self):
        s = ContentStore()
        value = b"some value"
        key = content_key(value)
        assert s.put(key, value) is True
        assert s.get(key) == value
        assert key in s

    def test_poisoning_rejected(self):
        s = ContentStore()
        assert s.put(b"\x00" * 20, b"not the preimage") is False
        assert s.get(b"\x00" * 20) is None

    def test_oversized_rejected(self):
        s = ContentStore()
        big = b"x" * (MAX_VALUE + 1)
        assert s.put(content_key(big), big) is False

    def test_lru_eviction(self):
        s = ContentStore(max_entries=3, max_bytes=10 ** 9)
        keys = []
        for i in range(5):
            v = f"value-{i}".encode()
            k = content_key(v)
            s.put(k, v)
            keys.append(k)
        assert len(s) == 3
        assert keys[0] not in s and keys[1] not in s   # oldest evicted
        assert keys[4] in s

    def test_fuzz_put(self):
        s = ContentStore()
        rng = random.Random(0x5107)
        for _ in range(2000):
            value = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 64)))
            key = content_key(value) if rng.random() < 0.5 else os.urandom(20)
            ok = s.put(key, value)
            # Stored only when the key actually addresses the content.
            assert ok == (key == content_key(value) and len(value) <= MAX_VALUE)
