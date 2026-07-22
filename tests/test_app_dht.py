"""
Per-app DHT overlay tests.

Two layers: the pure framing/crypto in src.app_dht (public vs private, namespace
isolation, hostile input never crashes), and the node-level put/get that lays it
over the content-addressed DHT (single node → values land in the local store).
"""
import os

import pytest

from src import app_dht
from src.app_dht import frame, read, AppDHTError, MAX_CONTENT, FLAG_PRIVATE
from src.node import MeshNode
from tests.conftest import make_manager

A = b"\xaa" * 8
B = b"\xbb" * 8
KEY = b"k" * 32
KEY2 = b"z" * 32


class TestFraming:
    def test_public_roundtrip(self):
        v = frame(A, b"hello")
        assert read(v, A) == b"hello"

    def test_private_roundtrip(self):
        v = frame(A, b"secret", KEY)
        assert read(v, A, KEY) == b"secret"

    def test_private_is_encrypted(self):
        v = frame(A, b"topsecret", KEY)
        assert b"topsecret" not in v

    def test_namespace_isolation_public(self):
        # App B cannot read app A's entry even holding the exact value/key bytes.
        v = frame(A, b"data")
        assert read(v, B) is None

    def test_namespace_isolation_private(self):
        v = frame(A, b"data", KEY)
        assert read(v, B, KEY) is None

    def test_private_needs_key(self):
        v = frame(A, b"data", KEY)
        assert read(v, A) is None            # no key supplied
        assert read(v, A, KEY2) is None      # wrong key

    def test_different_apps_get_different_keys(self):
        # Same content, different app → different framed bytes (→ different DHT key).
        assert frame(A, b"same") != frame(B, b"same")

    def test_bad_app_id_rejected(self):
        with pytest.raises(AppDHTError):
            frame(b"short", b"x")

    def test_oversized_content_rejected(self):
        with pytest.raises(AppDHTError):
            frame(A, b"x" * (MAX_CONTENT + 1))

    def test_bad_key_length_rejected(self):
        with pytest.raises(AppDHTError):
            frame(A, b"x", b"tooshort")

    def test_hostile_values_never_crash(self):
        for v in [b"", b"\x00", os.urandom(5), os.urandom(9), A,
                  A + bytes([FLAG_PRIVATE]),                       # private, no body
                  A + bytes([FLAG_PRIVATE]) + os.urandom(10),      # truncated ct
                  A + bytes([9]) + b"body",                        # unknown flag
                  A + bytes([0]) + os.urandom(1000)]:
            assert read(v, A) is None or isinstance(read(v, A), bytes)
        # tampered private ciphertext → None
        v = bytearray(frame(A, b"x", KEY)); v[-1] ^= 0xFF
        assert read(bytes(v), A, KEY) is None


class TestNodeAppDHT:
    async def _node(self):
        return MeshNode(transport_manager=make_manager())

    async def test_public_put_get(self):
        node = await self._node()
        try:
            key = await node.app_dht_put(A, b"public-entry")
            assert len(key) == 20
            assert await node.app_dht_get(A, key) == b"public-entry"
        finally:
            await node.stop()

    async def test_private_put_get(self):
        node = await self._node()
        try:
            key = await node.app_dht_put(A, b"private-entry", KEY)
            assert await node.app_dht_get(A, key, KEY) == b"private-entry"
            # Right namespace, wrong/no key → nothing.
            assert await node.app_dht_get(A, key) is None
            assert await node.app_dht_get(A, key, KEY2) is None
        finally:
            await node.stop()

    async def test_cross_app_cannot_read(self):
        node = await self._node()
        try:
            key = await node.app_dht_put(A, b"a-only")
            # Another app holding the exact key still reads nothing.
            assert await node.app_dht_get(B, key) is None
        finally:
            await node.stop()

    async def test_missing_key_returns_none(self):
        node = await self._node()
        try:
            assert await node.app_dht_get(A, os.urandom(20)) is None
        finally:
            await node.stop()

    async def test_oversized_content_raises(self):
        node = await self._node()
        try:
            with pytest.raises(AppDHTError):
                await node.app_dht_put(A, b"x" * (MAX_CONTENT + 1))
        finally:
            await node.stop()
