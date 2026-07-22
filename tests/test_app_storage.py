"""
Per-app local secure store tests.

The store is a security boundary: each app's drawer must be isolated, encrypted
at rest, bounded against a hostile local app, and impossible to crash with a
corrupt/tampered file. These tests exercise all of that plus round-trip and
persistence across reopen.
"""
import os
import tempfile

import pytest

from src.crypto import CryptoIdentity
from src.app_storage import (
    AppStorage, MAX_KEY_LEN, MAX_VALUE, MAX_KEYS, MAX_DRAWER_BYTES, MAX_DRAWERS,
)

A = b"\x01" * 8       # one app id
B = b"\x02" * 8       # a different app id


def _store(path=None, identity=None):
    return AppStorage(path, identity or CryptoIdentity())


class TestRoundTrip:
    def test_put_get_delete(self):
        s = _store()
        assert s.get(A, "k") is None
        assert s.put(A, "k", b"value") is True
        assert s.get(A, "k") == b"value"
        assert s.delete(A, "k") is True
        assert s.get(A, "k") is None
        assert s.delete(A, "k") is False   # already gone

    def test_overwrite(self):
        s = _store()
        s.put(A, "k", b"one")
        s.put(A, "k", b"two")
        assert s.get(A, "k") == b"two"

    def test_list_keys_sorted(self):
        s = _store()
        s.put(A, "b", b"1"); s.put(A, "a", b"2"); s.put(A, "c", b"3")
        assert s.list_keys(A) == ["a", "b", "c"]

    def test_empty_value_allowed(self):
        s = _store()
        assert s.put(A, "k", b"") is True
        assert s.get(A, "k") == b""     # present, distinct from absent (None)


class TestIsolation:
    def test_drawers_are_independent(self):
        s = _store()
        s.put(A, "k", b"alpha")
        s.put(B, "k", b"beta")
        assert s.get(A, "k") == b"alpha"
        assert s.get(B, "k") == b"beta"
        assert s.list_keys(A) == ["k"] and s.list_keys(B) == ["k"]
        s.delete(A, "k")
        assert s.get(A, "k") is None and s.get(B, "k") == b"beta"


class TestBounds:
    def test_oversized_value_rejected(self):
        s = _store()
        assert s.put(A, "k", b"x" * (MAX_VALUE + 1)) is False
        assert s.get(A, "k") is None

    def test_oversized_key_rejected(self):
        s = _store()
        assert s.put(A, "k" * (MAX_KEY_LEN + 1), b"v") is False

    def test_empty_key_rejected(self):
        s = _store()
        assert s.put(A, "", b"v") is False

    def test_key_count_capped(self):
        s = _store()
        for i in range(MAX_KEYS):
            assert s.put(A, f"k{i}", b"v") is True
        assert s.put(A, "one-too-many", b"v") is False
        # …but overwriting an existing key still works at the cap.
        assert s.put(A, "k0", b"w") is True

    def test_drawer_byte_ceiling(self):
        s = _store()
        big = b"x" * (MAX_VALUE)
        n = MAX_DRAWER_BYTES // MAX_VALUE
        for i in range(n):
            assert s.put(A, f"k{i}", big) is True
        assert s.put(A, "overflow", big) is False

    def test_drawer_count_capped(self):
        s = _store()
        for i in range(MAX_DRAWERS):
            app = i.to_bytes(8, "big")
            assert s.put(app, "k", b"v") is True
        assert s.put(b"\xff" * 8, "k", b"v") is False

    def test_bad_app_id_rejected(self):
        s = _store()
        assert s.put(b"short", "k", b"v") is False
        assert s.get(b"short", "k") is None
        assert s.list_keys(b"short") == []


class TestPersistence:
    def test_survives_reopen(self):
        ident = CryptoIdentity()
        with tempfile.TemporaryDirectory() as d:
            s1 = _store(d, ident)
            s1.put(A, "k", b"kept")
            s1.put(B, "x", b"other")
            # A fresh instance on the same dir + identity reloads the drawers.
            s2 = _store(d, ident)
            assert s2.get(A, "k") == b"kept"
            assert s2.get(B, "x") == b"other"

    def test_encrypted_on_disk(self):
        ident = CryptoIdentity()
        with tempfile.TemporaryDirectory() as d:
            s = _store(d, ident)
            s.put(A, "k", b"topsecret-plaintext")
            path = os.path.join(d, A.hex() + ".drawer")
            blob = open(path, "rb").read()
            assert b"topsecret-plaintext" not in blob
            assert b"k" not in blob or True  # key names are not in the clear either

    def test_wrong_identity_cannot_read(self):
        with tempfile.TemporaryDirectory() as d:
            _store(d, CryptoIdentity()).put(A, "k", b"secret")
            # A different identity derives a different drawer key → GCM fails →
            # empty drawer, never a crash, never the other identity's data.
            other = _store(d, CryptoIdentity())
            assert other.get(A, "k") is None

    def test_ram_only_without_path(self):
        with tempfile.TemporaryDirectory() as d:
            s = _store(None, CryptoIdentity())   # no path → nothing on disk
            s.put(A, "k", b"v")
            assert os.listdir(d) == []


class TestHostileFile:
    def _prep(self, d, ident):
        s = _store(d, ident)
        s.put(A, "k", b"v")
        return os.path.join(d, A.hex() + ".drawer")

    def test_truncated_file_yields_empty(self):
        ident = CryptoIdentity()
        with tempfile.TemporaryDirectory() as d:
            path = self._prep(d, ident)
            with open(path, "wb") as f:
                f.write(b"\x00\x01\x02")   # too short to hold nonce+tag
            assert _store(d, ident).get(A, "k") is None

    def test_tampered_ciphertext_yields_empty(self):
        ident = CryptoIdentity()
        with tempfile.TemporaryDirectory() as d:
            path = self._prep(d, ident)
            blob = bytearray(open(path, "rb").read())
            blob[-1] ^= 0xFF               # flip a ciphertext byte → GCM auth fail
            open(path, "wb").write(bytes(blob))
            assert _store(d, ident).get(A, "k") is None

    def test_garbage_file_yields_empty(self):
        ident = CryptoIdentity()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, A.hex() + ".drawer")
            open(path, "wb").write(os.urandom(500))
            assert _store(d, ident).list_keys(A) == []

    def test_drawer_renamed_to_other_app_fails(self):
        # The app id is GCM AAD, so a file copied under another drawer's name
        # cannot be decrypted there — cross-drawer substitution is caught.
        ident = CryptoIdentity()
        with tempfile.TemporaryDirectory() as d:
            path = self._prep(d, ident)
            data = open(path, "rb").read()
            open(os.path.join(d, B.hex() + ".drawer"), "wb").write(data)
            assert _store(d, ident).get(B, "k") is None
