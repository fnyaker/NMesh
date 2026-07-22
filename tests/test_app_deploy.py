"""
Signed app deployment.

Content addressing proves *what* the bytes are; a signed release descriptor
proves *who* published them and binds the runtime app id to the author's ML-DSA
key. These tests cover the descriptor primitives (sign/verify, and every
rejection gate) and the node-level publish/fetch round-trip.
"""
import os

import pytest

from src.app_channel import APP_ID_LEN, deployed_id
from src.app_package import build_release, parse_release, AppPackageError
from src.crypto import CryptoIdentity
from tests.conftest import make_node


ROOT_KEY = os.urandom(20)
ROOT_SHA = "a" * 64


def _release(identity, name="widget", version="1.0.0"):
    return build_release(ROOT_KEY, ROOT_SHA, name, version,
                         identity.dsa_public_key, identity.sign)


class TestReleaseDescriptor:
    def test_roundtrip_and_binding(self):
        idn = CryptoIdentity()
        blob, app_id = _release(idn)
        # The app id is bound to the author key + name.
        assert app_id == deployed_id(idn.dsa_public_key, "widget")
        assert len(app_id) == APP_ID_LEN
        doc = parse_release(blob, idn.verify)
        assert doc["app_id"] == app_id
        assert doc["author"] == idn.dsa_public_key
        assert doc["root_key"] == ROOT_KEY
        assert doc["name"] == "widget" and doc["version"] == "1.0.0"

    def test_tampered_name_rejected(self):
        idn = CryptoIdentity()
        blob, _ = _release(idn)
        # Flip the name in the JSON: the app-id binding (and the signature) break.
        tampered = blob.replace(b'"widget"', b'"evilxx"')
        with pytest.raises(AppPackageError):
            parse_release(tampered, idn.verify)

    def test_forged_app_id_rejected(self):
        idn = CryptoIdentity()
        blob, _ = _release(idn)
        # Any app id not equal to deployed_id(author, name) is refused, even
        # before the signature check.
        forged = blob.replace(deployed_id(idn.dsa_public_key, "widget").hex().encode(),
                              (b"00" * APP_ID_LEN))
        with pytest.raises(AppPackageError):
            parse_release(forged, idn.verify)

    def test_wrong_author_key_rejected(self):
        idn = CryptoIdentity()
        other = CryptoIdentity()
        blob, _ = _release(idn)
        # Verifying against a different key must fail the signature gate.
        with pytest.raises(AppPackageError):
            parse_release(blob, lambda m, s, k: other.verify(m, s, other.dsa_public_key))

    def test_garbage_rejected(self):
        idn = CryptoIdentity()
        for bad in (b"", b"{", b"not json", b'{"v":2}', os.urandom(40)):
            with pytest.raises(AppPackageError):
                parse_release(bad, idn.verify)


class TestNodeSignedPublish:
    async def test_publish_fetch_roundtrip(self):
        node, _ = await make_node()
        try:
            files = {"main.py": b"print('hi')\n", "data.bin": os.urandom(5000)}
            info = await node.publish_signed_app("widget", "2.1.0", files)
            release_id = bytes.fromhex(info["release_id"])
            expected_app = deployed_id(node._identity.dsa_public_key, "widget")
            assert info["app_id"] == expected_app.hex()

            result = await node.fetch_signed_app(release_id)
            assert result is not None
            meta, got = result
            assert got == files
            assert meta["app_id"] == expected_app.hex()
            assert meta["name"] == "widget" and meta["version"] == "2.1.0"
            assert meta["author"] == node._identity.dsa_public_key.hex()
        finally:
            await node.stop()

    async def test_fetch_missing_release_returns_none(self):
        node, _ = await make_node()
        try:
            assert await node.fetch_signed_app(os.urandom(20)) is None
        finally:
            await node.stop()
