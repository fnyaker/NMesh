"""
App store: the shared catalog, the local installed set, and the node lifecycle.

Security focus: the catalog only accepts author-signed releases, never rolls
back to a stale one (signed ``ts``), stays bounded, and its epidemic gossip
terminates. Installed-app paths can't escape their directory. Nothing hostile
crashes the node.
"""
import os
import tempfile

import pytest

from src.app_catalog import AppCatalog, InstalledApps, _safe_rel, MAX_APPS
from src.app_package import build_release, content_key
from src.app_channel import deployed_id
from src.crypto import CryptoIdentity
from src.node import MeshNode, CATALOG_ANNOUNCE
from src.node_id import NodeID
from src.packet import Packet
from tests.conftest import make_manager

ROOT_KEY = os.urandom(20)
ROOT_SHA = "a" * 64


def _release(identity, name="widget", version="1.0.0", ts=1000):
    blob, app_id = build_release(ROOT_KEY, ROOT_SHA, name, version,
                                 identity.dsa_public_key, identity.sign, ts)
    return blob, app_id


class TestAppCatalog:
    def test_offer_new_then_duplicate(self):
        idn = CryptoIdentity()
        cat = AppCatalog()
        blob, app_id = _release(idn)
        assert cat.offer(blob, idn.verify) == "new"
        assert cat.offer(blob, idn.verify) is None   # duplicate ts → no re-gossip
        assert cat.get(app_id)["version"] == "1.0.0"

    def test_newer_ts_supersedes(self):
        idn = CryptoIdentity()
        cat = AppCatalog()
        old, app_id = _release(idn, version="1.0.0", ts=1000)
        new, _ = _release(idn, version="2.0.0", ts=2000)
        assert cat.offer(old, idn.verify) == "new"
        assert cat.offer(new, idn.verify) == "updated"
        assert cat.get(app_id)["version"] == "2.0.0"

    def test_older_ts_rejected_antirollback(self):
        idn = CryptoIdentity()
        cat = AppCatalog()
        new, _ = _release(idn, version="2.0.0", ts=2000)
        old, _ = _release(idn, version="1.0.0", ts=1000)
        assert cat.offer(new, idn.verify) == "new"
        # A relay replaying the older signed release must not roll us back.
        assert cat.offer(old, idn.verify) is None
        assert cat.list()[0]["version"] == "2.0.0"

    def test_bad_signature_rejected(self):
        idn = CryptoIdentity()
        other = CryptoIdentity()
        cat = AppCatalog()
        blob, _ = _release(idn)
        # Verify against the wrong key → invalid → not admitted, not gossiped.
        assert cat.offer(blob, lambda m, s, k: other.verify(m, s, other.dsa_public_key)) is None
        assert len(cat) == 0

    def test_garbage_rejected(self):
        idn = CryptoIdentity()
        cat = AppCatalog()
        for bad in (b"", b"{", os.urandom(50)):
            assert cat.offer(bad, idn.verify) is None
        assert len(cat) == 0

    def test_capacity_bounded(self):
        cat = AppCatalog(max_apps=3)
        idn = CryptoIdentity()
        for i in range(3):
            blob, _ = _release(idn, name=f"app{i}")
            assert cat.offer(blob, idn.verify) == "new"
        blob, _ = _release(idn, name="overflow")
        assert cat.offer(blob, idn.verify) is None
        assert len(cat) == 3

    def test_list_sorted_newest_first(self):
        idn = CryptoIdentity()
        cat = AppCatalog()
        cat.offer(_release(idn, name="a", ts=100)[0], idn.verify)
        cat.offer(_release(idn, name="b", ts=300)[0], idn.verify)
        cat.offer(_release(idn, name="c", ts=200)[0], idn.verify)
        assert [e["name"] for e in cat.list()] == ["b", "c", "a"]


class TestInstalledApps:
    def test_record_remove_persist(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "installed.json")
            reg = InstalledApps(path, os.path.join(d, "apps"))
            meta = {"app_id": "aa" * 8, "name": "x", "version": "1", "ts": 5}
            assert reg.record(meta) is True
            assert reg.is_installed("aa" * 8)
            # Reload from disk → survives.
            reg2 = InstalledApps(path, os.path.join(d, "apps"))
            assert reg2.get("aa" * 8)["name"] == "x"
            assert reg2.remove("aa" * 8) is True
            assert not InstalledApps(path).is_installed("aa" * 8)

    def test_capacity_bounded(self):
        reg = InstalledApps(None, None, max_installed=2)
        assert reg.record({"app_id": "aa" * 8, "name": "a"})
        assert reg.record({"app_id": "bb" * 8, "name": "b"})
        assert reg.record({"app_id": "cc" * 8, "name": "c"}) is False
        # Updating an existing record still works at the cap.
        assert reg.record({"app_id": "aa" * 8, "name": "a2"})

    def test_corrupt_registry_yields_empty(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "installed.json")
            open(path, "w").write("}{ not json")
            assert InstalledApps(path).list() == []

    def test_write_files_sanitizes_paths(self):
        with tempfile.TemporaryDirectory() as d:
            reg = InstalledApps(os.path.join(d, "i.json"), os.path.join(d, "apps"))
            reg.write_files("cc" * 8, {
                "ok/main.py": b"code",
                "../escape.txt": b"nope",       # dropped
                "/abs.txt": b"nope",            # dropped
            })
            app_dir = reg.app_dir("cc" * 8)
            assert os.path.exists(os.path.join(app_dir, "ok", "main.py"))
            assert not os.path.exists(os.path.join(d, "escape.txt"))

    def test_safe_rel(self):
        assert _safe_rel("a/b.py") == os.path.join("a", "b.py")
        for bad in ("", "/abs", "../up", "a/../../x", "x\x00y", "."):
            assert _safe_rel(bad) is None


class TestNodeStoreLifecycle:
    async def _node(self, d):
        return MeshNode(transport_manager=make_manager(),
                        app_store_dir=os.path.join(d, "appstore"))

    async def test_publish_install_update_uninstall(self):
        with tempfile.TemporaryDirectory() as d:
            node = await self._node(d)
            try:
                files = {"main.py": b"print('v1')\n", "data.bin": os.urandom(3000)}
                info = await node.publish_store_app("widget", "1.0.0", files, ts=1000)
                app_id_hex = info["app_id"]
                # Publishing announces to the local catalog.
                assert any(e["app_id"] == app_id_hex for e in node.catalog_list())

                # Install: content fetched, verified, written; recorded.
                meta = await node.install_app(app_id_hex)
                assert meta is not None and meta["version"] == "1.0.0"
                assert any(m["app_id"] == app_id_hex for m in node.installed_list())
                inst_dir = node._installed.app_dir(app_id_hex)
                assert open(os.path.join(inst_dir, "main.py"), "rb").read() == files["main.py"]

                # No newer release yet → update is a no-op.
                assert await node.update_app(app_id_hex) is None

                # Publish a newer version, then update pulls it.
                await node.publish_store_app("widget", "2.0.0",
                                             {"main.py": b"print('v2')\n"}, ts=2000)
                updated = await node.update_app(app_id_hex)
                assert updated is not None and updated["version"] == "2.0.0"
                assert open(os.path.join(inst_dir, "main.py"), "rb").read() == b"print('v2')\n"

                # Uninstall removes the record and the files.
                assert node.uninstall_app(app_id_hex) is True
                assert not any(m["app_id"] == app_id_hex for m in node.installed_list())
                assert not os.path.isdir(inst_dir)
            finally:
                await node.stop()

    async def test_install_unknown_app_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            node = await self._node(d)
            try:
                assert await node.install_app("ab" * 8) is None
                assert await node.install_app("not-hex") is None
            finally:
                await node.stop()


class _FakePeer:
    """Minimal authenticated peer that records what the node sends it."""
    def __init__(self):
        self.authenticated_id = NodeID(os.urandom(20))
        self.session = object()
        self.sent = []
        self.relay_only = False
    async def send(self, pkt):
        self.sent.append(pkt)
    async def stop(self):
        pass


class TestCatalogGossip:
    async def _release_from(self, node):
        info = await node.publish_store_app("widget", "1.0.0",
                                            {"m": b"x"}, ts=1234)
        return await node.dht_get(bytes.fromhex(info["release_id"])), info["app_id"]

    async def test_announce_updates_and_regossips(self):
        author = MeshNode(transport_manager=make_manager())
        node = MeshNode(transport_manager=make_manager())
        try:
            release_bytes, app_id = await self._release_from(author)
            ingress = _FakePeer()
            downstream = _FakePeer()
            node._peers = [ingress, downstream]
            pkt = Packet.create(CATALOG_ANNOUNCE, ingress.authenticated_id.raw,
                                b"\xff" * 20, release_bytes)
            await node._handle_catalog_announce(ingress, pkt)
            # Catalog learned the app…
            assert any(e["app_id"] == app_id for e in node.catalog_list())
            # …and re-gossiped it downstream, but not back to the sender.
            assert any(p.type == CATALOG_ANNOUNCE for p in downstream.sent)
            assert ingress.sent == []
        finally:
            await author.stop(); await node.stop()

    async def test_duplicate_announce_not_regossiped(self):
        author = MeshNode(transport_manager=make_manager())
        node = MeshNode(transport_manager=make_manager())
        try:
            release_bytes, _ = await self._release_from(author)
            ingress, downstream = _FakePeer(), _FakePeer()
            node._peers = [ingress, downstream]
            pkt = Packet.create(CATALOG_ANNOUNCE, ingress.authenticated_id.raw,
                                b"\xff" * 20, release_bytes)
            await node._handle_catalog_announce(ingress, pkt)
            downstream.sent.clear()
            # Second time: already known → must NOT re-gossip (epidemic ends).
            await node._handle_catalog_announce(ingress, pkt)
            assert downstream.sent == []
        finally:
            await author.stop(); await node.stop()

    async def test_sync_pushes_catalog_to_new_peer(self):
        # The catch-up path: a freshly authenticated peer receives our whole
        # catalog so a joining node learns apps published before it arrived.
        author = MeshNode(transport_manager=make_manager())
        node = MeshNode(transport_manager=make_manager())
        try:
            release_bytes, _ = await self._release_from(author)
            node._catalog.offer(release_bytes, node._identity.verify)
            peer = _FakePeer()
            await node._sync_catalog_to(peer)
            assert any(p.type == CATALOG_ANNOUNCE for p in peer.sent)
        finally:
            await author.stop(); await node.stop()

    async def test_rate_limit_blocks_flood(self):
        node = MeshNode(transport_manager=make_manager())
        try:
            peer = _FakePeer()
            from src.node import _CATALOG_RATE_MAX
            allowed = sum(node._catalog_allowed(peer) for _ in range(_CATALOG_RATE_MAX + 20))
            assert allowed == _CATALOG_RATE_MAX
        finally:
            await node.stop()
