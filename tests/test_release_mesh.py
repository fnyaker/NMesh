"""
Releases over the mesh: publishing, gossip, and what may install what.

The unit half (`test_core_release.py`) proves the format refuses what it should.
This half proves the node does: that publishing really puts a verifiable tree on
the DHT, that an announce propagates once and stops, that an unpinned publisher
gets nothing installed however valid its signature, and that a release cannot
walk a node backwards or sideways.

A release replaces the node's own code — of everything the mesh carries, this is
the payload with the most authority — so most of these tests are refusals.
"""
import asyncio
import os
import tempfile

import pytest

from src import core_release as cr
from src import updater
from src.node import MeshNode, RELEASE_ANNOUNCE
from src.node_id import NodeID
from src.packet import Packet
from tests.conftest import make_manager


def _tree(root, version="9.9.9", extra=None):
    """The smallest thing `read_tree` accepts as a node."""
    os.makedirs(os.path.join(root, "src"), exist_ok=True)
    with open(os.path.join(root, "src", "version.py"), "w") as handle:
        handle.write(f'__version__ = "{version}"\n')
    with open(os.path.join(root, "src", "node.py"), "w") as handle:
        handle.write("# the code\n")
    with open(os.path.join(root, "start.sh"), "w") as handle:
        handle.write("#!/bin/sh\necho hi\n")
    for path, content in (extra or {}).items():
        full = os.path.join(root, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as handle:
            handle.write(content)
    return root


class _FakePeer:
    """An authenticated peer that records what the node sends it."""

    def __init__(self):
        self.authenticated_id = NodeID(os.urandom(20))
        self.session = object()
        self.sent = []
        self.relay_only = False

    async def send(self, packet):
        self.sent.append(packet)

    async def stop(self):
        pass


def _node(release_dir=None):
    return MeshNode(transport_manager=make_manager(), release_dir=release_dir)


class TestPublishing:
    async def test_a_published_tree_comes_back_byte_for_byte(self, tmp_path):
        node = _node()
        try:
            info = await node.publish_release(_tree(str(tmp_path)),
                                              notes="first cut")
            assert info["version"] == "9.9.9"
            node.trust_publisher(node._identity.dsa_public_key.hex(), "me")
            fetched = await node.fetch_release(info["publisher_id"])
            assert fetched is not None
            entry, files = fetched
            assert entry["notes"] == "first cut"
            assert files["src/node.py"] == b"# the code\n"
            assert cr.version_of(files) == "9.9.9"
        finally:
            await node.stop()

    async def test_publishing_something_that_is_not_a_node_is_refused(self, tmp_path):
        node = _node()
        try:
            (tmp_path / "README.md").write_text("hello")
            with pytest.raises(cr.ReleaseError):
                await node.publish_release(str(tmp_path))
        finally:
            await node.stop()

    async def test_a_tree_whose_version_is_unreadable_is_refused(self, tmp_path):
        node = _node()
        try:
            root = _tree(str(tmp_path))
            (tmp_path / "src" / "version.py").write_text("# no version here\n")
            with pytest.raises(cr.ReleaseError):
                await node.publish_release(root)
        finally:
            await node.stop()

    async def test_publishing_announces_to_our_own_view(self, tmp_path):
        node = _node()
        try:
            info = await node.publish_release(_tree(str(tmp_path)))
            listed = node.release_overview()["releases"]
            assert [entry["version"] for entry in listed] == ["9.9.9"]
            assert listed[0]["publisher_id"] == info["publisher_id"]
        finally:
            await node.stop()

    async def test_our_own_release_is_untrusted_until_we_pin_ourselves(self, tmp_path):
        """Publishing is not trusting. A node that signs a release still has to
        be told that this key is one it accepts code from."""
        node = _node()
        try:
            await node.publish_release(_tree(str(tmp_path)))
            assert node.release_overview()["releases"][0]["trusted"] is False
            node.trust_publisher(node._identity.dsa_public_key.hex())
            assert node.release_overview()["releases"][0]["trusted"] is True
        finally:
            await node.stop()


class TestPublishingTouchesNothing:
    """Publishing is signing and announcing. The first cut of this pushed the
    tree onto the DHT as ~120 chunks, a Kademlia lookup each, paid up front for
    nodes that may never ask — which is what made publishing take minutes on a
    real mesh. Nothing goes anywhere now until somebody wants it."""

    async def test_publishing_makes_no_lookups_at_all(self, tmp_path):
        node = _node()
        try:
            lookups = []

            async def counted(node_id, *args, **kwargs):
                lookups.append(node_id)
                return []

            node.kad_lookup = counted
            await node.publish_release(_tree(str(tmp_path)))
            assert lookups == []
        finally:
            await node.stop()

    async def test_a_publisher_with_no_peers_still_publishes(self, tmp_path):
        node = _node()
        try:
            info = await node.publish_release(_tree(str(tmp_path)))
            assert info["version"] == "9.9.9"
            # And it holds the package, so it can answer whoever turns up.
            assert node._packages.has(info["release_id"])
        finally:
            await node.stop()

    async def test_the_package_is_kept_to_be_served(self, tmp_path):
        node = _node()
        try:
            info = await node.publish_release(_tree(str(tmp_path)))
            package = node._packages.get(info["release_id"])
            assert package is not None
            assert cr.open_package(package)["src/node.py"] == b"# the code\n"
            assert info["package_bytes"] == len(package)
            # (Whether the package is smaller than the tree depends on the
            # tree: tar headers dominate a three-file fixture. The real one is
            # measured in tests/integration/test_release.py.)
        finally:
            await node.stop()


class TestGossip:
    async def _release_from(self, publisher, tmp_path, version="9.9.9"):
        info = await publisher.publish_release(_tree(str(tmp_path), version))
        return (publisher._releases.get(info["publisher_id"])["release"],
                info["publisher_id"])

    async def test_an_announce_is_learned_and_passed_on_once(self, tmp_path):
        publisher, node = _node(), _node()
        try:
            blob, publisher_id = await self._release_from(publisher, tmp_path)
            ingress, downstream = _FakePeer(), _FakePeer()
            node._peers = [ingress, downstream]
            packet = Packet.create(RELEASE_ANNOUNCE,
                                   ingress.authenticated_id.raw,
                                   b"\xff" * 20, b"\x00" + blob)
            await node._handle_release_announce(ingress, packet)
            assert node._releases.get(publisher_id) is not None
            assert any(p.type == RELEASE_ANNOUNCE for p in downstream.sent)
            assert ingress.sent == []          # never back where it came from

            downstream.sent.clear()
            await node._handle_release_announce(ingress, packet)
            assert downstream.sent == []       # the epidemic terminates
        finally:
            await publisher.stop(); await node.stop()

    async def test_an_untrusted_publisher_is_still_relayed(self, tmp_path):
        """Refusing to carry what we would not install would break discovery
        for every other operator."""
        publisher, node = _node(), _node()
        try:
            blob, publisher_id = await self._release_from(publisher, tmp_path)
            ingress, downstream = _FakePeer(), _FakePeer()
            node._peers = [ingress, downstream]
            await node._handle_release_announce(
                ingress, Packet.create(RELEASE_ANNOUNCE,
                                       ingress.authenticated_id.raw,
                                       b"\xff" * 20, b"\x00" + blob))
            assert any(p.type == RELEASE_ANNOUNCE for p in downstream.sent)
            listed = node.release_overview()["releases"][0]
            assert listed["trusted"] is False and listed["state"] == "untrusted"
            assert listed["action"] is None
        finally:
            await publisher.stop(); await node.stop()

    async def test_a_forged_announce_is_dropped_and_not_relayed(self, tmp_path):
        publisher, node = _node(), _node()
        try:
            blob, _ = await self._release_from(publisher, tmp_path)
            ingress, downstream = _FakePeer(), _FakePeer()
            node._peers = [ingress, downstream]
            for payload in (b"", b"garbage", os.urandom(300),
                            bytearray(blob[:-4] + b"0000")):
                await node._handle_release_announce(
                    ingress, Packet.create(RELEASE_ANNOUNCE,
                                           ingress.authenticated_id.raw,
                                           b"\xff" * 20, b"\x00" + bytes(payload)))
            assert len(node._releases) == 0
            assert downstream.sent == []
        finally:
            await publisher.stop(); await node.stop()

    async def test_a_flood_of_announces_is_rate_limited(self, tmp_path):
        publisher, node = _node(), _node()
        try:
            blob, _ = await self._release_from(publisher, tmp_path)
            ingress = _FakePeer()
            node._peers = [ingress]
            packet = Packet.create(RELEASE_ANNOUNCE,
                                   ingress.authenticated_id.raw,
                                   b"\xff" * 20, b"\x00" + blob)
            for _ in range(500):
                await node._handle_release_announce(ingress, packet)
            from src.node import _RELEASE_RATE_MAX
            assert node._release_rate[id(ingress)][0] <= _RELEASE_RATE_MAX
        finally:
            await publisher.stop(); await node.stop()

    async def test_a_new_peer_is_caught_up_on_what_we_know(self, tmp_path):
        publisher, node = _node(), _node()
        try:
            blob, _ = await self._release_from(publisher, tmp_path)
            node._releases.offer(blob, node._identity.verify)
            peer = _FakePeer()
            await node._sync_releases_to(peer)
            assert any(p.type == RELEASE_ANNOUNCE for p in peer.sent)
        finally:
            await publisher.stop(); await node.stop()

    async def test_replaying_an_older_release_does_not_walk_us_back(self, tmp_path):
        publisher, node = _node(), _node()
        try:
            old_root = _tree(str(tmp_path / "old"), "1.0.0")
            new_root = _tree(str(tmp_path / "new"), "2.0.0")
            old = await publisher.publish_release(old_root, ts=1000)
            old_descriptor = publisher._releases.get(old["publisher_id"])["release"]
            new = await publisher.publish_release(new_root, ts=2000)
            old_blob = old_descriptor
            new_blob = publisher._releases.get(new["publisher_id"])["release"]
            ingress = _FakePeer()
            node._peers = [ingress]
            for blob in (new_blob, old_blob):
                await node._handle_release_announce(
                    ingress, Packet.create(RELEASE_ANNOUNCE,
                                           ingress.authenticated_id.raw,
                                           b"\xff" * 20, b"\x00" + blob))
            assert node._releases.get(new["publisher_id"])["version"] == "2.0.0"
        finally:
            await publisher.stop(); await node.stop()


class TestWhatMayBeInstalled:
    async def _offer(self, node, publisher, tmp_path, version="9.9.9", ts=None):
        info = await publisher.publish_release(_tree(str(tmp_path), version),
                                               ts=ts)
        blob = publisher._releases.get(info["publisher_id"])["release"]
        node._releases.offer(blob, node._identity.verify,
                             node._trusts_publisher)
        # The package lives with the publisher; in a two-node test with no link
        # between them, hand the node that store so the fetch is real.
        node._packages = publisher._packages
        return info

    async def test_an_unpinned_publisher_installs_nothing(self, tmp_path):
        publisher, node = _node(), _node()
        try:
            info = await self._offer(node, publisher, tmp_path)
            with pytest.raises(cr.ReleaseError, match="not trusted"):
                await node.install_release(info["publisher_id"])
        finally:
            await publisher.stop(); await node.stop()

    async def test_pinning_the_publisher_makes_it_installable(self, tmp_path,
                                                              monkeypatch):
        publisher, node = _node(), _node()
        try:
            info = await self._offer(node, publisher, tmp_path)
            node.trust_publisher(publisher._identity.dsa_public_key.hex(), "them")
            overview = node.release_overview()["releases"][0]
            assert overview["state"] == "available" and overview["action"] == "install"

            applied = {}
            async def fake_apply(files, version, **kwargs):
                applied.update({"files": files, "version": version})
                return {"applied": version, "restart_required": True}

            monkeypatch.setattr(updater, "apply_files", fake_apply)
            result = await node.install_release(info["publisher_id"])
            assert result["version"] == "9.9.9"
            assert applied["files"]["src/node.py"] == b"# the code\n"
        finally:
            await publisher.stop(); await node.stop()

    async def test_a_version_that_is_not_newer_is_refused(self, tmp_path,
                                                          monkeypatch):
        """Anti-rollback at the point it matters: the catalogue orders by
        signed time, but what gets installed is ordered by version."""
        publisher, node = _node(), _node()
        try:
            monkeypatch.setattr("src.version.__version__", "5.0.0")
            info = await self._offer(node, publisher, tmp_path, version="1.0.0")
            node.trust_publisher(publisher._identity.dsa_public_key.hex())
            assert node.release_overview()["releases"][0]["state"] == "older"
            with pytest.raises(cr.ReleaseError, match="not newer"):
                await node.install_release(info["publisher_id"])
        finally:
            await publisher.stop(); await node.stop()

    async def test_the_version_we_already_run_is_not_offered(self, tmp_path,
                                                             monkeypatch):
        publisher, node = _node(), _node()
        try:
            monkeypatch.setattr("src.version.__version__", "9.9.9")
            await self._offer(node, publisher, tmp_path, version="9.9.9")
            node.trust_publisher(publisher._identity.dsa_public_key.hex())
            entry = node.release_overview()["releases"][0]
            assert entry["state"] == "running" and entry["action"] is None
        finally:
            await publisher.stop(); await node.stop()

    async def test_an_unknown_release_is_refused(self, tmp_path):
        node = _node()
        try:
            for bad in ("", "zz", "aa" * 20, "not hex"):
                with pytest.raises(cr.ReleaseError):
                    await node.install_release(bad)
        finally:
            await node.stop()

    async def test_content_that_does_not_match_the_signed_root_is_refused(
            self, tmp_path, monkeypatch):
        """The descriptor names a root; if what comes back off the DHT is not
        that tree, nothing is installed. Content addressing does the work —
        this checks we actually act on it."""
        publisher, node = _node(), _node()
        try:
            info = await self._offer(node, publisher, tmp_path)
            node.trust_publisher(publisher._identity.dsa_public_key.hex())

            # A package that is a valid tree but not the version signed for.
            monkeypatch.setattr(
                node._packages, "get",
                lambda ident: cr.build_package(
                    {"src/version.py": b'__version__ = "6.6.6"\n',
                     "start.sh": b"#!/bin/sh\n"}))
            with pytest.raises(cr.ReleaseError, match="announces"):
                await node.install_release(info["publisher_id"])
        finally:
            await publisher.stop(); await node.stop()

    async def test_content_that_cannot_be_fetched_installs_nothing(
            self, tmp_path, monkeypatch):
        publisher, node = _node(), _node()
        try:
            info = await self._offer(node, publisher, tmp_path)
            node.trust_publisher(publisher._identity.dsa_public_key.hex())

            monkeypatch.setattr(node._packages, "get", lambda ident: None)
            monkeypatch.setattr(node, "_release_sources_for", lambda entry: [])
            with pytest.raises(cr.ReleaseError, match="could not be fetched"):
                await node.install_release(info["publisher_id"])
        finally:
            await publisher.stop(); await node.stop()


class TestPinsOnTheNode:
    async def test_a_pin_survives_a_restart(self, tmp_path):
        publisher = _node()
        try:
            key = publisher._identity.dsa_public_key.hex()
            first = _node(str(tmp_path))
            first.trust_publisher(key, "them", auto=True)
            await first.stop()
            again = _node(str(tmp_path))
            try:
                assert again._publishers.trusts(bytes.fromhex(key))
                assert again.release_overview()["publishers"][0]["auto"] is True
            finally:
                await again.stop()
        finally:
            await publisher.stop()

    async def test_pinning_applies_to_what_we_already_heard(self, tmp_path):
        publisher, node = _node(), _node()
        try:
            info = await publisher.publish_release(_tree(str(tmp_path)))
            blob = publisher._releases.get(info["publisher_id"])["release"]
            node._releases.offer(blob, node._identity.verify,
                                 node._trusts_publisher)
            assert node.release_overview()["releases"][0]["trusted"] is False
            node.trust_publisher(publisher._identity.dsa_public_key.hex())
            assert node.release_overview()["releases"][0]["trusted"] is True
        finally:
            await publisher.stop(); await node.stop()

    async def test_unpinning_takes_the_offer_away_again(self, tmp_path):
        publisher, node = _node(), _node()
        try:
            info = await publisher.publish_release(_tree(str(tmp_path)))
            blob = publisher._releases.get(info["publisher_id"])["release"]
            node._releases.offer(blob, node._identity.verify,
                                 node._trusts_publisher)
            entry = node.trust_publisher(
                publisher._identity.dsa_public_key.hex())
            assert node.release_overview()["releases"][0]["state"] == "available"
            assert node.untrust_publisher(entry["id"]) is True
            assert node.release_overview()["releases"][0]["state"] == "untrusted"
        finally:
            await publisher.stop(); await node.stop()

    async def test_a_stale_trusted_flag_never_authorises_an_install(self, tmp_path):
        """The flag on a catalogue entry is for display. What authorises an
        install is the pin, read at the moment it is asked."""
        publisher, node = _node(), _node()
        try:
            info = await publisher.publish_release(_tree(str(tmp_path)))
            blob = publisher._releases.get(info["publisher_id"])["release"]
            node.trust_publisher(publisher._identity.dsa_public_key.hex())
            node._releases.offer(blob, node._identity.verify,
                                 node._trusts_publisher)
            entry = node._releases.get(info["publisher_id"])
            assert entry["trusted"] is True

            # Drop the pin behind the catalogue's back, leaving the flag set.
            node._publishers.remove(cr.publisher_id(
                publisher._identity.dsa_public_key).hex())
            assert entry["trusted"] is True
            with pytest.raises(cr.ReleaseError, match="not trusted"):
                await node.install_release(info["publisher_id"])
        finally:
            await publisher.stop(); await node.stop()

    async def test_a_key_that_is_not_a_key_is_refused(self):
        node = _node()
        try:
            for bad in ("", "zz", "not hex"):
                with pytest.raises(cr.ReleaseError):
                    node.trust_publisher(bad)
        finally:
            await node.stop()


class TestAutomaticInstall:
    async def _ready(self, tmp_path, monkeypatch, auto=True):
        publisher, node = _node(), _node()
        info = await publisher.publish_release(_tree(str(tmp_path)))
        blob = publisher._releases.get(info["publisher_id"])["release"]
        node._packages = publisher._packages
        entry = node.trust_publisher(
            publisher._identity.dsa_public_key.hex(), "them", auto=auto)
        node._releases.offer(blob, node._identity.verify, node._trusts_publisher)
        installed = []

        async def fake_apply(files, version, **kwargs):
            installed.append(version)
            return {"applied": version, "restart_required": True}

        monkeypatch.setattr(updater, "apply_files", fake_apply)
        return publisher, node, info, entry, installed

    async def test_a_pass_installs_what_auto_was_asked_for(self, tmp_path,
                                                           monkeypatch):
        publisher, node, _info, _entry, installed = await self._ready(
            tmp_path, monkeypatch)
        try:
            assert await node._release_pass() == "9.9.9"
            assert installed == ["9.9.9"]
        finally:
            await publisher.stop(); await node.stop()

    async def test_trusting_without_auto_installs_nothing(self, tmp_path,
                                                          monkeypatch):
        """Two decisions: whose code we accept, and whether they get to install
        it while nobody is watching."""
        publisher, node, _info, _entry, installed = await self._ready(
            tmp_path, monkeypatch, auto=False)
        try:
            assert await node._release_pass() is None
            assert installed == []
        finally:
            await publisher.stop(); await node.stop()

    async def test_the_same_release_is_not_retried_in_a_loop(self, tmp_path,
                                                             monkeypatch):
        publisher, node, _info, _entry, installed = await self._ready(
            tmp_path, monkeypatch)
        try:
            await node._release_pass()
            assert await node._release_pass() is None
            assert installed == ["9.9.9"]
        finally:
            await publisher.stop(); await node.stop()

    async def test_a_failing_release_is_recorded_and_not_retried(self, tmp_path,
                                                                 monkeypatch):
        publisher, node, _info, _entry, _installed = await self._ready(
            tmp_path, monkeypatch)
        try:
            async def boom(files, version, **kwargs):
                raise updater.UpdateError("disk full")

            monkeypatch.setattr(updater, "apply_files", boom)
            assert await node._release_pass() is None
            assert node.release_overview()["log"][-1]["outcome"] == "failed"
            assert await node._release_pass() is None
        finally:
            await publisher.stop(); await node.stop()

    async def test_the_loop_survives_a_pass_that_explodes(self, tmp_path,
                                                          monkeypatch):
        """Zero crash: this loop dying would silently stop the updates an
        operator asked for."""
        import asyncio
        monkeypatch.setattr("src.node._RELEASE_TICK", 0.01)
        node = _node()
        node._running = True
        calls = []

        async def explode():
            calls.append(1)
            raise RuntimeError("boom")

        node._release_pass = explode
        task = asyncio.create_task(node._release_loop())
        try:
            for _ in range(50):
                await asyncio.sleep(0.01)
                if len(calls) >= 3:
                    break
            assert len(calls) >= 3 and not task.done()
        finally:
            node._running = False
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            await node.stop()
