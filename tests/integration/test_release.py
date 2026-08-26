"""
A release crossing a real mesh: publish here, install there.

The unit tests hand the installing node the publisher's DHT store, which proves
the gates but not the carriage. This one uses two real nodes over TCP: the
package is chunked onto the DHT, the announce travels as a packet, and the
content comes back the same way. Nothing is stubbed but the swap itself — the
node's own tree is not something a test may replace.

Excluded from the default suite (see the pyproject addopts); run it explicitly:
    pytest tests/integration/test_release.py -q
"""
import asyncio
import os

import pytest

from src import core_release as cr
from src import updater
from src.node import MeshNode
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer


def _mgr() -> TransportManager:
    mgr = TransportManager()
    mgr.register("tcp", TCPTransport, TCPServer)
    return mgr


def _tree(root: str, version: str) -> str:
    """A minimal tree that `read_tree` accepts, with enough files to chunk."""
    os.makedirs(os.path.join(root, "src"), exist_ok=True)
    os.makedirs(os.path.join(root, "scripts"), exist_ok=True)
    with open(os.path.join(root, "src", "version.py"), "w") as handle:
        handle.write(f'__version__ = "{version}"\n')
    with open(os.path.join(root, "src", "node.py"), "w") as handle:
        handle.write("# the code\n")
    # Incompressible, so the package really is bigger than one packet and the
    # slicing is exercised rather than merely available. Repetitive filler
    # gzips down to nothing and would prove the opposite of what it looks like.
    with open(os.path.join(root, "src", "blob.bin"), "wb") as handle:
        handle.write(os.urandom(200_000))
    with open(os.path.join(root, "scripts", "run.py"), "w") as handle:
        handle.write("print('hi')\n")
    with open(os.path.join(root, "start.sh"), "w") as handle:
        handle.write("#!/bin/sh\necho hi\n")
    return root


async def _pair(port: int) -> tuple[MeshNode, MeshNode]:
    publisher, node = MeshNode(_mgr()), MeshNode(_mgr())
    code = publisher.generate_invite()
    await publisher.start([f"tcp://127.0.0.1:{port}"])
    await node.join(f"tcp://127.0.0.1:{port}", code)
    await node.wait_for_session(timeout=15.0)
    await publisher.wait_for_session(timeout=15.0)
    return publisher, node


class TestAReleaseCrossesTheMesh:
    async def test_published_here_installed_there(self, tmp_path, monkeypatch):
        publisher, node = await _pair(19390)
        try:
            info = await publisher.publish_release(
                _tree(str(tmp_path / "src-tree"), "9.9.9"),
                notes="crossing the mesh")

            # The announce reaches the other node by itself.
            async with asyncio.timeout(20.0):
                while node._releases.get(info["publisher_id"]) is None:
                    await asyncio.sleep(0.1)

            entry = node.release_overview()["releases"][0]
            assert entry["version"] == "9.9.9"
            assert entry["notes"] == "crossing the mesh"
            # Signed by someone this node has not pinned: visible, not usable.
            assert entry["trusted"] is False and entry["action"] is None

            node.trust_publisher(publisher._identity.dsa_public_key.hex(), "them")

            # The package really crosses the mesh, in slices, and verifies.
            assert not node._packages.has(info["release_id"])
            fetched = await node.fetch_release(info["publisher_id"])
            assert fetched is not None
            _entry, files = fetched
            assert cr.version_of(files) == "9.9.9"
            assert files["scripts/run.py"] == b"print('hi')\n"
            assert len(files["src/blob.bin"]) == 200_000
            # Bigger than one packet: the slicing and reassembly are real.
            from src.node import _RELEASE_SLICE
            assert entry["size"] > _RELEASE_SLICE
            # Having received it, this node now holds it — and is somewhere
            # else to ask. That is the whole distribution model.
            assert node._packages.has(info["release_id"])

            # …and the install path runs end to end. The swap itself is the one
            # thing stubbed: replacing the tree this test runs from is not a
            # thing a test may do.
            applied = {}

            async def fake_apply(files, version, **kwargs):
                applied.update({"files": files, "version": version})
                return {"applied": version, "restart_required": True}

            monkeypatch.setattr(updater, "apply_files", fake_apply)
            result = await node.install_release(info["publisher_id"])
            assert result["version"] == "9.9.9"
            assert applied["files"]["src/version.py"] == b'__version__ = "9.9.9"\n'
        finally:
            await node.stop(); await publisher.stop()

    async def test_a_third_node_fetches_from_the_one_that_kept_it(self, tmp_path):
        """The swarm: a node that received a release serves it to the next,
        without the publisher being involved at all."""
        publisher, middle = await _pair(19393)
        latecomer = MeshNode(_mgr())
        try:
            info = await publisher.publish_release(
                _tree(str(tmp_path / "tree"), "9.9.9"))
            async with asyncio.timeout(20.0):
                while middle._releases.get(info["publisher_id"]) is None:
                    await asyncio.sleep(0.1)
            middle.trust_publisher(publisher._identity.dsa_public_key.hex())
            assert await middle.fetch_release(info["publisher_id"]) is not None
            assert middle._packages.has(info["release_id"])

            # A third node joins through the middle one, and the publisher is
            # taken off the air entirely.
            code = middle.generate_invite()
            await middle.start(["tcp://127.0.0.1:19394"])
            await latecomer.join("tcp://127.0.0.1:19394", code)
            await latecomer.wait_for_session(timeout=15.0)
            async with asyncio.timeout(20.0):
                while latecomer._releases.get(info["publisher_id"]) is None:
                    await asyncio.sleep(0.1)
            await publisher.stop()

            latecomer.trust_publisher(
                publisher._identity.dsa_public_key.hex())
            fetched = await latecomer.fetch_release(info["publisher_id"])
            assert fetched is not None, "the middle node did not serve it"
            assert cr.version_of(fetched[1]) == "9.9.9"
            assert latecomer._packages.has(info["release_id"])
        finally:
            await latecomer.stop(); await middle.stop()
            try:
                await publisher.stop()
            except Exception:
                pass

    async def test_a_newer_release_supersedes_over_the_wire(self, tmp_path):
        publisher, node = await _pair(19391)
        try:
            first = await publisher.publish_release(
                _tree(str(tmp_path / "one"), "1.0.0"), ts=1000)
            async with asyncio.timeout(20.0):
                while node._releases.get(first["publisher_id"]) is None:
                    await asyncio.sleep(0.1)

            await publisher.publish_release(
                _tree(str(tmp_path / "two"), "2.0.0"), ts=2000)
            async with asyncio.timeout(20.0):
                while (node._releases.get(first["publisher_id"])["version"]
                       != "2.0.0"):
                    await asyncio.sleep(0.1)

            # One entry per publisher, holding the newest thing they signed.
            assert len(node._releases) == 1
        finally:
            await node.stop(); await publisher.stop()

    async def test_a_node_joining_later_is_caught_up(self, tmp_path):
        """The catch-up at the handshake: a release published before this node
        arrived still reaches it."""
        publisher, first = await _pair(19392)
        latecomer = MeshNode(_mgr())
        try:
            info = await publisher.publish_release(
                _tree(str(tmp_path / "tree"), "3.0.0"))
            async with asyncio.timeout(20.0):
                while first._releases.get(info["publisher_id"]) is None:
                    await asyncio.sleep(0.1)

            code = publisher.generate_invite()
            await latecomer.join("tcp://127.0.0.1:19392", code)
            await latecomer.wait_for_session(timeout=15.0)
            async with asyncio.timeout(20.0):
                while latecomer._releases.get(info["publisher_id"]) is None:
                    await asyncio.sleep(0.1)
            assert latecomer.release_overview()["releases"][0]["version"] == "3.0.0"
        finally:
            await latecomer.stop(); await first.stop(); await publisher.stop()
