"""
Integration: publish an app on one node's DHT and fetch it from another, over
real TCP with real crypto. Exercises STORE / FIND_VALUE / FOUND_VALUE, the
content store, chunking, and end-to-end integrity verification.

Excluded from the default suite (see pyproject addopts).
"""
import asyncio

import pytest

from src import MeshNode
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer


def make_node() -> MeshNode:
    mgr = TransportManager()
    mgr.register("tcp", TCPTransport, TCPServer)
    return MeshNode(mgr)


async def _pair(addr: str):
    host = make_node()
    guest = make_node()
    code = host.generate_invite()
    await host.start([f"tcp://{addr}"])
    await guest.join(f"tcp://{addr}", code)
    await guest.wait_for_session(timeout=15.0)
    await host.wait_for_session(timeout=15.0)
    # Advertise addresses so on-demand DHT links can be built either way.
    await guest.bootstrap()
    await host.bootstrap()
    return host, guest


class TestDHTAppSharing:
    async def test_publish_then_fetch(self):
        host, guest = await _pair("127.0.0.1:19160")
        files = {
            "app.py": b"# a shared app\n" + b"payload " * 5000,  # multi-chunk
            "README": b"an app shared across the mesh",
            "empty": b"",
        }
        try:
            app_id = await guest.publish_app("chat", "0.1.0", files)
            result = await asyncio.wait_for(host.fetch_app(app_id), timeout=30.0)
            assert result is not None
            manifest, got = result
            assert manifest["name"] == "chat"
            assert got == files
            # Having fetched it, the host now caches it → it can re-share.
            assert app_id in host._dht_store
        finally:
            await guest.stop()
            await host.stop()

    async def test_fetch_unknown_returns_none(self):
        host, guest = await _pair("127.0.0.1:19161")
        try:
            missing = b"\x00" * 20
            assert await asyncio.wait_for(host.fetch_app(missing), timeout=15.0) is None
        finally:
            await guest.stop()
            await host.stop()

    async def test_third_node_fetches_via_query(self):
        # A node that joins AFTER publication holds none of the data locally, so
        # its fetch must go through FIND_VALUE / FOUND_VALUE against a holder.
        addr = "127.0.0.1:19162"
        host, guest = await _pair(addr)
        files = {"f": b"shared via query " * 300}
        try:
            app_id = await guest.publish_app("x", "1", files)

            third = make_node()
            code = host.generate_invite()
            await third.join(f"tcp://{addr}", code)
            await third.wait_for_session(timeout=15.0)
            await third.bootstrap()
            assert app_id not in third._dht_store  # nothing cached yet

            result = await asyncio.wait_for(third.fetch_app(app_id), timeout=30.0)
            assert result is not None
            _, got = result
            assert got == files
            await third.stop()
        finally:
            await guest.stop()
            await host.stop()
