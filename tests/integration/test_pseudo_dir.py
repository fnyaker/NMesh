"""
Integration: publish a pseudo on one node and find it from another, over real
TCP with real ML-DSA. Exercises DIR_STORE / DIR_FIND / DIR_FOUND, the self-
authenticating claims, and Kademlia replication.

Excluded from the default suite (see pyproject addopts).
"""
import asyncio

import pytest

from src import MeshNode
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer
from src.app_channel import CHAT_APP_ID
from src.pseudo_dir import dir_key


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
    await guest.bootstrap()
    await host.bootstrap()
    return host, guest


class TestPseudoDirectory:
    async def test_publish_then_lookup_from_peer(self):
        host, guest = await _pair("127.0.0.1:19170")
        try:
            await guest.publish_pseudo(CHAT_APP_ID, "alice")
            res = await asyncio.wait_for(
                host.lookup_pseudo(CHAT_APP_ID, "Alice"), timeout=30.0)
            assert any(r["id"] == guest.id.raw.hex() for r in res)
            # Having looked it up, the host now caches the claim → re-serves it.
            assert host._pseudo_store.get(dir_key(CHAT_APP_ID, "alice"))
        finally:
            await guest.stop()
            await host.stop()

    async def test_lookup_unknown_returns_empty(self):
        host, guest = await _pair("127.0.0.1:19171")
        try:
            res = await asyncio.wait_for(
                host.lookup_pseudo(CHAT_APP_ID, "ghost"), timeout=15.0)
            assert res == []
        finally:
            await guest.stop()
            await host.stop()

    async def test_hub_topology_lookup_via_relay(self):
        # A and B are NOT directly connected — both only reach a shared relay R
        # (a common real deployment). The directory must still resolve, because
        # publish/lookup also fan out to direct peers (the relay), not only the
        # abstract closest-to-key nodes.
        relay = make_node()
        a = make_node()
        b = make_node()
        await relay.start(["tcp://127.0.0.1:19173"])
        await a.join("tcp://127.0.0.1:19173", relay.generate_invite())
        await a.wait_for_session(timeout=15.0)
        await b.join("tcp://127.0.0.1:19173", relay.generate_invite())
        await b.wait_for_session(timeout=15.0)
        a._punch_enabled = False
        b._punch_enabled = False
        try:
            await a.publish_pseudo(CHAT_APP_ID, "alice")
            res = await asyncio.wait_for(
                b.lookup_pseudo(CHAT_APP_ID, "alice"), timeout=20.0)
            assert any(r["id"] == a.id.raw.hex() for r in res)
        finally:
            await a.stop()
            await b.stop()
            await relay.stop()
