"""
Integration: names across a real mesh, over real TCP with real ML-DSA.

Two planes are exercised. Gossip (``PSEUDO_ANNOUNCE``) is what makes a *partial*
search work at all: it fills every node's book, and a search is then answered
locally. The keyed directory (``DIR_STORE`` / ``DIR_FIND`` / ``DIR_FOUND``)
covers the rest — an exact name whose owner sits beyond the gossip horizon.

Excluded from the default suite (see pyproject addopts).
"""
import asyncio

import pytest

from src import MeshNode
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer
from src.pseudo_dir import dir_key


def make_node(pseudo=None) -> MeshNode:
    mgr = TransportManager()
    mgr.register("tcp", TCPTransport, TCPServer)
    return MeshNode(mgr, pseudo=pseudo)


async def _pair(addr: str, host_name=None, guest_name=None):
    host = make_node(host_name)
    guest = make_node(guest_name)
    code = host.generate_invite()
    await host.start([f"tcp://{addr}"])
    await guest.join(f"tcp://{addr}", code)
    await guest.wait_for_session(timeout=15.0)
    await host.wait_for_session(timeout=15.0)
    await guest.bootstrap()
    await host.bootstrap()
    return host, guest


async def _until(predicate, timeout=15.0):
    """Wait for gossip to land. Nothing acknowledges an announce, so the only
    honest way to wait for one is to watch for its effect."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.1)
    return predicate()


class TestGossip:
    async def test_each_side_learns_the_other_name_on_connect(self):
        host, guest = await _pair("127.0.0.1:19170", "Host Harriet", "guest")
        try:
            assert await _until(lambda: host.pseudo_of(guest.id) == "guest")
            assert await _until(lambda: guest.pseudo_of(host.id) == "Host Harriet")
        finally:
            await guest.stop()
            await host.stop()

    async def test_partial_search_finds_a_node_never_asked_about(self):
        host, guest = await _pair("127.0.0.1:19174", "Host Harriet", "Alice Ada")
        try:
            assert await _until(lambda: host.find_pseudo("ali") != [])
            hits = host.find_pseudo("ali")
            assert hits[0]["id"] == guest.id.raw.hex()
            assert hits[0]["pseudo"] == "Alice Ada"
            # A word inside the name, and the wrong case, both still find it.
            assert host.find_pseudo("ADA")[0]["id"] == guest.id.raw.hex()
            assert host.find_pseudo("nobody") == []
        finally:
            await guest.stop()
            await host.stop()

    async def test_a_rename_reaches_the_other_side(self):
        host, guest = await _pair("127.0.0.1:19175", "host", "before")
        try:
            assert await _until(lambda: host.pseudo_of(guest.id) == "before")
            guest.set_pseudo("after")
            assert await _until(lambda: host.pseudo_of(guest.id) == "after")
            # And the old name stops answering searches.
            assert host.find_pseudo("before") == []
        finally:
            await guest.stop()
            await host.stop()

    async def test_a_name_crosses_a_relay_it_was_never_sent_through(self):
        # A and B are not connected to each other; both only reach a relay. The
        # relay passes the claim on because accepting it changed its own view.
        relay = make_node("relay")
        a = make_node("Alice Ada")
        b = make_node("bob")
        await relay.start(["tcp://127.0.0.1:19176"])
        await a.join("tcp://127.0.0.1:19176", relay.generate_invite())
        await a.wait_for_session(timeout=15.0)
        await b.join("tcp://127.0.0.1:19176", relay.generate_invite())
        await b.wait_for_session(timeout=15.0)
        a._punch_enabled = False
        b._punch_enabled = False
        try:
            assert await _until(lambda: b.pseudo_of(a.id) == "Alice Ada", timeout=20.0)
            assert b.find_pseudo("ali")[0]["id"] == a.id.raw.hex()
        finally:
            await a.stop()
            await b.stop()
            await relay.stop()


class TestDirectory:
    async def test_publish_then_exact_lookup_from_peer(self):
        host, guest = await _pair("127.0.0.1:19171", None, "Alice")
        try:
            await guest.publish_pseudo()
            res = await asyncio.wait_for(host.lookup_pseudo("alice"), timeout=30.0)
            assert any(r["id"] == guest.id.raw.hex() for r in res)
            # Having looked it up, the host holds the claim → re-serves it.
            assert host._pseudo_book.get(dir_key("alice"))
        finally:
            await guest.stop()
            await host.stop()

    async def test_lookup_unknown_returns_empty(self):
        host, guest = await _pair("127.0.0.1:19172", "host", "guest")
        try:
            res = await asyncio.wait_for(host.lookup_pseudo("ghost"), timeout=15.0)
            assert res == []
        finally:
            await guest.stop()
            await host.stop()

    async def test_hub_topology_lookup_via_relay(self):
        # A and B are NOT directly connected — both only reach a shared relay
        # (a common real deployment). The directory must still resolve, because
        # publish/lookup also fan out to direct peers (the relay), not only the
        # abstract closest-to-key nodes.
        relay = make_node()
        a = make_node("alice")
        b = make_node()
        await relay.start(["tcp://127.0.0.1:19173"])
        await a.join("tcp://127.0.0.1:19173", relay.generate_invite())
        await a.wait_for_session(timeout=15.0)
        await b.join("tcp://127.0.0.1:19173", relay.generate_invite())
        await b.wait_for_session(timeout=15.0)
        a._punch_enabled = False
        b._punch_enabled = False
        try:
            await a.publish_pseudo()
            res = await asyncio.wait_for(b.lookup_pseudo("alice"), timeout=20.0)
            assert any(r["id"] == a.id.raw.hex() for r in res)
        finally:
            await a.stop()
            await b.stop()
            await relay.stop()
