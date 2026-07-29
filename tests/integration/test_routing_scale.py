"""
Integration: routing that keeps working once the mesh is more than tiny.

Every fault below only showed up past a handful of nodes, which is why the
smaller topology tests stayed green while real meshes went unstable:

  * a FOUND_NODE carrying post-quantum cert chains outgrew the packet cap, so
    from the fifth certified node on, every Kademlia lookup silently timed out
    and on-demand routing lost its only way to find an unknown id;
  * forwarding a packet with no live relay acquired the route *inside* the
    ingress link's receive loop, freezing that link for seconds — and the
    lookup it started needed an answer over that same frozen link;
  * replies were routed by a fresh XOR guess instead of the path the request
    had just proven.

Real TCP on loopback. Excluded from the default suite (see pyproject addopts).
These build several real nodes each, so they share one xdist group: run
sequentially rather than piling a few dozen post-quantum nodes on one machine.
"""
import asyncio
import os
import time

import pytest

from src import MeshNode
from src.app_channel import CHAT_APP_ID
from src.node import ECHO_REQUEST, _QID_LEN
from src.packet import Packet
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer
from tests.integration import free_port

pytestmark = pytest.mark.xdist_group("routing_scale")

LEAVES = 6


def _mgr() -> TransportManager:
    m = TransportManager()
    m.register("tcp", TCPTransport, TCPServer)
    return m


async def _relay_star(base: int, leaves: int = LEAVES):
    """One listening relay, ``leaves`` listener-less nodes joined to it — the
    NATted shape, where relaying is the only path between leaves."""
    relay = MeshNode(_mgr())
    await relay.start([f"tcp://127.0.0.1:{base}"])
    nodes = []
    for _ in range(leaves):
        leaf = MeshNode(_mgr())
        await leaf.start([])
        await leaf.join(f"tcp://127.0.0.1:{base}", relay.generate_invite())
        await leaf.wait_for_session(timeout=15.0)
        nodes.append(leaf)
    for n in [relay] + nodes:
        n._punch_enabled = False
        # Quiesce discovery so each assertion below observes the topology it
        # was written for, not whatever a background lookup happened to add.
        await n._stop_neighbor_maintenance()
    return relay, nodes


async def _line(base: int, count: int):
    """A-B-C-… with no shortcuts: neighbour maintenance is stopped, otherwise
    every node dials its XOR-nearest and the chain collapses (see gotchas)."""
    nodes = [MeshNode(_mgr()) for _ in range(count)]
    for i, nd in enumerate(nodes):
        await nd.start([f"tcp://127.0.0.1:{base + i}"])
    for i in range(count - 1):
        await nodes[i].join(f"tcp://127.0.0.1:{base + i + 1}",
                            nodes[i + 1].generate_invite())
        await nodes[i].wait_for_session(timeout=15.0)
    for nd in nodes:
        nd._punch_enabled = False
        await nd._stop_neighbor_maintenance()
    for x in nodes:                     # one trust anchor across the line
        for y in nodes:
            if x is not y:
                y._cert_store.add(x._identity.self_signed_cert())
                y._cert_store.add_root(x.id)
    return nodes


class TestBiggerMesh:
    async def test_lookup_and_relaying_survive_a_full_routing_table(self):
        """One star past the old breaking point, exercised end to end: the
        pieces all failed together when FOUND_NODE stopped fitting."""
        relay, leaves = await _relay_star(free_port())
        a, z = leaves[0], leaves[-1]
        try:
            certified = [e for e in relay._routing.all_entries()
                         if relay._cert_store.get_chain_to_root(e.node_id)]
            assert len(certified) >= 5, "topology must be past the old cliff"

            # 1) the relay can actually answer a lookup
            found = await asyncio.wait_for(
                a._kad_query_node(relay.id, z.id), timeout=15.0)
            assert found, "FIND_NODE must come back with entries"
            assert all(a._cert_store.verify_chain(e.cert_chain) is not None
                       for e in found)

            # 2) knowing only the relay, A must still find an id through it —
            #    the on-demand routing path for a node it has never met
            for entry in a._routing.all_entries():
                if entry.node_id != relay.id:
                    a._routing.remove(entry.node_id)
            assert await asyncio.wait_for(
                a._kademlia_lookup(z.id, timeout=10.0), timeout=15.0)
            assert a._routing.contains(z.id)

            # 3) leaf → leaf, only reachable through the relay
            assert not any(p.authenticated_id == z.id for p in a._peers)
            res = await asyncio.wait_for(
                a.console_ping_node(z.id.raw.hex()), timeout=15.0)
            assert res["reachable"] is True and res["via"] == "route"

            await a.send_data(z.id, b"through a crowded relay")
            got = await asyncio.wait_for(z.receive_data(), timeout=20.0)
            assert got[1] == b"through a crowded relay"

            # 4) the pseudo directory rides the same routed control plane
            await z.publish_pseudo(CHAT_APP_ID, "zoe")
            hits = await asyncio.wait_for(
                a.lookup_pseudo(CHAT_APP_ID, "zoe"), timeout=20.0)
            assert any(h["id"] == z.id.raw.hex() for h in hits)
        finally:
            for n in [relay] + leaves:
                await n.stop()

    async def test_packets_for_unreachable_ids_do_not_freeze_the_link(self):
        """One peer sending packets for destinations nobody can reach used to
        stall the relay's whole receive loop for that link, seconds at a time —
        a lever any authenticated peer could pull. With A as the relay's only
        peer the old inline acquisition could not even win: the lookup it
        started needed a FOUND_NODE from A, over the link it had just frozen."""
        relay, leaves = await _relay_star(free_port(), leaves=1)
        a = leaves[0]
        try:
            link = next(p for p in a._peers if p.authenticated_id == relay.id)
            for _ in range(10):
                await link.send(Packet.create(
                    ECHO_REQUEST, a.id.raw, os.urandom(20), os.urandom(_QID_LEN)))

            started = time.monotonic()
            res = await asyncio.wait_for(
                a.console_ping_node(relay.id.raw.hex()), timeout=15.0)
            elapsed = time.monotonic() - started
            assert res["reachable"] is True and res["via"] == "direct"
            assert elapsed < 3.0, f"direct ping took {elapsed:.1f}s behind junk"
        finally:
            for n in [relay] + leaves:
                await n.stop()


class TestReversePathOnAChain:
    async def test_a_relay_learns_the_way_back_from_the_request(self):
        """On A-B-C-D, C has no link to A: the only thing that tells it how to
        answer A is the link A's request arrived on."""
        nodes = await _line(free_port(4), 4)
        a, b, c, d = nodes
        try:
            assert c._route_hints.get(a.id) is None
            res = await asyncio.wait_for(
                a.console_ping_node(d.id.raw.hex()), timeout=20.0)
            assert res["reachable"] is True and res["via"] == "route"

            hint = c._route_hints.get(a.id)
            assert hint is not None, "the transiting request must teach C a way back"
            assert hint[0] == b.id, "and it must be the link it came in on"
        finally:
            for n in nodes:
                await n.stop()
