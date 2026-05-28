"""
Tests for on-demand routing — Roadmap point 3.

Policy: direct peer > forwarding via closer peer > on-demand connection.
On-demand is triggered when _forward_packet / _route_outbound have no
authenticated candidate to route through.
"""
import asyncio
import os
import pytest
from src.node import (
    MeshNode, DATA, FIND_NODE, FOUND_NODE,
    _encode_entries,
)
from src.node_id import NodeID
from src.crypto import SessionKey
from src.routing import NodeEntry
from src.packet import Packet
from tests.conftest import (
    FakeTransport, make_node, make_manager,
    LinkedFakeTransport, ConnectableFakeTransportManager,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cross_trust(node_x: MeshNode, node_y: MeshNode) -> None:
    """Mutual PKI trust: each node recognises the other's self-signed cert."""
    cert_x = node_x._identity.self_signed_cert()
    cert_y = node_y._identity.self_signed_cert()
    node_y._cert_store.add(cert_x)
    node_y._cert_store.add_root(node_x.id)
    node_x._cert_store.add(cert_y)
    node_x._cert_store.add_root(node_y.id)


def _register(manager: ConnectableFakeTransportManager,
               src: MeshNode, dst: MeshNode, addr: str) -> None:
    """Register dst at addr in manager and add it to src's routing table."""
    manager.register_target(addr, dst)
    src._routing.add(dst.id, [addr], dst._identity.dsa_public_key)


# ---------------------------------------------------------------------------
# 9.1 — _ensure_route_to
# ---------------------------------------------------------------------------

class TestEnsureRouteTo:
    async def test_returns_existing_peer(self):
        """Already-authenticated peer is returned immediately without opening a new connection."""
        manager = ConnectableFakeTransportManager()
        node_a = MeshNode(transport_manager=manager)
        fake = FakeTransport()
        await node_a._inject_peer(fake)
        node_b_id = NodeID(os.urandom(20))
        node_a._peers[0].authenticated_id = node_b_id
        node_a._peers[0].session = SessionKey(os.urandom(32))

        peer = await node_a._ensure_route_to(node_b_id)

        assert peer is node_a._peers[0]
        assert manager.connect_calls == 0
        await node_a.stop()

    async def test_returns_none_for_self(self):
        manager = ConnectableFakeTransportManager()
        node = MeshNode(transport_manager=manager)
        assert await node._ensure_route_to(node.id) is None
        await node.stop()

    async def test_opens_connection_when_in_routing_table(self):
        """Target in routing table → transport opened, handshake completes, peer returned."""
        manager = ConnectableFakeTransportManager()
        node_a = MeshNode(transport_manager=manager)
        node_b = MeshNode(transport_manager=make_manager())
        _cross_trust(node_a, node_b)
        _register(manager, node_a, node_b, "fake://node_b_open")

        peer = await asyncio.wait_for(
            node_a._ensure_route_to(node_b.id), timeout=5.0
        )

        assert peer is not None
        assert peer.authenticated_id == node_b.id
        assert peer.session is not None

        await node_a.stop()
        await node_b.stop()

    async def test_returns_none_on_lookup_miss(self):
        """No peers to query, no routing table entry → None."""
        manager = ConnectableFakeTransportManager()
        node = MeshNode(transport_manager=manager)
        unknown = NodeID(os.urandom(20))

        result = await asyncio.wait_for(
            node._ensure_route_to(unknown, timeout=0.2), timeout=2.0
        )

        assert result is None
        await node.stop()

    async def test_coalesces_concurrent_calls(self):
        """Two concurrent calls for the same target open only one transport."""
        manager = ConnectableFakeTransportManager()
        node_a = MeshNode(transport_manager=manager)
        node_b = MeshNode(transport_manager=make_manager())
        _cross_trust(node_a, node_b)
        _register(manager, node_a, node_b, "fake://node_b_coalesce")

        p1, p2 = await asyncio.wait_for(
            asyncio.gather(
                node_a._ensure_route_to(node_b.id),
                node_a._ensure_route_to(node_b.id),
            ),
            timeout=5.0,
        )

        assert p1 is not None
        assert p2 is not None
        assert manager.connect_calls == 1   # only one transport opened

        await node_a.stop()
        await node_b.stop()

    async def test_cleans_up_peer_on_handshake_timeout(self):
        """Dead address (no server side) → peer created then cleaned up, None returned."""
        manager = ConnectableFakeTransportManager()
        node_a = MeshNode(transport_manager=manager)
        node_b = MeshNode(transport_manager=make_manager())
        # Register None → no server side → CHALLENGE never sent → auth never completes
        manager.register_target("fake://dead", None)
        node_a._routing.add(node_b.id, ["fake://dead"], node_b._identity.dsa_public_key)

        initial = len(node_a._peers)
        result = await asyncio.wait_for(
            node_a._ensure_route_to(node_b.id, timeout=0.15), timeout=2.0
        )

        assert result is None
        assert len(node_a._peers) <= initial   # peer was cleaned up

        await node_a.stop()
        await node_b.stop()


# ---------------------------------------------------------------------------
# 9.2 — _route_outbound integration
# ---------------------------------------------------------------------------

class TestRouteOutboundOnDemand:
    async def test_falls_back_to_on_demand_when_no_peers(self):
        """No authenticated peers → on-demand connect → packet delivered."""
        manager = ConnectableFakeTransportManager()
        node_a = MeshNode(transport_manager=manager)
        node_b = MeshNode(transport_manager=make_manager())
        _cross_trust(node_a, node_b)
        _register(manager, node_a, node_b, "fake://node_b_route_out")

        # Pre-share E2E session (E2E handshake is a separate concern)
        shared = os.urandom(32)
        node_a._e2e_sessions[node_b.id] = SessionKey(shared)
        node_b._e2e_sessions[node_a.id] = SessionKey(shared)

        await asyncio.wait_for(
            node_a.send_data(node_b.id, b"on-demand data"),
            timeout=5.0,
        )
        src, payload = await asyncio.wait_for(node_b.receive_data(), timeout=2.0)

        assert src == node_a.id
        assert payload == b"on-demand data"

        await node_a.stop()
        await node_b.stop()


# ---------------------------------------------------------------------------
# 9.3 — _forward_packet integration
# ---------------------------------------------------------------------------

class TestForwardPacketOnDemand:
    async def test_relay_opens_connection_on_demand(self):
        """B receives a packet for C, has no peer for C, but C is in B's routing table.
        B opens a transport to C on-demand and forwards the packet."""
        manager_b = ConnectableFakeTransportManager()
        t_ba = FakeTransport()   # A's transport pointing at B

        node_a = MeshNode(transport_manager=make_manager())
        node_b = MeshNode(transport_manager=manager_b)
        node_c = MeshNode(transport_manager=make_manager())

        _cross_trust(node_a, node_b)
        _cross_trust(node_b, node_c)

        # Wire A → B via FakeTransport (manual auth, no real handshake needed here)
        await node_b._inject_peer(t_ba)
        shared_ab = os.urandom(32)
        node_b._peers[0].authenticated_id = node_a.id
        node_b._peers[0].session = SessionKey(shared_ab)

        # C in B's routing table; B can connect on-demand
        _register(manager_b, node_b, node_c, "fake://node_c_fwd")

        # Pre-share A↔C E2E session (skip E2E handshake)
        shared_ac = os.urandom(32)
        node_a._e2e_sessions[node_c.id] = SessionKey(shared_ac)
        node_c._e2e_sessions[node_a.id] = SessionKey(shared_ac)

        # A sends DATA destined for C; B must forward on-demand
        pkt = Packet.create_encrypted(
            DATA, node_a.id.raw, node_c.id.raw,
            b"relay on-demand", node_a._e2e_sessions[node_c.id],
        )
        t_ba.inject(pkt)

        src, payload = await asyncio.wait_for(node_c.receive_data(), timeout=5.0)

        assert src == node_a.id
        assert payload == b"relay on-demand"

        await node_a.stop()
        await node_b.stop()
        await node_c.stop()


# ---------------------------------------------------------------------------
# 9.4 — Kademlia lookup
# ---------------------------------------------------------------------------

class TestKademliaLookup:
    async def test_lookup_populates_routing_table(self):
        """FIND_NODE is sent; FOUND_NODE reply adds target to routing table → True."""
        node_a, fake_b = await make_node()
        node_b_id = NodeID(os.urandom(20))
        node_a._peers[0].authenticated_id = node_b_id
        node_a._peers[0].session = SessionKey(os.urandom(32))

        node_c = MeshNode(transport_manager=make_manager())
        # node_a must trust node_c's root for _handle_found_node to accept the entry
        node_a._cert_store.add(node_c._identity.self_signed_cert())
        node_a._cert_store.add_root(node_c.id)

        async def _reply_found_node() -> None:
            deadline = asyncio.get_event_loop().time() + 3.0
            while asyncio.get_event_loop().time() < deadline:
                fn_pkt = next((p for p in fake_b.sent if p.type == FIND_NODE), None)
                if fn_pkt is not None:
                    query_id = fn_pkt.payload[20:28]  # echo the query_id back
                    chain = [node_c._identity.self_signed_cert()]
                    entry = NodeEntry(
                        node_c.id, ["fake://node_c_kad"],
                        node_c._identity.dsa_public_key, chain,
                    )
                    reply = Packet.create(
                        FOUND_NODE, node_b_id.raw, node_a.id.raw,
                        query_id + _encode_entries([entry]),
                    )
                    fake_b.inject(reply)
                    return
                await asyncio.sleep(0.02)

        asyncio.create_task(_reply_found_node())

        found = await asyncio.wait_for(
            node_a._kademlia_lookup(node_c.id, timeout=2.0), timeout=4.0
        )

        assert found is True
        assert node_a._routing.contains(node_c.id)

        await node_a.stop()
        await node_c.stop()

    async def test_lookup_returns_false_when_no_replies(self):
        """No FOUND_NODE replies → lookup exhausts rounds, returns False."""
        node_a, fake_b = await make_node()
        node_b_id = NodeID(os.urandom(20))
        node_a._peers[0].authenticated_id = node_b_id
        node_a._peers[0].session = SessionKey(os.urandom(32))

        unknown = NodeID(os.urandom(20))
        found = await asyncio.wait_for(
            node_a._kademlia_lookup(unknown, timeout=0.3), timeout=3.0
        )

        assert found is False
        assert not node_a._routing.contains(unknown)

        await node_a.stop()
