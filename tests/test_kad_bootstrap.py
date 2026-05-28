"""
Integration tests for Kademlia bootstrap:
- dsa_pub stored at handshake time
- RoutingTable populated at handshake with empty addresses, filled by PING
- query_id echoed in FOUND_NODE responses
- iterative kad_lookup discovers nodes via an intermediate bridge
"""
import asyncio
import pytest
from src.node import (
    MeshNode, FIND_NODE, FOUND_NODE,
)
from src.node_id import NodeID
from src.packet import Packet
from tests.conftest import (
    FakeTransport, make_node, make_manager,
    ConnectableFakeTransportManager,
)


def _make_connectable_node() -> MeshNode:
    return MeshNode(transport_manager=ConnectableFakeTransportManager())


async def _full_handshake(node_a: MeshNode, node_b: MeshNode,
                           addr: str = "fake://b") -> None:
    """Connect node_a to node_b via invite, wait for session on both sides."""
    code = node_b.generate_invite()
    node_a._transport_manager.register_target(addr, node_b)
    await node_a.join(addr, code)
    await node_a.wait_for_session(timeout=5.0)
    deadline = asyncio.get_event_loop().time() + 5.0
    while asyncio.get_event_loop().time() < deadline:
        if any(p.session is not None for p in node_b._peers):
            break
        await asyncio.sleep(0.05)


@pytest.mark.asyncio
async def test_handshake_populates_routing_with_dsa_pub():
    """After a full handshake, both peers appear in each other's routing table with dsa_pub."""
    node_a = _make_connectable_node()
    node_b = _make_connectable_node()

    await _full_handshake(node_a, node_b)

    # node_a (joiner) must have node_b in routing with dsa_pub
    entry_b = node_a._routing.get(node_b.id)
    assert entry_b is not None, "node_b not in node_a routing table"
    assert entry_b.dsa_pub != b"", "dsa_pub not stored for node_b in node_a"
    assert entry_b.dsa_pub == node_b._identity.dsa_public_key

    # node_b (host) must have node_a in routing with dsa_pub
    entry_a = node_b._routing.get(node_a.id)
    assert entry_a is not None, "node_a not in node_b routing table"
    assert entry_a.dsa_pub != b"", "dsa_pub not stored for node_a in node_b"
    assert entry_a.dsa_pub == node_a._identity.dsa_public_key

    await node_a.stop()
    await node_b.stop()


@pytest.mark.asyncio
async def test_ping_updates_addresses_after_handshake():
    """PING after handshake merges addresses into the existing routing entry."""
    node_a = _make_connectable_node()
    node_b = _make_connectable_node()

    await _full_handshake(node_a, node_b)

    # Handshake created addressless entries — now node_a sends PING with an address
    node_a._addresses = ["tcp://node_a:9100"]
    for peer in node_a._peers:
        if peer.session is not None:
            await node_a.ping(peer)
    await asyncio.sleep(0.1)

    # node_b's routing entry for node_a should now have the address
    entry_a = node_b._routing.get(node_a.id)
    assert entry_a is not None
    assert "tcp://node_a:9100" in entry_a.addresses
    # dsa_pub must be preserved (not cleared by the PING merge)
    assert entry_a.dsa_pub == node_a._identity.dsa_public_key

    await node_a.stop()
    await node_b.stop()


@pytest.mark.asyncio
async def test_find_node_query_id_echoed():
    """FOUND_NODE response must start with the exact 8-byte query_id from FIND_NODE."""
    node, fake = await make_node()
    sender_id = NodeID.generate()
    node._peers[0].authenticated_id = sender_id

    target = NodeID.generate()
    query_id = b"\xde\xad\xbe\xef\x01\x02\x03\x04"
    query = Packet.create(FIND_NODE, sender_id.raw, node.id.raw, target.raw + query_id)
    fake.inject(query)
    await asyncio.sleep(0.05)
    await node.stop()

    fn_reply = next((p for p in fake.sent if p.type == FOUND_NODE), None)
    assert fn_reply is not None, "No FOUND_NODE reply sent"
    assert fn_reply.payload[:8] == query_id, "query_id not echoed in FOUND_NODE"


@pytest.mark.asyncio
async def test_kad_lookup_finds_node_via_bridge():
    """
    A ↔ B ↔ C topology (B is bridge).
    A does kad_lookup(C.id) — queries B, gets C back, adds C to routing table.
    """
    node_a = _make_connectable_node()
    node_b = _make_connectable_node()
    node_c = MeshNode(transport_manager=make_manager())  # just for identity

    # Full handshake A ↔ B so A trusts B's root
    await _full_handshake(node_a, node_b)

    # Populate B's cert store and routing table with C
    cert_c = node_b._identity.issue_cert(node_c.id, node_c._identity.dsa_public_key)
    node_b._cert_store.add(cert_c)
    node_b._routing.add(node_c.id, ["fake://c:9100"], node_c._identity.dsa_public_key)

    # A's lookup should query B → receive C in FOUND_NODE → add C to A's routing table
    discovered = await node_a.kad_lookup(node_c.id)
    assert node_c.id in discovered, "C not discovered via B"
    assert node_a._routing.get(node_c.id) is not None, "C not in A routing table after lookup"

    await node_a.stop()
    await node_b.stop()
