import asyncio
import pytest
from src.node import MeshNode, PING, PONG, FIND_NODE, FOUND_NODE, _encode_entries, _encode_addresses
from src.node_id import NodeID
from src.routing import NodeEntry
from src.packet import Packet
from src.crypto import CryptoIdentity
from tests.conftest import FakeTransport, make_node


def _make_entry(address: str, issuer_node: 'MeshNode | None' = None) -> NodeEntry:
    """
    Create a NodeEntry with a real DSA keypair.
    If issuer_node is provided, the entry includes a cert chain signed by that node.
    """
    identity = CryptoIdentity()
    dsa_pub  = identity.dsa_public_key
    node_id  = NodeID.from_public_key(dsa_pub)
    chain    = []
    if issuer_node is not None:
        cert      = issuer_node._identity.issue_cert(node_id, dsa_pub)
        self_cert = issuer_node._identity.self_signed_cert()
        chain     = [cert, self_cert]
    return NodeEntry(node_id, [address], dsa_pub, chain)


class TestPing:
    async def test_ping_sends_ping_type(self):
        node, fake = await make_node()
        await node.ping(node._peers[0])
        await node.stop()
        assert fake.sent[0].type == PING

    async def test_ping_src_is_own_id(self):
        node, fake = await make_node()
        await node.ping(node._peers[0])
        await node.stop()
        assert fake.sent[0].src_id == node.id.raw


class TestFindNode:
    async def test_find_node_sends_correct_type(self):
        node, fake = await make_node()
        target = NodeID.generate()
        await node.find_node(target)
        await node.stop()
        assert fake.sent[0].type == FIND_NODE

    async def test_find_node_payload_is_target_id(self):
        node, fake = await make_node()
        target = NodeID.generate()
        await node.find_node(target)
        await node.stop()
        assert fake.sent[0].payload[:20] == target.raw


class TestHandlePing:
    async def test_handle_ping_sends_pong(self):
        node, fake = await make_node()
        sender_id = NodeID.generate()
        node._peers[0].authenticated_id = sender_id
        payload = _encode_addresses(["tcp://127.0.0.1:9001"])
        ping = Packet.create(PING, sender_id.raw, node.id.raw, payload)
        fake.inject(ping)
        await asyncio.sleep(0.05)
        await node.stop()
        assert any(p.type == PONG for p in fake.sent)

    async def test_handle_ping_adds_sender_to_routing(self):
        node, fake = await make_node()
        sender_id = NodeID.generate()
        node._peers[0].authenticated_id = sender_id
        payload = _encode_addresses(["tcp://127.0.0.1:9001"])
        ping = Packet.create(PING, sender_id.raw, node.id.raw, payload)
        fake.inject(ping)
        await asyncio.sleep(0.05)
        await node.stop()
        closest = node._routing.get_closest(sender_id, 1)
        assert closest[0].node_id == sender_id

    async def test_handle_ping_invalid_uri_dropped(self):
        """A PING with a malformed URI in its address list is silently ignored."""
        node, fake = await make_node()
        sender_id = NodeID.generate()
        node._peers[0].authenticated_id = sender_id
        # Craft a payload with an invalid URI (no scheme separator)
        payload = _encode_addresses(["not-a-uri"])
        ping = Packet.create(PING, sender_id.raw, node.id.raw, payload)
        fake.inject(ping)
        await asyncio.sleep(0.05)
        await node.stop()
        assert node._routing.get(sender_id) is None

    async def test_handle_ping_old_plain_text_payload_ignored(self):
        """Old raw-string PING payload (no binary framing) must be silently dropped."""
        node, fake = await make_node()
        sender_id = NodeID.generate()
        node._peers[0].authenticated_id = sender_id
        ping = Packet.create(PING, sender_id.raw, node.id.raw, b"127.0.0.1:9001")
        fake.inject(ping)
        await asyncio.sleep(0.05)
        await node.stop()
        assert node._routing.get(sender_id) is None


class TestHandleFindNode:
    async def test_handle_find_node_sends_found_node(self):
        node, fake = await make_node()
        sender_id = NodeID.generate()
        target = NodeID.generate()
        node._peers[0].authenticated_id = sender_id
        node._peers[0].session = object()   # FOUND_NODE now routes back via _route_outbound
        query = Packet.create(FIND_NODE, sender_id.raw, node.id.raw, target.raw + b"\x00" * 8)
        fake.inject(query)
        await asyncio.sleep(0.05)
        await node.stop()
        assert any(p.type == FOUND_NODE for p in fake.sent)


class TestHandleFoundNode:
    async def test_handle_found_node_populates_routing(self):
        node, fake = await make_node()
        sender_id = NodeID.generate()
        node._peers[0].authenticated_id = sender_id
        entry = _make_entry("tcp://127.0.0.1:9002", issuer_node=node)
        found = Packet.create(FOUND_NODE, sender_id.raw, node.id.raw,
                              b"\x00" * 8 + _encode_entries([entry]))
        fake.inject(found)
        await asyncio.sleep(0.05)
        await node.stop()
        closest = node._routing.get_closest(entry.node_id, 1)
        assert closest[0].node_id == entry.node_id

    async def test_handle_found_node_malformed_uri_drops_entry(self):
        """Entry with a malformed URI must be dropped (section 9.3)."""
        node, fake = await make_node()
        sender_id = NodeID.generate()
        node._peers[0].authenticated_id = sender_id
        # Create entry with invalid URI — _encode_entries will include it raw;
        # _decode_entries must then drop the entire entry.
        entry = _make_entry("not-a-uri", issuer_node=node)
        found = Packet.create(FOUND_NODE, sender_id.raw, node.id.raw,
                              b"\x00" * 8 + _encode_entries([entry]))
        fake.inject(found)
        await asyncio.sleep(0.05)
        await node.stop()
        assert node._routing.get(entry.node_id) is None


class TestBootstrap:
    async def test_find_node_sends_to_peer(self):
        node, fake = await make_node()
        await node.find_node(node.id)
        await node.stop()
        assert fake.sent[0].type == FIND_NODE

    async def test_find_node_targets_own_id(self):
        node, fake = await make_node()
        await node.find_node(node.id)
        await node.stop()
        assert fake.sent[0].payload[:20] == node.id.raw
