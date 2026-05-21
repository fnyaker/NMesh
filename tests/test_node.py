import asyncio
import pytest
from src.node import MeshNode, PING, PONG, FIND_NODE, FOUND_NODE, _encode_entries
from src.node_id import NodeID
from src.routing import NodeEntry
from src.packet import Packet
from tests.conftest import FakeTransport, make_node


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
        assert fake.sent[0].payload == target.raw


class TestHandlePing:
    async def test_handle_ping_sends_pong(self):
        node, fake = await make_node()
        sender_id = NodeID.generate()
        ping = Packet.create(PING, sender_id.raw, node.id.raw, b"127.0.0.1:9001")
        fake.inject(ping)
        await asyncio.sleep(0.05)
        await node.stop()
        assert any(p.type == PONG for p in fake.sent)

    async def test_handle_ping_adds_sender_to_routing(self):
        node, fake = await make_node()
        sender_id = NodeID.generate()
        ping = Packet.create(PING, sender_id.raw, node.id.raw, b"127.0.0.1:9001")
        fake.inject(ping)
        await asyncio.sleep(0.05)
        await node.stop()
        closest = node._routing.get_closest(sender_id, 1)
        assert closest[0].node_id == sender_id


class TestHandleFindNode:
    async def test_handle_find_node_sends_found_node(self):
        node, fake = await make_node()
        target = NodeID.generate()
        query = Packet.create(FIND_NODE, NodeID.generate().raw, node.id.raw, target.raw)
        fake.inject(query)
        await asyncio.sleep(0.05)
        await node.stop()
        assert any(p.type == FOUND_NODE for p in fake.sent)


class TestHandleFoundNode:
    async def test_handle_found_node_populates_routing(self):
        node, fake = await make_node()
        remote_id = NodeID.generate()
        entries = [NodeEntry(remote_id, "127.0.0.1:9002")]
        found = Packet.create(FOUND_NODE, NodeID.generate().raw, node.id.raw,
                              _encode_entries(entries))
        fake.inject(found)
        await asyncio.sleep(0.05)
        await node.stop()
        closest = node._routing.get_closest(remote_id, 1)
        assert closest[0].node_id == remote_id


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
        assert fake.sent[0].payload == node.id.raw
