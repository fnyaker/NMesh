import asyncio
import pytest
from src.node import MeshNode, DATA
from src.node_id import NodeID
from src.packet import Packet
from tests.conftest import FakeTransport, make_node


async def make_connected_pair() -> tuple[MeshNode, FakeTransport, MeshNode, FakeTransport]:
    node_a, fake_a = await make_node()
    node_b, fake_b = await make_node()
    await node_a.initiate_handshake(node_a._peers[0])
    fake_b.inject(fake_a.sent[-1])
    await asyncio.sleep(0.1)
    ack = next(p for p in fake_b.sent if p.type == 0x09)
    fake_a.inject(ack)
    await asyncio.sleep(0.1)
    return node_a, fake_a, node_b, fake_b


class TestSendData:
    async def test_send_without_session_raises(self):
        node, fake = await make_node()
        with pytest.raises(RuntimeError):
            await node.send_data(b"hello")
        await node.stop()

    async def test_send_produces_data_packet(self):
        node_a, fake_a, node_b, fake_b = await make_connected_pair()
        await node_a.send_data(b"hello mesh")
        await node_a.stop()
        await node_b.stop()
        data_packets = [p for p in fake_a.sent if p.type == DATA]
        assert len(data_packets) == 1

    async def test_payload_is_encrypted(self):
        node_a, fake_a, node_b, fake_b = await make_connected_pair()
        plaintext = b"secret message"
        await node_a.send_data(plaintext)
        await node_a.stop()
        await node_b.stop()
        data_pkt = next(p for p in fake_a.sent if p.type == DATA)
        assert data_pkt.payload != plaintext


class TestReceiveData:
    async def test_receive_decrypts_payload(self):
        node_a, fake_a, node_b, fake_b = await make_connected_pair()
        plaintext = b"hello from A"
        await node_a.send_data(plaintext)
        data_pkt = next(p for p in fake_a.sent if p.type == DATA)
        fake_b.inject(data_pkt)
        received = await asyncio.wait_for(node_b.receive_data(), timeout=1.0)
        await node_a.stop()
        await node_b.stop()
        assert received == plaintext

    async def test_data_without_session_ignored(self):
        node_a, fake_a, node_b, fake_b = await make_connected_pair()
        node_b._peers[0].session = None
        await node_a.send_data(b"hello")
        data_pkt = next(p for p in fake_a.sent if p.type == DATA)
        fake_b.inject(data_pkt)
        await asyncio.sleep(0.05)
        await node_a.stop()
        await node_b.stop()
        assert node_b._data_queue.empty()

    async def test_multiple_messages_in_order(self):
        node_a, fake_a, node_b, fake_b = await make_connected_pair()
        messages = [f"msg{i}".encode() for i in range(5)]
        sent_before = len(fake_a.sent)
        for msg in messages:
            await node_a.send_data(msg)
        data_packets = [p for p in fake_a.sent[sent_before:] if p.type == DATA]
        for pkt in data_packets:
            fake_b.inject(pkt)
        received = []
        for _ in messages:
            received.append(await asyncio.wait_for(node_b.receive_data(), timeout=1.0))
        await node_a.stop()
        await node_b.stop()
        assert received == messages
