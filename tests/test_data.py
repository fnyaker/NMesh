import asyncio
import os
import pytest
from src.node import MeshNode, DATA
from src.node_id import NodeID
from src.crypto import SessionKey
from src.packet import Packet
from tests.conftest import FakeTransport, make_node


async def make_connected_pair() -> tuple[MeshNode, FakeTransport, MeshNode, FakeTransport]:
    """Two nodes with a direct peer session AND pre-shared E2E sessions."""
    node_a, fake_a = await make_node()
    node_b, fake_b = await make_node()
    shared_challenge = os.urandom(32)
    node_b._peers[0].invite_accepted = True
    node_b._peers[0].pending_challenge = shared_challenge
    node_a._peers[0].joined_by_invite = True
    node_a._peers[0].received_challenge = shared_challenge
    await node_a.initiate_handshake(node_a._peers[0])
    fake_b.inject(fake_a.sent[-1])
    await asyncio.sleep(0.1)
    ack = next(p for p in fake_b.sent if p.type == 0x09)
    fake_a.inject(ack)
    await asyncio.sleep(0.1)
    # Pre-share an E2E session so tests can send DATA without going through
    # the full E2E handshake (that is covered by test_e2e.py).
    shared_secret = os.urandom(32)
    node_a._e2e_sessions[node_b.id] = SessionKey(shared_secret)
    node_b._e2e_sessions[node_a.id] = SessionKey(shared_secret)
    return node_a, fake_a, node_b, fake_b


class TestSendData:
    async def test_send_to_self_raises(self):
        node, fake = await make_node()
        with pytest.raises(ValueError):
            await node.send_data(node.id, b"hello")
        await node.stop()

    async def test_send_produces_data_packet(self):
        node_a, fake_a, node_b, fake_b = await make_connected_pair()
        await node_a.send_data(node_b.id, b"hello mesh")
        await node_a.stop()
        await node_b.stop()
        data_packets = [p for p in fake_a.sent if p.type == DATA]
        assert len(data_packets) == 1

    async def test_payload_is_encrypted(self):
        node_a, fake_a, node_b, fake_b = await make_connected_pair()
        plaintext = b"secret message"
        await node_a.send_data(node_b.id, plaintext)
        await node_a.stop()
        await node_b.stop()
        data_pkt = next(p for p in fake_a.sent if p.type == DATA)
        assert data_pkt.payload != plaintext


class TestReceiveData:
    async def test_receive_decrypts_payload(self):
        node_a, fake_a, node_b, fake_b = await make_connected_pair()
        plaintext = b"hello from A"
        await node_a.send_data(node_b.id, plaintext)
        data_pkt = next(p for p in fake_a.sent if p.type == DATA)
        fake_b.inject(data_pkt)
        src, received = await asyncio.wait_for(node_b.receive_data(), timeout=1.0)
        await node_a.stop()
        await node_b.stop()
        assert src == node_a.id
        assert received == plaintext

    async def test_data_without_e2e_session_ignored(self):
        node_a, fake_a, node_b, fake_b = await make_connected_pair()
        # Remove E2E session on receiver — packet should be dropped
        node_b._e2e_sessions.clear()
        await node_a.send_data(node_b.id, b"hello")
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
            await node_a.send_data(node_b.id, msg)
        data_packets = [p for p in fake_a.sent[sent_before:] if p.type == DATA]
        for pkt in data_packets:
            fake_b.inject(pkt)
        received = []
        for _ in messages:
            src, payload = await asyncio.wait_for(node_b.receive_data(), timeout=1.0)
            received.append(payload)
        await node_a.stop()
        await node_b.stop()
        assert received == messages


class TestBounds:
    """What a peer may cost us in memory once an E2E session exists."""

    async def test_data_queue_drops_instead_of_growing(self):
        """A node relaying with no app attached never drains this queue.

        Dropping is the only honest thing a full one can do: `_handle_data`
        runs inside the peer's receive loop, so awaiting a full queue would
        freeze the link, and the E2E plane promises no delivery anyway."""
        from src.node import _MAX_DATA_QUEUE
        node_a, fake_a, node_b, fake_b = await make_connected_pair()
        session = node_b._e2e_sessions[node_a.id]
        for _ in range(_MAX_DATA_QUEUE + 50):
            packet = Packet.create_encrypted(
                DATA, node_a.id.raw, node_b.id.raw, b"x" * 100, session)
            await node_b._handle_data(node_b._peers[0], packet)
        assert node_b._data_queue.qsize() <= _MAX_DATA_QUEUE
        assert node_b._metrics.total.dropped > 0
        await node_a.stop()
        await node_b.stop()

    async def test_e2e_session_table_is_bounded(self):
        """`src_id` is proven against the key inside the handshake, not against
        the link, so a fresh identity per handshake used to buy a permanent
        entry — and re-wrote the whole session store on the way."""
        from src.node import _MAX_E2E_SESSIONS
        from src.crypto import SessionKey
        node, fake = await make_node()
        for _ in range(_MAX_E2E_SESSIONS + 20):
            node._keep_e2e_session(NodeID(os.urandom(20)),
                                   SessionKey(os.urandom(32)))
        assert len(node._e2e_sessions) <= _MAX_E2E_SESSIONS
        await node.stop()

    async def test_eviction_forgets_a_destination_whole(self):
        """The four tables describe one relationship; forgetting one and not
        the others left an ML-KEM secret and a nonce behind for a target
        nothing would ever mention again."""
        node, fake = await make_node()
        target = NodeID(os.urandom(20))
        node._e2e_pending_kem[target] = b"k" * 32
        node._e2e_pending_nonce[target] = b"n" * 32
        node._e2e_pending_data[target] = [b"queued"]
        node._e2e_attempt[target] = 0.0
        node._forget_e2e(target)
        assert target not in node._e2e_pending_kem
        assert target not in node._e2e_pending_nonce
        assert target not in node._e2e_pending_data
        assert target not in node._e2e_attempt
        await node.stop()

    async def test_a_session_with_queued_data_is_not_the_one_evicted(self):
        """Evicting it would strand the backlog and the retry loop would
        re-handshake for it immediately."""
        from src.node import _MAX_E2E_SESSIONS
        from src.crypto import SessionKey
        node, fake = await make_node()
        keeper = NodeID(os.urandom(20))
        node._keep_e2e_session(keeper, SessionKey(os.urandom(32)))
        node._e2e_pending_data[keeper] = [b"queued"]
        for _ in range(_MAX_E2E_SESSIONS + 10):
            node._keep_e2e_session(NodeID(os.urandom(20)),
                                   SessionKey(os.urandom(32)))
        assert keeper in node._e2e_sessions
        await node.stop()
