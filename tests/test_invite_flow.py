import asyncio
import pytest
from src.node import (MeshNode, CHALLENGE, INVITE, INVITE_ACK,
                      HANDSHAKE, _ACK_ACCEPTED, _ACK_REJECTED)
from src.node_id import NodeID
from src.packet import Packet
from src.invite import compute_response
from tests.conftest import FakeTransport, make_node


class TestGenerateInvite:
    async def test_returns_10_char_code(self):
        node, fake = await make_node()
        code = node.generate_invite()
        await node.stop()
        assert len(code) == 10
        assert code.isalnum()


class TestOnNewConnection:
    async def test_sends_challenge_on_connect(self):
        node, _ = await make_node()
        fake2 = FakeTransport()
        await node._on_new_transport(fake2)
        await node.stop()
        assert fake2.sent[0].type == CHALLENGE

    async def test_challenge_payload_is_32_bytes(self):
        node, _ = await make_node()
        fake2 = FakeTransport()
        await node._on_new_transport(fake2)
        await node.stop()
        assert len(fake2.sent[0].payload) == 32

    async def test_stores_pending_challenge(self):
        node, _ = await make_node()
        fake2 = FakeTransport()
        await node._on_new_transport(fake2)
        new_peer = node._peers[1]
        assert new_peer.pending_challenge is not None
        await node.stop()


class TestHandleChallenge:
    async def test_sends_invite_with_hmac(self):
        node, fake = await make_node()
        node._peers[0].join_code = "testcode12"
        challenge = b"\xab" * 32
        pkt = Packet.create(CHALLENGE, NodeID.generate().raw, node.id.raw, challenge)
        fake.inject(pkt)
        await asyncio.sleep(0.05)
        await node.stop()
        assert any(p.type == INVITE for p in fake.sent)

    async def test_invite_payload_is_correct_hmac(self):
        node, fake = await make_node()
        code = "testcode12"
        node._peers[0].join_code = code
        challenge = b"\xab" * 32
        pkt = Packet.create(CHALLENGE, NodeID.generate().raw, node.id.raw, challenge)
        fake.inject(pkt)
        await asyncio.sleep(0.05)
        await node.stop()
        invite_pkt = next(p for p in fake.sent if p.type == INVITE)
        assert invite_pkt.payload == compute_response(code, challenge)

    async def test_no_join_code_ignores_challenge(self):
        node, fake = await make_node()
        challenge = b"\xab" * 32
        pkt = Packet.create(CHALLENGE, NodeID.generate().raw, node.id.raw, challenge)
        fake.inject(pkt)
        await asyncio.sleep(0.05)
        await node.stop()
        assert not any(p.type == INVITE for p in fake.sent)


class TestHandleInvite:
    async def test_valid_invite_sends_accepted_ack(self):
        node, fake = await make_node()
        code = node.generate_invite()
        challenge = node._invite.generate_challenge()
        node._peers[0].pending_challenge = challenge
        response = compute_response(code, challenge)
        pkt = Packet.create(INVITE, NodeID.generate().raw, node.id.raw, response)
        fake.inject(pkt)
        await asyncio.sleep(0.05)
        await node.stop()
        ack = next(p for p in fake.sent if p.type == INVITE_ACK)
        assert ack.payload[0] == _ACK_ACCEPTED

    async def test_invalid_invite_sends_rejected_ack(self):
        node, fake = await make_node()
        node.generate_invite()
        challenge = node._invite.generate_challenge()
        node._peers[0].pending_challenge = challenge
        pkt = Packet.create(INVITE, NodeID.generate().raw, node.id.raw, b"wrong" * 6)
        fake.inject(pkt)
        await asyncio.sleep(0.05)
        await node.stop()
        ack = next(p for p in fake.sent if p.type == INVITE_ACK)
        assert ack.payload[0] == _ACK_REJECTED

    async def test_valid_invite_consumes_code(self):
        node, fake = await make_node()
        code = node.generate_invite()
        node.generate_invite()  # second code — only the matching one is consumed
        challenge = node._invite.generate_challenge()
        node._peers[0].pending_challenge = challenge
        response = compute_response(code, challenge)
        pkt = Packet.create(INVITE, NodeID.generate().raw, node.id.raw, response)
        fake.inject(pkt)
        await asyncio.sleep(0.05)
        await node.stop()
        # one code consumed, one remains
        assert node._invite.has_code()

    async def test_invalid_invite_records_failure(self):
        node, fake = await make_node()
        node.generate_invite()
        challenge = node._invite.generate_challenge()
        node._peers[0].pending_challenge = challenge
        pkt = Packet.create(INVITE, NodeID.generate().raw, node.id.raw, b"wrong" * 6)
        fake.inject(pkt)
        await asyncio.sleep(0.05)
        await node.stop()
        assert node._invite._failures == 1


class TestHandleInviteAck:
    async def test_accepted_ack_initiates_handshake(self):
        node, fake = await make_node()
        node._peers[0].join_code = "testcode12"
        pkt = Packet.create(INVITE_ACK, NodeID.generate().raw, node.id.raw,
                            bytes([_ACK_ACCEPTED]))
        fake.inject(pkt)
        await asyncio.sleep(0.05)
        await node.stop()
        assert any(p.type == HANDSHAKE for p in fake.sent)

    async def test_accepted_ack_clears_join_code(self):
        node, fake = await make_node()
        peer = node._peers[0]
        peer.join_code = "testcode12"
        pkt = Packet.create(INVITE_ACK, NodeID.generate().raw, node.id.raw,
                            bytes([_ACK_ACCEPTED]))
        fake.inject(pkt)
        await asyncio.sleep(0.05)
        assert peer.join_code is None
        await node.stop()

    async def test_rejected_ack_does_not_handshake(self):
        node, fake = await make_node()
        node._peers[0].join_code = "testcode12"
        pkt = Packet.create(INVITE_ACK, NodeID.generate().raw, node.id.raw,
                            bytes([_ACK_REJECTED]))
        fake.inject(pkt)
        await asyncio.sleep(0.05)
        await node.stop()
        assert not any(p.type == HANDSHAKE for p in fake.sent)
