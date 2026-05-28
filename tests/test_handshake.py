import asyncio
import os
import pytest
from src.node import (MeshNode, HANDSHAKE, HANDSHAKE_ACK,
                      _encode_handshake, _decode_handshake,
                      _decode_handshake_ack)
from src.node_id import NodeID
from src.packet import Packet
from src.crypto import CryptoIdentity
from tests.conftest import FakeTransport, make_node


def _setup_challenge_pair(node_a, node_b) -> bytes:
    """Set matching challenge on both sides to satisfy C3 binding."""
    challenge = os.urandom(32)
    node_b._peers[0].pending_challenge = challenge
    node_a._peers[0].received_challenge = challenge
    return challenge


class TestInitiateHandshake:
    async def test_sends_handshake_type(self):
        node, fake = await make_node()
        await node.initiate_handshake(node._peers[0])
        await node.stop()
        assert fake.sent[0].type == HANDSHAKE

    async def test_payload_decodable(self):
        node, fake = await make_node()
        await node.initiate_handshake(node._peers[0])
        await node.stop()
        kem_pub, dsa_pub, chain, signature = _decode_handshake(fake.sent[0].payload)
        assert len(kem_pub) > 0
        assert len(dsa_pub) > 0
        assert len(signature) > 0

    async def test_sets_pending_kem_secret(self):
        node, fake = await make_node()
        peer = node._peers[0]
        await node.initiate_handshake(peer)
        assert peer.pending_kem_secret is not None
        await node.stop()


class TestHandleHandshake:
    async def test_sends_handshake_ack(self):
        node_a, fake_a = await make_node()
        node_b, fake_b = await make_node()
        node_b._peers[0].invite_accepted = True
        _setup_challenge_pair(node_a, node_b)
        await node_a.initiate_handshake(node_a._peers[0])
        fake_b.inject(fake_a.sent[0])
        await asyncio.sleep(0.1)
        await node_a.stop()
        await node_b.stop()
        assert any(p.type == HANDSHAKE_ACK for p in fake_b.sent)

    async def test_sets_session_on_responder(self):
        node_a, fake_a = await make_node()
        node_b, fake_b = await make_node()
        node_b._peers[0].invite_accepted = True
        _setup_challenge_pair(node_a, node_b)
        await node_a.initiate_handshake(node_a._peers[0])
        fake_b.inject(fake_a.sent[0])
        await asyncio.sleep(0.1)
        assert node_b.session is not None
        await node_a.stop()
        await node_b.stop()

    async def test_invalid_signature_ignored(self):
        node_b, fake_b = await make_node()
        identity = CryptoIdentity()
        kem_pub, _ = identity.generate_kem_keypair()
        dsa_pub = identity.dsa_public_key
        bad_sig = bytes(len(identity.sign(kem_pub + dsa_pub)))
        payload = _encode_handshake(kem_pub, dsa_pub, [], bad_sig)
        pkt = Packet.create(HANDSHAKE, NodeID.generate().raw, node_b.id.raw, payload)
        fake_b.inject(pkt)
        await asyncio.sleep(0.1)
        await node_b.stop()
        assert node_b.session is None
        assert not any(p.type == HANDSHAKE_ACK for p in fake_b.sent)


class TestFullHandshakeRoundtrip:
    async def test_both_nodes_get_session(self):
        node_a, fake_a = await make_node()
        node_b, fake_b = await make_node()
        node_b._peers[0].invite_accepted = True
        _setup_challenge_pair(node_a, node_b)
        await node_a.initiate_handshake(node_a._peers[0])
        fake_b.inject(fake_a.sent[0])
        await asyncio.sleep(0.1)
        ack = next(p for p in fake_b.sent if p.type == HANDSHAKE_ACK)
        fake_a.inject(ack)
        await asyncio.sleep(0.1)
        assert node_a.session is not None
        assert node_b.session is not None
        await node_a.stop()
        await node_b.stop()

    async def test_sessions_are_symmetric(self):
        node_a, fake_a = await make_node()
        node_b, fake_b = await make_node()
        node_b._peers[0].invite_accepted = True
        _setup_challenge_pair(node_a, node_b)
        await node_a.initiate_handshake(node_a._peers[0])
        fake_b.inject(fake_a.sent[0])
        await asyncio.sleep(0.1)
        ack = next(p for p in fake_b.sent if p.type == HANDSHAKE_ACK)
        fake_a.inject(ack)
        await asyncio.sleep(0.1)
        nonce = os.urandom(12)
        ciphertext, tag = node_b.session.encrypt(b"hello mesh", nonce, b"aad")
        assert node_a.session.decrypt(ciphertext, nonce, tag, b"aad") == b"hello mesh"
        await node_a.stop()
        await node_b.stop()

    async def test_ack_without_pending_secret_ignored(self):
        node_a, fake_a = await make_node()
        node_b, fake_b = await make_node()
        node_b._peers[0].invite_accepted = True
        _setup_challenge_pair(node_a, node_b)
        peer_a = node_a._peers[0]
        await node_a.initiate_handshake(peer_a)
        fake_b.inject(fake_a.sent[0])
        await asyncio.sleep(0.1)
        ack = next(p for p in fake_b.sent if p.type == HANDSHAKE_ACK)
        peer_a.pending_kem_secret = None
        fake_a.inject(ack)
        await asyncio.sleep(0.1)
        assert node_a.session is None
        await node_a.stop()
        await node_b.stop()
