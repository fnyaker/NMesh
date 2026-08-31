import asyncio
import os
import time
import pytest
from src.node import (MeshNode, HANDSHAKE, HANDSHAKE_ACK, _Peer,
                      _encode_handshake, _decode_handshake,
                      _decode_handshake_ack)
from src.node_id import NodeID
from src.packet import Packet
from src.crypto import CryptoIdentity
from tests.conftest import FakeTransport, make_node


def _setup_challenge_pair(node_a, node_b) -> bytes:
    """Set matching challenge on both sides to satisfy C3 binding.

    ``joined_by_invite`` on the client stands in for the INVITE/INVITE_ACK
    exchange these tests skip: it is what `_handle_handshake_ack` reads before
    it will accept a root from the host (see security.md)."""
    challenge = os.urandom(32)
    node_b._peers[0].pending_challenge = challenge
    node_a._peers[0].received_challenge = challenge
    node_a._peers[0].joined_by_invite = True
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


def _stale_link(node, target, *, canonical: bool):
    """A link this node still holds to ``target`` and the far end does not.

    ``canonical=True`` makes it the one the duplicate-link rule would keep,
    which is the case that used to eat the handshake."""
    we_dial = node.id.raw > target.raw
    peer = _Peer(FakeTransport(),
                 is_client_side=we_dial if canonical else not we_dial)
    peer.authenticated_id = target
    peer.session = object()
    peer.remote_addr = "fake://gone:1"
    peer.connected_at = time.monotonic() - 3600.0
    node._peers.append(peer)
    return peer


class TestSayingWhyAHandshakeWasRefused:
    """A node that refuses in silence cannot be debugged.

    Rejecting anything unverified is the rule and stays the rule. What was
    missing is the other half: eleven attempts in two minutes, each dropped at
    one of a dozen tests, and nothing anywhere saying which one. The packet is
    still dropped with no side effect — the difference is that the operator can
    ask."""

    async def test_a_chain_from_another_network_says_so(self):
        """The answer an operator with a mesh that will not connect needs."""
        node_a, fake_a = await make_node()
        node_b, fake_b = await make_node()          # no root in common
        _setup_challenge_pair(node_a, node_b)
        await node_a.initiate_handshake(node_a._peers[0])
        fake_b.inject(fake_a.sent[0])
        await asyncio.sleep(0.1)
        await node_a.stop()
        await node_b.stop()
        assert not any(p.type == HANDSHAKE_ACK for p in fake_b.sent)
        reasons = [row["reason"] for row in node_b.handshake_refusals()]
        assert reasons == ["the certificate chain reaches no root we trust"]

    async def test_a_malformed_handshake_says_so(self):
        node, fake = await make_node()
        node._peers[0].pending_challenge = os.urandom(32)
        fake.inject(Packet.create(HANDSHAKE, b"\x01" * 20, node.id.raw, b"junk"))
        await asyncio.sleep(0.05)
        await node.stop()
        assert [row["reason"] for row in node.handshake_refusals()] == [
            "handshake was malformed"]

    async def test_retrying_climbs_one_reason_rather_than_listing_many(self):
        node, fake = await make_node()
        for _ in range(5):
            node._peers[0].pending_challenge = os.urandom(32)
            fake.inject(Packet.create(HANDSHAKE, b"\x01" * 20, node.id.raw, b"junk"))
            await asyncio.sleep(0)
        await asyncio.sleep(0.05)
        await node.stop()
        rows = node.handshake_refusals()
        assert len(rows) == 1
        assert rows[0]["count"] == 5

    async def test_the_peer_that_was_turned_away_is_named(self):
        node, fake = await make_node()
        node._peers[0].pending_challenge = os.urandom(32)
        fake.inject(Packet.create(HANDSHAKE, b"\x07" * 20, node.id.raw, b"junk"))
        await asyncio.sleep(0.05)
        await node.stop()
        assert node.handshake_refusals()[0]["peer"] == "07" * 20

    async def test_a_link_that_is_already_up_is_not_a_refusal(self):
        """A repeat of a handshake we already answered is noise, not a reason."""
        node, fake = await make_node()
        node._peers[0].authenticated_id = NodeID(b"\x02" * 20)
        fake.inject(Packet.create(HANDSHAKE, b"\x02" * 20, node.id.raw, b"junk"))
        await asyncio.sleep(0.05)
        await node.stop()
        assert node.handshake_refusals() == []

    async def test_the_reasons_are_bounded_and_newest_first(self):
        node, _fake = await make_node()
        from src.node import _REFUSALS_KEPT
        packet = Packet.create(HANDSHAKE, b"\x03" * 20, node.id.raw, b"x")
        for index in range(_REFUSALS_KEPT + 10):
            node._refuse_handshake(packet, "reason %d" % index)
        await node.stop()
        rows = node.handshake_refusals()
        assert len(rows) == _REFUSALS_KEPT
        assert rows[0]["reason"] == "reason %d" % (_REFUSALS_KEPT + 9)


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

    async def test_a_link_the_far_end_lost_does_not_eat_the_handshake(self):
        """The whole mesh stopped connecting on this.

        A node that restarts is dialled by peers still holding the link it had
        before. On the answering side that link was authenticated, so the
        duplicate-link rule fired — and because the rule keeps the link *this*
        side dialled, it closed the one that had just proved itself, before the
        ACK went out. The dialler saw its CHALLENGE answered, sent its
        HANDSHAKE, and waited forever. Both halves are proved here: the answer
        leaves before any bookkeeping, and the bookkeeping keeps the right
        link."""
        node_a, fake_a = await make_node()
        node_b, fake_b = await make_node()
        node_b._peers[0].invite_accepted = True
        node_b._peers[0].remote_addr = "fake://here:1"
        _setup_challenge_pair(node_a, node_b)
        stale = _stale_link(node_b, node_a.id, canonical=True)
        await node_a.initiate_handshake(node_a._peers[0])
        fake_b.inject(fake_a.sent[0])
        await asyncio.sleep(0.1)
        fresh = node_b._peers[0]
        held = list(node_b._peers)             # stop() empties it
        await node_a.stop()
        await node_b.stop()
        assert any(p.type == HANDSHAKE_ACK for p in fake_b.sent)
        assert fresh.session is not None
        assert fresh in held                   # the proven link is the keeper
        assert stale not in held               # the ghost is the one dropped

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


class TestPreAuthWorkIsBounded:
    """`_handle_handshake` runs on an *unauthenticated* link, and a failed
    attempt clears neither of its guards, so the same connection may try again.
    Both the order of the work and the number of tries have to be bounded."""

    async def test_identity_mismatch_costs_no_signature_check(self, monkeypatch):
        """Two SHA-256s rule the packet out; the chain must not be parsed
        (which verifies a post-quantum signature per certificate) and neither
        must the handshake signature."""
        node_a, fake_a = await make_node()
        node_b, fake_b = await make_node()
        _setup_challenge_pair(node_a, node_b)
        await node_a.initiate_handshake(node_a._peers[0])
        handshake = fake_a.sent[0]

        verifications = []
        real_verify = node_b._identity.verify
        monkeypatch.setattr(node_b._identity, "verify",
                            lambda *a, **k: (verifications.append(1),
                                             real_verify(*a, **k))[1])
        # src_id names somebody other than the key inside the payload.
        lying = Packet.create(HANDSHAKE, os.urandom(20),
                              NodeID(b"\xff" * 20).raw, handshake.payload)
        await node_b._handle_handshake(node_b._peers[0], lying)
        assert verifications == [], "a lie about the id bought a signature check"
        assert node_b._peers[0].authenticated_id is None
        await node_a.stop()
        await node_b.stop()

    async def test_attempts_per_link_are_bounded(self):
        from src.node import _MAX_HANDSHAKE_ATTEMPTS
        node_a, fake_a = await make_node()
        node_b, fake_b = await make_node()
        node_b._peers[0].invite_accepted = True
        _setup_challenge_pair(node_a, node_b)
        await node_a.initiate_handshake(node_a._peers[0])
        handshake = fake_a.sent[0]
        # Same packet, over and over: the signature is valid, so only the
        # attempt budget can stop it.
        for _ in range(_MAX_HANDSHAKE_ATTEMPTS + 5):
            node_b._peers[0].authenticated_id = None
            node_b._peers[0].pending_challenge = node_a._peers[0].received_challenge
            await node_b._handle_handshake(node_b._peers[0], handshake)
        assert node_b._peers[0]._handshake_attempts <= _MAX_HANDSHAKE_ATTEMPTS + 5
        acks = [p for p in fake_b.sent if p.type == HANDSHAKE_ACK]
        assert len(acks) <= _MAX_HANDSHAKE_ATTEMPTS
        await node_a.stop()
        await node_b.stop()
