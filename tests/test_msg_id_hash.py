"""
The hash a `msg_id` is computed with, negotiated per link.

SHA-256 over a 60 kB packet was over half of what that packet cost a node, and
BLAKE2b binds the same bytes in about half the time. Changing it is a change to
what every relay verifies, so it is negotiated (`features.BLAKE2B_IDS`) — and
the three properties worth defending are the ones that decide whether an update
splits the mesh:

  - **A node that has not said it speaks BLAKE2b ids only ever gets SHA-256
    ones**, computed exactly as every build always has. That is the whole of
    "an updated node can still talk to an old one".
  - **A receiver accepts either id whatever was agreed.** The two ends learn
    each other's set at different moments; a packet sent in that gap must not
    be lost.
  - **One packet is one entry in the replay window however it arrived.** A
    packet that came down a SHA-256 link and again down a BLAKE2b one is still
    a replay the second time.
"""
import hashlib
import os
import random
import struct

from src import features
from src.crypto import SessionKey
from src.node import DATA, MeshNode
from src.node_id import NodeID
from src.packet import (MSG_ID_BLAKE2B, MSG_ID_FORMAT, MSG_ID_SHA256, Packet,
                        PacketError)
from tests.conftest import FakeTransport, make_manager


def _historical_sha256_id(p: Packet) -> int:
    """The id exactly as every build before the negotiation computes it —
    written out here rather than asked of `Packet`, so this file notices if
    the code it is checking ever stops matching the wire."""
    data = struct.pack(MSG_ID_FORMAT, 1, p.type, p.src_id, p.dst_id, p.nonce,
                       p.pack()[63:79]) + p.payload
    return int.from_bytes(hashlib.sha256(data).digest()[:8], 'big')


def _announcing(peer, names) -> None:
    peer.features = frozenset(names)
    peer.agreed = features.agree(peer.features)


def _authenticated(peer):
    peer.authenticated_id = NodeID(os.urandom(20))
    peer.session = SessionKey(os.urandom(32))
    peer.dsa_pub = os.urandom(64)
    return peer


async def _relay(*links: FakeTransport) -> MeshNode:
    node = MeshNode(transport_manager=make_manager())
    for link in links:
        await node._inject_peer(link)
    for peer in node._peers:
        _authenticated(peer)
    return node


class TestTheTwoIds:
    def test_the_sha256_id_is_the_one_every_build_computes(self):
        p = Packet.create(DATA, os.urandom(20), os.urandom(20), b"payload")
        assert p.msg_id == p.compute_msg_id() == _historical_sha256_id(p)
        assert Packet.unpack(p.pack()).msg_id == _historical_sha256_id(p)

    def test_the_two_ids_differ(self):
        p = Packet.create(DATA, os.urandom(20), os.urandom(20), b"payload")
        assert p.id_under(MSG_ID_BLAKE2B) != p.id_under(MSG_ID_SHA256)

    def test_the_blake2b_id_binds_every_field_the_sha256_one_does(self):
        """Anti-amplification rests on this, under either hash: a relay must
        not be able to change the content and keep the id."""
        base = dict(version=1, type=0x01, src_id=b"\x11" * 20,
                    dst_id=b"\x22" * 20, nonce=b"\x00" * 12,
                    gcm_tag=b"\x00" * 16, payload=b"body")
        first = Packet.msg_id_over(**base, algorithm=MSG_ID_BLAKE2B)
        for field, other in (("type", 0x02), ("src_id", b"\x33" * 20),
                             ("dst_id", b"\x44" * 20), ("nonce", b"\x01" * 12),
                             ("gcm_tag", b"\x01" * 16), ("payload", b"bodz"),
                             ("version", 2)):
            changed = Packet.msg_id_over(**{**base, field: other},
                                         algorithm=MSG_ID_BLAKE2B)
            assert changed != first, field

    def test_the_ttl_is_outside_both(self):
        p = Packet.create(DATA, os.urandom(20), os.urandom(20), b"x")
        hop = p.with_ttl(3)
        for algorithm in (MSG_ID_SHA256, MSG_ID_BLAKE2B):
            assert hop.id_under(algorithm) == p.id_under(algorithm)

    def test_re_heading_a_packet_leaves_it_decryptable(self):
        """The id is rewritten per hop, exactly like the TTL — and like the
        TTL it has to stay outside the AAD, or the first relay to rewrite it
        would make the packet undecryptable at its destination."""
        session = SessionKey(os.urandom(32))
        p = Packet.create_encrypted(DATA, os.urandom(20), os.urandom(20),
                                    b"secret", session)
        on_the_wire = Packet.unpack(p.for_link(MSG_ID_BLAKE2B).pack())
        assert on_the_wire.decrypt_payload(session) == b"secret"


class TestTheReplayKey:
    def test_either_header_is_accepted_and_files_under_one_key(self):
        p = Packet.create(DATA, os.urandom(20), os.urandom(20), b"x" * 500)
        sha = Packet.unpack(p.for_link(MSG_ID_SHA256).pack())
        blake = Packet.unpack(p.for_link(MSG_ID_BLAKE2B).pack())
        assert sha.msg_id != blake.msg_id
        assert sha.replay_key() == blake.replay_key() == p.id_under(MSG_ID_BLAKE2B)

    def test_a_header_matching_neither_is_refused(self):
        p = Packet.create(DATA, os.urandom(20), os.urandom(20), b"x")
        for wrong in (p.id_under(MSG_ID_SHA256) ^ 1,
                      p.id_under(MSG_ID_BLAKE2B) ^ 1, 0):
            forged = Packet.unpack(p.pack()[:43] + struct.pack("!Q", wrong)
                                   + p.pack()[51:])
            assert forged.replay_key() is None

    def test_a_changed_payload_under_a_kept_header_is_refused(self):
        p = Packet.create(DATA, os.urandom(20), os.urandom(20), b"original")
        for algorithm in (MSG_ID_SHA256, MSG_ID_BLAKE2B):
            raw = p.for_link(algorithm).pack()
            assert Packet.unpack(raw[:-1] + b"X").replay_key() is None

    def test_random_headers_never_raise(self):
        rng = random.Random(0xB1A4E)
        for _ in range(2000):
            raw = bytes(rng.getrandbits(8) for _ in range(79 + rng.randint(0, 64)))
            try:
                packet = Packet.unpack(raw)
            except PacketError:
                continue
            assert packet.replay_key() is None


class TestEachHashIsComputedOnce:
    def test_a_relay_trying_five_links_hashes_once(self, monkeypatch):
        import src.packet as packet_module
        calls = []
        real = packet_module._blake2b_id
        monkeypatch.setattr(packet_module, "_blake2b_id",
                            lambda *a: calls.append(1) or real(*a))
        p = Packet.create(DATA, os.urandom(20), os.urandom(20), b"x" * 1000)
        received = Packet.unpack(p.for_link(MSG_ID_BLAKE2B).pack())
        calls.clear()
        received.replay_key()
        outgoing = received.with_decremented_ttl()
        for _ in range(5):
            outgoing.for_link(MSG_ID_BLAKE2B).pack()
        assert len(calls) == 1


class TestWhatALinkSends:
    async def test_a_peer_that_announced_nothing_gets_the_historical_id(self):
        """A node from before the negotiation, or one that has not spoken yet:
        it verifies SHA-256 and nothing else, so that is all it may get."""
        link = FakeTransport()
        node = await _relay(link)
        try:
            peer = node._peers[0]
            assert peer.agreed is None
            p = Packet.create(DATA, node.id.raw, os.urandom(20), b"hello")
            await peer.send(p)
            sent = Packet.unpack(link.sent[-1].pack())
            assert sent.msg_id == _historical_sha256_id(p)
        finally:
            await node.stop()

    async def test_a_peer_whose_record_lacks_the_name_gets_the_historical_id(self):
        link = FakeTransport()
        node = await _relay(link)
        try:
            peer = node._peers[0]
            _announcing(peer, features.SPOKEN - {features.BLAKE2B_IDS})
            p = Packet.create(DATA, node.id.raw, os.urandom(20), b"hello")
            await peer.send(p)
            assert link.sent[-1].msg_id == _historical_sha256_id(p)
        finally:
            await node.stop()

    async def test_a_peer_that_announced_it_gets_the_blake2b_id(self):
        link = FakeTransport()
        node = await _relay(link)
        try:
            peer = node._peers[0]
            _announcing(peer, features.SPOKEN)
            p = Packet.create(DATA, node.id.raw, os.urandom(20), b"hello")
            await peer.send(p)
            assert link.sent[-1].msg_id == p.id_under(MSG_ID_BLAKE2B)
        finally:
            await node.stop()


class TestARelayBetweenTheTwo:
    async def test_it_re_heads_a_packet_for_an_old_link(self):
        """In from a link speaking BLAKE2b, out to one that never said it does:
        the old node downstream has to be handed an id it can verify."""
        new_link, old_link = FakeTransport(), FakeTransport()
        node = await _relay(new_link, old_link)
        try:
            new, _old = node._peers
            _announcing(new, features.SPOKEN)
            p = Packet.create(DATA, os.urandom(20), os.urandom(20), b"onward")
            arriving = Packet.unpack(p.for_link(MSG_ID_BLAKE2B).pack())
            await node._handle_packet(new, arriving)
            forwarded = [q for q in old_link.sent if q.type == DATA]
            assert len(forwarded) == 1
            assert forwarded[0].msg_id == _historical_sha256_id(p)
            assert forwarded[0].ttl == p.ttl - 1
        finally:
            await node.stop()

    async def test_it_accepts_a_blake2b_id_before_hearing_the_announcement(self):
        """The gap: the sender has our record, we do not have its record yet."""
        quiet_link, out_link = FakeTransport(), FakeTransport()
        node = await _relay(quiet_link, out_link)
        try:
            quiet, out = node._peers
            assert quiet.agreed is None
            _announcing(out, features.SPOKEN)
            p = Packet.create(DATA, os.urandom(20), os.urandom(20), b"early")
            await node._handle_packet(
                quiet, Packet.unpack(p.for_link(MSG_ID_BLAKE2B).pack()))
            assert [q for q in out_link.sent if q.type == DATA]
        finally:
            await node.stop()

    async def test_one_packet_down_both_kinds_of_link_is_one_packet(self):
        """Filed under its header, a packet arriving once under each hash
        would be two packets — and a relay holding one link of each kind could
        replay anything once more."""
        old_link, new_link, out_link = (FakeTransport(), FakeTransport(),
                                        FakeTransport())
        node = await _relay(old_link, new_link, out_link)
        try:
            old, new, out = node._peers
            _announcing(new, features.SPOKEN)
            target = NodeID(os.urandom(20))
            # Make `out` the only way onward, whichever link a copy came in on.
            out.authenticated_id = target
            p = Packet.create(DATA, os.urandom(20), target.raw, b"once")
            await node._handle_packet(
                old, Packet.unpack(p.for_link(MSG_ID_SHA256).pack()))
            await node._handle_packet(
                new, Packet.unpack(p.for_link(MSG_ID_BLAKE2B).pack()))
            assert len([q for q in out_link.sent if q.type == DATA]) == 1
        finally:
            await node.stop()
