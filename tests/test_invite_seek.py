"""
INVITE_SEEK — relayed invitation seek (step 2).

A joiner routes a *signed* seek toward the inviter through the mesh. The seek
is the only packet allowed to traverse the mesh pre-authentication, so it is
strictly bounded and token-gated. These tests cover the codec, the token
verification (a seek must be signed by the key whose hash is the inviter id),
the relay routing, the bounded rendezvous (reverse-path) table, the per-link
rate limit, dedup and TTL — all the hostile-input surface.
"""
import os
import time

import pytest

from src.node import (
    MeshNode, INVITE_OFFER, INVITE_SEEK, _make_invite_seek, _encode_seek,
    _decode_seek, _h_code, _seek_signed_blob, _SEEK_RATE_MAX, _RDV_MAX,
    _SEEK_MAX_PAYLOAD, _SEEK_TTL, _SEEK_TTL_PREAUTH, _OFFER_MAX,
    _OFFER_RATE_MAX, _SHORT_SEEK_LEN, _SHORT_SEEK_GAP,
)
from src.node_id import NodeID
from src.crypto import SessionKey, CryptoIdentity
from src.packet import Packet
from tests.conftest import make_manager, make_node, FakeTransport


def _exp(dt=300):
    return int(time.time() + dt)


async def _ingress(node) -> object:
    """A fresh peer standing in for the link a seek arrives on."""
    return await node._inject_peer(FakeTransport())


def _authed_peer_to(node, target: NodeID) -> object:
    """Inject an authenticated peer whose id is *target* (a relay's link
    toward the inviter)."""
    async def _mk():
        p = await node._inject_peer(FakeTransport())
        p.authenticated_id = target
        p.session = SessionKey(b"\x00" * 32)
        p.remote_addr = "fake://relay:1"
        return p
    return _mk()


class TestCodec:
    def test_roundtrip(self):
        a = CryptoIdentity()
        pub = a.dsa_public_key
        h = _h_code("abc1234567")
        exp = _exp()
        token = a.sign(_seek_signed_blob(h, exp))
        payload = _encode_seek(exp, h, pub, token)
        out = _decode_seek(payload)
        assert out == (exp, h, pub, token)

    def test_rejects_malformed(self):
        assert _decode_seek(b"") is None
        assert _decode_seek(b"\x00" * 10) is None            # too short
        assert _decode_seek(b"\x00" * (_SEEK_MAX_PAYLOAD + 1)) is None  # oversized
        # truncated length prefix
        a = CryptoIdentity()
        good = _encode_seek(_exp(), _h_code("x"), a.dsa_public_key, a.sign(b"m"))
        assert _decode_seek(good[:50]) is None


class TestVerification:
    async def test_valid_seek_for_self_is_recognized(self):
        node, _ = await make_node()
        code = node.generate_invite()
        seeker = NodeID(b"\x09" * 20)
        seek = _make_invite_seek(node._identity, seeker, code, _exp())
        ingress = await _ingress(node)
        await node._handle_invite_seek(ingress, seek)
        assert seeker.raw in node._pending_seeks
        assert node._pending_seeks[seeker.raw]["recognized"] is True

    async def test_seek_for_self_unknown_code_not_recognized(self):
        node, _ = await make_node()
        seeker = NodeID(b"\x09" * 20)
        seek = _make_invite_seek(node._identity, seeker, "never-issued", _exp())
        await node._handle_invite_seek(await _ingress(node), seek)
        assert node._pending_seeks[seeker.raw]["recognized"] is False

    async def test_forged_token_rejected(self):
        node, _ = await make_node()
        # build a seek "for" node but sign with a DIFFERENT key
        attacker = CryptoIdentity()
        pub = node._identity.dsa_public_key          # claims node's key…
        exp = _exp()
        h = _h_code("x")
        bad_token = attacker.sign(_seek_signed_blob(h, exp))  # …but wrong signature
        payload = _encode_seek(exp, h, pub, bad_token)
        seek = Packet.create(INVITE_SEEK, b"\x09" * 20, node.id.raw, payload)
        await node._handle_invite_seek(await _ingress(node), seek)
        assert node._pending_seeks == {}

    async def test_key_not_matching_inviter_id_rejected(self):
        node, _ = await make_node()
        # a self-consistent seek, but addressed (dst) to node while carrying a
        # different key → NodeID(pub) != dst_id → rejected
        other = CryptoIdentity()
        exp, h = _exp(), _h_code("x")
        payload = _encode_seek(exp, h, other.dsa_public_key,
                               other.sign(_seek_signed_blob(h, exp)))
        seek = Packet.create(INVITE_SEEK, b"\x09" * 20, node.id.raw, payload)
        await node._handle_invite_seek(await _ingress(node), seek)
        assert node._pending_seeks == {}

    async def test_expired_seek_rejected(self):
        node, _ = await make_node()
        code = node.generate_invite()
        seek = _make_invite_seek(node._identity, NodeID(b"\x09" * 20), code,
                                 int(time.time() - 10))
        await node._handle_invite_seek(await _ingress(node), seek)
        assert node._pending_seeks == {}

    async def test_far_future_seek_rejected(self):
        node, _ = await make_node()
        code = node.generate_invite()
        seek = _make_invite_seek(node._identity, NodeID(b"\x09" * 20), code,
                                 int(time.time() + 99999))
        await node._handle_invite_seek(await _ingress(node), seek)
        assert node._pending_seeks == {}

    async def test_own_seek_looped_back_ignored(self):
        node, _ = await make_node()
        code = node.generate_invite()
        seek = _make_invite_seek(node._identity, node.id, code, _exp())
        await node._handle_invite_seek(await _ingress(node), seek)
        assert node._pending_seeks == {}


class TestRelay:
    async def test_relays_toward_inviter_over_authed_peer(self):
        relay, _ = await make_node()
        inviter = CryptoIdentity()
        inviter_id = NodeID.from_public_key(inviter.dsa_public_key)
        link = await _authed_peer_to(relay, inviter_id)
        ingress = await _ingress(relay)
        seek = _make_invite_seek(inviter, NodeID(b"\x09" * 20), "abc1234567", _exp())
        await relay._handle_invite_seek(ingress, seek)
        fwd = [p for p in link.transport.sent if p.type == INVITE_SEEK]
        assert len(fwd) == 1
        # The ingress link has not authenticated — that is the whole point of
        # this plane — so its budget is `_SEEK_TTL_PREAUTH`, then decremented.
        assert fwd[0].ttl == _SEEK_TTL_PREAUTH - 1
        assert fwd[0].dst_id == inviter_id.raw
        # reverse path was recorded for the seeker
        assert relay._rdv_lookup(b"\x09" * 20) is ingress

    async def test_ttl_zero_not_forwarded(self):
        relay, _ = await make_node()
        inviter = CryptoIdentity()
        inviter_id = NodeID.from_public_key(inviter.dsa_public_key)
        link = await _authed_peer_to(relay, inviter_id)
        seek = _make_invite_seek(inviter, NodeID(b"\x09" * 20), "abc1234567",
                                 _exp(), ttl=1)
        await relay._handle_invite_seek(await _ingress(relay), seek)
        assert [p for p in link.transport.sent if p.type == INVITE_SEEK] == []

    async def test_dedup_forwards_once(self):
        relay, _ = await make_node()
        inviter = CryptoIdentity()
        inviter_id = NodeID.from_public_key(inviter.dsa_public_key)
        link = await _authed_peer_to(relay, inviter_id)
        ingress = await _ingress(relay)
        seek = _make_invite_seek(inviter, NodeID(b"\x09" * 20), "abc1234567", _exp())
        await relay._handle_invite_seek(ingress, seek)
        await relay._handle_invite_seek(ingress, seek)  # same msg_id → dropped
        assert len([p for p in link.transport.sent if p.type == INVITE_SEEK]) == 1


class TestBounds:
    async def test_rate_limited_per_ingress(self):
        relay, _ = await make_node()
        inviter = CryptoIdentity()
        inviter_id = NodeID.from_public_key(inviter.dsa_public_key)
        link = await _authed_peer_to(relay, inviter_id)
        ingress = await _ingress(relay)
        # distinct seekers → distinct packets (no dedup); one ingress link
        for i in range(_SEEK_RATE_MAX + 8):
            seeker = NodeID(i.to_bytes(20, "big"))
            seek = _make_invite_seek(inviter, seeker, "abc1234567", _exp())
            await relay._handle_invite_seek(ingress, seek)
        fwd = len([p for p in link.transport.sent if p.type == INVITE_SEEK])
        assert fwd == _SEEK_RATE_MAX  # extra seeks over the window are dropped

    async def test_rdv_table_is_bounded(self):
        relay, _ = await make_node()
        inviter = CryptoIdentity()
        inviter_id = NodeID.from_public_key(inviter.dsa_public_key)
        await _authed_peer_to(relay, inviter_id)
        ingress = await _ingress(relay)
        # bypass the rate limit to exercise the rdv bound directly
        for i in range(_RDV_MAX + 50):
            relay._seek_rate.clear()
            seeker = NodeID((i + 1000).to_bytes(20, "big"))
            seek = _make_invite_seek(inviter, seeker, "abc1234567", _exp())
            await relay._handle_invite_seek(ingress, seek)
        assert len(relay._rdv) <= _RDV_MAX

    async def test_pending_seeks_bounded(self):
        node, _ = await make_node()
        code = node.generate_invite()
        ingress = await _ingress(node)
        from src.node import _MAX_PENDING_SEEKS
        for i in range(_MAX_PENDING_SEEKS + 20):
            node._seek_rate.clear()
            seeker = NodeID((i + 5000).to_bytes(20, "big"))
            seek = _make_invite_seek(node._identity, seeker, code, _exp())
            await node._handle_invite_seek(ingress, seek)
        assert len(node._pending_seeks) <= _MAX_PENDING_SEEKS

    async def test_rdv_expires(self):
        relay, _ = await make_node()
        ingress = await _ingress(relay)
        relay._rdv_record(b"\x07" * 20, ingress)
        assert relay._rdv_lookup(b"\x07" * 20) is ingress
        # force expiry
        peer, _old = relay._rdv[b"\x07" * 20]
        relay._rdv[b"\x07" * 20] = (peer, time.monotonic() - 1)
        assert relay._rdv_lookup(b"\x07" * 20) is None


class TestDispatch:
    async def test_seek_reaches_handler_via_handle_packet(self):
        # INVITE_SEEK is intercepted in _handle_packet before the auth gates
        node, _ = await make_node()
        code = node.generate_invite()
        seeker = NodeID(b"\x09" * 20)
        seek = _make_invite_seek(node._identity, seeker, code, _exp())
        await node._handle_packet(await _ingress(node), seek)
        assert seeker.raw in node._pending_seeks

    async def test_snapshot_reports_pending_seeks(self):
        node, _ = await make_node()
        snap = await node.console_snapshot()
        assert snap["pending_seeks"] == 0


class TestPreAuthBudget:
    """A seek from a link that has not authenticated is carried by links that
    have. One packet handed to the edge of the mesh should not buy the mesh's
    whole diameter — a joiner needs enough hops to find an inviter."""

    async def test_an_unauthenticated_seek_gets_the_shorter_budget(self):
        relay, _ = await make_node()
        inviter = CryptoIdentity()
        inviter_id = NodeID.from_public_key(inviter.dsa_public_key)
        link = await _authed_peer_to(relay, inviter_id)
        ingress = await _ingress(relay)
        seek = _make_invite_seek(inviter, NodeID(b"\x09" * 20), "abc1234567",
                                 _exp(), ttl=_SEEK_TTL)
        await relay._handle_invite_seek(ingress, seek)
        fwd = next(p for p in link.transport.sent if p.type == INVITE_SEEK)
        assert fwd.ttl == _SEEK_TTL_PREAUTH - 1
        await relay.stop()

    async def test_a_member_relaying_onward_keeps_the_full_budget(self):
        """Between members the seek is ordinary mesh traffic: clamping there
        would cut off inviters that are simply far away."""
        relay, _ = await make_node()
        inviter = CryptoIdentity()
        inviter_id = NodeID.from_public_key(inviter.dsa_public_key)
        link = await _authed_peer_to(relay, inviter_id)
        ingress = await _authed_peer_to(relay, NodeID(b"\x33" * 20))
        seek = _make_invite_seek(inviter, NodeID(b"\x09" * 20), "abc1234567",
                                 _exp(), ttl=_SEEK_TTL)
        await relay._handle_invite_seek(ingress, seek)
        fwd = next(p for p in link.transport.sent if p.type == INVITE_SEEK)
        assert fwd.ttl == _SEEK_TTL - 1
        await relay.stop()


class TestPreAuthOrdering:
    """`_is_seen` is not a query — it inserts. Both pre-auth handlers therefore
    take their rate limit first: with the order the other way round, any socket
    that connected could flush the node-wide replay window at line rate, and
    dedup is what stops a routed packet looping and a relay re-injecting the
    same payload."""

    async def test_a_seek_flood_cannot_flush_the_dedup_window(self):
        from src.node import _SEEK_RATE_MAX, INVITE_SEEK
        node, fake = await make_node()
        peer = node._peers[0]
        assert peer.authenticated_id is None       # pre-auth, on purpose
        for _ in range(_SEEK_RATE_MAX * 20):
            packet = Packet.create(INVITE_SEEK, os.urandom(20), node.id.raw,
                                   os.urandom(64), ttl=8)
            await node._handle_invite_seek(peer, packet)
        assert len(node._seen_msgs) <= _SEEK_RATE_MAX
        await node.stop()

    async def test_a_carry_flood_cannot_flush_the_dedup_window(self):
        from src.node import _CARRY_RATE_MAX, RELAY_CARRY
        node, fake = await make_node()
        peer = node._peers[0]
        for _ in range(_CARRY_RATE_MAX * 4):
            packet = Packet.create(RELAY_CARRY, os.urandom(20), os.urandom(20),
                                   os.urandom(64), ttl=8)
            await node._handle_relay_carry(peer, packet)
        assert len(node._seen_msgs) <= _CARRY_RATE_MAX
        await node.stop()


# ---------------------------------------------------------------------------
# The rendezvous: a short seek, and the offer that makes it mean anything
# ---------------------------------------------------------------------------
#
# This is what lets an invitation reach a node with no address of its own out of
# a string short enough to put in a QR code. The heavy part of a relayed
# invitation — an ML-DSA key and a signature, five kilobytes of it — stays with
# the relay; the ticket carries an identity and a seed.
#
# The whole security of it is in one sentence: a short seek is honoured **only**
# where the inviter itself left a rendezvous under that code hash, over an
# authenticated link, naming the very identity the packet is addressed to. The
# offer is the authorisation; the short seek is a pointer at one.

import struct


def _offer_from(inviter: CryptoIdentity, code: str, exp: int) -> Packet:
    h = _h_code(code)
    token = inviter.sign(_seek_signed_blob(h, exp))
    return Packet.create(
        INVITE_OFFER, NodeID.from_public_key(inviter.dsa_public_key).raw,
        b"\x01" * 20, _encode_seek(exp, h, inviter.dsa_public_key, token))


def _short_seek(seeker: bytes, inviter: NodeID, code: str, exp: int) -> Packet:
    return Packet.create(INVITE_SEEK, seeker, inviter.raw,
                         struct.pack("!Q", exp) + _h_code(code), ttl=_SEEK_TTL)


class TestRendezvousOffer:
    async def test_an_offer_is_only_ever_about_its_own_sender(self):
        """The key in it has to hash to the sender's id and to have signed the
        token — the same pair of checks a full seek goes through. So holding one
        is holding a statement the sender could have made to anybody, never an
        authority over a third node."""
        relay, _ = await make_node()
        inviter = CryptoIdentity()
        link = await _authed_peer_to(
            relay, NodeID.from_public_key(inviter.dsa_public_key))
        relay._handle_invite_offer(link, _offer_from(inviter, "abc1234567", _exp()))
        assert _h_code("abc1234567") in relay._offers

    async def test_an_offer_from_an_unauthenticated_link_is_dropped(self):
        relay, _ = await make_node()
        inviter = CryptoIdentity()
        relay._handle_invite_offer(await _ingress(relay),
                                   _offer_from(inviter, "abc1234567", _exp()))
        assert relay._offers == {}

    async def test_an_offer_naming_somebody_elses_key_is_dropped(self):
        """Otherwise a peer could aim a rendezvous at a node it has nothing to
        do with, and every seek for that code would be routed on its say-so."""
        relay, _ = await make_node()
        inviter, stranger = CryptoIdentity(), CryptoIdentity()
        link = await _authed_peer_to(
            relay, NodeID.from_public_key(stranger.dsa_public_key))
        relay._handle_invite_offer(link, _offer_from(inviter, "abc1234567", _exp()))
        assert relay._offers == {}

    async def test_a_forged_token_is_dropped(self):
        relay, _ = await make_node()
        inviter, other = CryptoIdentity(), CryptoIdentity()
        inviter_id = NodeID.from_public_key(inviter.dsa_public_key)
        link = await _authed_peer_to(relay, inviter_id)
        h = _h_code("abc1234567")
        exp = _exp()
        packet = Packet.create(
            INVITE_OFFER, inviter_id.raw, b"\x01" * 20,
            _encode_seek(exp, h, inviter.dsa_public_key,
                         other.sign(_seek_signed_blob(h, exp))))
        relay._handle_invite_offer(link, packet)
        assert relay._offers == {}

    async def test_an_expired_offer_is_not_taken(self):
        relay, _ = await make_node()
        inviter = CryptoIdentity()
        link = await _authed_peer_to(
            relay, NodeID.from_public_key(inviter.dsa_public_key))
        relay._handle_invite_offer(link, _offer_from(inviter, "abc1234567", _exp(-10)))
        assert relay._offers == {}

    async def test_offers_are_bounded_and_rate_limited(self):
        relay, _ = await make_node()
        inviter = CryptoIdentity()
        link = await _authed_peer_to(
            relay, NodeID.from_public_key(inviter.dsa_public_key))
        for index in range(_OFFER_RATE_MAX + 5):
            relay._handle_invite_offer(
                link, _offer_from(inviter, f"code{index:06d}", _exp()))
        assert len(relay._offers) <= _OFFER_RATE_MAX
        assert len(relay._offers) <= _OFFER_MAX


class TestShortSeek:
    async def _relay_holding(self, code="abc1234567", exp=None):
        relay, _ = await make_node()
        inviter = CryptoIdentity()
        inviter_id = NodeID.from_public_key(inviter.dsa_public_key)
        link = await _authed_peer_to(relay, inviter_id)
        relay._handle_invite_offer(link, _offer_from(inviter, code,
                                                     exp or _exp()))
        return relay, inviter_id, link

    async def test_it_becomes_a_real_seek_where_the_offer_is(self):
        relay, inviter_id, link = await self._relay_holding()
        ingress = await _ingress(relay)
        await relay._handle_invite_seek(
            ingress, _short_seek(b"\x09" * 20, inviter_id, "abc1234567", _exp()))
        forwarded = [p for p in link.transport.sent if p.type == INVITE_SEEK]
        assert len(forwarded) == 1
        # What leaves is an ordinary signed seek: every node past this one
        # verifies it exactly as it always did.
        decoded = _decode_seek(forwarded[0].payload)
        assert decoded is not None and decoded[1] == _h_code("abc1234567")
        assert forwarded[0].dst_id == inviter_id.raw
        assert forwarded[0].src_id == b"\x09" * 20
        # And the way back is remembered, or the inviter's answer has nowhere
        # to go.
        assert relay._rdv_lookup(b"\x09" * 20) is ingress

    async def test_a_node_holding_no_offer_says_nothing(self):
        """Silence rather than a refusal: an answer would be a way to ask
        whether a code exists."""
        relay, _ = await make_node()
        inviter_id = NodeID(b"\x07" * 20)
        link = await _authed_peer_to(relay, inviter_id)
        await relay._handle_invite_seek(
            await _ingress(relay),
            _short_seek(b"\x09" * 20, inviter_id, "abc1234567", _exp()))
        assert [p for p in link.transport.sent if p.type == INVITE_SEEK] == []

    async def test_it_cannot_be_aimed_at_a_node_the_offer_does_not_name(self):
        relay, _inviter_id, link = await self._relay_holding()
        await relay._handle_invite_seek(
            await _ingress(relay),
            _short_seek(b"\x09" * 20, NodeID(b"\x05" * 20), "abc1234567", _exp()))
        assert [p for p in link.transport.sent if p.type == INVITE_SEEK] == []

    async def test_a_code_nobody_offered_forwards_nothing(self):
        relay, inviter_id, link = await self._relay_holding()
        await relay._handle_invite_seek(
            await _ingress(relay),
            _short_seek(b"\x09" * 20, inviter_id, "zzzzzzzzzz", _exp()))
        assert [p for p in link.transport.sent if p.type == INVITE_SEEK] == []

    async def test_an_expired_one_is_dropped_and_forgotten(self):
        relay, inviter_id, link = await self._relay_holding()
        relay._offers[_h_code("abc1234567")]["exp"] = int(time.time()) - 5
        await relay._handle_invite_seek(
            await _ingress(relay),
            _short_seek(b"\x09" * 20, inviter_id, "abc1234567", _exp()))
        assert [p for p in link.transport.sent if p.type == INVITE_SEEK] == []
        assert relay._offers == {}

    async def test_an_expired_seek_is_dropped(self):
        relay, inviter_id, link = await self._relay_holding()
        await relay._handle_invite_seek(
            await _ingress(relay),
            _short_seek(b"\x09" * 20, inviter_id, "abc1234567", _exp(-10)))
        assert [p for p in link.transport.sent if p.type == INVITE_SEEK] == []

    async def test_a_seeker_cannot_be_the_inviter(self):
        relay, inviter_id, link = await self._relay_holding()
        await relay._handle_invite_seek(
            await _ingress(relay),
            _short_seek(inviter_id.raw, inviter_id, "abc1234567", _exp()))
        assert [p for p in link.transport.sent if p.type == INVITE_SEEK] == []

    async def test_one_forward_per_rendezvous_per_gap(self):
        """Forty bytes in becomes five kilobytes out — the key and signature the
        offer holds. Without a gap, somebody holding a ticket could vary the
        expiry, mint a fresh msg_id past dedup, and spend the inviter's link at
        the seek limit's full width."""
        relay, inviter_id, link = await self._relay_holding()
        ingress = await _ingress(relay)
        for step in range(6):
            await relay._handle_invite_seek(
                ingress,
                _short_seek(b"\x09" * 20, inviter_id, "abc1234567",
                            _exp(300 + step)))
        assert len([p for p in link.transport.sent if p.type == INVITE_SEEK]) == 1
        # …and it opens again once the gap has passed.
        relay._offers[_h_code("abc1234567")]["last"] -= _SHORT_SEEK_GAP + 1
        await relay._handle_invite_seek(
            ingress, _short_seek(b"\x09" * 20, inviter_id, "abc1234567", _exp(999)))
        assert len([p for p in link.transport.sent if p.type == INVITE_SEEK]) == 2

    def test_the_short_form_is_told_apart_by_its_length_alone(self):
        """40 bytes exactly, which is one byte under what the full decoder will
        even look at — so there is no shape that is both."""
        assert _SHORT_SEEK_LEN == 40
        assert _decode_seek(b"\x00" * _SHORT_SEEK_LEN) is None
