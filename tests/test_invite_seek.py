"""
INVITE_SEEK — relayed invitation seek (étape 2).

A joiner routes a *signed* seek toward the inviter through the mesh. The seek
is the only packet allowed to traverse the mesh pre-authentication, so it is
strictly bounded and token-gated. These tests cover the codec, the token
verification (a seek must be signed by the key whose hash is the inviter id),
the relay routing, the bounded rendezvous (reverse-path) table, the per-link
rate limit, dedup and TTL — all the hostile-input surface.
"""
import time

import pytest

from src.node import (
    MeshNode, INVITE_SEEK, _make_invite_seek, _encode_seek, _decode_seek,
    _h_code, _seek_signed_blob, _SEEK_RATE_MAX, _RDV_MAX, _SEEK_MAX_PAYLOAD,
    _SEEK_TTL,
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
        assert fwd[0].ttl == seek.ttl - 1              # TTL decremented
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
