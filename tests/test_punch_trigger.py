"""
Hole-punch *triggering* tests.

The punch machinery (PUNCH_REQUEST/RELAY/PROBE/ACK) is exercised by the
integration suite; these cover when the node decides to punch at all:
- _ensure_route_to falls back to a punch when no address connects,
- _route_outbound schedules a relayed→direct path upgrade,
- both are bounded and rate-limited (no punch/connect storms).
"""
import asyncio
import os

import pytest

from src.node import (
    MeshNode, _UPGRADE_COOLDOWN, _PUNCH_SIG_MAX,
    _build_punch_probe, _parse_punch_probe,
    _build_punch_ack, _parse_punch_ack,
)
from src.node_id import NodeID
from src.crypto import CryptoIdentity, SessionKey
from src.packet import Packet
from tests.conftest import make_manager, make_node


class TestPunchCodec:
    """Regression: probes/acks carry a full ML-DSA-65 signature (3309 bytes),
    not a truncated 64-byte one — the old fixed length silently broke every
    real punch by mangling the signature before verify()."""

    def test_probe_roundtrip_preserves_full_signature(self):
        ident = CryptoIdentity()
        node_id = os.urandom(20)
        nonce = os.urandom(16)
        sig = ident.sign(b"NPPB" + node_id + nonce)
        assert len(sig) > 64  # ML-DSA-65 signatures are ~3309 bytes
        parsed = _parse_punch_probe(_build_punch_probe(node_id, nonce, sig))
        assert parsed is not None
        pid, pnonce, psig = parsed
        assert pid == node_id and pnonce == nonce and psig == sig
        # and the signature still verifies against the signer's key
        assert ident.verify(b"NPPB" + node_id + nonce, psig, ident.dsa_public_key)

    def test_ack_roundtrip_preserves_full_signature(self):
        ident = CryptoIdentity()
        node_id = os.urandom(20)
        nonce = os.urandom(16)
        sig = ident.sign(b"NPAK" + node_id + nonce)
        parsed = _parse_punch_ack(_build_punch_ack(node_id, nonce, sig))
        assert parsed is not None and parsed[2] == sig

    def test_oversized_signature_rejected(self):
        blob = b"NPPB" + os.urandom(20) + os.urandom(16) + os.urandom(_PUNCH_SIG_MAX + 1)
        assert _parse_punch_probe(blob) is None

    def test_no_signature_rejected(self):
        blob = b"NPPB" + os.urandom(20) + os.urandom(16)  # header only
        assert _parse_punch_probe(blob) is None

    def test_wrong_magic_rejected(self):
        sig = os.urandom(3309)
        # an ack blob is not a probe
        assert _parse_punch_probe(_build_punch_ack(os.urandom(20), os.urandom(16), sig)) is None


def _authed_peer(node: MeshNode, nid: NodeID) -> None:
    """Mark the node's injected peer as an authenticated session with *nid*."""
    peer = node._peers[0]
    peer.authenticated_id = nid
    peer.session = SessionKey(os.urandom(32))
    return peer


class TestPunchRouteTo:
    async def test_requires_punch_enabled(self):
        node, _ = await make_node()
        node.console_set_punch_enabled(False)
        assert await node._punch_route_to(NodeID(b"\x01" * 20)) is None

    async def test_requires_udp_listener(self):
        node, _ = await make_node()
        assert node._udp_server is None
        assert await node._punch_route_to(NodeID(b"\x01" * 20)) is None

    async def test_requires_a_relay(self):
        node, _ = await make_node()
        await node.start_udp(0, "127.0.0.1")
        try:
            # the only peer is not authenticated — no relay available
            assert await node._punch_route_to(NodeID(b"\x01" * 20)) is None
        finally:
            await node.stop_udp()

    async def test_sends_punch_request_and_waits(self):
        node, fake = await make_node()
        relay_id = NodeID(b"\x02" * 20)
        target_id = NodeID(b"\x03" * 20)
        _authed_peer(node, relay_id)
        await node.start_udp(0, "127.0.0.1")
        try:
            peer = await node._punch_route_to(target_id, timeout=0.3)
            assert peer is None  # nobody answered
            from src.node import PUNCH_REQUEST
            reqs = [p for p in fake.sent if p.type == PUNCH_REQUEST]
            assert len(reqs) == 1
            assert reqs[0].payload[:20] == target_id.raw
        finally:
            await node.stop_udp()

    async def test_returns_peer_once_punched_link_authenticates(self):
        node, fake = await make_node()
        relay_id = NodeID(b"\x02" * 20)
        target_id = NodeID(b"\x03" * 20)
        _authed_peer(node, relay_id)
        await node.start_udp(0, "127.0.0.1")
        try:
            task = asyncio.create_task(
                node._punch_route_to(target_id, timeout=3.0))
            await asyncio.sleep(0.1)
            # Simulate the punched UDP link completing its handshake
            from tests.conftest import FakeTransport
            punched = await node._inject_peer(FakeTransport())
            punched.authenticated_id = target_id
            punched.session = SessionKey(os.urandom(32))
            peer = await asyncio.wait_for(task, timeout=2.0)
            assert peer is punched
        finally:
            await node.stop_udp()


class TestPathUpgrade:
    async def test_relayed_send_schedules_upgrade(self, monkeypatch):
        node, fake = await make_node()
        relay_id = NodeID(b"\x02" * 20)
        target_id = NodeID(b"\x03" * 20)
        _authed_peer(node, relay_id)

        calls = []
        async def fake_ensure(target, timeout=5.0):
            calls.append(target)
        monkeypatch.setattr(node, "_ensure_route_to", fake_ensure)

        pkt = Packet.create(0x00, node.id.raw, target_id.raw, b"x")
        await node._route_outbound(pkt)
        await asyncio.sleep(0.05)
        # sent via the relay, and an upgrade attempt was scheduled
        assert fake.sent and calls == [target_id]

    async def test_upgrade_is_rate_limited_per_target(self, monkeypatch):
        node, _ = await make_node()
        target_id = NodeID(b"\x03" * 20)
        calls = []
        async def fake_ensure(target, timeout=5.0):
            calls.append(target)
        monkeypatch.setattr(node, "_ensure_route_to", fake_ensure)

        for _ in range(10):
            node._maybe_upgrade_path(target_id)
        await asyncio.sleep(0.05)
        assert calls == [target_id]  # one attempt within the cooldown window

        node._upgrade_last.clear()   # cooldown elapsed (simulated)
        node._maybe_upgrade_path(target_id)
        await asyncio.sleep(0.05)
        assert len(calls) == 2

    async def test_upgrade_table_is_bounded(self, monkeypatch):
        node, _ = await make_node()
        async def fake_ensure(target, timeout=5.0):
            pass
        monkeypatch.setattr(node, "_ensure_route_to", fake_ensure)
        for i in range(1000):
            node._maybe_upgrade_path(NodeID(i.to_bytes(20, "big")))
        assert len(node._upgrade_last) <= 256

    async def test_no_upgrade_for_direct_peer(self, monkeypatch):
        node, fake = await make_node()
        target_id = NodeID(b"\x03" * 20)
        _authed_peer(node, target_id)  # the peer IS the target

        calls = []
        async def fake_ensure(target, timeout=5.0):
            calls.append(target)
        monkeypatch.setattr(node, "_ensure_route_to", fake_ensure)

        pkt = Packet.create(0x00, node.id.raw, target_id.raw, b"x")
        await node._route_outbound(pkt)
        await asyncio.sleep(0.05)
        assert calls == []  # direct link — nothing to upgrade
