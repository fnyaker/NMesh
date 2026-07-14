"""
Unit tests for NAT hole-punching coordination messages.

Tests the PUNCH_REQUEST / PUNCH_RELAY handlers and the punch probe/ack
codec, using the FakeTransport pattern from conftest.py (no real UDP
sockets needed for the coordination layer).
"""
import os
import struct
import pytest

from src.node import (
    MeshNode, PUNCH_REQUEST, PUNCH_RELAY,
    _encode_punch_request, _decode_punch_request,
    _encode_punch_relay, _decode_punch_relay,
    _build_punch_probe, _parse_punch_probe,
    _build_punch_ack, _parse_punch_ack,
    _PUNCH_PROBE_MAGIC, _PUNCH_ACK_MAGIC,
    _PunchState, _PUNCH_MAX_PENDING,
)
from src.node_id import NodeID
from src.packet import Packet
from tests.conftest import make_node, FakeTransport


# ---------------------------------------------------------------------------
# Codec tests
# ---------------------------------------------------------------------------

class TestPunchCodecs:
    def test_punch_request_roundtrip(self):
        target = os.urandom(20)
        encoded = _encode_punch_request(target, 9000)
        decoded = _decode_punch_request(encoded)
        assert decoded is not None
        assert decoded[0] == target
        assert decoded[1] == 9000

    def test_punch_request_truncated(self):
        assert _decode_punch_request(b"\x00" * 10) is None

    def test_punch_relay_roundtrip(self):
        peer_id = os.urandom(20)
        peer_addr = "203.0.113.5:9000"
        observed = "198.51.100.1"
        encoded = _encode_punch_relay(peer_id, peer_addr, observed)
        decoded = _decode_punch_relay(encoded)
        assert decoded is not None
        assert decoded[0] == peer_id
        assert decoded[1] == peer_addr
        assert decoded[2] == observed

    def test_punch_relay_truncated(self):
        assert _decode_punch_relay(b"\x00" * 10) is None

    def test_punch_probe_roundtrip(self):
        node_id = os.urandom(20)
        nonce = os.urandom(16)
        signature = os.urandom(64)
        probe = _build_punch_probe(node_id, nonce, signature)
        parsed = _parse_punch_probe(probe)
        assert parsed is not None
        assert parsed[0] == node_id
        assert parsed[1] == nonce
        assert parsed[2] == signature

    def test_punch_probe_bad_magic(self):
        node_id = os.urandom(20)
        nonce = os.urandom(16)
        signature = os.urandom(64)
        probe = b"XXXX" + node_id + nonce + signature
        assert _parse_punch_probe(probe) is None

    def test_punch_probe_truncated(self):
        assert _parse_punch_probe(b"NPPB" + b"\x00" * 10) is None

    def test_punch_ack_roundtrip(self):
        node_id = os.urandom(20)
        nonce = os.urandom(16)
        signature = os.urandom(64)
        ack = _build_punch_ack(node_id, nonce, signature)
        parsed = _parse_punch_ack(ack)
        assert parsed is not None
        assert parsed[0] == node_id
        assert parsed[1] == nonce
        assert parsed[2] == signature

    def test_punch_ack_bad_magic(self):
        node_id = os.urandom(20)
        nonce = os.urandom(16)
        signature = os.urandom(64)
        ack = b"XXXX" + node_id + nonce + signature
        assert _parse_punch_ack(ack) is None


# ---------------------------------------------------------------------------
# Handler tests (using FakeTransport from conftest)
# ---------------------------------------------------------------------------

async def _authed(node):
    """Authenticate the node's fake peer."""
    peer = node._peers[0]
    peer.authenticated_id = NodeID(os.urandom(20))
    peer.dsa_pub = os.urandom(32)  # fake key
    return peer


class TestPunchRequestHandler:
    async def test_unauthenticated_ignored(self):
        node, _ = await make_node()
        peer = node._peers[0]  # not authenticated
        target = os.urandom(20)
        payload = _encode_punch_request(target, 9000)
        pkt = Packet.create(PUNCH_REQUEST, os.urandom(20),
                            b"\xff" * 20, payload)
        await node._handle_packet(peer, pkt)
        # Should not crash, should not send anything
        assert len(node._peers[0].transport.sent) == 0
        await node.stop()

    async def test_malformed_payload_ignored(self):
        node, _ = await make_node()
        peer = await _authed(node)
        pkt = Packet.create(PUNCH_REQUEST, peer.authenticated_id.raw,
                            b"\xff" * 20, b"\x00" * 5)
        await node._handle_packet(peer, pkt)
        assert len(peer.transport.sent) == 0
        await node.stop()


class TestPunchRelayHandler:
    async def test_unauthenticated_ignored(self):
        node, _ = await make_node()
        peer = node._peers[0]  # not authenticated
        peer_id = os.urandom(20)
        payload = _encode_punch_relay(peer_id, "10.0.0.1:9000", "10.0.0.2")
        pkt = Packet.create(PUNCH_RELAY, os.urandom(20),
                            b"\xff" * 20, payload)
        await node._handle_packet(peer, pkt)
        assert len(node._punch_pending) == 0
        await node.stop()

    async def test_no_udp_server_ignored(self):
        node, _ = await make_node()
        peer = await _authed(node)
        peer_id = os.urandom(20)
        payload = _encode_punch_relay(peer_id, "10.0.0.1:9000", "10.0.0.2")
        pkt = Packet.create(PUNCH_RELAY, peer.authenticated_id.raw,
                            b"\xff" * 20, payload)
        await node._handle_packet(peer, pkt)
        # No UDP server → should not create punch state
        assert len(node._punch_pending) == 0
        await node.stop()

    async def test_malformed_payload_ignored(self):
        node, _ = await make_node()
        peer = await _authed(node)
        pkt = Packet.create(PUNCH_RELAY, peer.authenticated_id.raw,
                            b"\xff" * 20, b"\x00" * 5)
        await node._handle_packet(peer, pkt)
        assert len(node._punch_pending) == 0
        await node.stop()


class TestPunchState:
    def test_init(self):
        target = NodeID(os.urandom(20))
        state = _PunchState(target, "10.0.0.1:9000", "10.0.0.2")
        assert state.target == target
        assert state.remote_udp_addr == "10.0.0.1:9000"
        assert state.my_udp_addr == "10.0.0.2"
        assert state.probes_sent == 0
        assert state.probes_received == 0
        assert state.ack_received is False
        assert state.completed is False
        assert len(state.nonce) == 16

    def test_max_pending_constant(self):
        assert _PUNCH_MAX_PENDING == 16
