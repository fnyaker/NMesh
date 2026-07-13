"""
Mesh-native public-IP discovery: a peer that accepts our connection tells us the
source IP it saw (OBSERVED_ADDR). We record it, validated and bounded, and it
feeds address advertisement.
"""
import os

import pytest

from src.node import OBSERVED_ADDR, _MAX_EXTRA_ADDRS
from src.node_id import NodeID
from src.packet import Packet
from tests.conftest import make_node


async def _authed(node):
    peer = node._peers[0]
    peer.authenticated_id = NodeID(os.urandom(20))
    return peer


def _observed(peer, ip: bytes) -> Packet:
    return Packet.create(OBSERVED_ADDR, peer.authenticated_id.raw,
                         b"\xff" * 20, ip)


class TestObservedAddr:
    async def test_valid_ip_recorded(self):
        node, _ = await make_node()
        peer = await _authed(node)
        await node._handle_packet(peer, _observed(peer, b"198.51.100.7"))
        assert "198.51.100.7" in node._extra_addrs
        await node.stop()

    async def test_ipv6_recorded(self):
        node, _ = await make_node()
        peer = await _authed(node)
        await node._handle_packet(peer, _observed(peer, b"2001:db8::1234"))
        assert "2001:db8::1234" in node._extra_addrs
        await node.stop()

    async def test_garbage_ignored(self):
        node, _ = await make_node()
        peer = await _authed(node)
        await node._handle_packet(peer, _observed(peer, b"not-an-ip"))
        await node._handle_packet(peer, _observed(peer, b"\xff\xfe\x00"))
        assert node._extra_addrs == []
        await node.stop()

    async def test_unauthenticated_ignored(self):
        node, _ = await make_node()
        peer = node._peers[0]              # authenticated_id is None
        pkt = Packet.create(OBSERVED_ADDR, os.urandom(20), b"\xff" * 20, b"203.0.113.1")
        await node._handle_packet(peer, pkt)
        assert node._extra_addrs == []     # DIRECT type dropped before the handler
        await node.stop()

    async def test_bounded(self):
        node, _ = await make_node()
        peer = await _authed(node)
        for i in range(_MAX_EXTRA_ADDRS + 5):
            await node._handle_packet(peer, _observed(peer, f"198.51.100.{i}".encode()))
        assert len(node._extra_addrs) == _MAX_EXTRA_ADDRS
        await node.stop()

    async def test_feeds_advertised(self):
        node, _ = await make_node()
        peer = await _authed(node)
        node._addresses = ["tcp://0.0.0.0:9000"]
        node._local_ips = []
        await node._handle_packet(peer, _observed(peer, b"198.51.100.7"))
        assert "tcp://198.51.100.7:9000" in node.advertised_uris()
        await node.stop()
