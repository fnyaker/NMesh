"""
IPv6-first connect ordering + AutoNAT active reachability (étape 6).

IPv6-first: when a peer advertises both a NAT'd IPv4 and a global IPv6, trying
the IPv6 endpoint first often gives a direct, NAT-free link. AutoNAT: a node
confirms it is reachable by asking a peer to dial it back at the address the
peer OBSERVED it come from (never an arbitrary one → no amplification), rather
than waiting for a passive inbound connection.
"""
import asyncio
import random
import struct

import pytest

from src.node import (
    MeshNode, _order_by_preference, _uri_preference,
    REACH_PROBE, REACH_PROBE_ACK, CHALLENGE,
)
from src.node_id import NodeID
from src.crypto import SessionKey
from src.packet import Packet
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer
from tests.conftest import make_node, FakeTransport


def _tcp_mgr() -> TransportManager:
    m = TransportManager()
    m.register("tcp", TCPTransport, TCPServer)
    return m


class TestIPv6Preference:
    def test_global_ipv6_sorts_first(self):
        uris = ["tcp://192.168.1.5:9000", "tcp://[2a01:e0a:1::5]:9000",
                "udp://8.8.8.8:9001"]
        ordered = _order_by_preference(uris)
        assert ordered[0] == "tcp://[2a01:e0a:1::5]:9000"

    def test_link_local_ipv6_not_preferred(self):
        # fe80:: is not global → not moved ahead of an IPv4 that came first
        uris = ["tcp://1.2.3.4:9000", "tcp://[fe80::1]:9000"]
        assert _order_by_preference(uris) == uris

    def test_preference_is_stable(self):
        # two non-preferred URIs keep their relative order
        uris = ["tcp://a.example:1", "tcp://b.example:2"]
        assert _order_by_preference(uris) == uris

    def test_uri_preference_key(self):
        assert _uri_preference("tcp://[2a01::1]:1") == 0
        assert _uri_preference("tcp://10.0.0.1:1") == 1
        assert _uri_preference("garbage") == 1

    async def test_valid_candidates_are_ipv6_first(self):
        node, _ = await make_node()   # "fake" scheme
        # fake scheme is supported; ordering still applies by host family
        node._transport_manager.register  # noqa: keep ref
        got = node._valid_candidate_uris(
            ["fake://10.0.0.1:1", "fake://[2a01::9]:1"])
        assert got[0] == "fake://[2a01::9]:1"


class TestAutoNAT:
    async def test_dial_back_confirms_reachable(self):
        base = random.randint(20000, 40000)
        A, P = MeshNode(_tcp_mgr()), MeshNode(_tcp_mgr())
        await A.start([f"tcp://127.0.0.1:{base}"])
        await P.join(f"tcp://127.0.0.1:{base}", A.generate_invite())
        await asyncio.wait_for(P.wait_for_session(10), 15)
        await asyncio.wait_for(A.wait_for_session(10), 15)
        try:
            A._inbound_schemes.clear()          # isolate AutoNAT from passive signal
            assert A.relay_capable() is False
            sent = await A.probe_reachability()
            assert sent == 1
            # dial-back succeeds → the peer confirms our tcp scheme is inbound.
            # (world-scope, hence relay_capable(), needs a *global* address —
            #  a loopback endpoint can never qualify, so we assert the signal
            #  AutoNAT actually produces: the confirmed inbound scheme.)
            async with asyncio.timeout(8):
                while "tcp" not in A._inbound_schemes:
                    await asyncio.sleep(0.05)
            assert "tcp" in A._inbound_schemes   # confirmed reachable via dial-back
        finally:
            await A.stop(); await P.stop()

    async def test_probe_needs_a_peer(self):
        node, _ = await make_node()
        node._peers.clear()
        assert await node.probe_reachability() == 0

    async def test_dial_back_only_uses_observed_address(self):
        # the responder must dial the OBSERVED ip, never an attacker-supplied one
        node, _ = await make_node()
        peer = node._peers[0]
        peer.authenticated_id = NodeID(b"\x02" * 20)
        peer.session = SessionKey(b"\x00" * 32)
        dialed = []

        async def fake_dial(scheme, ip, port):
            dialed.append((scheme, ip, port))
            return False
        node._dial_back = fake_dial
        # peer's transport reports the observed source
        peer.transport.remote_ip = lambda: "203.0.113.9"
        node._transport_manager.register("tcp", TCPTransport, TCPServer)
        payload = struct.pack("!BH", 3, 9000) + b"tcp"
        pkt = Packet.create(REACH_PROBE, b"\x02" * 20, node.id.raw, payload)
        await node._handle_reach_probe(peer, pkt)
        assert dialed == [("tcp", "203.0.113.9", 9000)]   # observed ip, not claimed

    async def test_reach_probe_rate_limited(self):
        node, _ = await make_node()
        peer = node._peers[0]
        peer.authenticated_id = NodeID(b"\x02" * 20)
        peer.session = SessionKey(b"\x00" * 32)
        peer.transport.remote_ip = lambda: "203.0.113.9"
        node._transport_manager.register("tcp", TCPTransport, TCPServer)
        calls = {"n": 0}
        async def fake_dial(*a):
            calls["n"] += 1
            return False
        node._dial_back = fake_dial
        payload = struct.pack("!BH", 3, 9000) + b"tcp"
        for _ in range(20):
            pkt = Packet.create(REACH_PROBE, b"\x02" * 20, node.id.raw, payload)
            await node._handle_reach_probe(peer, pkt)
        from src.node import _REACH_PROBE_RATE_MAX
        assert calls["n"] <= _REACH_PROBE_RATE_MAX

    async def test_ack_confirms_scheme(self):
        node, _ = await make_node()
        node._transport_manager.register("tcp", TCPTransport, TCPServer)
        peer = node._peers[0]
        peer.authenticated_id = NodeID(b"\x02" * 20)
        assert "tcp" not in node._inbound_schemes
        ack = Packet.create(REACH_PROBE_ACK, b"\x02" * 20, node.id.raw,
                            struct.pack("!BB", 3, 1) + b"tcp")
        await node._handle_reach_probe_ack(peer, ack)
        assert "tcp" in node._inbound_schemes

    async def test_ack_failure_does_not_confirm(self):
        node, _ = await make_node()
        node._transport_manager.register("tcp", TCPTransport, TCPServer)
        peer = node._peers[0]
        peer.authenticated_id = NodeID(b"\x02" * 20)
        ack = Packet.create(REACH_PROBE_ACK, b"\x02" * 20, node.id.raw,
                            struct.pack("!BB", 3, 0) + b"tcp")
        await node._handle_reach_probe_ack(peer, ack)
        assert "tcp" not in node._inbound_schemes
