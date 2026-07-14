"""
Continuous hole-punch keepalive + NAT'd-relay tests.

Continuous mode keeps the UDP listener's NAT mapping open so a node stays
reachable — and can relay for others — even behind NAT. These cover the
keepalive loop, the STUN-response handling that learns our public UDP
mapping, and that a node whose only links are UDP (i.e. itself NAT'd) can
still act as a hole-punch relay.
"""
import asyncio
import socket
import struct

import pytest

from src.node import MeshNode, PUNCH_RELAY, _decode_punch_relay
from src.node_id import NodeID
from src.crypto import SessionKey
from src.packet import Packet
from tests.conftest import make_manager, make_node, FakeTransport


def _stun_response(ip: str, port: int, txn: bytes = b"\x00" * 12) -> bytes:
    """Build a minimal STUN Binding Response with an XOR-MAPPED-ADDRESS."""
    cookie = 0x2112A442
    xport = port ^ (cookie >> 16)
    xip = struct.unpack("!I", socket.inet_aton(ip))[0] ^ cookie
    attr = struct.pack("!HHBBH", 0x0020, 8, 0, 0x01, xport) + struct.pack("!I", xip)
    header = struct.pack("!HH", 0x0101, len(attr)) + struct.pack("!I", cookie) + txn
    return header + attr


class _FakeSock:
    def __init__(self):
        self.sent = []
    def sendto(self, data, addr):
        self.sent.append((data, addr))
    def get_extra_info(self, _):
        return None


class _FakeUDPServer:
    def __init__(self):
        self._sock = _FakeSock()


class TestKeepaliveControl:
    async def test_off_by_default(self):
        node, _ = await make_node()
        assert node._punch_keepalive is False
        snap = await node.console_snapshot()
        assert snap["punch_keepalive"] is False

    async def test_toggle_starts_and_stops_loop(self):
        node, _ = await make_node()
        node._running = True
        node._udp_server = _FakeUDPServer()
        assert node.console_set_punch_keepalive(True) is True
        assert node._punch_keepalive_task is not None
        assert not node._punch_keepalive_task.done()
        node.console_set_punch_keepalive(False)
        await asyncio.sleep(0.05)
        assert node._punch_keepalive is False
        assert node._punch_keepalive_task is None

    async def test_keepalive_sends_stun_from_listener_socket(self, monkeypatch):
        node, _ = await make_node()
        node._udp_server = _FakeUDPServer()
        loop = asyncio.get_running_loop()
        async def fake_gai(*a, **k):
            return [(socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("1.2.3.4", 3478))]
        monkeypatch.setattr(loop, "getaddrinfo", fake_gai)

        await node._send_nat_keepalive()
        assert len(node._udp_server._sock.sent) == 1
        data, addr = node._udp_server._sock.sent[0]
        assert addr == ("1.2.3.4", 3478)
        assert data[4:8] == b"\x21\x12\xa4\x42"  # STUN magic cookie
        assert node._punch_stats["keepalives"] == 1

    async def test_keepalive_noop_without_udp(self):
        node, _ = await make_node()
        assert node._udp_server is None
        await node._send_nat_keepalive()  # must not raise

    async def test_keepalive_noop_when_punch_disabled(self, monkeypatch):
        node, _ = await make_node()
        node._udp_server = _FakeUDPServer()
        node.console_set_punch_enabled(False)
        await node._send_nat_keepalive()
        assert node._udp_server._sock.sent == []


class TestStunResponse:
    async def test_learns_public_udp_mapping(self):
        node, _ = await make_node()
        node._handle_stun_keepalive_response(_stun_response("198.51.100.9", 41234))
        assert node._observed_udp_addr == ("198.51.100.9", 41234)
        assert "198.51.100.9" in node._extra_addrs

    async def test_reported_in_snapshot(self):
        node, _ = await make_node()
        node._udp_server = _FakeUDPServer()
        node._udp_listen_uri = "udp://0.0.0.0:9001"
        node._punch_keepalive = True
        node._handle_stun_keepalive_response(_stun_response("198.51.100.9", 41234))
        snap = await node.console_snapshot()
        udp = next(t for t in snap["transport_details"] if t["scheme"] == "udp")
        assert udp["hole_punch"]["public_udp"] == "198.51.100.9:41234"
        assert udp["hole_punch"]["keepalive"] is True

    async def test_garbage_stun_ignored(self):
        node, _ = await make_node()
        node._handle_stun_keepalive_response(b"\x01\x01\x00\x00" + b"\x21\x12\xa4\x42" + b"\x00" * 12)
        assert node._observed_udp_addr is None

    async def test_stun_handled_even_when_punch_disabled(self):
        node, _ = await make_node()
        node.console_set_punch_enabled(False)
        # STUN responses keep working so continuous mode still learns our addr
        node.handle_udp_datagram(_stun_response("198.51.100.9", 41234),
                                 ("1.2.3.4", 3478))
        assert node._observed_udp_addr == ("198.51.100.9", 41234)


class TestUDPServerStunDispatch:
    async def test_server_forwards_stun_response_to_callback(self):
        from src.udp_transport import UDPServer
        server = UDPServer()
        got = []
        server.on_raw_datagram = lambda data, addr: got.append((data, addr))
        server._dispatch_datagram(_stun_response("203.0.113.1", 5000),
                                  ("1.2.3.4", 3478))
        assert len(got) == 1


class TestNatRelay:
    async def test_nat_node_relays_via_udp_links(self):
        """A relay whose links to both requester and target are UDP transports
        (i.e. the relay is itself behind NAT, reachable only via punched UDP)
        still coordinates a punch: it emits PUNCH_RELAY to both sides."""
        relay = MeshNode(transport_manager=make_manager())

        # Two authenticated UDP peers, standing in for punched links
        req_t, tgt_t = FakeTransport(), FakeTransport()
        req_id, tgt_id = NodeID(b"\x11" * 20), NodeID(b"\x22" * 20)
        req_peer = await relay._inject_peer(req_t)
        tgt_peer = await relay._inject_peer(tgt_t)
        for peer, nid, ip in ((req_peer, req_id, "198.51.100.9"),
                              (tgt_peer, tgt_id, "203.0.113.7")):
            peer.authenticated_id = nid
            peer.session = SessionKey(b"\x00" * 32)
            peer.remote_addr = f"udp://{ip}:40000"
            # NAT'd relay observes each peer's UDP source address
            peer.transport.remote_ip = lambda ip=ip: ip

        from src.node import _encode_punch_request
        payload = _encode_punch_request(tgt_id.raw, 40001)
        pkt = Packet.create(0x10, req_id.raw, relay.id.raw, payload)  # PUNCH_REQUEST
        await relay._handle_punch_request(req_peer, pkt)

        # Relay sent PUNCH_RELAY to the target (with requester's UDP addr)...
        tgt_relays = [p for p in tgt_t.sent if p.type == PUNCH_RELAY]
        assert len(tgt_relays) == 1
        peer_id, peer_addr, observed = _decode_punch_relay(tgt_relays[0].payload)
        assert peer_id == req_id.raw
        assert peer_addr == "198.51.100.9:40001"
        # ...and to the requester (with the target's punchable UDP addr)
        req_relays = [p for p in req_t.sent if p.type == PUNCH_RELAY]
        assert len(req_relays) == 1
        pid2, addr2, _ = _decode_punch_relay(req_relays[0].payload)
        assert pid2 == tgt_id.raw
        assert addr2 == "udp://203.0.113.7:40000"  # directly punchable
