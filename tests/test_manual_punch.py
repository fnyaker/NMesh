"""
Manual (out-of-band) hole punching + relay-readiness diagnostic.

Manual punching removes the shared-relay requirement: two operators exchange
their public UDP endpoints by hand, each opens a hole toward the other, then
one joins with the other's invite block over the *listener* socket (so it
reuses the opened hole). These cover the open-hole primitive, the UDP join
reusing the listener socket, the readiness reason strings, and a full
no-relay join between two nodes.
"""
import asyncio
import base64
import json
import socket

import pytest

from src.node import MeshNode, _HOLE_OPEN_MAGIC, _MANUAL_HOLE_MAX
from src.udp_transport import UDPTransport, UDPServer
from src.transport_manager import TransportManager
from tests.conftest import make_manager, make_node


def _udp_manager() -> TransportManager:
    m = TransportManager()
    m.register("udp", UDPTransport, UDPServer)
    return m


def _free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


async def _udp_authed(node, other):
    return any(p.authenticated_id == other and p.session is not None
               and isinstance(p.transport, UDPTransport) for p in node._peers)


class TestOpenHole:
    async def test_requires_udp(self):
        node, _ = await make_node()
        with pytest.raises(ValueError):
            node.console_open_hole("1.2.3.4", 5000)

    async def test_rejects_bad_input(self):
        node = MeshNode(transport_manager=_udp_manager())
        await node.start_udp(0, "127.0.0.1")
        try:
            for host, port in (("not-an-ip", 5000), ("1.2.3.4", 0),
                               ("1.2.3.4", 70000), ("1.2.3.4", "x")):
                with pytest.raises(ValueError):
                    node.console_open_hole(host, port)
        finally:
            await node.stop_udp()

    async def test_sends_hole_open_datagrams(self):
        node = MeshNode(transport_manager=_udp_manager())
        await node.start_udp(0, "127.0.0.1")
        # capture what leaves the listener socket
        sent = []
        node._udp_server._sock.sendto = lambda data, addr: sent.append((data, addr))
        try:
            node.console_open_hole("198.51.100.9", 40001)
            await asyncio.sleep(0.15)
            assert sent, "no hole-open datagram sent"
            assert sent[0][0] == _HOLE_OPEN_MAGIC
            assert sent[0][1] == ("198.51.100.9", 40001)
            assert node._manual_holes[("198.51.100.9", 40001)]["sent"] >= 1
        finally:
            node._cancel_manual_holes()
            await node.stop_udp()

    async def test_table_is_bounded(self):
        node = MeshNode(transport_manager=_udp_manager())
        await node.start_udp(0, "127.0.0.1")
        node._udp_server._sock.sendto = lambda *a: None
        try:
            for i in range(_MANUAL_HOLE_MAX + 20):
                node.console_open_hole(f"198.51.100.{i % 250}", 40000 + i)
            assert len(node._manual_holes) <= _MANUAL_HOLE_MAX
        finally:
            node._cancel_manual_holes()
            await node.stop_udp()

    async def test_reported_in_snapshot(self):
        node = MeshNode(transport_manager=_udp_manager())
        await node.start_udp(0, "127.0.0.1")
        node._udp_server._sock.sendto = lambda *a: None
        try:
            node.console_open_hole("198.51.100.9", 40001)
            await asyncio.sleep(0.05)
            snap = await node.console_snapshot()
            udp = next(t for t in snap["transport_details"] if t["scheme"] == "udp")
            holes = udp["hole_punch"]["manual_holes"]
            assert any(h["addr"] == "198.51.100.9:40001" for h in holes)
            json.dumps(snap)
        finally:
            node._cancel_manual_holes()
            await node.stop_udp()


class TestHoleOpenIgnoredByReceiver:
    async def test_receiver_drops_hole_open_magic(self):
        server = UDPServer()
        accepted = []
        server.on_new_connection = lambda t: accepted.append(t)
        raw = []
        server.on_raw_datagram = lambda data, addr: raw.append(data)
        # a hole-open datagram must neither create a transport nor be treated
        # as a raw punch signal — it only opens the *sender's* NAT
        server._dispatch_datagram(_HOLE_OPEN_MAGIC, ("1.2.3.4", 5000))
        assert accepted == [] and raw == []


class TestUDPJoinReusesListener:
    async def test_udp_join_binds_to_listener_socket(self):
        node = MeshNode(transport_manager=_udp_manager())
        await node.start_udp(0, "127.0.0.1")
        try:
            transport = await node._connect_for_join("udp://198.51.100.9:41000")
            # bound to the shared listener socket, registered for dispatch
            assert isinstance(transport, UDPTransport)
            assert transport._sock is node._udp_server._sock
            assert ("198.51.100.9", 41000) in node._udp_server._transports
        finally:
            await node.stop_udp()


class TestReadiness:
    async def test_reason_when_punch_off(self):
        node = MeshNode(transport_manager=_udp_manager())
        await node.start_udp(0, "127.0.0.1")
        try:
            node.console_set_punch_enabled(False)
            ready, reason = node._punch_readiness()
            assert ready is False and "off" in reason
        finally:
            await node.stop_udp()

    async def test_reason_when_no_relay(self):
        node = MeshNode(transport_manager=_udp_manager())
        await node.start_udp(0, "127.0.0.1")
        try:
            ready, reason = node._punch_readiness()
            assert ready is False and "reachable node" in reason
        finally:
            await node.stop_udp()

    async def test_ready_with_relay_peer(self):
        from src.crypto import SessionKey
        from src.node_id import NodeID
        node, _ = await make_node()
        await node.start_udp(0, "127.0.0.1")
        try:
            node._peers[0].authenticated_id = NodeID(b"\x01" * 20)
            node._peers[0].session = SessionKey(b"\x00" * 32)
            ready, reason = node._punch_readiness()
            assert ready is True and "ready" in reason
        finally:
            await node.stop_udp()


class TestManualPunchEndToEnd:
    async def test_join_with_no_shared_relay(self):
        """A joins B with zero shared relay — only manual coordination: both
        open a hole toward the other, A joins with B's invite block."""
        pa, pb = _free_udp_port(), _free_udp_port()
        A = MeshNode(transport_manager=_udp_manager())
        B = MeshNode(transport_manager=_udp_manager())
        await A.start_udp(pa, "127.0.0.1")
        await B.start_udp(pb, "127.0.0.1")
        try:
            B._addresses = [f"udp://127.0.0.1:{pb}"]
            block = B.console_invite_block()
            assert f"udp://127.0.0.1:{pb}" in json.loads(base64.b64decode(block))["uris"]

            # out-of-band: each opens a hole toward the other's public UDP addr
            B.console_open_hole("127.0.0.1", pa)
            A.console_open_hole("127.0.0.1", pb)
            await asyncio.sleep(0.2)

            A.console_join_block(block)
            async with asyncio.timeout(15):
                while A._join_status["running"]:
                    await asyncio.sleep(0.05)
            assert A._join_status["connected"] == f"udp://127.0.0.1:{pb}"
            assert await _udp_authed(A, B.id)
            assert await _udp_authed(B, A.id)
        finally:
            await A.stop()
            await B.stop()
