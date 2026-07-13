"""
Unit tests for the UDP transport — reliability layer, framing, keepalive,
and bidirectional communication over loopback UDP.

These tests use real UDP sockets on localhost. They are fast (no crypto,
no mesh protocol) and focus on the transport contract: send/receive
ordering, loss recovery, and hostile-input resilience.
"""
import asyncio
import struct
import pytest

from src.udp_transport import (
    UDPTransport, UDPServer, _ReliableLink, _FRAME, _MAGIC,
    FLAG_DATA, FLAG_ACK_ONLY, FLAG_KEEPALIVE,
    _MAX_UNACKED, _MAX_REORDER, _MAX_SEND_QUEUE,
)
from src.packet import Packet

ADDRESS = "127.0.0.1:19877"

SRC     = bytes(range(20))
DST     = bytes(range(20, 40))
NONCE   = bytes(range(12))
GCM_TAG = bytes(range(16))


def make_packet(payload: bytes = b"hello") -> Packet:
    return Packet(
        version=1, type=0x01, ttl=64,
        src_id=SRC, dst_id=DST, msg_id=0,
        nonce=NONCE, gcm_tag=GCM_TAG,
        payload=payload,
    )


# ---------------------------------------------------------------------------
# _ReliableLink unit tests
# ---------------------------------------------------------------------------

class TestReliableLink:
    def test_build_frame_increments_seq(self):
        link = _ReliableLink()
        p1 = make_packet(b"first")
        p2 = make_packet(b"second")
        f1 = link.build_frame(p1)
        f2 = link.build_frame(p2)
        seq1 = struct.unpack("!I", f1[len(_MAGIC):len(_MAGIC) + 4])[0]
        seq2 = struct.unpack("!I", f2[len(_MAGIC):len(_MAGIC) + 4])[0]
        assert seq2 == seq1 + 1

    def test_process_ack_removes_unacked(self):
        link = _ReliableLink()
        p = make_packet(b"data")
        frame = link.build_frame(p)
        seq = struct.unpack("!I", frame[len(_MAGIC):len(_MAGIC) + 4])[0]
        assert link.unacked_count() == 1
        link.process_ack(seq, 0)
        assert link.unacked_count() == 0

    def test_process_in_order_delivers(self):
        link = _ReliableLink()
        payload = b"hello"
        delivered = link.process_incoming(0, FLAG_DATA, payload)
        assert delivered == [payload]

    def test_process_out_of_order_buffers(self):
        link = _ReliableLink()
        # Receive seq 1 before seq 0 — should buffer, not deliver
        delivered = link.process_incoming(1, FLAG_DATA, b"second")
        assert delivered == []
        # Now receive seq 0 — should deliver both in order
        delivered = link.process_incoming(0, FLAG_DATA, b"first")
        assert delivered == [b"first", b"second"]

    def test_duplicate_ignored(self):
        link = _ReliableLink()
        link.process_incoming(0, FLAG_DATA, b"first")
        delivered = link.process_incoming(0, FLAG_DATA, b"first")
        assert delivered == []

    def test_reorder_buffer_bounded(self):
        link = _ReliableLink()
        # Fill reorder buffer beyond limit
        for i in range(_MAX_REORDER + 10):
            link.process_incoming(_MAX_REORDER + 100 + i, FLAG_DATA, b"x")
        assert len(link._reorder) <= _MAX_REORDER

    def test_keepalive_flag_no_delivery(self):
        link = _ReliableLink()
        delivered = link.process_incoming(0, FLAG_KEEPALIVE, b"")
        assert delivered == []

    def test_ack_only_flag_no_delivery(self):
        link = _ReliableLink()
        delivered = link.process_incoming(0, FLAG_ACK_ONLY, b"")
        assert delivered == []


# ---------------------------------------------------------------------------
# UDPTransport integration tests (real loopback UDP)
# ---------------------------------------------------------------------------

@pytest.fixture
async def udp_pair():
    """Create a server + client UDP transport pair over loopback."""
    server = UDPServer()
    server.on_new_connection = None  # set below
    accepted = asyncio.Event()
    server_transport: list[UDPTransport] = []

    async def on_new_conn(t):
        server_transport.append(t)
        accepted.set()

    server.on_new_connection = on_new_conn
    await server.listen("127.0.0.1:19890")

    client = UDPTransport()
    await client.connect("127.0.0.1:19890")

    # Wait for the server to accept the client
    try:
        await asyncio.wait_for(accepted.wait(), timeout=2.0)
    except asyncio.TimeoutError:
        pass

    # Send a packet from client to trigger server transport creation
    pkt = make_packet(b"init")
    await client.send(pkt)

    # Wait a bit for the server to receive and create the transport
    await asyncio.sleep(0.3)

    # Drain the init packet from the server transport so tests start clean
    if server_transport:
        try:
            await asyncio.wait_for(server_transport[0].receive(), timeout=1.0)
        except asyncio.TimeoutError:
            pass

    yield server, server_transport[0] if server_transport else None, client

    await client.close()
    if server_transport:
        await server_transport[0].close()
    await server.close()


class TestUDPTransport:
    async def test_send_receive(self, udp_pair):
        server, srv_transport, client = udp_pair
        assert srv_transport is not None, "server transport was not created"
        pkt = make_packet(b"hello udp")
        await client.send(pkt)
        received = await asyncio.wait_for(srv_transport.receive(), timeout=3.0)
        assert received.pack() == pkt.pack()

    async def test_bidirectional(self, udp_pair):
        server, srv_transport, client = udp_pair
        assert srv_transport is not None
        p1 = make_packet(b"client to server")
        p2 = make_packet(b"server to client")
        await client.send(p1)
        await srv_transport.send(p2)
        got1 = await asyncio.wait_for(srv_transport.receive(), timeout=3.0)
        got2 = await asyncio.wait_for(client.receive(), timeout=3.0)
        assert got1.pack() == p1.pack()
        assert got2.pack() == p2.pack()

    async def test_multiple_packets_ordered(self, udp_pair):
        server, srv_transport, client = udp_pair
        assert srv_transport is not None
        packets = [make_packet(f"msg{i}".encode()) for i in range(5)]
        for p in packets:
            await client.send(p)
        for p in packets:
            received = await asyncio.wait_for(srv_transport.receive(), timeout=5.0)
            assert received.pack() == p.pack()

    async def test_remote_ip(self, udp_pair):
        server, srv_transport, client = udp_pair
        assert srv_transport is not None
        assert srv_transport.remote_ip() == "127.0.0.1"
        assert client.remote_ip() == "127.0.0.1"

    async def test_garbage_datagram_no_crash(self, udp_pair):
        """A hostile/garbage datagram must not crash the transport."""
        server, srv_transport, client = udp_pair
        assert srv_transport is not None
        # Send garbage directly via the raw socket
        if server._sock:
            server._sock.sendto(b"\xff" * 100, ("127.0.0.1", 19890))
        # The transport should still work after garbage
        pkt = make_packet(b"after garbage")
        await client.send(pkt)
        received = await asyncio.wait_for(srv_transport.receive(), timeout=5.0)
        assert received.pack() == pkt.pack()

    async def test_send_not_connected(self):
        t = UDPTransport()
        with pytest.raises(ConnectionError):
            await t.send(make_packet())

    async def test_receive_closed(self):
        t = UDPTransport()
        t._closed = True
        with pytest.raises(ConnectionError):
            await t.receive()

    async def test_close_cleans_up(self, udp_pair):
        server, srv_transport, client = udp_pair
        assert srv_transport is not None
        await client.close()
        assert client._closed
        # Receiving from a closed transport should raise
        with pytest.raises(ConnectionError):
            await client.receive()


# ---------------------------------------------------------------------------
# UDPServer tests
# ---------------------------------------------------------------------------

class TestUDPServer:
    async def test_listen_and_close(self):
        server = UDPServer()
        await server.listen("127.0.0.1:19891")
        assert server._sock is not None
        await server.close()
        assert server._sock is None

    async def test_dispatch_creates_transport(self):
        server = UDPServer()
        accepted: list[UDPTransport] = []

        async def on_new_conn(t):
            accepted.append(t)

        server.on_new_connection = on_new_conn
        await server.listen("127.0.0.1:19892")

        client = UDPTransport()
        await client.connect("127.0.0.1:19892")
        pkt = make_packet(b"trigger")
        await client.send(pkt)
        await asyncio.sleep(0.3)

        assert len(accepted) == 1
        await client.close()
        await server.close()

    async def test_punch_probe_not_treated_as_transport(self):
        """A punch probe datagram (NPPB magic) should not create a transport."""
        server = UDPServer()
        raw_received: list[tuple] = []
        server.on_raw_datagram = lambda data, addr: raw_received.append((data, addr))
        await server.listen("127.0.0.1:19893")

        # Send a fake punch probe
        probe = b"NPPB" + b"\x00" * 100
        server._sock.sendto(probe, ("127.0.0.1", 19893))
        await asyncio.sleep(0.1)

        assert len(raw_received) == 1
        assert len(server._transports) == 0  # no transport created
        await server.close()
