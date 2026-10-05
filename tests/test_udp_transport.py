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
    FLAG_DATA, FLAG_ACK_ONLY, FLAG_KEEPALIVE, FLAG_FIN,
    _MAX_UNACKED, _MAX_REORDER, _MAX_REORDER_BYTES,
    _MAX_DECODED_BYTES, _MAX_SEND_QUEUE, _MAX_PEERS_UDP,
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

def _opened_link() -> _ReliableLink:
    """A link whose cursor is established, as `connect()`'s first keepalive
    does on a real one. The sending sequence is random (the frame header is not
    authenticated and the endpoints of a link are public gossip, so a
    predictable cursor was a free spoofing target), and the receiver learns it
    from the first frame of any kind."""
    link = _ReliableLink()
    link.process_incoming(0, FLAG_KEEPALIVE, b"")
    return link


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
        link = _opened_link()
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

    def test_reorder_buffer_bounded_in_bytes_not_only_frames(self):
        """A frame count is not a memory bound.

        A frame carries up to 60 000 bytes, so 256 of them is 15 MB per link —
        and the sender chooses every byte by sending sequence numbers ahead of
        the cursor and never filling the gap."""
        link = _opened_link()
        big = b"x" * 60_000
        for i in range(_MAX_REORDER):
            link.process_incoming(1_000 + i, FLAG_DATA, big)
        assert link._reorder_bytes <= _MAX_REORDER_BYTES
        assert sum(len(v) for v in link._reorder.values()) == link._reorder_bytes

    def test_reorder_bytes_released_when_the_gap_fills(self):
        link = _opened_link()
        link.process_incoming(1, FLAG_DATA, b"y" * 100)
        assert link._reorder_bytes == 100
        link.process_incoming(0, FLAG_DATA, b"y" * 100)   # fills the gap
        assert link._reorder_bytes == 0

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
    # Ephemeral port (":0"): the OS assigns a free one, so parallel test workers
    # never collide on a fixed number. Read it back to point the client at it.
    await server.listen("127.0.0.1:0")
    port = server._sock.get_extra_info("socket").getsockname()[1]

    client = UDPTransport()
    await client.connect(f"127.0.0.1:{port}")

    # The connect() keepalive makes the server accept and create the transport.
    try:
        await asyncio.wait_for(accepted.wait(), timeout=2.0)
    except asyncio.TimeoutError:
        pass

    # Send a packet from client to trigger server transport creation
    pkt = make_packet(b"init")
    await client.send(pkt)

    # Drain the init packet from the server transport so tests start clean
    # (receive() blocks until it lands — no fixed sleep needed).
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
    async def test_decoded_queue_bounded_in_bytes(self):
        """Nothing couples arrival to consumption, so the decode queue has to
        bound itself: a sender faster than the receive loop — or a transport
        whose consumer never started — grew this without limit."""
        transport = UDPTransport()
        transport._remote = ("127.0.0.1", 9)
        big = b"z" * 59_000
        for seq in range(200):
            packet = make_packet(big).pack()
            transport._process_frame(
                _MAGIC + _FRAME.pack(seq, 0, 0, FLAG_DATA, len(packet)) + packet)
        assert transport._decoded_bytes <= _MAX_DECODED_BYTES

    async def test_receive_is_woken_not_polled(self):
        """A parked receive() returns as soon as a datagram lands.

        The old poll cost 10 ms of latency per packet and 100 wakeups a second
        per link at rest; with 128 links that is 12 800 timer wakeups doing
        nothing."""
        transport = UDPTransport()
        transport._remote = ("127.0.0.1", 9)
        waiter = asyncio.create_task(transport.receive())
        await asyncio.sleep(0)
        packet = make_packet(b"woken").pack()
        transport._process_frame(
            _MAGIC + _FRAME.pack(0, 0, 0, FLAG_DATA, len(packet)) + packet)
        got = await asyncio.wait_for(waiter, timeout=0.2)
        assert got.payload == make_packet(b"woken").payload

    async def test_close_wakes_a_parked_receive(self):
        transport = UDPTransport()
        transport._remote = ("127.0.0.1", 9)
        waiter = asyncio.create_task(transport.receive())
        await asyncio.sleep(0)
        await transport.close()
        with pytest.raises(ConnectionError):
            await asyncio.wait_for(waiter, timeout=0.2)

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

class TestUDPServerSlots:
    """`remove_transport` existed and was called nowhere, so a closed entry sat
    in the dispatch table for the life of the process — and the ceiling counted
    it. 128 datagrams from 128 source ports therefore disabled UDP for good,
    including for a known peer whose link had died and wanted to come back."""

    def _frame(self) -> bytes:
        return _MAGIC + _FRAME.pack(0, 0, 0, FLAG_KEEPALIVE, 0)

    async def _full_server(self):
        server = UDPServer()
        server.on_new_connection = lambda transport: asyncio.sleep(0)
        server._sock = _StubSock()
        for port in range(_MAX_PEERS_UDP):
            server._dispatch_datagram(self._frame(), ("10.0.0.1", 30000 + port))
        await asyncio.sleep(0)
        return server

    async def test_dead_transports_free_their_slot(self):
        server = await self._full_server()
        assert len(server._transports) == _MAX_PEERS_UDP
        for transport in server._transports.values():
            transport._closed = True
        server._dispatch_datagram(self._frame(), ("10.0.0.2", 40000))
        await asyncio.sleep(0)
        assert ("10.0.0.2", 40000) in server._transports

    async def test_a_known_peer_can_come_back(self):
        server = await self._full_server()
        addr = ("10.0.0.1", 30000)
        for transport in server._transports.values():
            transport._closed = True
        server._dispatch_datagram(self._frame(), addr)
        await asyncio.sleep(0)
        assert addr in server._transports
        assert not server._transports[addr]._closed

    async def test_closing_releases_the_slot_without_waiting_for_a_sweep(self):
        server = await self._full_server()
        addr = ("10.0.0.1", 30000)
        await server._transports[addr].close()
        assert addr not in server._transports

    async def test_the_ceiling_still_holds_for_live_peers(self):
        server = await self._full_server()
        server._dispatch_datagram(self._frame(), ("10.0.0.9", 50000))
        await asyncio.sleep(0)
        assert len(server._transports) == _MAX_PEERS_UDP


class _StubSock:
    def sendto(self, *a, **k): ...
    def get_extra_info(self, *a, **k): return None
    def close(self): ...


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


class TestSequenceIsNotGuessable:
    """The frame header is not authenticated — only the mesh Packet inside it
    is — and a link's endpoints are public: they are gossiped in
    `advertised_uris` and in FOUND_NODE. A cursor starting at zero was therefore
    a free target: one spoofed frame at the next expected sequence advanced it,
    and the real peer's next frame was dropped as a duplicate."""

    def test_initial_sequence_is_random(self):
        seqs = {_ReliableLink()._send_seq for _ in range(32)}
        assert len(seqs) > 30, "sending sequences repeat"

    def test_the_receiver_learns_the_peers_starting_point(self):
        link = _ReliableLink()
        link.process_incoming(9_000, FLAG_KEEPALIVE, b"")
        assert link.process_incoming(9_000, FLAG_DATA, b"first") == [b"first"]
        assert link.process_incoming(9_001, FLAG_DATA, b"second") == [b"second"]

    async def test_an_undecodable_payload_is_counted(self):
        """A delivered payload that is not a packet is a fault, not noise: a
        real peer's frames decode."""
        transport = UDPTransport()
        transport._remote = ("127.0.0.1", 9)
        transport._process_frame(
            _MAGIC + _FRAME.pack(0, 0, 0, FLAG_KEEPALIVE, 0))
        rubbish = b"not a packet"
        transport._process_frame(
            _MAGIC + _FRAME.pack(0, 0, 0, FLAG_DATA, len(rubbish)) + rubbish)
        assert transport.undecodable == 1
        assert transport.stats()["undecodable"] == 1


class TestAKeepaliveKeepsTheLinkAlive:
    """A keepalive is the only thing an idle link ever sends, and it is what
    the death verdict is measured against — `_KEEPALIVE_TIMEOUT` is three times
    the interval precisely so that three of them may go missing.

    `_process_frame` handed the reliability layer the frames carrying data and
    nothing else, so the arrival that `is_alive` reads was recorded for mesh
    traffic alone. A link with a peer answering every keepalive was declared
    dead the moment the traffic above it paused for the timeout, and the branch
    inside `process_incoming` that exists to return nothing for a keepalive was
    unreachable from the transport.
    """

    def _transport(self) -> UDPTransport:
        transport = UDPTransport()
        transport._remote = ("127.0.0.1", 9)
        return transport

    def _aged(self, transport: UDPTransport, seconds: float) -> float:
        """Push the last arrival back, as a quiet link does by itself."""
        transport._link._last_recv_time -= seconds
        return transport._link._last_recv_time

    def test_a_keepalive_is_an_arrival(self):
        transport = self._transport()
        silent = self._aged(transport, 50.0)
        transport._process_frame(_MAGIC + _FRAME.pack(0, 0, 0, FLAG_KEEPALIVE, 0))
        assert transport._link._last_recv_time > silent

    def test_a_link_answering_keepalives_is_not_declared_dead(self):
        transport = self._transport()
        self._aged(transport, UDPTransport.setting("keepalive_timeout") + 10.0)
        assert not transport._link.is_alive()
        transport._process_frame(_MAGIC + _FRAME.pack(0, 0, 0, FLAG_KEEPALIVE, 0))
        assert transport._link.is_alive()

    def test_a_peer_that_stopped_answering_still_dies(self):
        """The fix must not make a link immortal: silence is still silence."""
        transport = self._transport()
        self._aged(transport, UDPTransport.setting("keepalive_timeout") + 10.0)
        assert not transport._link.is_alive()

    def test_an_ack_and_a_fin_are_arrivals_too(self):
        for flag in (FLAG_ACK_ONLY, FLAG_FIN):
            transport = self._transport()
            silent = self._aged(transport, 50.0)
            transport._process_frame(_MAGIC + _FRAME.pack(0, 0, 0, flag, 0))
            assert transport._link._last_recv_time > silent, flag

    def test_the_cursor_is_adopted_from_the_opening_keepalive(self):
        """`connect()` sends a keepalive before any data, and that is the frame
        the receiver is meant to learn the peer's random starting point from.
        Learning it from the first *data* frame instead means a reordered
        opening frame moves the cursor past its predecessors, and those are
        then dropped as duplicates for ever."""
        transport = self._transport()
        transport._process_frame(
            _MAGIC + _FRAME.pack(9_000, 0, 0, FLAG_KEEPALIVE, 0))
        assert transport._link._recv_started
        assert transport._link._recv_next == 9_000

    def test_a_keepalive_delivers_nothing_and_answers_nothing(self):
        """Seeing a frame is not replying to one: a keepalive must not schedule
        an ack, or two idle links would answer each other for ever."""
        transport = self._transport()
        transport._process_frame(_MAGIC + _FRAME.pack(0, 0, 0, FLAG_KEEPALIVE, 0))
        assert not transport._decoded
        assert not transport._link.needs_ack()

    def test_a_data_frame_with_no_payload_moves_nothing(self):
        """No sender builds one, so it is malformed — and malformed input is
        dropped with no side effect, cursor included."""
        transport = self._transport()
        transport._process_frame(
            _MAGIC + _FRAME.pack(7, 0, 0, FLAG_KEEPALIVE, 0))   # opens the cursor
        transport._process_frame(_MAGIC + _FRAME.pack(7, 0, 0, FLAG_DATA, 0))
        assert transport._link._recv_next == 7
        assert transport.undecodable == 0

    async def test_a_quiet_link_survives_on_keepalives_alone(self, monkeypatch):
        """Over real sockets, with the real keepalive loop, and no traffic.

        This is the property the unit tests above assert one frame at a time:
        two nodes that say nothing to each other for longer than the death
        timeout must still hold the link, because the keepalive loop is talking
        underneath them. The cadence is shortened so the test costs a second
        rather than the 75 s the shipped bound is — `SETTINGS` is replaced
        rather than edited, as `configure()` does, so nothing leaks to the next
        test."""
        monkeypatch.setattr(UDPTransport, "SETTINGS",
                            {"keepalive_interval": 0.2, "keepalive_timeout": 0.6})

        server = UDPServer()
        accepted: list[UDPTransport] = []
        landed = asyncio.Event()

        async def on_new_conn(transport):
            accepted.append(transport)
            landed.set()

        server.on_new_connection = on_new_conn
        await server.listen("127.0.0.1:0")
        port = server._sock.get_extra_info("socket").getsockname()[1]

        client = UDPTransport()
        await client.connect(f"127.0.0.1:{port}")
        await asyncio.wait_for(landed.wait(), timeout=2.0)
        accepted_transport = accepted[0]

        try:
            # Three death timeouts' worth of silence, carried by keepalives.
            await asyncio.sleep(0.6 * 3)
            assert not client.is_closed(), "the dialled half died while quiet"
            assert not accepted_transport.is_closed(), \
                "the accepted half died while quiet"
            assert client._link.is_alive() and accepted_transport._link.is_alive()
        finally:
            await client.close()
            await accepted_transport.close()
            await server.close()
