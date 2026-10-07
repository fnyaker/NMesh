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
    FLAG_DATA, FLAG_ACK_ONLY, FLAG_KEEPALIVE, FLAG_FIN, FLAG_MORE, FLAG_SEGMENTS,
    _SEGMENT, _SEGMENT_PAYLOAD, _MAX_PAYLOAD,
    _MAX_UNACKED, _MAX_REORDER, _MAX_REORDER_BYTES,
    _MAX_DECODED_BYTES, _MAX_SEND_QUEUE, _MAX_PEERS_UDP,
)
from src.packet import HEADER_SIZE, Packet

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
        assert sum(len(v) for v, _more in link._reorder.values()) == link._reorder_bytes

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

    def test_an_ack_is_an_arrival_too(self):
        transport = self._transport()
        silent = self._aged(transport, 50.0)
        transport._process_frame(_MAGIC + _FRAME.pack(0, 0, 0, FLAG_ACK_ONLY, 0))
        assert transport._link._last_recv_time > silent

    def test_a_fin_is_not_an_arrival_it_is_the_end(self):
        """A FIN used to be counted as an arrival like an ACK — it *refreshed*
        the liveness it announces the end of. See `TestAFinEndsTheLink`."""
        transport = self._transport()
        transport._process_frame(_MAGIC + _FRAME.pack(0, 0, 0, FLAG_KEEPALIVE, 0))
        silent = self._aged(transport, 50.0)
        transport._process_frame(_MAGIC + _FRAME.pack(0, 0, 0, FLAG_FIN, 0))
        assert transport._link._last_recv_time == silent
        assert transport.is_closed()

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


# ---------------------------------------------------------------------------
# A burst must not collapse the link
# ---------------------------------------------------------------------------
# Sixteen 16 kB packets in flight took a loopback link from ~100 MB/s to 4 MB/s
# and 80 % of a speed test lost; thirty-two took 83 seconds to move 20 MB. Three
# causes, each held below: the retransmit timer doubled once per *frame* lost,
# nothing limited what was put on the wire, and a frame past the unacked window
# was sent without being tracked — so a lost one was never resent.

def _seq_of(frame: bytes) -> int:
    return struct.unpack("!I", frame[len(_MAGIC):len(_MAGIC) + 4])[0]


def _expire_all(link: _ReliableLink) -> None:
    for entry in link._unacked.values():
        entry.deadline = 0.0


class TestABurstDoesNotCollapseTheLink:
    def test_the_timer_backs_off_once_per_timeout_not_once_per_frame(self):
        """Doubling for every frame of a lost burst pinned the timeout at its
        two-second ceiling in one pass; every frame after it waited that long."""
        link = _ReliableLink()
        for _ in range(16):
            link.build_frame(make_packet(b"x" * 1000))
        before = link._rto
        _expire_all(link)
        resent = link.get_retransmit_frames()
        assert resent
        assert link._rto <= before * 2 + 1e-9

    def test_a_frame_is_never_sent_untracked(self):
        """Past `_MAX_UNACKED` the old link sent the frame and forgot it: lost
        once, it was never resent, and the receiver waited for it for ever."""
        link = _ReliableLink()
        link._cwnd = float(10 ** 9)          # only the frame bound is in play
        for _ in range(_MAX_UNACKED):
            assert link.can_send(100)
            link.build_frame(make_packet(b"y"))
        assert not link.can_send(100)
        assert link.unacked_count() == _MAX_UNACKED

    def test_the_window_bounds_what_is_in_flight(self):
        link = _ReliableLink()
        sent = 0
        while link.can_send(16_000):
            link.build_frame(make_packet(b"z" * 16_000))
            sent += 1
        assert 1 <= sent <= _MAX_UNACKED
        assert link._inflight <= max(link._cwnd, 16_100)

    def test_a_large_frame_still_goes_when_nothing_is_in_flight(self):
        link = _ReliableLink()
        link._cwnd = 1.0
        assert link.can_send(60_000)

    def test_a_burst_lost_together_halves_the_window_once(self):
        """Twenty frames lost to one queue overflowing are one event."""
        link = _ReliableLink()
        link._cwnd = 1024 * 1024.0
        frames = [link.build_frame(make_packet(b"w" * 1000)) for _ in range(20)]
        for frame in frames:
            link._loss(_seq_of(frame), timeout=False)
        assert link._cwnd == 512 * 1024.0
        # A loss among frames sent *after* the reduction is a new event.
        later = link.build_frame(make_packet(b"v"))
        link._loss(_seq_of(later), timeout=False)
        assert link._cwnd == 256 * 1024.0

    def test_acknowledged_data_grows_the_window_and_measures_the_link(self):
        link = _ReliableLink()
        start = link._cwnd
        frame = link.build_frame(make_packet(b"u" * 4000))
        link.process_ack(_seq_of(frame), 0)
        assert link._cwnd > start
        assert link._srtt is not None
        assert link._inflight == 0

    def test_a_resent_frame_is_never_timed(self):
        """Karn: an ACK for a retransmitted frame cannot say which copy it
        answers, so its round trip would be a guess."""
        link = _ReliableLink()
        frame = link.build_frame(make_packet(b"t"))
        _expire_all(link)
        link.get_retransmit_frames()
        link.process_ack(_seq_of(frame), 0)
        assert link._srtt is None

    def test_three_frames_past_a_hole_resend_it_at_once(self):
        link = _ReliableLink()
        frames = [link.build_frame(make_packet(b"s" * 100)) for _ in range(5)]
        hole = _seq_of(frames[0])
        ack = (hole - 1) & 0xFFFFFFFF
        # Frames hole+1..hole+3 arrived: bits 1, 2, 3 above the cumulative ack.
        resend = link.process_ack(ack, 0b1110)
        assert resend == [frames[0]]
        # Once: the same SACK again does not resend it a second time.
        assert link.process_ack(ack, 0b1110) == []

    def test_a_single_out_of_order_frame_is_not_a_loss(self):
        link = _ReliableLink()
        frames = [link.build_frame(make_packet(b"r")) for _ in range(3)]
        ack = (_seq_of(frames[0]) - 1) & 0xFFFFFFFF
        assert link.process_ack(ack, 0b10) == []

    async def test_a_reader_that_is_behind_refuses_rather_than_drops(self):
        """Taking a frame, acknowledging it, then dropping it because the queue
        was full lost a packet on a link that promises not to. Refused before
        the ACK, it stays with the sender and comes back."""
        transport = UDPTransport()
        transport._remote = ("127.0.0.1", 9)
        big = make_packet(b"q" * 59_000).pack()
        seq = 0
        while transport._decoded_bytes + len(big) <= _MAX_DECODED_BYTES:
            transport._process_frame(
                _MAGIC + _FRAME.pack(seq, 0, 0, FLAG_DATA, len(big)) + big)
            seq += 1
        cursor = transport._link._recv_next
        transport._process_frame(
            _MAGIC + _FRAME.pack(seq, 0, 0, FLAG_DATA, len(big)) + big)
        assert transport._link._recv_next == cursor     # not acknowledged
        await transport.receive()                       # the reader catches up
        transport._process_frame(
            _MAGIC + _FRAME.pack(seq, 0, 0, FLAG_DATA, len(big)) + big)
        assert transport._link._recv_next == (cursor + 1) & 0xFFFFFFFF

    async def test_a_burst_crosses_loopback_intact_and_quickly(self, udp_pair):
        """The measurement that found it: sixty-four 16 kB packets at once,
        echoed back. Before, thirty-two of them took 83 seconds."""
        _server, srv, client = udp_pair
        assert srv is not None

        async def echo():
            while True:
                await srv.send(await srv.receive())

        task = asyncio.create_task(echo())
        try:
            loop = asyncio.get_running_loop()
            started = loop.time()
            for _ in range(3):
                sent = [make_packet(bytes([i]) * 16_000) for i in range(64)]
                for packet in sent:
                    await client.send(packet)
                for packet in sent:
                    got = await asyncio.wait_for(client.receive(), 10)
                    assert got.payload == packet.payload
            assert loop.time() - started < 10
        finally:
            task.cancel()

    async def test_a_full_queue_waits_for_room_instead_of_failing(self):
        """A full queue is a busy link, not a broken one: refusing the packet
        turned every burst into an error at the caller."""
        transport = UDPTransport()
        transport._remote = ("127.0.0.1", 9)
        transport._sock = object()          # "connected", with no send loop
        for _ in range(_MAX_SEND_QUEUE):
            await transport.send(make_packet(b"p"))
        pending = asyncio.create_task(transport.send(make_packet(b"p")))
        await asyncio.sleep(0.05)
        assert not pending.done()
        transport._link._send_queue.get_nowait()        # room appears
        await asyncio.wait_for(pending, 1)


class TestATimeoutOnALatePathIsFoundOut:
    """A path that grew slower than the timer used to be resent whole on every
    timeout, so no frame could be timed (Karn), the estimate stayed on the idle
    round trip, and the timer backed off to its ceiling: a live link read 30 ms
    measured and waited 1.6 s, right after a speed test had filled it."""

    @staticmethod
    def _window(n: int = 5, cwnd: float = 512 * 1024.0):
        link = _ReliableLink()
        link._cwnd = cwnd
        frames = [link.build_frame(make_packet(b"f" * 1000)) for _ in range(n)]
        _expire_all(link)
        return link, frames

    def test_a_timeout_resends_the_oldest_frame_alone(self):
        link, frames = self._window()
        assert link.get_retransmit_frames() == [frames[0]]
        assert link.timeouts == 1

    def test_originals_arriving_late_undo_the_cut_and_measure_the_path(self):
        link, frames = self._window()
        link.get_retransmit_frames()
        assert link._cwnd < 512 * 1024.0
        link.process_ack(_seq_of(frames[0]), 0)
        link.process_ack(_seq_of(frames[1]), 0)
        assert link.spurious == 1
        assert link._cwnd >= 512 * 1024.0
        # frames[1] went out once, so its round trip counts and the timer
        # comes back off its backoff.
        assert link._srtt is not None
        assert link._backoff == 1

    def test_a_duplicate_ack_is_a_real_loss_and_the_rest_goes_without_backing_off(self):
        link, frames = self._window()
        link.get_retransmit_frames()
        hole = (_seq_of(frames[0]) - 1) & 0xFFFFFFFF
        link.process_ack(hole, 0b10)          # frames[1] arrived, frames[0] did not
        assert link.spurious == 0
        resent = link.get_retransmit_frames()
        assert frames[2] in resent and frames[3] in resent
        assert link.timeouts == 1             # the same loss, not a new one

    def test_frames_held_back_by_a_timeout_do_not_back_the_timer_off(self):
        """The frames a window too small to resend at once held back came due
        a round later and doubled the timer each time, until it sat at its
        ceiling."""
        link, frames = self._window(n=20, cwnd=64 * 1024.0)
        link.get_retransmit_frames()
        backoff = link._backoff
        link.process_ack((_seq_of(frames[0]) - 1) & 0xFFFFFFFF, 0b10)
        for _ in range(4):
            for entry in link._unacked.values():
                if not entry.resent:
                    entry.deadline = 0.0
            link.get_retransmit_frames()
        assert link.timeouts == 1
        assert link._backoff <= backoff

    def test_a_lost_resend_backs_off_again(self):
        link, frames = self._window()
        link.get_retransmit_frames()
        rto = link._rto
        _expire_all(link)
        assert frames[0] in link.get_retransmit_frames()
        assert link.timeouts == 2
        assert link._rto > rto
        assert link._frto == 0

    def test_a_window_that_empties_keeps_the_backoff_until_a_measurement(self):
        """Emptying the window put the timer back on the estimate that had just
        fired too early, without anything having been measured."""
        link, frames = self._window(n=1)
        link.get_retransmit_frames()
        backed_off = link._rto
        link.process_ack(_seq_of(frames[0]), 0)
        assert not link._unacked
        assert link._rto == backed_off
        fresh = link.build_frame(make_packet(b"g"))
        link.process_ack(_seq_of(fresh), 0)
        assert link._backoff == 1


class TestTheTwoHalvesAgreeOnTheSack:
    """Each half was tested alone, against its own idea of what bit ``i`` names,
    and the two ideas were one apart: the receiver set bit ``i`` for
    ``ack + 2 + i`` and the sender read ``ack + 1 + i``. A lost frame followed
    by any other was therefore retired by the sender as delivered, never resent,
    and the receiver's cursor waited on it for ever — a live link carrying
    nothing, reorder buffer full, until the mesh probes cut it."""

    @staticmethod
    def _pair():
        sender, receiver = _ReliableLink(), _ReliableLink()
        receiver.process_incoming(sender._send_seq, FLAG_KEEPALIVE, b"")
        return sender, receiver

    @staticmethod
    def _deliver(receiver, frame):
        seq, _ack, _sack, flags, length = _FRAME.unpack_from(frame, len(_MAGIC))
        return receiver.process_incoming(
            seq, flags, frame[len(_MAGIC) + _FRAME.size:])

    def test_a_lost_frame_stays_with_the_sender(self):
        sender, receiver = self._pair()
        frames = [sender.build_frame(make_packet(bytes([i]) * 50))
                  for i in range(5)]
        for frame in frames[1:]:
            assert self._deliver(receiver, frame) == []
        sender.process_ack(*receiver._build_ack())
        assert list(sender._unacked) == [_seq_of(frames[0])]

    def test_the_hole_is_resent_and_the_link_moves_on(self):
        sender, receiver = self._pair()
        frames = [sender.build_frame(make_packet(bytes([i]) * 50))
                  for i in range(5)]
        for frame in frames[1:]:
            self._deliver(receiver, frame)
        resend = sender.process_ack(*receiver._build_ack())
        assert resend == [frames[0]]
        delivered = self._deliver(receiver, resend[0])
        assert [Packet.unpack(raw).payload[0] for raw in delivered] == [0, 1, 2, 3, 4]
        sender.process_ack(*receiver._build_ack())
        assert not sender._unacked

    def test_the_bit_for_the_hole_is_never_set(self):
        sender, receiver = self._pair()
        frames = [sender.build_frame(make_packet(b"p")) for _ in range(40)]
        for frame in frames[1:]:
            self._deliver(receiver, frame)
        _ack, sack = receiver._build_ack()
        assert not sack & 1
        assert sack == 0xFFFFFFFE      # ack+2 .. ack+32, the most 32 bits hold
        sender.process_ack(*receiver._build_ack())
        assert _seq_of(frames[0]) in sender._unacked

    def test_a_lossy_exchange_delivers_everything_in_order(self):
        """Every third frame lost on its first crossing, both directions of the
        exchange driven by the real code: nothing may be lost or stall."""
        sender, receiver = self._pair()
        got: list[int] = []
        sent = 0
        for _round in range(200):
            while sent < 120 and sender.can_send(200):
                frame = sender.build_frame(make_packet(sent.to_bytes(2, "big")))
                if sent % 3 != 1:
                    got.extend(int.from_bytes(Packet.unpack(raw).payload[:2], "big")
                               for raw in self._deliver(receiver, frame))
                sent += 1
            for frame in sender.process_ack(*receiver._build_ack()):
                got.extend(int.from_bytes(Packet.unpack(raw).payload[:2], "big")
                           for raw in self._deliver(receiver, frame))
            _expire_all(sender)
            for frame in sender.get_retransmit_frames():
                got.extend(int.from_bytes(Packet.unpack(raw).payload[:2], "big")
                           for raw in self._deliver(receiver, frame))
            if sent == 120 and not sender._unacked:
                break
        assert got == list(range(120))
        assert not receiver._reorder

    async def test_a_frame_lost_on_the_wire_still_arrives(self, udp_pair):
        """The same over real sockets: the first data frame of a run is dropped
        on its way out, the rest cross. Before, the run never arrived at all."""
        _server, srv, client = udp_pair
        assert srv is not None
        real_send, dropped = client._send_raw, []

        def lossy(frame):
            flags = _FRAME.unpack_from(frame, len(_MAGIC))[3]
            if flags & FLAG_DATA and not dropped:
                dropped.append(frame)
                return
            real_send(frame)

        client._send_raw = lossy
        packets = [make_packet(f"lost{i}".encode()) for i in range(10)]
        for packet in packets:
            await client.send(packet)
        for packet in packets:
            received = await asyncio.wait_for(srv.receive(), timeout=5.0)
            assert received.pack() == packet.pack()
        assert dropped


# ---------------------------------------------------------------------------
# A packet larger than a datagram should be is split, and put back together
# ---------------------------------------------------------------------------
# One frame per packet made a 16 kB speed-test probe a dozen IP fragments, and
# losing any of them lost the frame: through a VPN, 16 kB pings lost 62 % where
# 1.1 kB pings lost 6 % (BUGSVULNS 63).

def _flags(frame: bytes) -> int:
    return _FRAME.unpack_from(frame, len(_MAGIC))[3]


class TestAPacketIsSplitUnderTheDatagramSize:
    @staticmethod
    def _pair():
        sender, receiver = _ReliableLink(), _ReliableLink()
        receiver.process_incoming(sender._send_seq, FLAG_KEEPALIVE, b"")
        sender.peer_reassembles = True
        return sender, receiver

    @staticmethod
    def _frames(sender, packet):
        pieces = sender.segments(packet.pack())
        return [sender.build_segment(piece, more=i < len(pieces) - 1)
                for i, piece in enumerate(pieces)]

    @staticmethod
    def _deliver(receiver, frame):
        seq, _ack, _sack, flags, _length = _FRAME.unpack_from(frame, len(_MAGIC))
        return receiver.process_incoming(
            seq, flags, frame[len(_MAGIC) + _FRAME.size:])

    def test_every_frame_fits_the_datagram_size(self):
        sender, _receiver = self._pair()
        frames = self._frames(sender, make_packet(b"x" * 16_000))
        assert len(frames) > 1
        assert all(len(frame) <= _SEGMENT for frame in frames)
        assert [bool(_flags(f) & FLAG_MORE) for f in frames] == \
            [True] * (len(frames) - 1) + [False]

    def test_a_far_end_that_never_said_it_reassembles_gets_whole_packets(self):
        """An old node delivers each frame as a packet: a segment would be an
        undecodable packet there, and the link would carry nothing."""
        sender, _receiver = self._pair()
        sender.peer_reassembles = False
        frames = self._frames(sender, make_packet(b"x" * 16_000))
        assert len(frames) == 1
        assert not _flags(frames[0]) & FLAG_MORE

    def test_a_small_packet_is_one_frame(self):
        sender, _receiver = self._pair()
        frames = self._frames(sender, make_packet(b"x" * 100))
        assert len(frames) == 1 and not _flags(frames[0]) & FLAG_MORE

    def test_the_segments_make_the_packet_again(self):
        sender, receiver = self._pair()
        packet = make_packet(bytes(range(256)) * 60)
        delivered = []
        for frame in self._frames(sender, packet):
            delivered.extend(self._deliver(receiver, frame))
        assert delivered == [packet.pack()]

    def test_segments_out_of_order_still_make_the_packet(self):
        sender, receiver = self._pair()
        packet = make_packet(bytes(range(256)) * 60)
        frames = self._frames(sender, packet)
        for frame in reversed(frames[1:]):
            assert self._deliver(receiver, frame) == []
        assert self._deliver(receiver, frames[0]) == [packet.pack()]

    def test_a_lost_segment_is_resent_and_the_packets_arrive_in_order(self):
        sender, receiver = self._pair()
        packets = [make_packet(bytes([i]) * 5_000) for i in range(6)]
        frames = [f for p in packets for f in self._frames(sender, p)]
        delivered = []
        for i, frame in enumerate(frames):
            if i != 2:
                delivered.extend(self._deliver(receiver, frame))
        for frame in sender.process_ack(*receiver._build_ack()):
            delivered.extend(self._deliver(receiver, frame))
        _expire_all(sender)
        for frame in sender.get_retransmit_frames():
            delivered.extend(self._deliver(receiver, frame))
        assert delivered == [p.pack() for p in packets]

    def test_a_packet_that_never_ends_is_dropped_and_the_next_one_arrives(self):
        """A far end can flag every frame as one more segment. What it builds is
        bounded by one packet, and the frames after the lie are untouched."""
        _sender, receiver = self._pair()
        seq = receiver._recv_next
        chunk = b"z" * 1000
        for _ in range((HEADER_SIZE + _MAX_PAYLOAD) // 1000 + 5):
            assert receiver.process_incoming(seq, FLAG_DATA | FLAG_MORE, chunk) == []
            assert receiver._partial_bytes <= HEADER_SIZE + _MAX_PAYLOAD
            seq = (seq + 1) & 0xFFFFFFFF
        assert receiver.process_incoming(seq, FLAG_DATA, b"end") == []
        assert receiver._partial_bytes == 0
        seq = (seq + 1) & 0xFFFFFFFF
        assert receiver.process_incoming(seq, FLAG_DATA, b"next") == [b"next"]

    def test_every_frame_says_this_side_reassembles(self):
        link = _ReliableLink()
        for frame in (link.build_keepalive(), link.build_ack_only(),
                      link.build_fin(), link.build_frame(make_packet())):
            assert _flags(frame) & FLAG_SEGMENTS

    def test_the_far_end_is_believed_only_inside_its_window(self):
        """The header is not authenticated: a spoofed bit would have this side
        segment to a node that cannot put the pieces back."""
        link = _opened_link()
        link.note_segments(0x4000_0000, FLAG_KEEPALIVE | FLAG_SEGMENTS)
        assert not link.peer_reassembles
        link.note_segments(link._recv_next, FLAG_KEEPALIVE)
        assert not link.peer_reassembles
        link.note_segments(link._recv_next, FLAG_KEEPALIVE | FLAG_SEGMENTS)
        assert link.peer_reassembles

    async def test_over_loopback_both_ends_segment_and_nothing_is_lost(self, udp_pair):
        _server, srv, client = udp_pair
        assert srv is not None
        sizes: list[int] = []
        real_send = client._send_raw

        def record(frame):
            sizes.append(len(frame))
            real_send(frame)

        client._send_raw = record
        assert client._link.peer_reassembles and srv._link.peer_reassembles
        packets = [make_packet(bytes([i]) * 16_000) for i in range(20)]
        for packet in packets:
            await client.send(packet)
        for packet in packets:
            got = await asyncio.wait_for(srv.receive(), 10)
            assert got.payload == packet.payload
        assert sizes and max(sizes) <= _SEGMENT

    async def test_an_old_far_end_still_gets_whole_packets(self, udp_pair):
        """Mixed versions: frames from a node that predates segments carry no
        FLAG_SEGMENTS, so nothing is ever split towards it."""
        _server, srv, client = udp_pair
        assert srv is not None
        client._link.peer_reassembles = False
        real_note = client._link.note_segments
        client._link.note_segments = lambda seq, flags: real_note(
            seq, flags & ~FLAG_SEGMENTS)
        packet = make_packet(b"w" * 16_000)
        await client.send(packet)
        got = await asyncio.wait_for(srv.receive(), 10)
        assert got.payload == packet.payload
        assert not client._link.peer_reassembles
