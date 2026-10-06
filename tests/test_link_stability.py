"""
Links that came and went under load, and the log that could not say why.

A node working over the internet saw its links drop again and again, UDP worst
of all and worse the more it carried. Its log said "link dropped", an id and an
address — nothing else — and its trace showed one link answering nothing for a
quarter of a minute, then ten seconds in which no probe left for *any* peer.
Four defects lined up behind that, and each is held here:

* **A FIN refreshed the link it ended.** The UDP layer counted a FIN as an
  arrival, like a keepalive, so the side that missed a close kept a zombie: its
  frames were acknowledged and kept alive by a fresh transport on the far side,
  which dropped every packet as unauthenticated.
* **Full was read as gone.** A UDP queue that stayed full raised the same
  `ConnectionError` as a dead link, and the routing path tore the link down —
  under load, which is exactly when a queue is full.
* **A TCP send could wait for ever**, and the keepalive loop sends one probe
  after another: one peer not reading stopped every probe on every link.
* **The log said nothing**, and the trace could not tell two links to one node
  apart. Both now name the link (``L17/udp``) and the log says why it ended.
"""
import asyncio
import base64
import json
import socket
import time

import pytest

from src import logbook
from src.mesh import peers as peers_mod
from src.node import MeshNode, _Peer, PING
from src.node_id import NodeID
from src.packet import Packet
from src.trace import Trace
from src.transports import tcp as tcp_mod
from src.transports import udp as udp_mod
from src.transports.contract import LinkBusy
from src.transports.tcp import TCPServer, TCPTransport
from src.transports.udp import (
    FLAG_ACK_ONLY, FLAG_DATA, FLAG_FIN, FLAG_KEEPALIVE, UDPServer, UDPTransport,
    _FRAME, _MAGIC, _MAX_SEND_QUEUE,
)
from tests.conftest import FakeTransport, make_manager

TARGET = NodeID(b"\x22" * 20)
OTHER = NodeID(b"\x33" * 20)


def _packet(payload: bytes = b"x") -> Packet:
    return Packet(version=1, type=0x01, ttl=64, src_id=bytes(20),
                  dst_id=bytes(range(20)), msg_id=0, nonce=bytes(12),
                  gcm_tag=bytes(16), payload=payload)


def _frame(seq: int, flags: int, payload: bytes = b"") -> bytes:
    return _MAGIC + _FRAME.pack(seq, 0, 0, flags, len(payload)) + payload


def _udp(cursor: int = 1000) -> UDPTransport:
    """A transport whose peer's cursor is known, as after `connect()`'s first
    keepalive."""
    transport = UDPTransport()
    transport._remote = ("127.0.0.1", 9)
    transport._process_frame(_frame(cursor, FLAG_KEEPALIVE))
    return transport


class _Capture:
    def __init__(self) -> None:
        self.sent: list = []

    def sendto(self, data, addr) -> None:
        self.sent.append((bytes(data), addr))

    def get_extra_info(self, *a, **k):
        return None

    def close(self) -> None: ...


# ---------------------------------------------------------------------------
# UDP: a FIN ends the link, and only a FIN the peer could have sent
# ---------------------------------------------------------------------------

class TestAFinEndsTheLink:

    async def test_a_fin_inside_the_window_closes_the_link(self):
        transport = _udp(cursor=1000)
        transport._process_frame(_frame(1000, FLAG_FIN))
        assert transport.is_closed()
        assert "closed the link" in transport.end_reason()
        with pytest.raises(ConnectionError, match="closed the link"):
            await asyncio.wait_for(transport.receive(), timeout=1.0)

    async def test_a_fin_with_frames_still_in_flight_is_believed(self):
        """The sender's FIN carries its *next* sequence; frames it sent before
        may still be on the way, so the FIN sits that far ahead of our cursor."""
        transport = _udp(cursor=1000)
        transport._process_frame(_frame(1000 + 40, FLAG_FIN))
        assert transport.is_closed()

    async def test_a_spoofed_fin_outside_the_window_changes_nothing(self):
        """The header is not authenticated: a FIN is believed on the evidence a
        data frame is, the peer's random cursor. One outside it is somebody
        guessing — the link stays, and it earns no liveness either."""
        transport = _udp(cursor=1000)
        transport._link._last_recv_time -= 30.0
        quiet = transport._link._last_recv_time
        for seq in (0, 999, 1000 + udp_mod._MAX_UNACKED, 0x80000000):
            transport._process_frame(_frame(seq, FLAG_FIN))
        assert not transport.is_closed()
        assert transport._link._last_recv_time == quiet

    async def test_a_fin_before_any_frame_is_ignored(self):
        transport = UDPTransport()
        transport._remote = ("127.0.0.1", 9)
        transport._process_frame(_frame(5, FLAG_FIN))
        assert not transport.is_closed()

    async def test_a_link_closed_on_one_side_ends_on_the_other(self):
        """End to end over loopback: closing the server's half reaches the
        client as a FIN, and the client's receive loop ends with the reason."""
        server = UDPServer()
        accepted: list = []
        ready = asyncio.Event()

        async def on_new(transport):
            accepted.append(transport)
            ready.set()

        server.on_new_connection = on_new
        await server.listen("127.0.0.1:0")
        port = server._sock.get_extra_info("socket").getsockname()[1]
        client = UDPTransport()
        await client.connect(f"127.0.0.1:{port}")
        await asyncio.wait_for(ready.wait(), timeout=2.0)
        await client.send(_packet(b"hello"))
        await asyncio.wait_for(accepted[0].receive(), timeout=2.0)
        await accepted[0].close()
        with pytest.raises(ConnectionError, match="closed the link"):
            await asyncio.wait_for(client.receive(), timeout=2.0)
        assert client.is_closed()
        await client.close()
        await server.close()


class TestAClosedLinkIsNotReopenedByItsOwnFrames:
    """The frames of a far end that missed our FIN used to open a brand-new
    transport here, which acknowledged them and kept them alive while the node
    dropped every packet on it. Both ends then held a link carrying nothing."""

    def _server_with_closed_link(self):
        server = UDPServer()
        server._sock = _Capture()
        opened: list = []

        async def on_new(transport):
            opened.append(transport)

        server.on_new_connection = on_new
        transport = UDPTransport._from_server(server._sock, ("10.0.0.5", 4000),
                                              server)
        transport._process_frame(_frame(500, FLAG_KEEPALIVE))
        server._transports[("10.0.0.5", 4000)] = transport
        return server, transport, opened

    async def test_a_frame_from_the_closed_link_is_answered_with_a_fin(self):
        server, transport, opened = self._server_with_closed_link()
        await transport.close()
        server._sock.sent.clear()
        server._dispatch_datagram(_frame(501, FLAG_DATA, b"late"),
                                  ("10.0.0.5", 4000))
        await asyncio.sleep(0)
        assert opened == []
        assert ("10.0.0.5", 4000) not in server._transports
        fins = [data for data, _ in server._sock.sent
                if _FRAME.unpack_from(data, len(_MAGIC))[3] & FLAG_FIN]
        assert len(fins) == 1

    async def test_the_fin_it_answers_with_is_one_the_far_end_believes(self):
        """The answer has to land inside the zombie's window, or it is one more
        datagram the zombie ignores."""
        server, transport, _opened = self._server_with_closed_link()
        zombie = _udp(cursor=transport._link._send_seq)
        await transport.close()
        server._sock.sent.clear()
        server._dispatch_datagram(_frame(501, FLAG_KEEPALIVE), ("10.0.0.5", 4000))
        fin = server._sock.sent[-1][0]
        zombie._process_frame(fin)
        assert zombie.is_closed()

    async def test_the_answer_is_rate_limited(self):
        """A datagram answering a datagram must never be a way to make this
        node send more than it is sent."""
        server, transport, _opened = self._server_with_closed_link()
        await transport.close()
        server._sock.sent.clear()
        for _ in range(20):
            server._dispatch_datagram(_frame(502, FLAG_ACK_ONLY),
                                      ("10.0.0.5", 4000))
        assert len(server._sock.sent) == 1

    async def test_a_genuinely_new_dial_from_the_same_port_is_accepted(self):
        """A new dial starts from a fresh random cursor, nowhere near ours."""
        server, transport, opened = self._server_with_closed_link()
        await transport.close()
        server._dispatch_datagram(_frame(0x7000_0000, FLAG_KEEPALIVE),
                                  ("10.0.0.5", 4000))
        await asyncio.sleep(0)
        assert len(opened) == 1

    async def test_a_fin_from_a_stranger_opens_nothing(self):
        server = UDPServer()
        server._sock = _Capture()
        opened: list = []

        async def on_new(transport):
            opened.append(transport)

        server.on_new_connection = on_new
        server._dispatch_datagram(_frame(1, FLAG_FIN), ("10.0.0.7", 5000))
        await asyncio.sleep(0)
        assert opened == [] and server._transports == {}
        assert server._sock.sent == []

    async def test_the_memory_is_bounded(self):
        server = UDPServer()
        server._sock = _Capture()
        for port in range(udp_mod._CLOSED_TRACKED * 2):
            server.remember_closed(("10.0.0.9", port), udp_mod._ReliableLink())
        assert len(server._closed_links) <= udp_mod._CLOSED_TRACKED


# ---------------------------------------------------------------------------
# Full is not gone
# ---------------------------------------------------------------------------

class TestFullIsNotGone:

    async def test_a_full_udp_queue_raises_link_busy(self, monkeypatch):
        monkeypatch.setattr(udp_mod, "_SEND_WAIT", 0.05)
        transport = UDPTransport()
        transport._remote = ("127.0.0.1", 9)
        transport._sock = _Capture()
        for _ in range(_MAX_SEND_QUEUE):
            assert transport._link.enqueue(_packet())
        with pytest.raises(LinkBusy):
            await transport.send(_packet())
        assert not transport.is_closed()

    async def test_link_busy_is_not_a_connection_error(self):
        """Every place that reads `ConnectionError` as "the link is dead" must
        not read this one that way."""
        assert not issubclass(LinkBusy, ConnectionError)
        assert not issubclass(LinkBusy, OSError)

    async def test_a_busy_link_is_not_dropped_by_routing(self):
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        busy, spare = _authed(node, TARGET), _authed(node, OTHER)

        async def full(packet):
            raise LinkBusy("full")

        busy.transport.send = full
        chosen = await node._send_to_candidates(_packet(), [busy, spare])
        assert chosen is spare
        assert busy in node._peers
        await node.stop()

    async def test_a_dead_link_is_still_dropped_and_says_why(self):
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        node.logs.hold()
        dead = _authed(node, TARGET)

        async def gone(packet):
            raise ConnectionError("reset")

        dead.transport.send = gone
        await node._send_to_candidates(_packet(), [dead])
        assert dead not in node._peers
        lines = _lines(node, "link dropped")
        assert lines and "send failed" in lines[0]["fields"]["reason"]
        await node.stop()


class TestATcpSendIsBounded:

    async def test_a_peer_that_never_reads_gets_link_busy_not_a_hang(
            self, monkeypatch):
        monkeypatch.setattr(tcp_mod, "_SEND_WAIT", 0.2)
        accepted = asyncio.Event()

        async def stall(reader, writer):          # accepts, never reads
            accepted.set()
            await asyncio.sleep(30)

        listener = await asyncio.start_server(stall, "127.0.0.1", 0)
        port = listener.sockets[0].getsockname()[1]
        transport = TCPTransport()
        await transport.connect(f"127.0.0.1:{port}")
        await asyncio.wait_for(accepted.wait(), timeout=2.0)
        sock = transport._writer.get_extra_info("socket")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        big = _packet(b"y" * 50_000)
        started = time.monotonic()
        with pytest.raises(LinkBusy):
            async with asyncio.timeout(20):
                while True:
                    await transport.send(big)
        assert time.monotonic() - started < 20
        # Room was waited for *before* the write: what is buffered is whole
        # frames, never half of one.
        assert transport._writer.transport.get_write_buffer_size() <= (
            transport._high() + 2 + len(big.pack()))
        await transport.close()
        listener.close()

    @pytest.mark.skipif(not hasattr(socket, "TCP_NOTSENT_LOWAT"),
                        reason="the system has no unsent-data limit")
    async def test_the_kernel_holds_little_unsent_data(self):
        """Left alone, Linux holds up to 4 MB unsent per socket, and a probe
        queued behind that waits seconds on a slow uplink — past the deadline
        that calls it lost, on a link that lost nothing."""
        async def idle(reader, writer):
            await asyncio.sleep(5)

        listener = await asyncio.start_server(idle, "127.0.0.1", 0)
        port = listener.sockets[0].getsockname()[1]
        transport = TCPTransport()
        await transport.connect(f"127.0.0.1:{port}")
        sock = transport._writer.get_extra_info("socket")
        assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NOTSENT_LOWAT) == (
            TCPTransport.setting("unsent_limit") * 1024)
        if hasattr(socket, "TCP_INFO"):
            assert "kernel retransmits" in transport.stats()
        await transport.close()
        listener.close()

    async def test_a_tcp_link_says_how_it_ended(self):
        server = TCPServer()
        accepted: list = []
        ready = asyncio.Event()

        async def on_new(transport):
            accepted.append(transport)
            ready.set()

        server.on_new_connection = on_new
        await server.listen("127.0.0.1:0")
        port = server._server.sockets[0].getsockname()[1]
        client = TCPTransport()
        await client.connect(f"127.0.0.1:{port}")
        await asyncio.wait_for(ready.wait(), timeout=2.0)
        await accepted[0].close()
        with pytest.raises(ConnectionError):
            await asyncio.wait_for(client.receive(), timeout=2.0)
        assert client.end_reason() == "the peer closed the connection"
        await client.close()
        await server.close()

    async def test_a_read_timeout_says_so(self, monkeypatch):
        monkeypatch.setitem(TCPTransport.SETTINGS, "read_timeout", 0.1)

        async def silent(reader, writer):        # holds the line, says nothing
            await asyncio.sleep(30)

        listener = await asyncio.start_server(silent, "127.0.0.1", 0)
        port = listener.sockets[0].getsockname()[1]
        client = TCPTransport()
        await client.connect(f"127.0.0.1:{port}")
        with pytest.raises(ConnectionError, match="read timeout"):
            await client.receive()
        assert "nothing received" in client.end_reason()
        await client.close()
        listener.close()


# ---------------------------------------------------------------------------
# One busy link must not stop the probes of every other
# ---------------------------------------------------------------------------

class _Stuck(FakeTransport):
    """A medium whose send never returns — a peer that stopped reading."""

    async def send(self, packet):
        await asyncio.sleep(3600)


class TestAProbeIsBounded:

    async def test_a_stuck_link_does_not_hold_the_others(self, monkeypatch):
        from src import node as node_mod
        monkeypatch.setattr(node_mod, "_KA_SEND_WAIT", 0.05)
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        stuck = _authed(node, TARGET, transport=_Stuck())
        healthy = _authed(node, OTHER)
        now = time.monotonic()
        stuck.ka_due = healthy.ka_due = now - 1.0
        loop = asyncio.create_task(node._link_keepalive_loop())
        try:
            async with asyncio.timeout(5):
                while not any(p.type == PING for p in healthy.transport.sent):
                    await asyncio.sleep(0.01)
        finally:
            node._running = False
            loop.cancel()
            await asyncio.gather(loop, return_exceptions=True)
        assert stuck.ka_due > now      # rescheduled, not left due for ever
        await node.stop()


# ---------------------------------------------------------------------------
# The log says which link, and why
# ---------------------------------------------------------------------------

def _authed(node: MeshNode, target: NodeID, *, transport=None) -> _Peer:
    peer = node._new_peer(transport or FakeTransport(), is_client_side=True)
    peer.authenticated_id = target
    peer.session = object()
    peer.remote_addr = "fake://a:1"
    node._peers.append(peer)
    return peer


def _lines(node: MeshNode, message: str) -> list:
    return [line for line in node.logs.query(limit=500)["lines"]
            if line["message"] == message]


class TestTheLogSaysWhy:

    async def test_every_link_has_a_name_and_it_never_repeats(self):
        first, second = _Peer(FakeTransport()), _Peer(FakeTransport())
        assert first.label != second.label
        assert first.label.startswith("L")

    async def test_a_link_that_died_on_its_own_says_how(self):
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        node.logs.hold()

        class Ends(FakeTransport):
            async def receive(self):
                raise ConnectionError("x")

            def end_reason(self):
                return "the peer closed the connection"

        peer = _authed(node, TARGET, transport=Ends())
        await peer.start(node._handle_packet)
        await asyncio.wait_for(peer._task, timeout=2.0)
        await asyncio.sleep(0)
        line = _lines(node, "link dropped")[0]
        assert line["level"] == logbook.WARN
        assert line["fields"]["reason"] == "the peer closed the connection"
        assert line["fields"]["link"] == peer.label
        assert "quiet_s" in line["fields"]
        await node.stop()

    async def test_a_link_we_cut_says_who_cut_it(self):
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        node.logs.hold()
        peer = _authed(node, TARGET)
        peer.quality.since_pong = 10
        peer.quality.answered_at -= 600.0
        node._reap_silent_links()
        await asyncio.sleep(0.05)
        line = _lines(node, "link dropped")[0]
        assert line["level"] == logbook.INFO
        assert line["fields"]["reason"].startswith("cut: 10 probes unanswered")
        await node.stop()

    async def test_one_link_one_line(self):
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        node.logs.hold()
        peer = _authed(node, TARGET)
        await node._safe_stop_peer(peer, "first")
        await node._reap_peer(peer, "second")
        assert len(_lines(node, "link dropped")) == 1
        await node.stop()

    async def test_nothing_is_built_while_nobody_keeps_a_log(self):
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        peer = _authed(node, TARGET)
        node._log_link_end(peer, "ignored")
        assert not peer.end_logged
        await node.stop()

    async def test_a_slow_handler_is_named(self):
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        node.logs.hold()
        peer = _authed(node, TARGET)
        node._on_slow_handler(peer, PING, 2.5)
        line = _lines(node, "a handler held the receive loop")[0]
        assert line["fields"]["type"] == "PING"
        assert line["fields"]["held_s"] == 2.5
        await node.stop()

    async def test_the_receive_loop_reports_a_handler_that_held_it(
            self, monkeypatch):
        monkeypatch.setattr(peers_mod, "_SLOW_HANDLER", 0.01)
        held: list = []
        transport = FakeTransport()
        peer = _Peer(transport)
        peer.on_slow = lambda link, kind, seconds: held.append((kind, seconds))

        async def slow(link, packet):
            await asyncio.sleep(0.05)

        transport.inject(_packet())
        await peer.start(slow)
        async with asyncio.timeout(2):
            while not held:
                await asyncio.sleep(0.01)
        assert held[0][1] >= 0.01
        await peer.stop()

    async def test_a_medium_cannot_flood_the_log(self):
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        node.logs.hold()
        peer = _authed(node, TARGET)
        for _ in range(1000):
            peer.transport.note("noise", "warn", spam="x" * 10_000)
        lines = _lines(node, "noise")
        assert 1 <= len(lines) <= 30          # heard — and bounded
        assert lines[0]["fields"]["link"] == peer.label
        assert len(lines[0]["fields"]["spam"]) <= logbook.MAX_FIELD_TEXT
        await node.stop()

    async def test_a_medium_cannot_speak_as_the_node(self):
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        node.logs.hold()
        peer = _authed(node, TARGET)
        peer.transport.note("hello", "info", node="forged", link="L0/x",
                            source="core", honest=1)
        line = _lines(node, "hello")[0]
        assert line["source"] == "transport"
        assert line["fields"]["link"] == peer.label
        assert line["fields"]["node"] == TARGET.raw.hex()[:16]
        assert line["fields"]["honest"] == 1
        await node.stop()

    async def test_a_throttled_line_counts_what_it_folded(self, monkeypatch):
        from src import node as node_mod
        monkeypatch.setattr(node_mod, "_LOG_THROTTLE", 0.05)
        node = MeshNode(transport_manager=make_manager())
        node.logs.hold()
        for _ in range(5):
            node._log_throttled("k", "busy")
        await asyncio.sleep(0.06)
        node._log_throttled("k", "busy")
        lines = _lines(node, "busy")
        assert len(lines) == 2
        assert lines[0]["fields"]["folded"] == 4      # newest first
        await node.stop()


class TestNoLinkEndsWithoutALine:
    """A link to a live node vanished from the console with no "link dropped"
    at all: the dial that had opened it reached a different node than the one
    it was for, and its clean-up stopped the link without a word. Every path
    that takes a link out of the list says so."""

    async def test_a_dial_that_reached_somebody_else(self):
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        node.logs.hold()

        async def answered_elsewhere(peer, want, timeout):
            peer.answered_as = NodeID(b"\x33" * 20)
            return False
        node._wait_for_peer_authenticated = answered_elsewhere
        await node._dial_uri(TARGET, "fake://h:1", 0.5)
        [line] = _lines(node, "unauthenticated link ended")
        assert line["fields"]["reason"] == "the dial did not reach the node it was for"
        await node.stop()

    async def test_a_node_the_operator_forgets(self):
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        node.logs.hold()
        _authed(node, TARGET)
        await node.console_forget_node(TARGET.raw.hex())
        [line] = _lines(node, "link dropped")
        assert line["fields"]["reason"] == "the operator forgot this node"
        await node.stop()

    async def test_a_join_that_failed(self):
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        node._join_try_timeout = 0.05
        node.logs.hold()
        block = base64.b64encode(json.dumps(
            {"v": 1, "code": "c" * 10, "uris": ["fake://a:1"]}).encode()).decode()
        node.console_join_block(block)
        await asyncio.wait_for(node._join_task, 5.0)
        [line] = _lines(node, "unauthenticated link ended")
        assert line["fields"]["reason"] == "the join through this address failed"
        await node.stop()


# ---------------------------------------------------------------------------
# The trace names the link, and an export carries what it recorded
# ---------------------------------------------------------------------------

class TestTheTraceNamesTheLink:

    def test_an_event_names_its_link(self):
        trace = Trace()
        trace.start(seconds=5)
        trace.record("in", _packet(), 80, TARGET, "L7/udp")
        assert trace.events()[0]["link"] == "L7/udp"

    def test_a_link_records_its_own_name(self):
        trace = Trace()
        trace.start(seconds=5)
        peer = _Peer(FakeTransport())
        peer.trace = trace
        asyncio.run(peer.send(_packet()))
        assert trace.events()[0]["link"] == peer.label

    def test_an_export_carries_everything_it_recorded(self):
        """It used to hand over the 2 000 newest of 5 000 and say nothing."""
        trace = Trace()
        trace.start(seconds=60, events=5000)
        for _ in range(5000):
            trace.record("out", _packet(), 80)
        document = trace.export()
        assert len(document["events"]) == 5000
        assert document["omitted"] == 0

    def test_an_export_with_a_budget_says_what_it_left_out(self):
        trace = Trace()
        trace.start(seconds=60, events=5000)
        for _ in range(5000):
            trace.record("out", _packet(), 80)
        document = trace.export(budget=128 * 1024)
        assert document["exported"] == len(document["events"]) < 5000
        assert document["omitted"] == 5000 - document["exported"]


class TestATraceExportFitsTheChannelItTravels:
    """A page on this machine gets everything; a console driving the node from
    elsewhere gets one capped reply, so it gets the newest that fit — and is
    told how many did not, rather than getting nothing at all."""

    def _module(self, events: int):
        from types import SimpleNamespace
        from src.control.modules.trace import TraceModule
        trace = Trace()
        trace.start(seconds=60, events=events)
        for _ in range(events):
            trace.record("out", _packet(), 80, TARGET, "L1/tcp")
        node = SimpleNamespace(trace=trace)
        return TraceModule(SimpleNamespace(node=node))

    def test_a_local_page_gets_everything(self):
        from src.control.plane import Origin
        document = self._module(5000).op_export(origin=Origin.LOCAL)
        assert len(document["events"]) == 5000 and document["omitted"] == 0

    def test_a_remote_console_gets_what_one_reply_carries(self):
        import json
        from src.control.frame import MAX_REPLY
        from src.control.plane import Origin
        document = self._module(5000).op_export(origin=Origin.REMOTE)
        assert len(json.dumps(document, separators=(",", ":"))) < MAX_REPLY
        assert document["omitted"] == 5000 - len(document["events"])
        assert document["events"]          # the newest are there
