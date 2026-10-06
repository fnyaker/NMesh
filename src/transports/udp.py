"""
UDP transport — the mesh over UDP with a reliability layer and NAT hole punching.

UDP is connectionless and unreliable: datagrams can be lost, duplicated, or
reordered. The mesh protocol (handshake, E2E key exchange, data) assumes
reliable, in-order delivery. This transport bridges that gap with a lightweight
reliability layer on top of asyncio datagram sockets:

- Sequence numbers + cumulative/selective ACKs
- Retransmission on a timer measured from the link's own round trips
  (RFC 6298), backed off once per timeout rather than once per frame
- A congestion window (slow start, then additive increase, halved on loss)
  and a hard flow-control window: a frame is never sent untracked
- Reordering buffer (bounded)
- Keepalive frames to maintain NAT mappings

Because it speaks the same ``BaseTransport`` / ``BaseServer`` interface as TCP,
the whole mesh — invite, handshake, routing, E2E — runs over it unchanged.

A single ``UDPServer`` binds one UDP socket and multiplexes all peer transports
through a dispatch table keyed by ``(ip, port)``. Incoming datagrams from an
unknown source create a new ``UDPTransport`` and trigger
``on_new_connection`` — exactly like a TCP accept loop.

Robustness (see AGENTS.md): every buffer is bounded, every frame is
structurally validated, and hostile datagrams are counted and dropped — never
crashing the receive loop.
"""
from __future__ import annotations

import asyncio
import os
import socket
import struct
import time
from collections import deque

from .contract import BaseTransport, BaseServer, LinkBusy, option
from ..packet import HEADER_SIZE, Packet
from ..ip_utils import split_host_port

# ---------------------------------------------------------------------------
# Frame format
#
#   seq(4)        — sequence number of this frame (uint32, wraps at 2^32)
#   ack(4)        — highest consecutive seq received from peer
#   sack(4)       — bitmap: bit i set = seq (ack+1+i) received (selective ACK)
#   flags(1)      — 0x01=ACK-only, 0x02=keepalive, 0x04=data, 0x08=fin
#   payload_len(2)— length of payload (0 for keepalive/ACK-only)
#   payload(N)    — Packet.pack() bytes, or empty
#
# Total header: 15 bytes. Max payload: 65535 (but Packet limits to 60000).
# ---------------------------------------------------------------------------

_FRAME = struct.Struct("!IIIBH")
_FRAME_SIZE = _FRAME.size
_MAGIC = b"NUDP"  # 4-byte magic prefix to distinguish from raw garbage / probes

FLAG_ACK_ONLY = 0x01
FLAG_KEEPALIVE = 0x02
FLAG_DATA = 0x04
FLAG_FIN = 0x08

_MAX_PAYLOAD = 60000
_MAX_UNACKED = 256          # max unacknowledged frames in retransmit buffer
_MAX_REORDER = 256          # max out-of-order frames buffered
# A frame count is not a memory bound: a frame carries up to _MAX_PAYLOAD, so
# 256 of them is 15 MB per link and an attacker chooses every byte by sending
# sequence numbers ahead of the cursor and never filling the gap. Both buffers
# are therefore bounded in bytes as well as in entries — whichever binds first.
_MAX_REORDER_BYTES = 2 * 1024 * 1024    # out-of-order frames held, in bytes
_MAX_DECODED_BYTES = 2 * 1024 * 1024    # decoded packets waiting for receive()
_MAX_SEND_QUEUE = 128       # max packets waiting to be framed and sent
# How long send() waits for room in that queue before refusing the packet.
# Waiting, not failing: a full queue is a link that is busy, and refusing the
# packet outright turned every burst into an error at the caller. What it
# raises then is `LinkBusy`, never `ConnectionError`: the link is full, not gone,
# and the caller that read "gone" tore down a working link under load.
_SEND_WAIT = 10.0
_RTO_MIN = 0.050            # floor of the retransmit timeout, seconds
_RTO_INITIAL = 0.200        # before the first round trip has been measured
_RTO_MAX = 2.0              # max retransmit timeout after backoff
# The congestion window, in bytes of frames in flight. It starts small, doubles
# every round trip that loses nothing (slow start), grows by one step per round
# trip past the threshold, and halves on a loss — once per window, not once per
# frame lost. Sending everything queued at once is what overflowed a 208 kB
# socket buffer and turned one burst into a two-second stall.
_CWND_INITIAL = 64 * 1024
_CWND_MIN = 32 * 1024
_CWND_MAX = 8 * 1024 * 1024
_CWND_STEP = 16 * 1024      # congestion-avoidance growth per round trip
# Selectively acknowledged frames above a hole that make the hole a loss rather
# than a reordering (TCP's three duplicate ACKs).
_DUP_THRESHOLD = 3
# What the socket asks the kernel for. Best effort: the kernel caps it at
# net.core.rmem_max / wmem_max, and the window above is what actually keeps a
# burst inside whatever buffer it grants.
_SOCK_BUFFER = 4 * 1024 * 1024
_RTX_CHECK = 0.020          # retransmit check interval
_KEEPALIVE_INTERVAL = 25.0  # NAT mapping refresh, seconds
# Dead-link horizon: 3 missed keepalives, so it MUST exceed both this interval
# and the mesh-level PING cadence (20s) — a shorter value condemns healthy,
# merely-quiet links whenever the two timers' phases align (route flapping).
_KEEPALIVE_TIMEOUT = 75.0   # 3 missed keepalives → dead link
_ACK_DELAY = 0.010          # max delay before sending a standalone ACK
_RECV_TIMEOUT = 120.0       # overall receive inactivity timeout
# A waiting receive() is woken by the arrival event; this only bounds how long
# it sits there before re-reading `_closed`, which nothing signals.
_RECV_WAKE = 0.5
# A link closed here is remembered for this long, so that frames still arriving
# from a far end that missed our FIN are answered with one rather than taken
# for a new connection (see `UDPServer._answer_closed`). Bounded in entries, and
# the answer is rate-limited per address: it is a datagram sent in reply to a
# datagram, and must never be a way to make this node send more than it gets.
_CLOSED_MEMORY = 30.0
_CLOSED_TRACKED = 256
_FIN_REPLY_GAP = 1.0
# How often one link may report a retransmit timeout or a refused send. Under
# real loss these happen many times a second, and a log that says so many times
# a second says nothing the count beside it does not.
_NOTE_GAP = 5.0


def _host_port(address: str) -> tuple[str, int]:
    """Parse host:port (IPv6-safe). Raises ValueError on malformed input."""
    hp = split_host_port(address)
    if hp is None:
        raise ValueError(f"invalid address: {address!r}")
    host, port = hp
    return host, int(port)


def _fmt_addr(host: str, port: int) -> str:
    """Format an address for display / logging."""
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _uri(scheme: str, host: str, port: int) -> str:
    host = str(host).split("%", 1)[0]
    return f"{scheme}://[{host}]:{port}" if ":" in host else f"{scheme}://{host}:{port}"


class _Sent:
    """One frame in flight: what to resend, when, and whether its round trip
    can still be trusted as a measurement (Karn: never time a retransmit)."""

    __slots__ = ("frame", "deadline", "sent_at", "resent", "fast")

    def __init__(self, frame: bytes, deadline: float, sent_at: float) -> None:
        self.frame = frame
        self.deadline = deadline
        self.sent_at = sent_at
        self.resent = False
        self.fast = False


def _grow_buffers(transport) -> None:
    """Ask for larger socket buffers. Never fatal: the kernel may refuse or cap
    it, and the congestion window copes with whatever it grants."""
    try:
        sock = transport.get_extra_info("socket")
        if sock is None:
            return
        for option in (socket.SO_RCVBUF, socket.SO_SNDBUF):
            try:
                sock.setsockopt(socket.SOL_SOCKET, option, _SOCK_BUFFER)
            except OSError:
                pass
    except Exception:
        pass


class _ReliableLink:
    """
    Reliability state for one direction of a UDP transport.

    Manages sequence numbers, retransmission, ACK tracking, and reordering.
    Both send and receive sides are encapsulated here so UDPTransport stays
    thin.
    """

    def __init__(self) -> None:
        # Send side. The initial sequence is random, not zero: the frame header
        # is not authenticated (only the mesh Packet inside it is), and the
        # endpoints of a link are public — they are gossiped in
        # `advertised_uris` and in FOUND_NODE. A predictable cursor let anyone
        # who knew both addresses spoof a frame at exactly the next expected
        # sequence, so the real peer's next frame looked like a duplicate and
        # was dropped. Randomising costs nothing and removes the guess.
        self._send_seq: int = int.from_bytes(os.urandom(4), "big")
        self._unacked: dict[int, _Sent] = {}   # seq → frame in flight, in order
        self._inflight: int = 0                # bytes of those frames
        self._send_queue: asyncio.Queue[Packet | None] = asyncio.Queue(_MAX_SEND_QUEUE)
        self._send_event: asyncio.Event = asyncio.Event()
        # Set when an ACK frees room in the window, so a send loop parked on a
        # full window wakes the moment it can go rather than on a timer.
        self._room: asyncio.Event = asyncio.Event()
        # Round-trip estimate (RFC 6298). `_rto` is what a frame waits now: the
        # estimate times the backoff, which doubles once per timeout of the
        # oldest frame and resets on the next clean measurement.
        self._srtt: float | None = None
        self._rttvar: float = 0.0
        self._rto_base: float = _RTO_INITIAL
        self._backoff: int = 1
        self._rto: float = _RTO_INITIAL
        # Congestion control. `_recover` is the first sequence sent after the
        # last reduction: a loss among frames sent before it belongs to the
        # same event and does not halve the window a second time.
        self._cwnd: float = float(_CWND_INITIAL)
        self._ssthresh: float = float(_CWND_MAX)
        self._recover: int = self._send_seq
        # F-RTO (RFC 5682). A timeout resends the oldest frame alone, then the
        # next two ACKs say whether anything was lost: 1 waits for the first
        # one that moves the cursor, 2 for the second. `_undo` holds what the
        # window and threshold were before the timeout cut them, for the case
        # where it answered no loss at all.
        self._frto: int = 0
        self._undo: tuple[float, float] | None = None

        # Receive side. Set from the first frame that arrives, so the peer's
        # random initial sequence is adopted rather than assumed to be zero.
        self._recv_next: int = 0          # next expected seq to deliver in-order
        self._recv_started: bool = False
        self._reorder: dict[int, bytes] = {}  # seq → payload (out-of-order buffer)
        self._reorder_bytes: int = 0      # what that buffer is actually holding
        self._sack: int = 0               # selective-ack bitmap, kept in step

        # ACK coalescing
        self._ack_pending: bool = False
        self._ack_timer: asyncio.Task | None = None

        # Keepalive
        self._last_recv_time: float = time.monotonic()
        self._keepalive_misses: int = 0
        # Observability: how much work the reliability layer had to redo.
        self.retransmits: int = 0
        self.reordered: int = 0
        # Times the oldest frame ran out its timer — the event that drops the
        # window to its floor, and the one that says a path stopped carrying.
        self.timeouts: int = 0
        # Timeouts F-RTO found spurious: the originals were only late.
        self.spurious: int = 0

    # -- send side --------------------------------------------------------

    def enqueue(self, packet: Packet) -> bool:
        """Queue a packet for sending. Returns False if the queue is full."""
        try:
            self._send_queue.put_nowait(packet)
            self._send_event.set()
            return True
        except asyncio.QueueFull:
            return False

    def can_send(self, size: int) -> bool:
        """Is there room in the window for a frame of ``size`` bytes?

        Always yes for the first frame in flight, so a single frame larger
        than the congestion window still goes. Never past `_MAX_UNACKED`
        frames: a frame sent without being tracked is a frame nobody will ever
        resend, and the receiver's cursor then waits for it for ever — the
        reliable link silently stops being one."""
        if not self._unacked:
            return True
        return (len(self._unacked) < _MAX_UNACKED
                and self._inflight + size <= self._cwnd)

    def build_frame(self, packet: Packet) -> bytes:
        """Build a data frame for the given packet and track it for retransmit.

        Always tracked. The window is the send loop's to respect
        (`can_send`); this never drops a frame from the book to make room."""
        payload = packet.pack()
        seq = self._send_seq
        self._send_seq = (self._send_seq + 1) & 0xFFFFFFFF
        ack, sack = self._build_ack()
        header = _FRAME.pack(seq, ack, sack, FLAG_DATA, len(payload))
        frame = _MAGIC + header + payload
        now = time.monotonic()
        self._unacked[seq] = _Sent(frame, now + self._rto, now)
        self._inflight += len(frame)
        return frame

    def build_keepalive(self) -> bytes:
        """Build a keepalive frame (no payload, no retransmit tracking)."""
        ack, sack = self._build_ack()
        header = _FRAME.pack(self._send_seq, ack, sack, FLAG_KEEPALIVE, 0)
        return _MAGIC + header

    def build_ack_only(self) -> bytes:
        """Build a standalone ACK frame."""
        ack, sack = self._build_ack()
        header = _FRAME.pack(self._send_seq, ack, sack, FLAG_ACK_ONLY, 0)
        return _MAGIC + header

    def build_fin(self) -> bytes:
        """Build a FIN frame to signal graceful close."""
        ack, sack = self._build_ack()
        header = _FRAME.pack(self._send_seq, ack, sack, FLAG_FIN, 0)
        return _MAGIC + header

    def _build_ack(self) -> tuple[int, int]:
        """Build cumulative ack + selective ack bitmap.

        The bitmap is maintained as frames land rather than rebuilt here: this
        is called for every frame built *and* every standalone ACK, which
        `_process_frame` emits after every data frame, and it used to walk the
        whole reorder buffer each time — up to 1 024 entries at the maximum
        setting."""
        return (self._recv_next - 1) & 0xFFFFFFFF, self._sack

    def _recompute_sack(self) -> None:
        """Rebuild the bitmap from the buffer. Only when the cursor moves.

        Bit ``i`` is sequence ``ack + 1 + i`` — the sender reads it so
        (`process_ack`), and bit 0 is the hole the cursor waits on, so it is
        never set. One bit off and the sender retires the very frame that is
        missing, never resends it, and the cursor waits on it for ever."""
        sack = 0
        base = self._recv_next
        for seq in self._reorder:
            offset = (seq - base) & 0xFFFFFFFF
            if 0 < offset < 32:
                sack |= (1 << offset)
        self._sack = sack

    def process_ack(self, ack: int, sack: int) -> list[bytes]:
        """Process incoming ACK + SACK, removing acknowledged frames.

        Cumulative ACK means all frames with seq <= ack have been received.
        We use unsigned wraparound distance: a frame s is cumulatively ACKed
        if the forward distance (ack - s) mod 2^32 is small (< _MAX_UNACKED).

        Returns the frames to resend *now*: a hole with `_DUP_THRESHOLD`
        selectively acknowledged frames above it is a loss, and waiting out the
        timer for it would idle the whole window behind one frame.
        """
        now = time.monotonic()
        acked = 0
        advanced = 0
        # Sequence numbers are issued in order, so `_unacked` is in order too:
        # the cumulative ack clears a *prefix*. Walking the whole window (and
        # copying its key list) on every incoming frame was O(window) per
        # datagram, for a window of up to `_MAX_UNACKED`.
        for s in list(self._unacked.keys()):
            if ((ack - s) & 0xFFFFFFFF) >= _MAX_UNACKED:
                break
            acked += self._acknowledge(self._unacked.pop(s), now)
            advanced += 1

        # Selective ACK: bits indicate seqs received above the cumulative ack
        base = (ack + 1) & 0xFFFFFFFF
        if sack:
            for i in range(32):
                if sack & (1 << i):
                    entry = self._unacked.pop((base + i) & 0xFFFFFFFF, None)
                    if entry is not None:
                        acked += self._acknowledge(entry, now)

        if self._frto:
            self._frto_step(advanced, sack, now)
        if acked:
            self._grow(acked)
        if acked or not self._unacked:
            self._room.set()
        return self._fast_retransmit(base, sack, now) if sack else []

    def _frto_step(self, advanced: int, sack: int, now: float) -> None:
        """Decide a timeout from the ACKs that follow it (RFC 5682).

        Only the oldest frame went out again, so every other frame of the
        window is an original. An ACK that moves the cursor twice running is
        those originals arriving: the timer fired on a late path, not a lossy
        one, the cut is undone, and their round trips — which Karn's rule
        allows, since they were sent once — teach the estimate how late the
        path is. A duplicate ACK at either step says a frame really is missing,
        and the rest of the window is resent as before.

        Without this a path that grew slower than the timer was resent whole
        on every timeout, no frame could be timed, and the estimate stayed on
        the idle round trip while the timer backed off to its ceiling: 30 ms
        measured, 1.6 s waited, on a link a speed test had just filled."""
        if not advanced:
            if sack:
                self._frto_lost(now)
            return
        if self._frto == 1 and self._outstanding_before_recover():
            self._frto = 2
            return
        if self._frto == 2:
            self.spurious += 1
            if self._undo is not None:
                self._cwnd = max(self._cwnd, self._undo[0])
                self._ssthresh = max(self._ssthresh, self._undo[1])
        self._frto = 0
        self._undo = None

    def _frto_lost(self, now: float) -> None:
        """A real loss after all: what the timeout held back goes now."""
        self._frto = 0
        self._undo = None
        for seq, entry in self._unacked.items():
            if not entry.resent and self._before_recover(seq):
                entry.deadline = now

    def _before_recover(self, seq: int) -> bool:
        """Was ``seq`` sent before the last reduction of the window?"""
        return ((seq - self._recover) & 0xFFFFFFFF) >= 0x80000000

    def _outstanding_before_recover(self) -> bool:
        return any(self._before_recover(seq) for seq in self._unacked)

    def _acknowledge(self, entry: _Sent, now: float) -> int:
        """Retire one frame; time it if its round trip means anything."""
        self._inflight -= len(entry.frame)
        if not entry.resent:
            self._sample(now - entry.sent_at)
        return len(entry.frame)

    def _sample(self, rtt: float) -> None:
        """RFC 6298, with a floor of `_RTO_MIN` rather than a second: a mesh
        link across a room must not wait a second to resend.

        The only thing that brings a backed-off timer back down. A window that
        merely emptied says nothing about the path: resetting there put the
        timer back on the very estimate that had just fired too early."""
        rtt = max(0.0, rtt)
        if self._srtt is None:
            self._srtt, self._rttvar = rtt, rtt / 2
        else:
            self._rttvar = 0.75 * self._rttvar + 0.25 * abs(self._srtt - rtt)
            self._srtt = 0.875 * self._srtt + 0.125 * rtt
        self._rto_base = min(_RTO_MAX, max(
            _RTO_MIN, self._srtt + max(_RTX_CHECK, 4 * self._rttvar)))
        self._backoff = 1
        self._rto = self._rto_base

    def _grow(self, acked: int) -> None:
        if self._cwnd < self._ssthresh:
            self._cwnd += acked                              # slow start
        else:
            self._cwnd += acked * _CWND_STEP / self._cwnd    # one step per RTT
        self._cwnd = min(self._cwnd, float(_CWND_MAX))

    def _loss(self, seq: int, timeout: bool) -> None:
        """One congestion event: halve the window, once per window of frames.

        A loss of a frame sent before the last reduction is the same event
        seen again — a burst that lost twenty frames lost them to one queue
        overflowing, and halving twenty times is what used to collapse the
        link. A timeout of the oldest frame is the stronger signal and drops
        the window to its floor, as TCP does."""
        if self._before_recover(seq):
            return                    # sent before the last reduction
        self._undo = (self._cwnd, self._ssthresh)
        self._ssthresh = max(self._cwnd / 2, float(_CWND_MIN))
        self._cwnd = float(_CWND_MIN) if timeout else self._ssthresh
        self._recover = self._send_seq

    def _fast_retransmit(self, base: int, sack: int, now: float) -> list[bytes]:
        frames: list[bytes] = []
        above = bin(sack).count("1")
        for i in range(32):
            if above < _DUP_THRESHOLD:
                break
            if sack & (1 << i):
                above -= 1
                continue
            seq = (base + i) & 0xFFFFFFFF
            entry = self._unacked.get(seq)
            if entry is None or entry.fast:
                continue
            entry.fast = entry.resent = True
            entry.deadline = now + self._rto
            self._loss(seq, timeout=False)
            frames.append(entry.frame)
        self.retransmits += len(frames)
        return frames

    def get_retransmit_frames(self) -> list[bytes]:
        """Return frames that have exceeded their RTO deadline for retransmit.

        The timer backs off once per timeout of the **oldest** frame — the one
        TCP keeps its single timer on — never once per frame: doubling for
        every frame of a lost burst took the timeout from 50 ms to its two
        second ceiling in one pass, and every frame after it then waited two
        seconds. What is resent at once is bounded by the congestion window
        too; the rest waits its turn rather than refilling the queue that has
        just overflowed.

        A first timeout resends the oldest frame **alone** and leaves the rest
        to the ACKs that follow (`_frto_step`). A frame of a loss event already
        being recovered running out its timer is that recovery, not a new
        timeout: it neither counts nor backs off again, or the frames a window
        too small to resend at once had to hold back doubled the timer once
        per round until it sat at its ceiling."""
        if not self._unacked:
            return []
        now = time.monotonic()
        oldest = next(iter(self._unacked))
        expired = [(seq, entry) for seq, entry in self._unacked.items()
                   if now >= entry.deadline]
        if not expired:
            return []
        if expired[0][0] == oldest:
            first = self._unacked[oldest]
            if first.resent or not self._before_recover(oldest):
                self.timeouts += 1
                self._backoff = min(self._backoff * 2, 64)
                self._rto = min(_RTO_MAX, self._rto_base * self._backoff)
                if not first.resent:
                    self._loss(oldest, timeout=True)
                    self._frto = 1
                    for _, entry in expired:
                        entry.deadline = now + self._rto
                    first.resent = True
                    self.retransmits += 1
                    return [first.frame]
            # The resend itself was lost, or the frames held back by the
            # timeout came due before the ACKs decided: a loss either way.
            self._frto = 0
            self._undo = None
        frames: list[bytes] = []
        budget = max(self._cwnd, float(len(expired[0][1].frame)))
        for seq, entry in expired:
            entry.deadline = now + self._rto
            if budget < len(entry.frame) and frames:
                continue              # deferred to the next round, not lost
            budget -= len(entry.frame)
            entry.resent = True
            frames.append(entry.frame)
        self.retransmits += len(frames)
        return frames

    # -- receive side -----------------------------------------------------

    def process_incoming(self, seq: int, flags: int, payload: bytes) -> list[bytes]:
        """
        Process an incoming frame. Returns list of deliverable payloads
        (in-order, possibly multiple if reordering gap was filled).
        Empty list if the frame is a duplicate, ACK-only, or out-of-order
        pending.

        Sequence comparison is modular (RFC 1982): a frame is "ahead" of the
        delivery cursor within half the 2^32 space, "behind" (a retransmit or
        a stale hostile replay) otherwise. Duplicate detection needs no seen
        set: ahead-and-buffered is already covered by ``_reorder``, and
        anything behind the cursor was delivered before. State stays bounded
        by ``_MAX_REORDER`` no matter how a peer sprays sequence numbers —
        and the seq wrap at 2^32 no longer wedges the link.
        """
        self._last_recv_time = time.monotonic()
        self._keepalive_misses = 0

        # The peer's starting sequence is learned from the FIRST frame of any
        # kind — which on a real link is the keepalive `connect()` sends before
        # any data, so the cursor is set before a data frame can arrive. Adopting
        # it from the first *data* frame instead would mean a reordered opening
        # frame moved the cursor past its predecessors, and those would then be
        # dropped as duplicates for ever: a stalled link, which is worse than
        # what randomising protects against.
        if not self._recv_started:
            self._recv_started = True
            self._recv_next = seq

        if flags & (FLAG_ACK_ONLY | FLAG_KEEPALIVE | FLAG_FIN):
            return []  # no data payload to deliver

        dist = (seq - self._recv_next) & 0xFFFFFFFF

        # In-order: deliver immediately and flush any buffered successors
        if dist == 0:
            self._recv_next = (self._recv_next + 1) & 0xFFFFFFFF
            delivered: list[bytes] = [payload]
            # Flush consecutive buffered frames
            while self._recv_next in self._reorder:
                buffered = self._reorder.pop(self._recv_next)
                self._reorder_bytes -= len(buffered)
                delivered.append(buffered)
                self._recv_next = (self._recv_next + 1) & 0xFFFFFFFF
            self._recompute_sack()        # the cursor moved
            self._schedule_ack()
            return delivered

        if dist < 0x80000000:
            # Ahead of the cursor: out-of-order. A seq already buffered is a
            # retransmit — drop it but re-ACK so the sender stops resending.
            if (seq not in self._reorder
                    and len(self._reorder) < UDPTransport.setting("max_reorder")
                    and self._reorder_bytes + len(payload) <= _MAX_REORDER_BYTES):
                self._reorder[seq] = payload
                self._reorder_bytes += len(payload)
                self.reordered += 1
                offset = (seq - self._recv_next) & 0xFFFFFFFF
                if 0 < offset < 32:
                    self._sack |= (1 << offset)
            self._schedule_ack()
            return []

        # Behind the cursor: delivered long ago (retransmit) or stale garbage —
        # drop, and re-ACK the current window so a lossy sender can move on.
        self._schedule_ack()
        return []

    def accepts_fin(self, seq: int) -> bool:
        """Is a FIN carrying ``seq`` one the peer could have sent?

        The frame header is not authenticated (`BUGSVULNS.MD` finding 13), so
        a FIN is believed on the same evidence a data frame is: it must sit in
        the window the peer's own random cursor defines. A sender's FIN carries
        its next sequence, which is our delivery cursor plus whatever it still
        has in flight — never more than `_MAX_UNACKED` ahead. Somebody spoofing
        the peer's address without seeing its traffic is guessing a 32-bit
        number, which is exactly the protection every data frame already has.

        Never before the first frame: a link whose cursor we have not learned
        has no window to be inside of."""
        if not self._recv_started:
            return False
        return ((seq - self._recv_next) & 0xFFFFFFFF) < _MAX_UNACKED

    def note_arrival(self) -> None:
        """A frame arrived that will not be processed (the reader is behind).
        The link is still alive; only the data waits for a retransmit."""
        self._last_recv_time = time.monotonic()
        self._keepalive_misses = 0

    def needs_ack(self) -> bool:
        return self._ack_pending

    def _schedule_ack(self) -> None:
        self._ack_pending = True

    def clear_ack_pending(self) -> None:
        self._ack_pending = False

    def is_alive(self) -> bool:
        """Check if the link is still alive based on keepalive timing."""
        return ((time.monotonic() - self._last_recv_time)
                < UDPTransport.setting("keepalive_timeout"))

    def pending_packets(self) -> int:
        """Number of packets queued for sending."""
        return self._send_queue.qsize()

    def unacked_count(self) -> int:
        """Number of unacknowledged frames."""
        return len(self._unacked)


class UDPTransport(BaseTransport):
    """
    A single bidirectional link over UDP with reliability.

    One instance = one peer connection. Uses a shared datagram socket
    (provided by UDPServer or created on connect) and a remote address.
    """

    SCHEME = "udp"

    OPTIONS = (
        option("keepalive_interval", "float", _KEEPALIVE_INTERVAL,
               "How often an idle link refreshes its NAT mapping. Longer means "
               "less traffic and a mapping more likely to have been dropped.",
               minimum=5.0, maximum=120.0, unit="s"),
        option("keepalive_timeout", "float", _KEEPALIVE_TIMEOUT,
               "A link with nothing arriving for this long is declared dead. "
               "Keep it well above the interval — three missed keepalives is "
               "the usual rule.",
               minimum=15.0, maximum=600.0, unit="s"),
        option("priority", "int", -10,
               "How much this node prefers UDP over another medium, from "
               "-254 to 254. Weighed against measured latency; the balance "
               "between the two is set once for the node, under Reachability. "
               "It ships below TCP: UDP is what reaches a node no listener "
               "can be opened to, and that is worth having — but a datagram "
               "path loses where a stream does not, and a link losing probes "
               "is a link an operator ends up reconnecting by hand. Raise it "
               "where UDP is the better medium and you know it.",
               minimum=-254, maximum=254),
        option("mlo", "bool", True,
               "Let this medium carry half of a peer's traffic beside another "
               "link (multi-link operation). It buys throughput and a much "
               "faster reaction to a link going bad, and it costs a probe "
               "every hundred milliseconds on every link it bundles — which on "
               "a socket over IP is cheap, so it is on here. Turn it off on a "
               "metered or battery-powered link.",
               label="MLO ready"),
        option("retry_interval", "float", 0.0,
               "How often to re-dial a known node this one has no link to, on "
               "each of its UDP addresses. Zero switches it off: nothing "
               "is retried until something needs a route. Raise it on a link "
               "that drops and comes back on its own; leave it off where a dial "
               "costs more than waiting.",
               minimum=0.0, maximum=3600.0, unit="s", label="retry interval"),
        option("max_reorder", "int", _MAX_REORDER,
               "Out-of-order frames held while waiting for the gap to fill. "
               "Bigger tolerates more reordering and costs more memory per link.",
               minimum=16, maximum=1024),
    )
    SETTINGS: dict = {}

    def __init__(self, sock: asyncio.DatagramTransport | None = None,
                 remote_addr: tuple[str, int] | None = None) -> None:
        super().__init__()
        self._sock: asyncio.DatagramTransport | None = sock
        self._remote: tuple[str, int] | None = remote_addr
        self._link = _ReliableLink()
        # Decoded packets waiting for receive(). A deque because the consumer
        # takes from the front, and bounded in bytes because nothing couples
        # arrival to consumption: a sender faster than _Peer._loop — or a
        # transport whose consumer never started — grew this without limit.
        self._decoded: deque[Packet] = deque()
        self._decoded_bytes: int = 0
        # Set when a packet lands, cleared when the queue empties. receive()
        # waits on it instead of polling: the poll cost 10 ms of latency per
        # packet and 100 wakeups a second per link, at rest, for nothing.
        self._arrived: asyncio.Event = asyncio.Event()
        self._closed: bool = False
        self._rtx_task: asyncio.Task | None = None
        self._keepalive_task: asyncio.Task | None = None
        self._send_task: asyncio.Task | None = None
        # When True, this transport owns its socket (connect path) and must
        # close it. When False, the socket is shared (server path).
        self._owns_socket: bool = False
        # The server whose dispatch table holds us, so closing can say so
        # rather than leaving a dead entry to be swept later.
        self._server: "UDPServer | None" = None
        # Callback set by the server to feed raw datagrams into this transport
        self._on_datagram = None
        # Delivered payloads that were not decodable packets. See _process_frame.
        self.undecodable: int = 0
        # Why this link ended, said by whatever ended it. A receive loop that
        # ends on a bare "closed" is a link dropped for a reason nobody can
        # read afterwards — and "the peer said goodbye", "the peer went silent
        # for 75 s" and "we closed it" are three different investigations.
        self._end_reason: str = ""
        # When each kind of trouble was last reported, and how many happened
        # since. See `_NOTE_GAP`.
        self._noted_at: dict = {}
        self._noted_timeouts: int = 0
        self._busy_since_note: int = 0

    def _note_throttled(self, kind: str, message: str, level: str,
                        **fields) -> bool:
        """Report at most once per `_NOTE_GAP` per kind of trouble."""
        now = time.monotonic()
        if now - self._noted_at.get(kind, -_NOTE_GAP) < _NOTE_GAP:
            return False
        self._noted_at[kind] = now
        self.note(message, level, **fields)
        return True

    def _link_figures(self) -> dict:
        """The numbers that say what state the reliability layer was in."""
        link = self._link
        return {
            "srtt_ms": None if link._srtt is None else round(link._srtt * 1000, 1),
            "rto_ms": round(link._rto * 1000, 1),
            "window_kb": round(link._cwnd / 1024),
            "unacked": len(link._unacked),
            "queued": link._send_queue.qsize(),
            "retransmits": link.retransmits,
        }

    def end_reason(self) -> str:
        return self._end_reason

    def endpoints(self) -> dict:
        local = None
        if self._sock is not None:
            try:
                name = self._sock.get_extra_info("sockname")
                if name:
                    local = _uri("udp", name[0], name[1])
            except Exception:
                pass
        remote = _uri("udp", *self._remote) if self._remote else None
        return {"local": local, "remote": remote}

    def stats(self) -> dict:
        """What the reliability layer is doing right now. Retransmits rising on
        a link whose RTT looks fine is the signature of a lossy path — a fact no
        packet counter shows."""
        link = self._link
        return {
            "retransmits": link.retransmits,
            "reordered": link.reordered,
            "unacked": len(link._unacked),
            "reorder buffer": len(link._reorder),
            "rto ms": round(link._rto * 1000, 1),
            "srtt ms": None if link._srtt is None else round(link._srtt * 1000, 2),
            "window kB": round(link._cwnd / 1024),
            "in flight kB": round(link._inflight / 1024),
            "keepalive misses": link._keepalive_misses,
            "timeouts": link.timeouts,
            "spurious timeouts": link.spurious,
            "undecodable": self.undecodable,
        }

    @classmethod
    def _from_server(cls, sock: asyncio.DatagramTransport,
                     remote_addr: tuple[str, int],
                     server: "UDPServer | None" = None) -> "UDPTransport":
        """Create a transport for an incoming connection accepted by the server."""
        t = cls(sock, remote_addr)
        t._owns_socket = False
        t._server = server
        return t

    async def connect(self, address: str) -> None:
        """Open an outgoing UDP connection to the given address.

        UDP is connectionless — connect() just creates the socket and sends
        an initial keepalive frame so the remote server learns our source
        address and can create a transport for us.
        """
        host, port = _host_port(address)
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _DatagramProtocol(self),
            remote_addr=(host, port),
        )
        self._sock = transport
        _grow_buffers(transport)
        self._remote = (host, port)
        self._owns_socket = True
        self._start_tasks()
        # Send an initial keepalive so the server discovers our source address
        # and creates a transport for us (UDP has no connection handshake).
        self._send_raw(self._link.build_keepalive())

    async def listen(self, address: str) -> None:
        """Listen for a single incoming connection (point-to-point mode).

        Binds a UDP socket and waits for the first datagram from any source.
        That source becomes the peer for this transport.
        """
        host, port = _host_port(address)
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _DatagramProtocol(self),
            local_addr=(host, port),
        )
        self._sock = transport
        self._owns_socket = True
        # Wait for the first datagram to establish the peer
        while self._remote is None and not self._closed:
            await asyncio.sleep(0.01)
        if self._remote is not None:
            self._start_tasks()

    def _start_tasks(self) -> None:
        """Start background tasks for retransmission, keepalive, and sending."""
        if self._rtx_task is None:
            self._rtx_task = asyncio.create_task(self._rtx_loop())
        if self._keepalive_task is None:
            self._keepalive_task = asyncio.create_task(self._keepalive_loop())
        if self._send_task is None:
            self._send_task = asyncio.create_task(self._send_loop())

    def feed_datagram(self, data: bytes, addr: tuple[str, int]) -> None:
        """Feed a raw datagram into this transport (called by the server or protocol)."""
        if self._remote is None:
            self._remote = addr
            self._start_tasks()
        self._process_frame(data)

    def _process_frame(self, data: bytes) -> None:
        """Parse and process a raw datagram frame."""
        # Validate magic
        if len(data) < len(_MAGIC) + _FRAME_SIZE or data[:len(_MAGIC)] != _MAGIC:
            return  # not our frame — could be a probe or garbage
        header = data[len(_MAGIC):len(_MAGIC) + _FRAME_SIZE]
        try:
            seq, ack, sack, flags, payload_len = _FRAME.unpack(header)
        except struct.error:
            return
        payload = data[len(_MAGIC) + _FRAME_SIZE:]
        if len(payload) != payload_len:
            return  # truncated or mismatched

        # Process ACK info, and resend at once what it shows was lost.
        for frame in self._link.process_ack(ack, sack):
            self._send_raw(frame)

        # The far end has closed its side. Believed only inside the window
        # (`accepts_fin`), and acted on at once: a FIN used to be counted as a
        # mere arrival — it *refreshed* the liveness it announces the end of —
        # so the link it closed lived on here as a zombie, its frames answered
        # by a fresh transport on the far side that drops them unauthenticated,
        # until our own probes gave up on it a minute and a half later.
        if flags & FLAG_FIN:
            if self._link.accepts_fin(seq):
                self._peer_finished()
            return

        # A reader that has fallen behind refuses the frame *before* it is
        # acknowledged, so the sender keeps it and resends it later — and sees a
        # loss, which is what slows it down. Taking it, acknowledging it and
        # then dropping it because the queue was full lost a packet on a link
        # that promises not to, with no one on either side able to tell.
        if (payload and flags & FLAG_DATA
                and self._decoded_bytes + len(payload) > _MAX_DECODED_BYTES):
            self._link.note_arrival()
            return

        # Every frame is handed over, not only the ones carrying data: an idle
        # link sends nothing but keepalives, and `process_incoming` is where an
        # arrival is recorded — the time `is_alive` reads for its death verdict,
        # and the peer's cursor, adopted from the first frame of any kind. It
        # returns nothing to deliver for a keepalive, an ack or a fin, so the
        # loop below does not run for them.
        # A DATA frame declaring no payload is the one exception: no sender
        # builds one, so it is dropped with no side effect rather than moving
        # the cursor on.
        if payload or not (flags & FLAG_DATA):
            delivered = self._link.process_incoming(seq, flags, payload)
            for raw in delivered:
                try:
                    packet = Packet.unpack(raw)
                except Exception:
                    # A delivered payload that is not a packet is a fault, not
                    # noise: a real peer's frames decode. Counting it is what
                    # lets an operator see a link being interfered with rather
                    # than one that has mysteriously gone quiet.
                    self.undecodable += 1
                    continue
                # Never reached from the check above for the frame itself, but a
                # frame that fills a gap also releases the reorder buffer behind
                # it. Those were acknowledged when they arrived, so they are
                # delivered rather than dropped: the queue may pass its bound by
                # at most the reorder buffer's, which is bounded too.
                if (self._decoded_bytes + len(raw)
                        > _MAX_DECODED_BYTES + _MAX_REORDER_BYTES + _MAX_PAYLOAD):
                    continue
                self._decoded.append(packet)
                self._decoded_bytes += len(raw)
                self._arrived.set()

        # Send a piggybacked or standalone ACK if needed
        if self._link.needs_ack():
            self._link.clear_ack_pending()
            self._send_raw(self._link.build_ack_only())

    def _peer_finished(self) -> None:
        """The far end closed this link: end it here too, without answering.

        No FIN back — the far end has already forgotten us, and a reply would
        only arrive at a socket that no longer has a link for it."""
        if self._closed:
            return
        self._end_reason = "the peer closed the link (FIN)"
        self._closed = True
        self._arrived.set()            # a parked receive() must not wait it out
        if self._server is not None and self._remote is not None:
            self._server.remove_transport(self._remote)
        self.note("the peer closed the link", "info", **self._link_figures())

    def _send_raw(self, frame: bytes) -> None:
        """Send a raw frame via the datagram socket."""
        if self._sock is None or self._remote is None:
            return
        try:
            self._sock.sendto(frame, self._remote)
        except (OSError, ConnectionError):
            pass

    async def send(self, packet: Packet) -> None:
        """Send a packet over the reliable UDP link."""
        if self._closed:
            raise ConnectionError(self._end_reason or "udp transport closed")
        if self._sock is None or self._remote is None:
            raise ConnectionError("udp transport not connected")
        if self._link.enqueue(packet):
            return
        try:
            async with asyncio.timeout(_SEND_WAIT):
                await self._link._send_queue.put(packet)
        except TimeoutError:
            self._busy_since_note += 1
            if self._note_throttled(
                    "busy", "send refused: the queue stayed full", "warn",
                    waited_s=_SEND_WAIT, refused=self._busy_since_note,
                    **self._link_figures()):
                self._busy_since_note = 0
            raise LinkBusy("udp send queue full") from None
        if self._closed:
            raise ConnectionError(self._end_reason or "udp transport closed")

    async def _send_loop(self) -> None:
        """Background task: dequeue packets and send them as reliable frames."""
        while not self._closed:
            try:
                packet = await asyncio.wait_for(
                    self._link._send_queue.get(), timeout=0.5
                )
            except asyncio.TimeoutError:
                continue
            if packet is None:
                break
            # Wait for the window rather than overrun it. Woken by the ACK that
            # makes room; the timeout only re-reads `_closed`.
            size = len(_MAGIC) + _FRAME_SIZE + HEADER_SIZE + len(packet.payload)
            while not self._closed and not self._link.can_send(size):
                self._link._room.clear()
                if self._link.can_send(size):
                    break
                try:
                    async with asyncio.timeout(0.5):
                        await self._link._room.wait()
                except TimeoutError:
                    pass
            if self._closed:
                break
            frame = self._link.build_frame(packet)
            self._send_raw(frame)

    async def _rtx_loop(self) -> None:
        """Background task: retransmit unacknowledged frames past their RTO."""
        while not self._closed:
            await asyncio.sleep(_RTX_CHECK)
            if self._closed:
                break
            for frame in self._link.get_retransmit_frames():
                self._send_raw(frame)
            if self._link.timeouts != self._noted_timeouts and self._note_throttled(
                    "timeout", "retransmit timeout: window dropped to its floor",
                    "warn", timeouts=self._link.timeouts - self._noted_timeouts,
                    **self._link_figures()):
                self._noted_timeouts = self._link.timeouts

    async def _keepalive_loop(self) -> None:
        """Background task: send keepalives and detect dead links."""
        while not self._closed:
            await asyncio.sleep(UDPTransport.setting("keepalive_interval"))
            if self._closed:
                break
            self._send_raw(self._link.build_keepalive())
            if not self._link.is_alive():
                silent = time.monotonic() - self._link._last_recv_time
                self._end_reason = (f"no frame from the peer for {silent:.0f} s "
                                    f"(udp keepalive timeout)")
                self.note("the peer went silent", "warn",
                          silent_s=round(silent, 1), **self._link_figures())
                self._closed = True
                self._arrived.set()    # a parked receive() must not wait it out
                if self._server is not None and self._remote is not None:
                    self._server.remove_transport(self._remote)
                break

    async def receive(self) -> Packet:
        """Block until a packet is received and return it."""
        while True:
            if self._decoded:
                packet = self._decoded.popleft()
                self._decoded_bytes -= HEADER_SIZE + len(packet.payload)
                if not self._decoded:
                    self._arrived.clear()
                return packet
            if self._closed:
                raise ConnectionError(self._end_reason or "udp transport closed")
            self._arrived.clear()
            if self._decoded or self._closed:
                continue          # raced with a datagram landing — go round
            try:
                async with asyncio.timeout(_RECV_WAKE):
                    await self._arrived.wait()
            except asyncio.TimeoutError:
                pass              # re-check _closed, which nothing signals

    def idle_timeout(self) -> float | None:
        """A UDP link with nothing arriving for this long is declared dead by
        the reliability layer's own keepalive. Read off the setting, so a value
        an operator changed is the value the cadence is held to."""
        return float(self.setting("keepalive_timeout") or 0.0) or None

    def remote_ip(self) -> str | None:
        """The peer's source IP as observed locally."""
        if self._remote is None:
            return None
        return str(self._remote[0]).split("%", 1)[0]

    def is_closed(self) -> bool:
        """Whether this link has been torn down."""
        return self._closed

    def keepalive(self) -> bool:
        """Put one reliable-link keepalive on the wire.

        Goes straight out as a frame rather than through ``send``: the whole
        point is to reach a peer whose accept loop has not challenged us yet,
        so there is no session to speak packets in. Returns False once the
        socket is gone, which is the caller's signal to stop its burst."""
        if self._closed or self._sock is None or self._remote is None:
            return False
        self._send_raw(self._link.build_keepalive())
        return True

    def remote_address(self) -> str | None:
        """The peer's full address as host:port string."""
        if self._remote is None:
            return None
        host, port = self._remote
        return _fmt_addr(host, port)

    async def close(self) -> None:
        """Close this connection and release resources."""
        if self._closed:
            return
        self._closed = True
        self._end_reason = self._end_reason or "closed by this node"
        self._arrived.set()        # wake a parked receive() so it can raise
        if self._server is not None and self._remote is not None:
            self._server.remove_transport(self._remote)
            self._server.remember_closed(self._remote, self._link)
        # Send FIN to signal graceful close. Twice: it is one unacknowledged
        # datagram, and losing it costs the far end a link that answers nothing
        # for as long as it takes its probes to give up. A third copy is sent
        # by the server if the far end keeps talking (`_answer_closed`).
        if self._sock is not None and self._remote is not None:
            try:
                fin = self._link.build_fin()
                self._send_raw(fin)
                self._send_raw(fin)
            except Exception:
                pass
        # Cancel background tasks
        for task in (self._rtx_task, self._keepalive_task, self._send_task):
            if task is not None:
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass
        self._rtx_task = None
        self._keepalive_task = None
        self._send_task = None
        # Close the socket if we own it
        if self._owns_socket and self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
        self._sock = None


class _DatagramProtocol(asyncio.DatagramProtocol):
    """asyncio datagram protocol that feeds received datagrams to a transport
    or to a server's dispatch callback."""

    def __init__(self, transport_or_server) -> None:
        self._owner = transport_or_server

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        if isinstance(self._owner, UDPTransport):
            self._owner._sock = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if isinstance(self._owner, UDPTransport):
            self._owner.feed_datagram(data, addr)
        elif isinstance(self._owner, UDPServer):
            self._owner._dispatch_datagram(data, addr)

    def error_received(self, exc: Exception) -> None:
        pass  # never crash on socket errors — the link will time out naturally


class UDPServer(BaseServer):
    """
    Accepts multiple incoming UDP connections via a single shared socket.

    Each unique source address gets its own UDPTransport. The server
    dispatches incoming datagrams to the appropriate transport based on
    the source (ip, port).
    """

    def __init__(self) -> None:
        super().__init__()
        self._sock: asyncio.DatagramTransport | None = None
        self._transports: dict[tuple[str, int], UDPTransport] = {}
        # Links this server closed lately: address → (forget at, the next
        # sequence we would have sent, the cursor we had reached, when we last
        # answered it). See `_answer_closed`.
        self._closed_links: dict = {}
        self._closed: bool = False
        # Callback for raw datagrams that are not reliable transport frames
        # (e.g. NAT hole-punch probes). Set by MeshNode.
        self.on_raw_datagram = None

    async def listen(self, address: str) -> None:
        """Bind to the given address and start accepting datagrams."""
        host, port = _host_port(address)
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _DatagramProtocol(self),
            local_addr=(host, port),
        )
        self._sock = transport
        _grow_buffers(transport)

    def reachability(self, uri: str, ctx: dict) -> list[dict]:
        from ..ip_utils import ip_reachability
        return ip_reachability(
            "udp", uri, ctx.get("local_ips", []), ctx.get("public_addrs", []),
            "udp" in ctx.get("inbound_schemes", ()),
            "udp" in ctx.get("public_schemes", ()))

    async def broadcast(self, data: bytes) -> bool:
        """Send a datagram to the LAN limited-broadcast address on our port."""
        if self._sock is None:
            return False
        sock = self._sock.get_extra_info("socket")
        port = None
        try:
            if sock is not None:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                port = sock.getsockname()[1]
        except OSError:
            return False
        if port is None:
            return False
        try:
            self._sock.sendto(data, ("255.255.255.255", port))
            return True
        except OSError:
            return False

    def _dispatch_datagram(self, data: bytes, addr: tuple[str, int]) -> None:
        """Dispatch an incoming datagram to the appropriate transport.

        Datagrams starting with the NUDP magic are reliable transport frames.
        Datagrams starting with punch probe/ack magic are hole-punching
        signals — forwarded to on_raw_datagram if set.
        Everything else is garbage — silently dropped.
        """
        # Hole-punch probe/ack magic, or a STUN binding response (magic cookie
        # 0x2112A442 at bytes 4:8) that keepalive STUN sent from this very
        # socket — both are handled by the node's raw-datagram callback, not
        # by a reliable transport.
        if (len(data) >= 4 and data[:4] in (b"NPPB", b"NPAK")) or (
                len(data) >= 8 and data[4:8] == b"\x21\x12\xa4\x42"):
            if self.on_raw_datagram is not None:
                try:
                    self.on_raw_datagram(data, addr)
                except Exception:
                    pass
            return

        # Check for our reliable transport magic
        if len(data) < len(_MAGIC) or data[:len(_MAGIC)] != _MAGIC:
            return  # garbage — silently drop

        transport = self._transports.get(addr)
        if transport is None or transport._closed:
            if self._answer_closed(data, addr):
                return
            # New peer — create a transport and notify
            if self._closed or self.on_new_connection is None:
                return
            # Count the *live* ones. A closed transport left in the table is not
            # a peer, and counting it meant 128 datagrams from 128 source ports
            # disabled UDP for the life of the process — including for a known
            # peer whose link had simply died and wanted to come back.
            self._reap_closed()
            if len(self._transports) >= _MAX_PEERS_UDP:
                return  # bounded — reject new peers when full
            transport = UDPTransport._from_server(self._sock, addr, self)
            self._transports[addr] = transport
            transport._start_tasks()
            asyncio.create_task(self._safe_on_new_connection(transport))
        transport.feed_datagram(data, addr)

    def remember_closed(self, addr: tuple[str, int], link: _ReliableLink) -> None:
        """Keep what is needed to tell a far end, later, that this link is gone.

        Bounded in time and in entries; the oldest goes first."""
        now = time.monotonic()
        for key in [key for key, entry in self._closed_links.items()
                    if entry[0] <= now]:
            del self._closed_links[key]
        while len(self._closed_links) >= _CLOSED_TRACKED:
            del self._closed_links[next(iter(self._closed_links))]
        self._closed_links[addr] = (now + _CLOSED_MEMORY, link._send_seq,
                                    (link._recv_next - 1) & 0xFFFFFFFF,
                                    link._recv_next, -_FIN_REPLY_GAP)

    def _answer_closed(self, data: bytes, addr: tuple[str, int]) -> bool:
        """A frame for a link we closed: answer it with a FIN, and say whether
        it was one.

        Without this, the frames of a far end that missed our FIN were taken
        for a **new connection**: a fresh transport, adopting their cursor,
        acknowledging their data and keeping their link alive with its
        keepalives — while the node dropped every packet on it as
        unauthenticated. Both ends then held a link that carried nothing.

        Which frames belong to the old link is read off their sequence: the far
        end continues from where we stopped receiving, and a genuinely new dial
        starts from a fresh random cursor, so it is taken as new as before. A
        FIN is never a new connection, whoever sends it."""
        if len(data) < len(_MAGIC) + _FRAME_SIZE:
            return False
        try:
            seq, _ack, _sack, flags, _length = _FRAME.unpack_from(data, len(_MAGIC))
        except struct.error:
            return False
        entry = self._closed_links.get(addr)
        now = time.monotonic()
        if entry is not None and entry[0] <= now:
            del self._closed_links[addr]
            entry = None
        if entry is None:
            return bool(flags & FLAG_FIN)
        until, send_seq, ack, recv_next, answered_at = entry
        # Either side of the cursor: a far end that never saw our last ACKs
        # resends frames we had already delivered.
        window = _MAX_UNACKED + _MAX_REORDER
        if (((seq - recv_next) & 0xFFFFFFFF) >= window
                and ((recv_next - seq) & 0xFFFFFFFF) > window):
            del self._closed_links[addr]      # a new dial from the same port
            return bool(flags & FLAG_FIN)
        if not flags & FLAG_FIN and now - answered_at >= _FIN_REPLY_GAP:
            self._closed_links[addr] = (until, send_seq, ack, recv_next, now)
            fin = _MAGIC + _FRAME.pack(send_seq, ack, 0, FLAG_FIN, 0)
            try:
                if self._sock is not None:
                    self._sock.sendto(fin, addr)
            except (OSError, ConnectionError):
                pass
        return True

    async def _safe_on_new_connection(self, transport: UDPTransport) -> None:
        try:
            if self.on_new_connection is not None:
                await self.on_new_connection(transport)
        except Exception:
            pass

    def remove_transport(self, addr: tuple[str, int]) -> None:
        """Remove a transport from the dispatch table (called on close)."""
        self._transports.pop(addr, None)

    def _reap_closed(self) -> None:
        """Drop entries whose transport has gone.

        A transport closes for three reasons — `close()`, the keepalive's death
        verdict, and the node reaping the peer — and only the first of them can
        reasonably call `remove_transport`. So the table is swept where it is
        read, which covers all three."""
        for addr in [a for a, t in self._transports.items() if t._closed]:
            del self._transports[addr]

    # -- the datagram capabilities the punch path asks for ------------------
    # See `BaseServer` for what each is for and why the core asks rather than
    # inspecting. These four are the whole of what NAT traversal needs, and
    # naming them here is what lets `node.py` stop reading `_sock` and
    # `_transports` — privates it had to know because there was no other door.

    def bound_endpoint(self) -> tuple[str, int] | None:
        """The host/port this listener is bound to, or None if it is not up.

        Read off the socket rather than remembered, so a listener bound to port
        0 reports the port the kernel actually gave it — the one a peer can
        reach, not the 0 that was asked for."""
        if self._sock is None:
            return None
        sock = self._sock.get_extra_info("socket")
        if sock is None:
            return None
        try:
            return sock.getsockname()[:2]
        except (OSError, IndexError):
            return None

    def holds(self, remote: tuple[str, int]) -> bool:
        """Whether a live link to ``remote`` already exists on this listener."""
        if self._closed:
            return False
        transport = self._transports.get(remote)
        return transport is not None and not transport._closed

    def adopt(self, remote: tuple[str, int]) -> UDPTransport | None:
        """A transport to ``remote`` over this listener's socket, or None.

        Idempotent by construction: an existing live transport for this address
        is returned untouched. That is not a convenience — two transports for
        one source address would both be fed the same datagrams and race each
        other's handshakes to a link that never authenticates, which is the
        duplicate-peer bug this table exists to prevent."""
        if self._closed or self._sock is None:
            return None
        existing = self._transports.get(remote)
        if existing is not None and not existing._closed:
            return existing
        self._reap_closed()
        if len(self._transports) >= _MAX_PEERS_UDP:
            return None        # bounded: the table is full, as on the accept path
        transport = UDPTransport._from_server(self._sock, remote, self)
        self._transports[remote] = transport
        transport._start_tasks()
        return transport

    def send_raw(self, data: bytes, remote: tuple[str, int]) -> bool:
        """Send ``data`` as-is from this listener's socket. Best-effort.

        Uses the listener socket on purpose — that is the mapping the punch
        opened — and never raises: a probe or a keepalive that does not leave is
        a punch that did not land, which the caller already treats as ordinary."""
        if self._closed or self._sock is None:
            return False
        try:
            self._sock.sendto(data, remote)
            return True
        except (OSError, ConnectionError):
            return False

    async def close(self) -> None:
        """Stop accepting connections and release resources."""
        self._closed = True
        for transport in list(self._transports.values()):
            try:
                await transport.close()
            except Exception:
                pass
        self._transports.clear()
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
        self._sock = None


_MAX_PEERS_UDP = 128