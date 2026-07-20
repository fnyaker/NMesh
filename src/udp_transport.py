"""
UDP transport — the mesh over UDP with a reliability layer and NAT hole punching.

UDP is connectionless and unreliable: datagrams can be lost, duplicated, or
reordered. The mesh protocol (handshake, E2E key exchange, data) assumes
reliable, in-order delivery. This transport bridges that gap with a lightweight
reliability layer on top of asyncio datagram sockets:

- Sequence numbers + cumulative/selective ACKs
- Retransmission with exponential backoff
- Reordering buffer (bounded)
- Keepalive frames to maintain NAT mappings

Because it speaks the same ``BaseTransport`` / ``BaseServer`` interface as TCP,
the whole mesh — invite, handshake, routing, E2E — runs over it unchanged.

A single ``UDPServer`` binds one UDP socket and multiplexes all peer transports
through a dispatch table keyed by ``(ip, port)``. Incoming datagrams from an
unknown source create a new ``UDPTransport`` and trigger
``on_new_connection`` — exactly like a TCP accept loop.

Robustness (see CLAUDE.md): every buffer is bounded, every frame is
structurally validated, and hostile datagrams are counted and dropped — never
crashing the receive loop.
"""
from __future__ import annotations

import asyncio
import os
import socket
import struct
import time

from .transport import BaseTransport, BaseServer
from .packet import Packet
from .ip_utils import split_host_port

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
_MAX_SEND_QUEUE = 128       # max packets waiting to be framed and sent
_RTO_MIN = 0.050            # initial retransmit timeout, seconds
_RTO_MAX = 2.0              # max retransmit timeout after backoff
_RTX_CHECK = 0.020          # retransmit check interval
_KEEPALIVE_INTERVAL = 25.0  # NAT mapping refresh, seconds
_KEEPALIVE_TIMEOUT = 15.0   # 3 missed keepalives → dead link
_ACK_DELAY = 0.010          # max delay before sending a standalone ACK
_RECV_TIMEOUT = 120.0       # overall receive inactivity timeout


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


class _ReliableLink:
    """
    Reliability state for one direction of a UDP transport.

    Manages sequence numbers, retransmission, ACK tracking, and reordering.
    Both send and receive sides are encapsulated here so UDPTransport stays
    thin.
    """

    def __init__(self) -> None:
        # Send side
        self._send_seq: int = 0
        self._unacked: dict[int, tuple[bytes, float]] = {}  # seq → (frame, rto_deadline)
        self._send_queue: asyncio.Queue[Packet | None] = asyncio.Queue(_MAX_SEND_QUEUE)
        self._send_event: asyncio.Event = asyncio.Event()
        self._rto: float = _RTO_MIN

        # Receive side
        self._recv_next: int = 0          # next expected seq to deliver in-order
        self._reorder: dict[int, bytes] = {}  # seq → payload (out-of-order buffer)
        self._recv_seen: set[int] = set()  # all seqs received (for SACK bitmap)
        self._max_recv_seen: int = -1     # highest seq ever received

        # ACK coalescing
        self._ack_pending: bool = False
        self._ack_timer: asyncio.Task | None = None

        # Keepalive
        self._last_recv_time: float = time.monotonic()
        self._keepalive_misses: int = 0

    # -- send side --------------------------------------------------------

    def enqueue(self, packet: Packet) -> bool:
        """Queue a packet for sending. Returns False if the queue is full."""
        try:
            self._send_queue.put_nowait(packet)
            self._send_event.set()
            return True
        except asyncio.QueueFull:
            return False

    def build_frame(self, packet: Packet) -> bytes:
        """Build a data frame for the given packet and track it for retransmit."""
        payload = packet.pack()
        seq = self._send_seq
        self._send_seq = (self._send_seq + 1) & 0xFFFFFFFF
        ack, sack = self._build_ack()
        header = _FRAME.pack(seq, ack, sack, FLAG_DATA, len(payload))
        frame = _MAGIC + header + payload
        if len(self._unacked) < _MAX_UNACKED:
            self._unacked[seq] = (frame, time.monotonic() + self._rto)
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
        """Build cumulative ack + selective ack bitmap."""
        ack = (self._recv_next - 1) & 0xFFFFFFFF
        sack = 0
        base = self._recv_next
        for seq in self._reorder:
            offset = (seq - base) & 0xFFFFFFFF
            if 0 < offset <= 32:
                sack |= (1 << (offset - 1))
        return ack, sack

    def process_ack(self, ack: int, sack: int) -> None:
        """Process incoming ACK + SACK, removing acknowledged frames.

        Cumulative ACK means all frames with seq <= ack have been received.
        We use unsigned wraparound distance: a frame s is cumulatively ACKed
        if the forward distance (ack - s) mod 2^32 is small (< _MAX_UNACKED).
        """
        for s in list(self._unacked.keys()):
            dist = (ack - s) & 0xFFFFFFFF
            if dist < _MAX_UNACKED:
                del self._unacked[s]

        # Selective ACK: bits indicate seqs received above the cumulative ack
        base = (ack + 1) & 0xFFFFFFFF
        for i in range(32):
            if sack & (1 << i):
                seq = (base + i) & 0xFFFFFFFF
                self._unacked.pop(seq, None)

        # Reset RTO on successful ACK
        if not self._unacked:
            self._rto = _RTO_MIN
        elif self._rto > _RTO_MIN:
            self._rto = max(_RTO_MIN, self._rto * 0.5)

    def get_retransmit_frames(self) -> list[bytes]:
        """Return frames that have exceeded their RTO deadline for retransmit."""
        now = time.monotonic()
        frames: list[bytes] = []
        for seq, (frame, deadline) in list(self._unacked.items()):
            if now >= deadline:
                self._unacked[seq] = (frame, now + min(self._rto * 2, _RTO_MAX))
                self._rto = min(self._rto * 2, _RTO_MAX)
                frames.append(frame)
        return frames

    # -- receive side -----------------------------------------------------

    def process_incoming(self, seq: int, flags: int, payload: bytes) -> list[bytes]:
        """
        Process an incoming frame. Returns list of deliverable payloads
        (in-order, possibly multiple if reordering gap was filled).
        Empty list if the frame is a duplicate, ACK-only, or out-of-order
        pending.
        """
        self._last_recv_time = time.monotonic()
        self._keepalive_misses = 0

        if flags & (FLAG_ACK_ONLY | FLAG_KEEPALIVE | FLAG_FIN):
            return []  # no data payload to deliver

        # Duplicate check
        if seq in self._recv_seen:
            return []

        self._recv_seen.add(seq)
        if seq > self._max_recv_seen or self._max_recv_seen < 0:
            self._max_recv_seen = seq

        # In-order: deliver immediately and flush any buffered successors
        if seq == self._recv_next:
            self._recv_next = (self._recv_next + 1) & 0xFFFFFFFF
            delivered: list[bytes] = [payload]
            # Flush consecutive buffered frames
            while self._recv_next in self._reorder:
                delivered.append(self._reorder.pop(self._recv_next))
                self._recv_next = (self._recv_next + 1) & 0xFFFFFFFF
            self._schedule_ack()
            return delivered

        # Out-of-order: buffer if space available
        if len(self._reorder) < _MAX_REORDER:
            self._reorder[seq] = payload
        self._schedule_ack()
        return []

    def needs_ack(self) -> bool:
        return self._ack_pending

    def _schedule_ack(self) -> None:
        self._ack_pending = True

    def clear_ack_pending(self) -> None:
        self._ack_pending = False

    def is_alive(self) -> bool:
        """Check if the link is still alive based on keepalive timing."""
        return (time.monotonic() - self._last_recv_time) < _KEEPALIVE_TIMEOUT

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

    def __init__(self, sock: asyncio.DatagramTransport | None = None,
                 remote_addr: tuple[str, int] | None = None) -> None:
        super().__init__()
        self._sock: asyncio.DatagramTransport | None = sock
        self._remote: tuple[str, int] | None = remote_addr
        self._link = _ReliableLink()
        self._decoded: list[Packet] = []
        self._closed: bool = False
        self._rtx_task: asyncio.Task | None = None
        self._keepalive_task: asyncio.Task | None = None
        self._send_task: asyncio.Task | None = None
        # When True, this transport owns its socket (connect path) and must
        # close it. When False, the socket is shared (server path).
        self._owns_socket: bool = False
        # Callback set by the server to feed raw datagrams into this transport
        self._on_datagram = None

    @classmethod
    def _from_server(cls, sock: asyncio.DatagramTransport,
                     remote_addr: tuple[str, int]) -> "UDPTransport":
        """Create a transport for an incoming connection accepted by the server."""
        t = cls(sock, remote_addr)
        t._owns_socket = False
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

        # Process ACK info
        self._link.process_ack(ack, sack)

        # Process data payload
        if flags & FLAG_DATA and payload:
            delivered = self._link.process_incoming(seq, flags, payload)
            for raw in delivered:
                try:
                    self._decoded.append(Packet.unpack(raw))
                except Exception:
                    pass  # hostile payload — drop, keep the link alive

        # Send a piggybacked or standalone ACK if needed
        if self._link.needs_ack():
            self._link.clear_ack_pending()
            self._send_raw(self._link.build_ack_only())

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
            raise ConnectionError("udp transport closed")
        if self._sock is None or self._remote is None:
            raise ConnectionError("udp transport not connected")
        if not self._link.enqueue(packet):
            raise ConnectionError("udp send queue full")

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

    async def _keepalive_loop(self) -> None:
        """Background task: send keepalives and detect dead links."""
        while not self._closed:
            await asyncio.sleep(_KEEPALIVE_INTERVAL)
            if self._closed:
                break
            self._send_raw(self._link.build_keepalive())
            if not self._link.is_alive():
                self._closed = True
                break

    async def receive(self) -> Packet:
        """Block until a packet is received and return it."""
        while True:
            if self._decoded:
                return self._decoded.pop(0)
            if self._closed:
                raise ConnectionError("udp transport closed")
            await asyncio.sleep(0.01)

    def remote_ip(self) -> str | None:
        """The peer's source IP as observed locally."""
        if self._remote is None:
            return None
        return str(self._remote[0]).split("%", 1)[0]

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
        # Send FIN to signal graceful close
        if self._sock is not None and self._remote is not None:
            try:
                self._send_raw(self._link.build_fin())
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

    def reachability(self, uri: str, ctx: dict) -> list[dict]:
        from .ip_utils import ip_reachability
        return ip_reachability(
            "udp", uri, ctx.get("local_ips", []), ctx.get("public_addrs", []),
            "udp" in ctx.get("inbound_schemes", ()))

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
            # New peer — create a transport and notify
            if self._closed or self.on_new_connection is None:
                return
            if len(self._transports) >= _MAX_PEERS_UDP:
                return  # bounded — reject new peers when full
            transport = UDPTransport._from_server(self._sock, addr)
            self._transports[addr] = transport
            transport._start_tasks()
            asyncio.create_task(self._safe_on_new_connection(transport))
        transport.feed_datagram(data, addr)

    async def _safe_on_new_connection(self, transport: UDPTransport) -> None:
        try:
            if self.on_new_connection is not None:
                await self.on_new_connection(transport)
        except Exception:
            pass

    def remove_transport(self, addr: tuple[str, int]) -> None:
        """Remove a transport from the dispatch table (called on close)."""
        self._transports.pop(addr, None)

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