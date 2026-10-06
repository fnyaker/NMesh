import asyncio
import struct
from .contract import BaseTransport, BaseServer, LinkBusy, option
from ..packet import Packet
from ..ip_utils import split_host_port, wait_closed_bounded

_FRAME = struct.Struct('!H')
_READ_TIMEOUT = 60.0
# A dial to an unreachable address (a NATted peer's private IP learned via
# gossip, a dead host) must fail fast: with no cap, the OS SYN timeout holds
# the caller — _ensure_route_to / join-block tries — for minutes.
_CONNECT_TIMEOUT = 4.0
# How long a send may wait for the socket to have room before the packet is
# refused (`LinkBusy`). There was no bound at all: a peer that stopped reading
# held every coroutine writing to it for as long as it liked — the keepalive
# loop probing every *other* link included, and the receive loop of any link
# forwarding through this one. Same figure as the UDP queue's wait.
_SEND_WAIT = 10.0
# asyncio's own default high-water mark, for a transport that will not say.
_HIGH_WATER = 64 * 1024
# How much *unsent* data the kernel may hold for one link (TCP_NOTSENT_LOWAT),
# in kB. Left alone, Linux holds up to `tcp_wmem`'s ceiling — 4 MB — and a probe
# queued behind that waits four seconds on a 1 MB/s uplink: past the deadline
# that calls it lost, on a link that has lost nothing. Bounded here, the backlog
# waits in the node's own buffer, where `send` sees it and pushes back.
_UNSENT_KB = 128


# The head of Linux's `struct tcp_info`: eight bytes, then twenty-four u32 up to
# `tcpi_total_retrans`. That prefix has not moved since 2.6; newer kernels only
# append, so asking for exactly this many bytes reads the same fields on all.
_TCP_INFO = struct.Struct("8B24I")


def _kernel_view(sock) -> dict:
    """What the kernel knows about this connection and the node does not: its
    own round-trip estimate, how much it had to resend, how much it is holding.
    Retransmissions climbing on a link whose probes look fine is a lossy path,
    and nothing above the socket can see it. Linux only; elsewhere, nothing."""
    import socket as _socket
    out: dict = {}
    option = getattr(_socket, "TCP_INFO", None)
    if option is not None:
        try:
            raw = sock.getsockopt(_socket.IPPROTO_TCP, option, _TCP_INFO.size)
            if len(raw) >= _TCP_INFO.size:
                info = _TCP_INFO.unpack_from(raw)
                words = info[8:]
                out["kernel rtt ms"] = round(words[15] / 1000, 1)
                out["kernel retransmits"] = words[23]
                out["kernel lost"] = words[6]
                out["kernel cwnd"] = words[18]
        except Exception:
            pass
    try:
        import fcntl
        import termios
        queued = fcntl.ioctl(sock.fileno(), termios.TIOCOUTQ, b"\0" * 4)
        out["kernel queue"] = struct.unpack("i", queued)[0]
    except Exception:
        pass
    return out


def _host_port(address: str) -> tuple[str, int]:
    """Parse host:port (IPv6-safe). Raises ValueError on malformed input."""
    hp = split_host_port(address)
    if hp is None:
        raise ValueError(f"invalid address: {address!r}")
    host, port = hp
    return host, int(port)


class TCPTransport(BaseTransport):

    SCHEME = "tcp"

    # Everything here is read where it is used, so a change applies to the next
    # dial or the next read — no restart, no reconnection.
    OPTIONS = (
        option("connect_timeout", "float", _CONNECT_TIMEOUT,
               "How long a dial may take before the address is given up on. "
               "Low on purpose: unreachable addresses are the normal case.",
               minimum=0.5, maximum=60.0, unit="s"),
        option("read_timeout", "float", _READ_TIMEOUT,
               "A link silent for this long is treated as dead. Must stay above "
               "the keepalive interval, or healthy links get reaped.",
               minimum=5.0, maximum=600.0, unit="s"),
        option("nodelay", "bool", True,
               "Send small packets immediately instead of coalescing them "
               "(TCP_NODELAY). Off trades latency for a few bytes."),
        option("unsent_limit", "int", _UNSENT_KB,
               "How much data waiting to leave the kernel may hold per link "
               "(TCP_NOTSENT_LOWAT). Small keeps a probe from queueing behind "
               "megabytes of bulk data on a slow uplink — which reads as loss "
               "and gets a working link replaced. Zero leaves the kernel's "
               "own limit; ignored where the system has no such option.",
               minimum=0, maximum=4096, unit="kB", label="unsent limit"),
        option("families", "multi", ["ipv4", "ipv6"],
               "Which address families outgoing connections may use. Dropping "
               "IPv6 is the usual fix on a network that advertises it and does "
               "not route it.",
               choices=[{"value": "ipv4", "label": "IPv4"},
                        {"value": "ipv6", "label": "IPv6"}]),
        option("priority", "int", 0,
               "How much this node prefers TCP over another medium, from "
               "-254 to 254. Weighed against measured latency; the balance "
               "between the two is set once for the node, under Reachability.",
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
               "each of its TCP addresses. Zero switches it off: nothing "
               "is retried until something needs a route. Raise it on a link "
               "that drops and comes back on its own; leave it off where a dial "
               "costs more than waiting.",
               minimum=0.0, maximum=3600.0, unit="s", label="retry interval"),
        option("source_address", "text", "",
               "Local address outgoing connections bind to. Empty lets the "
               "kernel choose; set it to pin traffic to one interface.",
               placeholder="192.168.1.20"),
    )
    SETTINGS: dict = {}

    def __init__(self) -> None:
        super().__init__()
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._server: asyncio.Server | None = None
        self._high_water: int | None = None
        # Why this link ended. See `BaseTransport.end_reason`.
        self._end_reason: str = ""
        self._busy_noted_at: float = -_SEND_WAIT

    @classmethod
    def _from_accepted(cls, reader: asyncio.StreamReader,
                       writer: asyncio.StreamWriter) -> 'TCPTransport':
        t = cls()
        t._reader = reader
        t._writer = writer
        t._apply_nodelay()
        return t

    def _apply_nodelay(self) -> None:
        socket_object = self._writer.get_extra_info("socket") if self._writer else None
        if socket_object is None:
            return
        import socket as _socket
        try:
            socket_object.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY,
                                     1 if self.setting("nodelay") else 0)
        except Exception:
            pass          # a medium that cannot take the hint still works
        unsent = int(self.setting("unsent_limit") or 0)
        lowat = getattr(_socket, "TCP_NOTSENT_LOWAT", None)
        if unsent > 0 and lowat is not None:
            try:
                socket_object.setsockopt(_socket.IPPROTO_TCP, lowat,
                                         unsent * 1024)
            except Exception:
                pass      # same: a hint, never a requirement

    @classmethod
    def _family(cls):
        import socket
        chosen = cls.setting("families") or ["ipv4", "ipv6"]
        if "ipv6" not in chosen:
            return socket.AF_INET
        if "ipv4" not in chosen:
            return socket.AF_INET6
        return socket.AF_UNSPEC

    async def connect(self, address: str) -> None:
        host, port = _host_port(address)
        source = self.setting("source_address") or None
        # asyncio.timeout (not wait_for): cancellation must propagate, and a
        # hanging dial must raise TimeoutError, not linger (see gotchas 3b).
        async with asyncio.timeout(self.setting("connect_timeout")):
            self._reader, self._writer = await asyncio.open_connection(
                host, port, family=self._family(),
                local_addr=(source, 0) if source else None)
        self._apply_nodelay()

    async def listen(self, address: str) -> None:
        host, port = _host_port(address)
        connected = asyncio.Event()

        async def _accept(reader, writer):
            self._reader = reader
            self._writer = writer
            connected.set()
            if self.on_connect is not None:
                await self.on_connect()

        self._server = await asyncio.start_server(_accept, host, port, reuse_address=True)
        await connected.wait()

    async def send(self, packet: Packet) -> None:
        writer = self._writer
        if writer is None:
            raise ConnectionError("not connected")
        if writer.transport.is_closing():
            raise ConnectionError(self._end_reason or "the tcp link is closed")
        data = packet.pack()
        # Room first, then the write — and room is waited for with a bound. In
        # that order a refused packet is one that never touched the stream, so
        # a frame can never be half-written by a cancellation or a timeout, and
        # what the buffer holds stays within one packet of the high-water mark.
        # Below the mark there is nothing to wait for and nothing is awaited:
        # this is the path of every packet.
        if writer.transport.get_write_buffer_size() > self._high():
            try:
                async with asyncio.timeout(_SEND_WAIT):
                    await writer.drain()
            except TimeoutError:
                self._note_busy(writer)
                raise LinkBusy("tcp send buffer full") from None
        # writelines, not `prefix + data`: the concatenation copied the whole
        # payload — up to 60 kB — once more per packet, for the sake of a
        # two-byte length. The asyncio transport gathers these without an
        # intermediate buffer, and TCP_NODELAY is already set so this does not
        # cost an extra segment.
        writer.writelines((_FRAME.pack(len(data)), data))

    def _high(self) -> int:
        if self._high_water is None:
            try:
                self._high_water = int(
                    self._writer.transport.get_write_buffer_limits()[1])
            except Exception:
                self._high_water = _HIGH_WATER
        return self._high_water

    def _note_busy(self, writer) -> None:
        now = asyncio.get_running_loop().time()
        if now - self._busy_noted_at < _SEND_WAIT:
            return
        self._busy_noted_at = now
        try:
            held = writer.transport.get_write_buffer_size()
        except Exception:
            held = None
        self.note("send refused: the peer is not reading", "warn",
                  waited_s=_SEND_WAIT, buffered_bytes=held)

    def end_reason(self) -> str:
        return self._end_reason

    async def receive(self) -> Packet:
        if self._reader is None:
            raise ConnectionError("not connected")
        # asyncio.timeout (not wait_for): wait_for can *lose* an outer
        # cancellation when its inner read completes in the same loop step, so a
        # cancelled receive loop would silently re-block instead of exiting —
        # wedging peer shutdown. asyncio.timeout propagates cancellation cleanly.
        timeout = self.setting("read_timeout")
        try:
            async with asyncio.timeout(timeout):
                raw_len = await self._reader.readexactly(_FRAME.size)
                length = _FRAME.unpack(raw_len)[0]
                data = await self._reader.readexactly(length)
        except asyncio.TimeoutError:
            self._end_reason = (f"nothing received for {float(timeout):.0f} s "
                                f"(tcp read timeout)")
            raise ConnectionError(self._end_reason) from None
        except asyncio.IncompleteReadError as exc:
            self._end_reason = ("the connection ended in the middle of a frame"
                                if exc.partial else
                                "the peer closed the connection")
            raise ConnectionError(self._end_reason) from None
        except (ConnectionError, OSError) as exc:
            self._end_reason = self._end_reason or (
                f"connection error: {type(exc).__name__}"
                + (f" ({exc.strerror})" if getattr(exc, "strerror", None) else ""))
            raise
        return Packet.unpack(data)

    def idle_timeout(self) -> float | None:
        """A TCP read with nothing on it for this long raises, and the link is
        reaped. It is the same number `receive()` waits on, read off the
        setting rather than copied — one value, one place."""
        return float(self.setting("read_timeout") or 0.0) or None

    def remote_ip(self) -> str | None:
        if self._writer is None:
            return None
        peer = self._writer.get_extra_info("peername")
        if not peer:
            return None
        return str(peer[0]).split("%", 1)[0]   # drop IPv6 scope id

    def endpoints(self) -> dict:
        if self._writer is None:
            return {"local": None, "remote": None}

        def name(kind):
            info = self._writer.get_extra_info(kind)
            if not info:
                return None
            host = str(info[0]).split("%", 1)[0]
            return f"tcp://[{host}]:{info[1]}" if ":" in host else f"tcp://{host}:{info[1]}"

        return {"local": name("sockname"), "remote": name("peername")}

    def stats(self) -> dict:
        """What the kernel is holding for us. The write buffer is the useful
        one: a number that stays high means this peer is not draining, which no
        packet counter shows."""
        if self._writer is None:
            return {}
        detail = {}
        try:
            detail["send buffer"] = self._writer.transport.get_write_buffer_size()
        except Exception:
            pass
        socket_object = self._writer.get_extra_info("socket")
        if socket_object is not None:
            try:
                import socket as _socket
                detail["nodelay"] = bool(socket_object.getsockopt(
                    _socket.IPPROTO_TCP, _socket.TCP_NODELAY))
            except Exception:
                pass
            detail.update(_kernel_view(socket_object))
        return detail

    async def close(self) -> None:
        self._end_reason = self._end_reason or "closed by this node"
        if self._writer:
            self._writer.close()
            await wait_closed_bounded(self._writer)
        if self._server:
            self._server.close()
            await wait_closed_bounded(self._server)


class TCPServer(BaseServer):
    """Accepts multiple incoming TCP connections — one TCPTransport per client."""

    def __init__(self) -> None:
        super().__init__()
        self._server: asyncio.Server | None = None

    async def listen(self, address: str) -> None:
        host, port = _host_port(address)

        async def _accept(reader, writer):
            transport = TCPTransport._from_accepted(reader, writer)
            if self.on_new_connection is not None:
                await self.on_new_connection(transport)

        self._server = await asyncio.start_server(_accept, host, port, reuse_address=True)

    def reachability(self, uri: str, ctx: dict) -> list[dict]:
        from ..ip_utils import ip_reachability
        return ip_reachability(
            "tcp", uri, ctx.get("local_ips", []), ctx.get("public_addrs", []),
            "tcp" in ctx.get("inbound_schemes", ()),
            "tcp" in ctx.get("public_schemes", ()))

    async def close(self) -> None:
        if self._server:
            self._server.close()
            await wait_closed_bounded(self._server)
