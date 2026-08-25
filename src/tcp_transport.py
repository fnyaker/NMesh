import asyncio
import struct
from .transport import BaseTransport, BaseServer, option
from .packet import Packet
from .ip_utils import split_host_port

_FRAME = struct.Struct('!H')
_READ_TIMEOUT = 60.0
# A dial to an unreachable address (a NATted peer's private IP learned via
# gossip, a dead host) must fail fast: with no cap, the OS SYN timeout holds
# the caller — _ensure_route_to / join-block tries — for minutes.
_CONNECT_TIMEOUT = 4.0


def _host_port(address: str) -> tuple[str, int]:
    """Parse host:port (IPv6-safe). Raises ValueError on malformed input."""
    hp = split_host_port(address)
    if hp is None:
        raise ValueError(f"invalid address: {address!r}")
    host, port = hp
    return host, int(port)


async def _wait_closed_bounded(obj) -> None:
    """Bounded ``wait_closed()``.

    Python 3.12 changed ``asyncio.Server.wait_closed()`` to block until every
    accepted client connection also closes, not just the listening socket. When
    we stop listening (or close a link) while a peer is still connected, that
    never returns and wedges the caller. ``close()`` has already closed the
    listening socket — all that matters here — so wait briefly and move on."""
    try:
        await asyncio.wait_for(obj.wait_closed(), timeout=1.0)
    except (asyncio.TimeoutError, Exception):
        pass


class TCPTransport(BaseTransport):

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
        try:
            import socket as _socket
            socket_object.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY,
                                     1 if self.setting("nodelay") else 0)
        except Exception:
            pass          # a medium that cannot take the hint still works

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
        if self._writer is None:
            raise ConnectionError("not connected")
        data = packet.pack()
        self._writer.write(_FRAME.pack(len(data)) + data)
        await self._writer.drain()

    async def receive(self) -> Packet:
        if self._reader is None:
            raise ConnectionError("not connected")
        # asyncio.timeout (not wait_for): wait_for can *lose* an outer
        # cancellation when its inner read completes in the same loop step, so a
        # cancelled receive loop would silently re-block instead of exiting —
        # wedging peer shutdown. asyncio.timeout propagates cancellation cleanly.
        try:
            async with asyncio.timeout(self.setting("read_timeout")):
                raw_len = await self._reader.readexactly(_FRAME.size)
                length = _FRAME.unpack(raw_len)[0]
                data = await self._reader.readexactly(length)
        except asyncio.TimeoutError:
            raise ConnectionError("read timeout")
        return Packet.unpack(data)

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
        return detail

    async def close(self) -> None:
        if self._writer:
            self._writer.close()
            await _wait_closed_bounded(self._writer)
        if self._server:
            self._server.close()
            await _wait_closed_bounded(self._server)


class TCPServer(BaseServer):
    """Accepts multiple incoming TCP connections — crée un TCPTransport par client."""

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
        from .ip_utils import ip_reachability
        return ip_reachability(
            "tcp", uri, ctx.get("local_ips", []), ctx.get("public_addrs", []),
            "tcp" in ctx.get("inbound_schemes", ()))

    async def close(self) -> None:
        if self._server:
            self._server.close()
            await _wait_closed_bounded(self._server)
