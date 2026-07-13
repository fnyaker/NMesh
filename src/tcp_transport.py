import asyncio
import struct
from .transport import BaseTransport, BaseServer
from .packet import Packet
from .ip_utils import split_host_port

_FRAME = struct.Struct('!H')
_READ_TIMEOUT = 60.0


def _host_port(address: str) -> tuple[str, int]:
    """Parse host:port (IPv6-safe). Raises ValueError on malformed input."""
    hp = split_host_port(address)
    if hp is None:
        raise ValueError(f"invalid address: {address!r}")
    host, port = hp
    return host, int(port)


class TCPTransport(BaseTransport):

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
        return t

    async def connect(self, address: str) -> None:
        host, port = _host_port(address)
        self._reader, self._writer = await asyncio.open_connection(host, port)

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
        try:
            raw_len = await asyncio.wait_for(
                self._reader.readexactly(_FRAME.size), _READ_TIMEOUT)
            length = _FRAME.unpack(raw_len)[0]
            data = await asyncio.wait_for(
                self._reader.readexactly(length), _READ_TIMEOUT)
        except asyncio.TimeoutError:
            raise ConnectionError("read timeout")
        return Packet.unpack(data)

    async def close(self) -> None:
        if self._writer:
            self._writer.close()
            await self._writer.wait_closed()
        if self._server:
            self._server.close()
            await self._server.wait_closed()


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

    async def close(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
