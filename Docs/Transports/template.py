"""
Template for writing your own NMesh transport.

Copy this file, rename the classes, implement the abstract methods. The TODO
comments say what you have to write.
"""
import asyncio
from src.transport import BaseTransport, BaseServer
from src.packet import Packet


# ---------------------------------------------------------------------------
# 1. Transport (one connection)
# ---------------------------------------------------------------------------

class MyTransport(BaseTransport):
    """
    A point-to-point transport over [your medium].

    The contract:
    - send() sends exactly one Packet, receive() returns exactly one.
    - If the medium is a stream (TCP, UART...), you must implement framing.
    - If the medium is datagram-based (UDP, LoRa...), no framing is needed.
    """

    def __init__(self) -> None:
        super().__init__()
        # TODO: initialise your resources (socket, handle, file descriptor…)

    async def connect(self, address: str) -> None:
        """Open an outbound connection to `address`."""
        # TODO: parse the address and open the connection
        # TCP example: host, port = address.rsplit(':', 1)
        raise NotImplementedError

    async def listen(self, address: str) -> None:
        """Listen on `address` and wait for one inbound connection (blocking)."""
        # Optional if you use MyServer for the multi-connection case.
        # Implement it if you need the single-connection mode.
        raise NotImplementedError

    async def send(self, packet: Packet) -> None:
        """Serialise and send the packet."""
        data = packet.pack()
        # TODO: stream → prefix the size
        #   frame = struct.pack('!H', len(data)) + data
        #   await self._writer.write(frame)
        # TODO: datagram → send it directly
        raise NotImplementedError

    async def receive(self) -> Packet:
        """Block until a packet arrives, and return it."""
        # TODO: stream → read the size prefix, then the N bytes
        #   length = struct.unpack('!H', await read(2))[0]
        #   data = await read(length)
        # TODO: datagram → read one whole datagram
        # Then deserialise:
        #   return Packet.unpack(data)
        raise NotImplementedError

    async def close(self) -> None:
        """Close the connection and release the resources."""
        # TODO: close the socket/handle cleanly
        raise NotImplementedError


# ---------------------------------------------------------------------------
# 2. Server (several inbound connections)
# ---------------------------------------------------------------------------

class MyServer(BaseServer):
    """
    A [your medium] server: listens and creates one MyTransport per accepted
    client.

    After listen(), every new connection triggers:
        await self.on_new_connection(transport)
    where `transport` is an already connected MyTransport instance.
    """

    def __init__(self) -> None:
        super().__init__()
        # TODO: initialise your server resources

    async def listen(self, address: str) -> None:
        """Start listening — returns as soon as the bind is done."""
        # TODO: bind the address and start the accept loop in the background
        #
        # asyncio TCP example:
        #   self._server = await asyncio.start_server(_accept, host, port)
        #
        # async def _accept(reader, writer):
        #     transport = MyTransport._from_accepted(reader, writer)
        #     if self.on_new_connection:
        #         await self.on_new_connection(transport)
        raise NotImplementedError

    async def close(self) -> None:
        """Stop accepting new connections."""
        # TODO: close the server cleanly
        raise NotImplementedError


# ---------------------------------------------------------------------------
# 3. Registering it with MeshNode
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import asyncio
    from src import MeshNode

    async def demo():
        # The host node
        host = MeshNode(
            transport_factory=MyTransport,
            server_factory=MyServer,
        )
        code = host.generate_invite()
        await host.start("mine://address:1234")

        # The invited node
        guest = MeshNode(
            transport_factory=MyTransport,
            server_factory=MyServer,
        )
        await guest.join("mine://address:1234", code)
        await guest.wait_for_session(timeout=10.0)

        await guest.send_data(b"hello over my transport")
        data = await host.receive_data()
        print(f"received: {data}")

        await guest.stop()
        await host.stop()

    asyncio.run(demo())


# ---------------------------------------------------------------------------
# 4. An in-memory transport (handy for unit tests)
# ---------------------------------------------------------------------------

class InMemoryTransport(BaseTransport):
    """
    An in-memory transport — two instances wired together by asyncio queues.
    Handy for testing the logic without a real network.

    Usage:
        a, b = InMemoryTransport.make_pair()
        # a.send() → b.receive(), b.send() → a.receive()
    """

    def __init__(self) -> None:
        super().__init__()
        self._inbox: asyncio.Queue[Packet] = asyncio.Queue()
        self._other: 'InMemoryTransport | None' = None

    @classmethod
    def make_pair(cls) -> tuple['InMemoryTransport', 'InMemoryTransport']:
        a, b = cls(), cls()
        a._other = b
        b._other = a
        return a, b

    async def connect(self, address: str) -> None:
        pass  # already connected through make_pair()

    async def listen(self, address: str) -> None:
        pass

    async def send(self, packet: Packet) -> None:
        if self._other is None:
            raise ConnectionError("not paired")
        await self._other._inbox.put(packet)

    async def receive(self) -> Packet:
        return await self._inbox.get()

    async def close(self) -> None:
        pass
