import asyncio
from .transport import BaseTransport
from .packet import Packet


class TransportError(Exception):
    pass


class TransportManager:

    def __init__(self) -> None:
        self._transport: BaseTransport | None = None
        self._queue: asyncio.Queue[Packet] = asyncio.Queue()
        self._task: asyncio.Task | None = None

    def register(self, transport: BaseTransport) -> None:
        if self._transport is not None:
            raise TransportError("a transport is already registered")
        self._transport = transport

    def unregister(self) -> None:
        self._transport = None

    async def start(self) -> None:
        if self._transport is None:
            raise TransportError("no transport registered")
        self._task = asyncio.create_task(self._receive_loop())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        if self._transport is not None:
            await self._transport.close()

    async def send(self, packet: Packet) -> None:
        if self._transport is None:
            raise TransportError("no transport registered")
        await self._transport.send(packet)

    async def receive(self) -> Packet:
        return await self._queue.get()

    async def _receive_loop(self) -> None:
        try:
            while True:
                packet = await self._transport.receive()
                await self._queue.put(packet)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
