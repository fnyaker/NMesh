import asyncio
import pytest
from src.transport import BaseTransport
from src.packet import Packet
from src.node import MeshNode


class FakeTransport(BaseTransport):
    def __init__(self) -> None:
        super().__init__()
        self.sent: list[Packet] = []
        self._queue: asyncio.Queue[Packet] = asyncio.Queue()

    async def connect(self, address: str) -> None: ...
    async def listen(self, address: str) -> None: ...
    async def close(self) -> None: ...

    async def send(self, packet: Packet) -> None:
        self.sent.append(packet)

    async def receive(self) -> Packet:
        return await self._queue.get()

    def inject(self, packet: Packet) -> None:
        self._queue.put_nowait(packet)


async def make_node() -> tuple[MeshNode, FakeTransport]:
    fake = FakeTransport()
    node = MeshNode()
    await node._inject_peer(fake)
    return node, fake
