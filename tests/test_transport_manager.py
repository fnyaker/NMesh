import asyncio
import pytest
from src.transport_manager import TransportManager, TransportError
from src.transport import BaseTransport
from src.packet import Packet

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


class FakeTransport(BaseTransport):
    def __init__(self) -> None:
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


class TestTransportManager:
    async def test_send(self):
        tm = TransportManager()
        fake = FakeTransport()
        tm.register(fake)
        p = make_packet()
        await tm.send(p)
        assert fake.sent == [p]

    async def test_receive(self):
        tm = TransportManager()
        fake = FakeTransport()
        tm.register(fake)
        await tm.start()
        p = make_packet()
        fake.inject(p)
        received = await asyncio.wait_for(tm.receive(), timeout=1.0)
        assert received.pack() == p.pack()
        await tm.stop()

    async def test_double_register_raises(self):
        tm = TransportManager()
        tm.register(FakeTransport())
        with pytest.raises(TransportError):
            tm.register(FakeTransport())

    async def test_send_no_transport_raises(self):
        tm = TransportManager()
        with pytest.raises(TransportError):
            await tm.send(make_packet())

    async def test_start_no_transport_raises(self):
        tm = TransportManager()
        with pytest.raises(TransportError):
            await tm.start()

    async def test_unregister_then_reregister(self):
        tm = TransportManager()
        fake = FakeTransport()
        tm.register(fake)
        tm.unregister()
        fake2 = FakeTransport()
        tm.register(fake2)
        p = make_packet()
        await tm.send(p)
        assert fake2.sent == [p]
        assert fake.sent == []

    async def test_stop_cancels_loop(self):
        tm = TransportManager()
        tm.register(FakeTransport())
        await tm.start()
        await tm.stop()
        assert tm._task is None
