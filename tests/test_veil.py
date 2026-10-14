"""
``veil://``: what a censor or a prober sees, and that a mesh link still works.

The properties are about the wire, so these tests put a recording relay between
the two ends and a raw socket where a prober would be.
"""
import asyncio
import math
import os
import time
from collections import Counter

import pytest

from src.packet import Packet
from src.transports import veil
from src.transports.veil import VeilServer, VeilTransport

KEY = "a shared phrase of the circle"


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setattr(VeilTransport, "SETTINGS", {"key": KEY})
    monkeypatch.setattr(veil, "HELLO_TIMEOUT", 2.0)


def _packet(size=64):
    return Packet.create(0x20, os.urandom(20), os.urandom(20), os.urandom(size))


async def _serve():
    arrived: asyncio.Queue = asyncio.Queue()
    server = VeilServer()

    async def on_new(transport):
        await arrived.put(transport)
    server.on_new_connection = on_new
    await server.listen("127.0.0.1:0")
    return server, server._server.sockets[0].getsockname()[1], arrived


class _Relay:
    """Forwards bytes both ways and keeps a copy, in order, of what crossed."""

    def __init__(self, target_port):
        self.target, self.seen, self.server = target_port, {"up": b"", "down": b""}, None
        self.port = None

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _handle(self, reader, writer):
        up_r, up_w = await asyncio.open_connection("127.0.0.1", self.target)

        async def pump(src, dst, name):
            try:
                while data := await src.read(4096):
                    self.seen[name] += data
                    dst.write(data)
                    await dst.drain()
            except OSError:
                pass
            finally:
                dst.close()
        await asyncio.gather(pump(reader, up_w, "up"), pump(up_r, writer, "down"))

    async def stop(self):
        self.server.close()


def _entropy(data: bytes) -> float:
    counts = Counter(data)
    return -sum(n / len(data) * math.log2(n / len(data)) for n in counts.values())


class TestALinkWorks:
    async def test_packets_cross_both_ways(self):
        server, port, arrived = await _serve()
        client = VeilTransport()
        try:
            await client.connect(f"127.0.0.1:{port}")
            accepted = await asyncio.wait_for(arrived.get(), 3)
            sent = _packet()
            await client.send(sent)
            assert (await asyncio.wait_for(accepted.receive(), 3)).pack() == sent.pack()
            back = _packet(900)
            await accepted.send(back)
            assert (await asyncio.wait_for(client.receive(), 3)).pack() == back.pack()
            assert client.scheme() == "veil" and accepted.scheme() == "veil"
        finally:
            await client.close()
            await server.close()


class TestWhatTheWireShows:
    async def test_nothing_on_it_is_the_same_twice_or_looks_like_text(self):
        server, port, arrived = await _serve()
        relay = _Relay(port)
        await relay.start()
        client = VeilTransport()
        try:
            await client.connect(f"127.0.0.1:{relay.port}")
            accepted = await asyncio.wait_for(arrived.get(), 3)
            for _ in range(20):
                await client.send(_packet(200))
                await accepted.send(_packet(200))
                await asyncio.wait_for(accepted.receive(), 3)
                await asyncio.wait_for(client.receive(), 3)
            for direction in ("up", "down"):
                data = relay.seen[direction]
                assert len(data) > 4000
                assert _entropy(data) > 7.9
                assert b"\xff" * 8 not in data
        finally:
            await client.close()
            await relay.stop()
            await server.close()

    async def test_two_hellos_share_no_prefix(self):
        server, port, arrived = await _serve()
        firsts = []
        for _ in range(3):
            relay = _Relay(port)
            await relay.start()
            client = VeilTransport()
            await client.connect(f"127.0.0.1:{relay.port}")
            firsts.append(relay.seen["up"][:32])
            await client.close()
            await relay.stop()
        await server.close()
        assert len({first[:4] for first in firsts}) == 3


class TestAProber:
    async def _talk(self, port, payload, wait=0.8):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(payload)
        await writer.drain()
        try:
            return await asyncio.wait_for(reader.read(4096), wait), writer
        except asyncio.TimeoutError:
            return None, writer

    @pytest.mark.parametrize("payload", [b"", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
                                         bytes(range(200)), b"\x00" * 64, b"\xff" * 3000])
    async def test_gets_no_byte_back(self, payload):
        server, port, arrived = await _serve()
        try:
            answer, writer = await self._talk(port, payload)
            assert answer is None, "a listener that has not been proved the key says nothing"
            writer.close()
            assert arrived.empty()
        finally:
            await server.close()

    async def test_a_wrong_key_is_not_answered(self):
        class Other(VeilTransport):
            SETTINGS = {"key": "some other long phrase"}
            _DEFAULTS = None

        server, port, arrived = await _serve()
        try:
            with pytest.raises((ConnectionError, asyncio.TimeoutError, OSError)):
                await Other().connect(f"127.0.0.1:{port}")
            assert arrived.empty()
        finally:
            await server.close()

    async def test_a_replayed_hello_is_not_answered(self):
        server, port, arrived = await _serve()
        relay = _Relay(port)
        await relay.start()
        try:
            client = VeilTransport()
            await client.connect(f"127.0.0.1:{relay.port}")
            await asyncio.wait_for(arrived.get(), 3)
            hello = relay.seen["up"][:veil.SALT + veil.TAG + 2 + veil.MAX_PADDING]
            await client.close()
            answer, writer = await self._talk(port, hello)
            assert answer is None
            writer.close()
            assert arrived.empty()
        finally:
            await relay.stop()
            await server.close()

    @pytest.mark.parametrize("minutes", [veil.CLOCK_WINDOW + 1, -(veil.CLOCK_WINDOW + 1), 60])
    async def test_a_hello_from_a_clock_far_away_is_not_answered(self, minutes):
        server, port, arrived = await _serve()
        try:
            salt = os.urandom(veil.SALT)
            hello = (salt + veil._tag(KEY.encode(), salt, veil._minute() + minutes)
                     + veil._stream(KEY.encode(), salt, b"c2s").update(veil._padding()))
            answer, writer = await self._talk(port, hello)
            assert answer is None
            writer.close()
            assert arrived.empty()
        finally:
            await server.close()

    async def test_a_hello_inside_the_window_is_answered(self):
        server, port, arrived = await _serve()
        try:
            salt = os.urandom(veil.SALT)
            hello = (salt + veil._tag(KEY.encode(), salt, veil._minute() - veil.CLOCK_WINDOW)
                     + veil._stream(KEY.encode(), salt, b"c2s").update(veil._padding()))
            answer, writer = await self._talk(port, hello, wait=2.0)
            assert answer, "the edge of the window is still the window"
            writer.close()
        finally:
            await server.close()

    async def test_the_silent_ones_are_bounded(self, monkeypatch):
        monkeypatch.setattr(veil, "MAX_SILENT", 2)
        server, port, _ = await _serve()
        try:
            held = [await asyncio.open_connection("127.0.0.1", port) for _ in range(2)]
            await asyncio.sleep(0.2)
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"x")
            await writer.drain()
            try:
                closed = await asyncio.wait_for(reader.read(10), 2) == b""
            except ConnectionResetError:
                closed = True
            assert closed, "the third is closed at once"
            for _, w in held:
                w.close()
        finally:
            await server.close()


class TestAKeyIsRequired:
    async def test_no_key_no_listener_and_no_dial(self, monkeypatch):
        monkeypatch.setattr(VeilTransport, "SETTINGS", {"key": "short"})
        with pytest.raises(ConnectionError):
            await VeilServer().listen("127.0.0.1:0")
        with pytest.raises(ConnectionError):
            await VeilTransport().connect("127.0.0.1:1")


class TestRegistered:
    def test_the_node_offers_it(self):
        from src.transports.manager import TransportManager
        from src.transports.registry import register_all
        assert "veil" in register_all(TransportManager()).schemes()
