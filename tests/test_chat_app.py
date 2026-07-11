"""
Chat application protocol tests (no network): drive one app's send_* methods,
capture the wire payloads, feed them to another app's dispatcher, and check the
events — plus fuzzing to prove no peer message can crash the app.
"""
import os
import random

import pytest

from src.apps.chat import (
    ChatApp, TextMessage, FileReceived, Frame, FILE_CHUNK_SIZE,
)
from src.node_id import NodeID


class StubClient:
    def __init__(self):
        self.sent = []
    async def send(self, target, payload):
        self.sent.append((target, payload))
    async def recv(self):
        raise NotImplementedError
    async def close(self):
        pass


def _feed(receiver: ChatApp, sender_stub: StubClient, src: NodeID):
    """Replay every payload the sender emitted into the receiver's dispatcher."""
    for _target, payload in sender_stub.sent:
        receiver._dispatch(src, payload)
    sender_stub.sent.clear()


def _drain(app: ChatApp):
    out = []
    while not app._events.empty():
        out.append(app._events.get_nowait())
    return out


SRC = NodeID(os.urandom(20))
DST = NodeID(os.urandom(20))


class TestText:
    async def test_text_roundtrip(self):
        a = ChatApp(StubClient())
        b = ChatApp(StubClient())
        await a.send_text(DST, "héllo mesh 🌐")
        _feed(b, a._client, SRC)
        events = _drain(b)
        assert events == [TextMessage(SRC, "héllo mesh 🌐")]


class TestFile:
    async def test_file_roundtrip_multichunk(self):
        a = ChatApp(StubClient())
        b = ChatApp(StubClient())
        data = os.urandom(FILE_CHUNK_SIZE * 2 + 123)
        await a.send_file(DST, "photo.bin", data)
        _feed(b, a._client, SRC)
        events = _drain(b)
        assert len(events) == 1
        ev = events[0]
        assert isinstance(ev, FileReceived)
        assert ev.name == "photo.bin" and ev.data == data

    async def test_empty_file(self):
        a = ChatApp(StubClient())
        b = ChatApp(StubClient())
        await a.send_file(DST, "empty", b"")
        _feed(b, a._client, SRC)
        events = _drain(b)
        assert events == [FileReceived(SRC, "empty", b"")]

    async def test_corrupt_chunk_no_delivery(self):
        a = ChatApp(StubClient())
        b = ChatApp(StubClient())
        await a.send_file(DST, "f", os.urandom(FILE_CHUNK_SIZE + 10))
        # Corrupt the first chunk payload before delivery.
        target, payload = a._client.sent[1]
        a._client.sent[1] = (target, payload[:5] + bytes([payload[5] ^ 0xFF]) + payload[6:])
        _feed(b, a._client, SRC)
        assert _drain(b) == []   # integrity check fails → nothing delivered

    async def test_too_large_rejected(self):
        a = ChatApp(StubClient())
        with pytest.raises(ValueError):
            await a.send_file(DST, "big", b"x" * (256 * 1024 * 1024 + 1))


class TestStream:
    async def test_frame_carries_latency(self):
        a = ChatApp(StubClient())
        b = ChatApp(StubClient())
        await a.send_frame(DST, stream_id=7, seq=42, payload=b"audioframe")
        _feed(b, a._client, SRC)
        events = _drain(b)
        assert len(events) == 1
        fr = events[0]
        assert isinstance(fr, Frame)
        assert fr.stream_id == 7 and fr.seq == 42 and fr.payload == b"audioframe"
        assert fr.latency_ms >= 0


class TestHardening:
    def test_dispatch_fuzz(self):
        app = ChatApp(StubClient())
        rng = random.Random(0xC0A7)
        src = NodeID(os.urandom(20))
        for _ in range(5000):
            payload = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 256)))
            app._dispatch(src, payload)   # must never raise
