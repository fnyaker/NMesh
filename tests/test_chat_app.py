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
    Edited, Deleted, Reaction, Receipt, Typing, ProfileReceived, new_mid,
    _DELIVERED, _READ,
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
        mid = await a.send_text(DST, "héllo mesh 🌐")
        _feed(b, a._client, SRC)
        events = _drain(b)
        assert len(events) == 1 and isinstance(events[0], TextMessage)
        assert events[0].src == SRC and events[0].text == "héllo mesh 🌐"
        assert events[0].mid == mid and events[0].reply_to is None

    async def test_text_reply_carries_target(self):
        a = ChatApp(StubClient())
        b = ChatApp(StubClient())
        target = os.urandom(16)
        await a.send_text(DST, "re", reply_to=target)
        _feed(b, a._client, SRC)
        ev = _drain(b)[0]
        assert ev.reply_to == target


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
        assert len(events) == 1 and isinstance(events[0], FileReceived)
        assert events[0].src == SRC and events[0].name == "empty" and events[0].data == b""

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


class TestRichProtocol:
    async def _pair(self):
        return ChatApp(StubClient()), ChatApp(StubClient())

    async def test_edit(self):
        a, b = await self._pair()
        mid = new_mid()
        await a.send_edit(DST, mid, "new text")
        _feed(b, a._client, SRC)
        ev = _drain(b)[0]
        assert isinstance(ev, Edited) and ev.mid == mid and ev.text == "new text"

    async def test_delete(self):
        a, b = await self._pair()
        mid = new_mid()
        await a.send_delete(DST, mid)
        _feed(b, a._client, SRC)
        ev = _drain(b)[0]
        assert isinstance(ev, Deleted) and ev.mid == mid

    async def test_reaction(self):
        a, b = await self._pair()
        mid = new_mid()
        await a.send_reaction(DST, mid, "👍")
        _feed(b, a._client, SRC)
        ev = _drain(b)[0]
        assert isinstance(ev, Reaction) and ev.mid == mid and ev.emoji == "👍"

    async def test_receipt(self):
        a, b = await self._pair()
        m1, m2 = new_mid(), new_mid()
        await a.send_receipt(DST, _READ, [m1, m2])
        _feed(b, a._client, SRC)
        ev = _drain(b)[0]
        assert isinstance(ev, Receipt) and ev.kind == _READ and ev.mids == [m1, m2]

    async def test_typing(self):
        a, b = await self._pair()
        await a.send_typing(DST, True)
        _feed(b, a._client, SRC)
        ev = _drain(b)[0]
        assert isinstance(ev, Typing) and ev.active is True

    async def test_profile_bio_and_avatar(self):
        a, b = await self._pair()
        a.state.set_profile(pseudo="Alice", bio="hi bio", avatar=b"AVATARBYTES")
        await a.send_profile(DST)
        _feed(b, a._client, SRC)
        ev = _drain(b)[0]
        assert isinstance(ev, ProfileReceived)
        assert ev.pseudo == "Alice" and ev.bio == "hi bio" and ev.avatar == b"AVATARBYTES"


class TestHardening:
    def test_dispatch_fuzz(self):
        app = ChatApp(StubClient())
        rng = random.Random(0xC0A7)
        src = NodeID(os.urandom(20))
        for _ in range(5000):
            payload = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 256)))
            app._dispatch(src, payload)   # must never raise
