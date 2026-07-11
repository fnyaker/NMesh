"""
Chat — the reference NMesh application.

Runs on top of the data connector: text messages, chunked file transfer with
integrity, and a real-time frame stream (the primitive a voice/video call would
use). It shows the mesh doing near-real-time work end to end.

Wire format inside each E2E DATA payload: a one-byte type followed by a body.
Everything a peer sends is validated and bounded; a malformed application
message is dropped, never fatal (the charter applies at the app layer too).
"""
from __future__ import annotations

import asyncio
import hashlib
import struct
import time
from dataclasses import dataclass

from ..node_id import NodeID

_TEXT = 0x01
_FILE_OFFER = 0x02
_FILE_CHUNK = 0x03
_STREAM = 0x04

# FILE_OFFER body: transfer_id(4) | total_chunks(4) | size(8) | sha256(32) | name_len(2) | name
_OFFER = struct.Struct("!IIQ32sH")
# FILE_CHUNK body: transfer_id(4) | index(4) | data
_CHUNK = struct.Struct("!II")
# STREAM body: stream_id(4) | seq(4) | ts_ns(8) | payload
_FRAME = struct.Struct("!IIQ")

FILE_CHUNK_SIZE = 48_000
_MAX_FILE = 256 * 1024 * 1024
_MAX_CHUNKS = _MAX_FILE // 1024
_MAX_TRANSFERS = 64
_MAX_NAME = 512


@dataclass
class TextMessage:
    src: NodeID
    text: str


@dataclass
class FileReceived:
    src: NodeID
    name: str
    data: bytes


@dataclass
class Frame:
    src: NodeID
    stream_id: int
    seq: int
    latency_ms: float
    payload: bytes


class _Transfer:
    __slots__ = ("name", "size", "digest", "total", "chunks")

    def __init__(self, name: str, size: int, digest: bytes, total: int) -> None:
        self.name = name
        self.size = size
        self.digest = digest
        self.total = total
        self.chunks: dict[int, bytes] = {}

    def complete(self) -> bool:
        return len(self.chunks) >= self.total

    def assemble(self) -> bytes:
        return b"".join(self.chunks[i] for i in range(self.total))


class ChatApp:
    """Text + file + real-time chat over a :class:`ConnectorClient`."""

    def __init__(self, client) -> None:
        self._client = client
        self._events: asyncio.Queue = asyncio.Queue()
        self._transfers: dict[tuple[bytes, int], _Transfer] = {}
        self._next_tid = 1
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        await self._client.close()

    async def next_event(self):
        return await self._events.get()

    # -- sending ----------------------------------------------------------

    async def send_text(self, target: NodeID, text: str) -> None:
        await self._client.send(target, bytes([_TEXT]) + text.encode("utf-8"))

    async def send_file(self, target: NodeID, name: str, data: bytes) -> int:
        if len(data) > _MAX_FILE:
            raise ValueError("file too large")
        tid = self._next_tid
        self._next_tid += 1
        name_b = name.encode("utf-8")[:_MAX_NAME]
        pieces = [data[i:i + FILE_CHUNK_SIZE] for i in range(0, len(data), FILE_CHUNK_SIZE)]
        digest = hashlib.sha256(data).digest()
        offer = (bytes([_FILE_OFFER])
                 + _OFFER.pack(tid, len(pieces), len(data), digest, len(name_b))
                 + name_b)
        await self._client.send(target, offer)
        for i, piece in enumerate(pieces):
            await self._client.send(
                target, bytes([_FILE_CHUNK]) + _CHUNK.pack(tid, i) + piece)
        return tid

    async def send_frame(self, target: NodeID, stream_id: int, seq: int,
                         payload: bytes) -> None:
        await self._client.send(
            target, bytes([_STREAM]) + _FRAME.pack(stream_id, seq, time.time_ns()) + payload)

    # -- receiving --------------------------------------------------------

    async def _loop(self) -> None:
        while True:
            try:
                src, payload = await self._client.recv()
            except (asyncio.IncompleteReadError, ConnectionError, OSError):
                return
            try:
                self._dispatch(src, payload)
            except Exception:
                pass  # malformed app message — drop, keep going

    def _dispatch(self, src: NodeID, payload: bytes) -> None:
        if not payload:
            return
        mtype, body = payload[0], payload[1:]
        if mtype == _TEXT:
            self._events.put_nowait(TextMessage(src, body.decode("utf-8", "replace")))
        elif mtype == _FILE_OFFER:
            self._on_offer(src, body)
        elif mtype == _FILE_CHUNK:
            self._on_chunk(src, body)
        elif mtype == _STREAM:
            self._on_frame(src, body)

    def _on_offer(self, src: NodeID, body: bytes) -> None:
        if len(body) < _OFFER.size:
            return
        tid, total, size, digest, name_len = _OFFER.unpack_from(body, 0)
        name = body[_OFFER.size:_OFFER.size + name_len].decode("utf-8", "replace")
        if size > _MAX_FILE or total > _MAX_CHUNKS:
            return
        if len(self._transfers) >= _MAX_TRANSFERS:
            return
        if total == 0:
            if size == 0 and digest == hashlib.sha256(b"").digest():
                self._events.put_nowait(FileReceived(src, name, b""))
            return
        self._transfers[(src.raw, tid)] = _Transfer(name, size, digest, total)

    def _on_chunk(self, src: NodeID, body: bytes) -> None:
        if len(body) < _CHUNK.size:
            return
        tid, index = _CHUNK.unpack_from(body, 0)
        data = body[_CHUNK.size:]
        t = self._transfers.get((src.raw, tid))
        if t is None or index >= t.total or index in t.chunks:
            return
        t.chunks[index] = data
        if t.complete():
            self._transfers.pop((src.raw, tid), None)
            assembled = t.assemble()
            if len(assembled) == t.size and hashlib.sha256(assembled).digest() == t.digest:
                self._events.put_nowait(FileReceived(src, t.name, assembled))

    def _on_frame(self, src: NodeID, body: bytes) -> None:
        if len(body) < _FRAME.size:
            return
        stream_id, seq, ts_ns = _FRAME.unpack_from(body, 0)
        payload = body[_FRAME.size:]
        latency_ms = (time.time_ns() - ts_ns) / 1e6
        self._events.put_nowait(Frame(src, stream_id, seq, latency_ms, payload))
