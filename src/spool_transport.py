"""
Spool transport — the mesh over a shared directory (a file medium, no sockets).

Each link is a directory holding two append-only spool files, one per direction.
A node writes packets into its outbound file and polls the peer's file for new
ones. Because it speaks the same ``BaseTransport`` / ``BaseServer`` interface as
TCP, the whole mesh — invite, handshake, routing, E2E — runs over it unchanged;
it is simply asynchronous and durable.

This is the substrate for store-and-forward: the directory can live on a
removable medium. When both endpoints are online on the same directory it
behaves like a (slow) live link; carrying a spool file offline to another
machine is the delay-tolerant case (see also ``spool.Bundle``).

Robustness (see CLAUDE.md): each record is length-prefixed and CRC-checked, and
the reader resynchronises on corruption instead of derailing — the medium is
untrusted. Writes are fsync'd so packets survive power loss or a yanked key.
"""
from __future__ import annotations

import asyncio
import os
import secrets
import struct
import zlib

from .transport import BaseTransport, BaseServer
from .packet import Packet

_REC_MAGIC = b"NMSR"
_REC = struct.Struct("!4sII")   # magic(4) | length(4) | crc32(4)
_MAX_REC = 65_535
_POLL = 0.02                     # directory poll interval, seconds
_C2S = "c2s.spool"               # client → server
_S2C = "s2c.spool"               # server → client


def _parse_records(data: bytes) -> tuple[list[bytes], int]:
    """Extract complete, CRC-valid records from ``data``.

    Returns (payloads, consumed). ``consumed`` bytes may be discarded; anything
    after is an incomplete record (or a resync tail) to retry once more arrives.
    Corrupt or garbage bytes are skipped by scanning to the next record magic.
    """
    payloads: list[bytes] = []
    i = 0
    n = len(data)
    while True:
        if i + _REC.size > n:
            break  # header not fully present yet
        magic, length, crc = _REC.unpack_from(data, i)
        if magic != _REC_MAGIC or length > _MAX_REC:
            nxt = data.find(_REC_MAGIC, i + 1)
            if nxt == -1:
                i = max(i, n - (len(_REC_MAGIC) - 1))  # keep a possible split magic
                break
            i = nxt
            continue
        rec_end = i + _REC.size + length
        if rec_end > n:
            break  # body not fully written yet
        payload = data[i + _REC.size:rec_end]
        if (zlib.crc32(payload) & 0xFFFFFFFF) == crc:
            payloads.append(payload)
            i = rec_end
        else:
            nxt = data.find(_REC_MAGIC, i + 1)  # corrupt body — resync
            if nxt == -1:
                i = max(i, n - (len(_REC_MAGIC) - 1))
                break
            i = nxt
    return payloads, i


class SpoolTransport(BaseTransport):
    def __init__(self) -> None:
        super().__init__()
        self._out_path: str | None = None
        self._in_path: str | None = None
        self._out_fd: int | None = None
        self._offset = 0
        self._decoded: list[Packet] = []
        self._closed = False

    # -- role binding -----------------------------------------------------

    def _bind_client(self, session_dir: str) -> None:
        self._out_path = os.path.join(session_dir, _C2S)
        self._in_path = os.path.join(session_dir, _S2C)

    def _bind_server(self, session_dir: str) -> None:
        self._out_path = os.path.join(session_dir, _S2C)
        self._in_path = os.path.join(session_dir, _C2S)

    async def connect(self, address: str) -> None:
        os.makedirs(address, exist_ok=True)
        session = "sess-" + secrets.token_hex(8)
        session_dir = os.path.join(address, session)
        os.makedirs(session_dir, exist_ok=True)
        self._bind_client(session_dir)
        self._ensure_out()  # create c2s so the server accepts this session

    async def listen(self, address: str) -> None:
        # Single-connection point-to-point: bind as server to the first session.
        os.makedirs(address, exist_ok=True)
        while not self._closed:
            for name in sorted(os.listdir(address)):
                sd = os.path.join(address, name)
                if name.startswith("sess-") and os.path.isdir(sd) \
                        and os.path.exists(os.path.join(sd, _C2S)):
                    self._bind_server(sd)
                    self._ensure_out()
                    return
            await asyncio.sleep(_POLL)

    # -- io ---------------------------------------------------------------

    def _ensure_out(self) -> None:
        if self._out_fd is None and self._out_path is not None:
            self._out_fd = os.open(
                self._out_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
            )

    async def send(self, packet: Packet) -> None:
        if self._closed or self._out_path is None:
            raise ConnectionError("spool transport not connected")
        self._ensure_out()
        payload = packet.pack()
        if len(payload) > _MAX_REC:
            raise ConnectionError("packet too large for spool record")
        record = _REC.pack(_REC_MAGIC, len(payload),
                           zlib.crc32(payload) & 0xFFFFFFFF) + payload
        os.write(self._out_fd, record)
        os.fsync(self._out_fd)

    def _read_new(self) -> bytes:
        if self._in_path is None:
            return b""
        try:
            with open(self._in_path, "rb") as f:
                f.seek(self._offset)
                return f.read()
        except FileNotFoundError:
            return b""

    async def receive(self) -> Packet:
        while True:
            if self._decoded:
                return self._decoded.pop(0)
            if self._closed:
                raise ConnectionError("spool transport closed")
            data = self._read_new()
            if data:
                payloads, consumed = _parse_records(data)
                self._offset += consumed
                for raw in payloads:
                    try:
                        self._decoded.append(Packet.unpack(raw))
                    except Exception:
                        pass  # medium noise — skip, keep the link alive
            if not self._decoded:
                await asyncio.sleep(_POLL)

    async def close(self) -> None:
        self._closed = True
        if self._out_fd is not None:
            try:
                os.close(self._out_fd)
            except OSError:
                pass
            self._out_fd = None


class SpoolServer(BaseServer):
    """Accepts multiple clients: each ``connect`` drops a new ``sess-*`` subdir
    into the link directory; the server binds one transport per session."""

    def __init__(self) -> None:
        super().__init__()
        self._dir: str | None = None
        self._seen: set[str] = set()
        self._task: asyncio.Task | None = None
        self._closed = False

    async def listen(self, address: str) -> None:
        self._dir = address
        os.makedirs(address, exist_ok=True)
        self._task = asyncio.create_task(self._accept_loop())

    async def _accept_loop(self) -> None:
        while not self._closed:
            try:
                names = os.listdir(self._dir)
            except (FileNotFoundError, OSError):
                names = []
            for name in sorted(names):
                if name in self._seen or not name.startswith("sess-"):
                    continue
                sd = os.path.join(self._dir, name)
                if not os.path.isdir(sd):
                    continue
                if not os.path.exists(os.path.join(sd, _C2S)):
                    continue  # client hasn't announced yet
                self._seen.add(name)
                transport = SpoolTransport()
                transport._bind_server(sd)
                transport._ensure_out()
                if self.on_new_connection is not None:
                    try:
                        await self.on_new_connection(transport)
                    except Exception:
                        pass
            await asyncio.sleep(_POLL)

    async def close(self) -> None:
        self._closed = True
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
