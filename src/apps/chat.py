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
import secrets
import struct
import time
from dataclasses import dataclass, field

from ..node_id import NodeID
from .chat_state import ChatState

_TEXT = 0x01
_FILE_OFFER = 0x02
_FILE_CHUNK = 0x03
_STREAM = 0x04
_PROFILE = 0x05        # announce my pseudo
_GROUP_INVITE = 0x06   # define/join a group (roster)
_GROUP_TEXT = 0x07     # a message addressed to a group
_DIR_QUERY = 0x08      # "who is <pseudo>?" (answered only about oneself)
_DIR_REPLY = 0x09      # "<pseudo> is <node_id>"

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

GROUP_ID_LEN = 16
_MAX_PSEUDO_BYTES = 256
_MAX_GROUP_NAME_BYTES = 256
_MAX_GROUP_MEMBERS = 256
_MAX_GROUP_TEXT = 16_000


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


@dataclass
class ProfileReceived:
    src: NodeID
    pseudo: str


@dataclass
class GroupMessage:
    group_id: bytes
    src: NodeID
    text: str


@dataclass
class GroupInvited:
    group_id: bytes
    name: str
    members: list = field(default_factory=list)   # list[NodeID]


@dataclass
class DirResult:
    query_id: int
    node_id: NodeID
    pseudo: str


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
    """Text + file + real-time chat over a :class:`ConnectorClient`, plus the
    app-level social layer: contacts, pseudos, groups and pseudo lookup — all
    kept in :class:`ChatState` (the node knows nothing of it)."""

    def __init__(self, client, *, node_id: NodeID | None = None,
                 state: ChatState | None = None) -> None:
        self._client = client
        self.node_id = node_id
        self.state = state or ChatState()
        self._events: asyncio.Queue = asyncio.Queue()
        self._listeners: list = []
        self._transfers: dict[tuple[bytes, int], _Transfer] = {}
        self._next_tid = 1
        self._task: asyncio.Task | None = None

    # -- event fan-out (everything the app receives flows through here) ----

    def add_listener(self, fn) -> None:
        """Register a callback invoked for every received event — used to
        surface messages to a UI. Everything still goes through this app."""
        self._listeners.append(fn)

    def remove_listener(self, fn) -> None:
        try:
            self._listeners.remove(fn)
        except ValueError:
            pass

    def _emit(self, event) -> None:
        # Bounded queue so a caller that never drains next_event() can't leak.
        if self._events.qsize() >= 1000:
            try:
                self._events.get_nowait()
            except asyncio.QueueEmpty:
                pass
        self._events.put_nowait(event)
        for fn in list(self._listeners):
            try:
                fn(event)
            except Exception:
                pass  # a bad listener must not break the app

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

    # -- social layer: pseudo, contacts, groups, lookup -------------------

    async def send_profile(self, target: NodeID) -> None:
        """Announce our pseudo to a peer (they record it in their directory)."""
        await self._client.send(
            target, bytes([_PROFILE]) + self.state.pseudo.encode("utf-8")[:_MAX_PSEUDO_BYTES])

    async def set_pseudo(self, pseudo: str, *, announce: bool = True) -> None:
        self.state.set_pseudo(pseudo)
        if announce:
            await self.announce_profile()
            await self._publish_pseudo_dir()

    async def _publish_pseudo_dir(self) -> None:
        """Publish our pseudo→node-id claim to the network directory, so people
        can find us by pseudo without being a contact first. Best-effort: a
        client without the capability (or a transient failure) is ignored."""
        fn = getattr(self._client, "publish_pseudo", None)
        if fn is None or not self.state.pseudo:
            return
        try:
            await fn(self.state.pseudo)
        except Exception:
            pass

    async def lookup_pseudo_network(self, pseudo: str) -> list[dict]:
        """Find people by pseudo across the whole network via the DHT directory.
        Learns the results into our directory and returns ``[{id, pseudo}]``."""
        fn = getattr(self._client, "lookup_pseudo", None)
        if fn is None:
            return []
        try:
            results = await fn(pseudo)
        except Exception:
            return []
        for r in results:
            nid, ps = r.get("id"), r.get("pseudo")
            if isinstance(nid, str) and isinstance(ps, str):
                self.state.learn_pseudo(nid, ps)
        return results

    async def announce_profile(self) -> None:
        """Push our pseudo to every contact (skips ourselves)."""
        for id_hex in [c["id"] for c in self.state.snapshot()["contacts"]]:
            target = NodeID(bytes.fromhex(id_hex))
            if self.node_id is None or target != self.node_id:
                try:
                    await self.send_profile(target)
                except Exception:
                    pass  # a dead contact must not stop the announce loop

    async def add_contact(self, target: NodeID, pseudo: str = "",
                          *, announce: bool = True) -> bool:
        ok = self.state.add_contact(target.raw.hex(), pseudo)
        if ok and announce and (self.node_id is None or target != self.node_id):
            try:
                await self.send_profile(target)
            except Exception:
                pass
        return ok

    def _roster_ids(self, group_id: bytes) -> list[NodeID]:
        return [NodeID(bytes.fromhex(h))
                for h in self.state.group_members(group_id.hex())]

    async def create_group(self, name: str, members: list[NodeID]) -> bytes:
        """Create a group with us + ``members`` and invite everyone else."""
        gid = secrets.token_bytes(GROUP_ID_LEN)
        roster = list(members)
        if self.node_id is not None and self.node_id not in roster:
            roster.insert(0, self.node_id)
        roster = roster[:_MAX_GROUP_MEMBERS]
        self.state.add_group(gid.hex(), name, [n.raw.hex() for n in roster])
        for m in roster:
            if self.node_id is None or m != self.node_id:
                try:
                    await self._send_group_invite(m, gid, name, roster)
                except Exception:
                    pass
        return gid

    async def _send_group_invite(self, target: NodeID, gid: bytes, name: str,
                                 roster: list[NodeID]) -> None:
        name_b = name.encode("utf-8")[:_MAX_GROUP_NAME_BYTES]
        body = (bytes([_GROUP_INVITE]) + gid
                + struct.pack("!H", len(name_b)) + name_b
                + struct.pack("!H", len(roster))
                + b"".join(n.raw for n in roster))
        await self._client.send(target, body)

    async def send_group_text(self, group_id: bytes, text: str) -> None:
        """Fan a group message out to every member (no relay by members, so it
        cannot loop or amplify)."""
        payload = (bytes([_GROUP_TEXT]) + group_id
                   + text.encode("utf-8")[:_MAX_GROUP_TEXT])
        for m in self._roster_ids(group_id):
            if self.node_id is None or m != self.node_id:
                try:
                    await self._client.send(m, payload)
                except Exception:
                    pass

    async def dir_query(self, pseudo: str) -> int:
        """Ask every contact 'who is <pseudo>?'. Each answers only about itself;
        replies arrive as :class:`DirResult`. Returns the query id."""
        qid = secrets.randbits(32)
        body = bytes([_DIR_QUERY]) + struct.pack("!I", qid) + pseudo.encode("utf-8")[:_MAX_PSEUDO_BYTES]
        for c in self.state.snapshot()["contacts"]:
            target = NodeID(bytes.fromhex(c["id"]))
            if self.node_id is None or target != self.node_id:
                try:
                    await self._client.send(target, body)
                except Exception:
                    pass
        return qid

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
            self._emit(TextMessage(src, body.decode("utf-8", "replace")))
        elif mtype == _FILE_OFFER:
            self._on_offer(src, body)
        elif mtype == _FILE_CHUNK:
            self._on_chunk(src, body)
        elif mtype == _STREAM:
            self._on_frame(src, body)
        elif mtype == _PROFILE:
            self._on_profile(src, body)
        elif mtype == _GROUP_INVITE:
            self._on_group_invite(src, body)
        elif mtype == _GROUP_TEXT:
            self._on_group_text(src, body)
        elif mtype == _DIR_QUERY:
            self._on_dir_query(src, body)
        elif mtype == _DIR_REPLY:
            self._on_dir_reply(src, body)

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
                self._emit(FileReceived(src, name, b""))
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
                self._emit(FileReceived(src, t.name, assembled))

    def _on_frame(self, src: NodeID, body: bytes) -> None:
        if len(body) < _FRAME.size:
            return
        stream_id, seq, ts_ns = _FRAME.unpack_from(body, 0)
        payload = body[_FRAME.size:]
        latency_ms = (time.time_ns() - ts_ns) / 1e6
        self._emit(Frame(src, stream_id, seq, latency_ms, payload))

    # -- social-layer handlers (all validated & bounded; drop on malformed) --

    def _on_profile(self, src: NodeID, body: bytes) -> None:
        pseudo = body[:_MAX_PSEUDO_BYTES].decode("utf-8", "replace").strip()
        if pseudo:
            self.state.learn_pseudo(src.raw.hex(), pseudo)
            self._emit(ProfileReceived(src, pseudo))

    def _on_group_invite(self, src: NodeID, body: bytes) -> None:
        if len(body) < GROUP_ID_LEN + 2:
            return
        gid = body[:GROUP_ID_LEN]
        off = GROUP_ID_LEN
        (name_len,) = struct.unpack_from("!H", body, off)
        off += 2
        if name_len > _MAX_GROUP_NAME_BYTES or off + name_len + 2 > len(body):
            return
        name = body[off:off + name_len].decode("utf-8", "replace")
        off += name_len
        (count,) = struct.unpack_from("!H", body, off)
        off += 2
        if count > _MAX_GROUP_MEMBERS or off + count * 20 > len(body):
            return
        members = [NodeID(body[off + i * 20:off + i * 20 + 20]) for i in range(count)]
        self.state.add_group(gid.hex(), name, [m.raw.hex() for m in members])
        self._emit(GroupInvited(gid, name, members))

    def _on_group_text(self, src: NodeID, body: bytes) -> None:
        if len(body) < GROUP_ID_LEN:
            return
        gid = body[:GROUP_ID_LEN]
        text = body[GROUP_ID_LEN:GROUP_ID_LEN + _MAX_GROUP_TEXT].decode("utf-8", "replace")
        self._emit(GroupMessage(gid, src, text))

    def _on_dir_query(self, src: NodeID, body: bytes) -> None:
        if len(body) < 4 or self.node_id is None:
            return
        (qid,) = struct.unpack_from("!I", body, 0)
        pseudo = body[4:4 + _MAX_PSEUDO_BYTES].decode("utf-8", "replace")
        # Answer only about ourselves — never disclose contacts (privacy).
        if self.state.matches_my_pseudo(pseudo):
            reply = (bytes([_DIR_REPLY]) + struct.pack("!I", qid) + self.node_id.raw
                     + self.state.pseudo.encode("utf-8")[:_MAX_PSEUDO_BYTES])
            asyncio.create_task(self._safe_send(src, reply))

    def _on_dir_reply(self, src: NodeID, body: bytes) -> None:
        if len(body) < 4 + 20:
            return
        (qid,) = struct.unpack_from("!I", body, 0)
        node_id = NodeID(body[4:24])
        pseudo = body[24:24 + _MAX_PSEUDO_BYTES].decode("utf-8", "replace").strip()
        # A peer may only assert its own id → the reply's id must be the sender.
        # This blocks a malicious contact from mapping a pseudo onto a victim id.
        if node_id != src:
            return
        if pseudo:
            self.state.learn_pseudo(node_id.raw.hex(), pseudo)
        self._emit(DirResult(qid, node_id, pseudo))

    async def _safe_send(self, target: NodeID, payload: bytes) -> None:
        try:
            await self._client.send(target, payload)
        except Exception:
            pass
