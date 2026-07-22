"""
Chat — the reference NMesh application.

Runs on top of the data connector: a full 1:1 and group messenger with rich
profiles, message replies, edits, deletes, emoji reactions, delivered/read
receipts, typing indicators, chunked+verified file/media transfer, and a
real-time frame stream (the primitive a voice/video call would use — see
:mod:`src.apps.call`).

Wire format inside each E2E DATA payload: a one-byte type followed by a body.
Every message a peer sends is validated and bounded; a malformed application
message is dropped, never fatal (the charter applies at the app layer too).

Message addressing: every user-visible message (text, group text, file) carries
a 16-byte **msg id** its sender minted, so replies / edits / deletes / reactions
/ receipts can reference it. A conversation scope is a 16-byte **group id**, or
all-zero for a direct (1:1) conversation with the sender.
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
_PROFILE = 0x05        # announce my pseudo + bio + avatar
_GROUP_INVITE = 0x06   # define/join a group (roster)
_GROUP_TEXT = 0x07     # a message addressed to a group
_DIR_QUERY = 0x08      # "who is <pseudo>?" (answered only about oneself)
_DIR_REPLY = 0x09      # "<pseudo> is <node_id>"
_RECEIPT = 0x0A        # delivered/read receipt for a set of msg ids
_TYPING = 0x0B         # typing / stopped-typing indicator
_EDIT = 0x0C           # replace the text of one of my earlier messages
_DELETE = 0x0D         # delete one of my earlier messages
_REACTION = 0x0E       # set/clear my emoji reaction on a message

MSG_ID_LEN = 16
GROUP_ID_LEN = 16
_ZERO_GID = b"\x00" * GROUP_ID_LEN

# FILE_OFFER body: msg_id(16) | reply_to(16) | transfer_id(4) | total_chunks(4)
#                  | size(8) | sha256(32) | name_len(2) | name
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

_MAX_PSEUDO_BYTES = 256
_MAX_BIO_BYTES = 1024
_MAX_AVATAR_BYTES = 48 * 1024
_MAX_GROUP_NAME_BYTES = 256
_MAX_GROUP_MEMBERS = 256
_MAX_TEXT = 16_000
_MAX_EMOJI_BYTES = 64
_MAX_RECEIPT_IDS = 256

_DELIVERED = 1
_READ = 2


# ---------------------------------------------------------------------------
# Events surfaced to listeners (the web bridge turns these into UI records).
# ---------------------------------------------------------------------------

@dataclass
class TextMessage:
    src: NodeID
    text: str
    mid: bytes = b""
    reply_to: bytes | None = None
    group_id: bytes | None = None      # set for group messages


@dataclass
class FileReceived:
    src: NodeID
    name: str
    data: bytes
    mid: bytes = b""
    reply_to: bytes | None = None
    group_id: bytes | None = None


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
    bio: str = ""
    avatar: bytes = b""


@dataclass
class GroupMessage:
    group_id: bytes
    src: NodeID
    text: str
    mid: bytes = b""
    reply_to: bytes | None = None


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


@dataclass
class Receipt:
    src: NodeID
    kind: int                  # _DELIVERED or _READ
    group_id: bytes | None     # None for direct
    mids: list                 # list[bytes]


@dataclass
class Typing:
    src: NodeID
    group_id: bytes | None
    active: bool


@dataclass
class Edited:
    src: NodeID
    group_id: bytes | None
    mid: bytes
    text: str


@dataclass
class Deleted:
    src: NodeID
    group_id: bytes | None
    mid: bytes


@dataclass
class Reaction:
    src: NodeID
    group_id: bytes | None
    mid: bytes
    emoji: str                 # empty string clears this sender's reaction


class _Transfer:
    __slots__ = ("name", "size", "digest", "total", "chunks", "mid", "reply_to")

    def __init__(self, name: str, size: int, digest: bytes, total: int,
                 mid: bytes, reply_to: bytes | None) -> None:
        self.name = name
        self.size = size
        self.digest = digest
        self.total = total
        self.mid = mid
        self.reply_to = reply_to
        self.chunks: dict[int, bytes] = {}

    def complete(self) -> bool:
        return len(self.chunks) >= self.total

    def assemble(self) -> bytes:
        return b"".join(self.chunks[i] for i in range(self.total))


def _gid_or_none(raw: bytes) -> bytes | None:
    return None if raw == _ZERO_GID else raw


def new_mid() -> bytes:
    return secrets.token_bytes(MSG_ID_LEN)


class ChatApp:
    """Text + file + real-time chat over a :class:`ConnectorClient`, plus the
    app-level social layer: profiles, contacts, groups, reactions, receipts, and
    pseudo lookup — all kept in :class:`ChatState` (the node knows none of it)."""

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
        self._listeners.append(fn)

    def remove_listener(self, fn) -> None:
        try:
            self._listeners.remove(fn)
        except ValueError:
            pass

    def _emit(self, event) -> None:
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

    # -- sending: text, replies, files ------------------------------------

    async def send_text(self, target: NodeID, text: str, *,
                        reply_to: bytes | None = None) -> bytes:
        mid = new_mid()
        body = (bytes([_TEXT]) + mid + (reply_to or _ZERO_GID)
                + text.encode("utf-8")[:_MAX_TEXT])
        await self._client.send(target, body)
        return mid

    async def send_file(self, target: NodeID, name: str, data: bytes, *,
                        reply_to: bytes | None = None) -> bytes:
        if len(data) > _MAX_FILE:
            raise ValueError("file too large")
        mid = new_mid()
        tid = self._next_tid
        self._next_tid += 1
        name_b = name.encode("utf-8")[:_MAX_NAME]
        pieces = [data[i:i + FILE_CHUNK_SIZE] for i in range(0, len(data), FILE_CHUNK_SIZE)]
        digest = hashlib.sha256(data).digest()
        offer = (bytes([_FILE_OFFER]) + mid + (reply_to or _ZERO_GID)
                 + _OFFER.pack(tid, len(pieces), len(data), digest, len(name_b))
                 + name_b)
        await self._client.send(target, offer)
        for i, piece in enumerate(pieces):
            await self._client.send(
                target, bytes([_FILE_CHUNK]) + _CHUNK.pack(tid, i) + piece)
        return mid

    async def send_frame(self, target: NodeID, stream_id: int, seq: int,
                         payload: bytes) -> None:
        await self._client.send(
            target, bytes([_STREAM]) + _FRAME.pack(stream_id, seq, time.time_ns()) + payload)

    # -- edits / deletes / reactions / receipts / typing ------------------

    async def send_edit(self, target: NodeID, mid: bytes, text: str, *,
                        group_id: bytes | None = None) -> None:
        body = (bytes([_EDIT]) + (group_id or _ZERO_GID) + mid
                + text.encode("utf-8")[:_MAX_TEXT])
        await self._client.send(target, body)

    async def send_delete(self, target: NodeID, mid: bytes, *,
                         group_id: bytes | None = None) -> None:
        await self._client.send(target, bytes([_DELETE]) + (group_id or _ZERO_GID) + mid)

    async def send_reaction(self, target: NodeID, mid: bytes, emoji: str, *,
                           group_id: bytes | None = None) -> None:
        body = (bytes([_REACTION]) + (group_id or _ZERO_GID) + mid
                + emoji.encode("utf-8")[:_MAX_EMOJI_BYTES])
        await self._client.send(target, body)

    async def send_receipt(self, target: NodeID, kind: int, mids: list, *,
                          group_id: bytes | None = None) -> None:
        mids = [m for m in mids if len(m) == MSG_ID_LEN][:_MAX_RECEIPT_IDS]
        if not mids:
            return
        body = (bytes([_RECEIPT, kind]) + (group_id or _ZERO_GID)
                + struct.pack("!H", len(mids)) + b"".join(mids))
        await self._client.send(target, body)

    async def send_typing(self, target: NodeID, active: bool, *,
                         group_id: bytes | None = None) -> None:
        await self._client.send(
            target, bytes([_TYPING]) + (group_id or _ZERO_GID) + bytes([1 if active else 0]))

    # -- social layer: profile, contacts, groups, lookup ------------------

    async def send_profile(self, target: NodeID) -> None:
        pseudo = self.state.pseudo.encode("utf-8")[:_MAX_PSEUDO_BYTES]
        bio = self.state.bio.encode("utf-8")[:_MAX_BIO_BYTES]
        avatar = self.state.avatar[:_MAX_AVATAR_BYTES]
        body = (bytes([_PROFILE]) + struct.pack("!H", len(pseudo)) + pseudo
                + struct.pack("!H", len(bio)) + bio + avatar)
        await self._client.send(target, body)

    async def set_pseudo(self, pseudo: str, *, announce: bool = True) -> None:
        self.state.set_pseudo(pseudo)
        if announce:
            await self.announce_profile()
            await self._publish_pseudo_dir()

    async def set_profile(self, *, pseudo: str | None = None, bio: str | None = None,
                         avatar: bytes | None = None, announce: bool = True) -> None:
        self.state.set_profile(pseudo=pseudo, bio=bio, avatar=avatar)
        if announce:
            await self.announce_profile()
            await self._publish_pseudo_dir()

    async def announce_profile(self) -> None:
        for id_hex in [c["id"] for c in self.state.snapshot()["contacts"]]:
            target = NodeID(bytes.fromhex(id_hex))
            if self.node_id is None or target != self.node_id:
                try:
                    await self.send_profile(target)
                except Exception:
                    pass  # a dead contact must not stop the announce loop

    async def _publish_pseudo_dir(self) -> None:
        fn = getattr(self._client, "publish_pseudo", None)
        if fn is None or not self.state.pseudo:
            return
        try:
            await fn(self.state.pseudo)
        except Exception:
            pass

    async def lookup_pseudo_network(self, pseudo: str) -> list[dict]:
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

    async def send_group_text(self, group_id: bytes, text: str, *,
                             reply_to: bytes | None = None) -> bytes:
        mid = new_mid()
        payload = (bytes([_GROUP_TEXT]) + group_id + mid + (reply_to or _ZERO_GID)
                   + text.encode("utf-8")[:_MAX_TEXT])
        for m in self._roster_ids(group_id):
            if self.node_id is None or m != self.node_id:
                try:
                    await self._client.send(m, payload)
                except Exception:
                    pass
        return mid

    async def dir_query(self, pseudo: str) -> int:
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
        handler = _HANDLERS.get(mtype)
        if handler is not None:
            handler(self, src, body)

    # text / files -------------------------------------------------------

    def _on_text(self, src: NodeID, body: bytes) -> None:
        if len(body) < MSG_ID_LEN + GROUP_ID_LEN:
            return
        mid = body[:MSG_ID_LEN]
        reply = _gid_or_none(body[MSG_ID_LEN:MSG_ID_LEN + GROUP_ID_LEN])
        text = body[MSG_ID_LEN + GROUP_ID_LEN:MSG_ID_LEN + GROUP_ID_LEN + _MAX_TEXT]
        self._emit(TextMessage(src, text.decode("utf-8", "replace"), mid, reply))

    def _on_offer(self, src: NodeID, body: bytes) -> None:
        if len(body) < MSG_ID_LEN + GROUP_ID_LEN + _OFFER.size:
            return
        mid = body[:MSG_ID_LEN]
        reply = _gid_or_none(body[MSG_ID_LEN:MSG_ID_LEN + GROUP_ID_LEN])
        off = MSG_ID_LEN + GROUP_ID_LEN
        tid, total, size, digest, name_len = _OFFER.unpack_from(body, off)
        name = body[off + _OFFER.size:off + _OFFER.size + name_len].decode("utf-8", "replace")
        if size > _MAX_FILE or total > _MAX_CHUNKS:
            return
        if total == 0:
            if size == 0 and digest == hashlib.sha256(b"").digest():
                self._emit(FileReceived(src, name, b"", mid, reply))
            return
        if len(self._transfers) >= _MAX_TRANSFERS:
            return
        self._transfers[(src.raw, tid)] = _Transfer(name, size, digest, total, mid, reply)

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
                self._emit(FileReceived(src, t.name, assembled, t.mid, t.reply_to))

    def _on_frame(self, src: NodeID, body: bytes) -> None:
        if len(body) < _FRAME.size:
            return
        stream_id, seq, ts_ns = _FRAME.unpack_from(body, 0)
        payload = body[_FRAME.size:]
        latency_ms = (time.time_ns() - ts_ns) / 1e6
        self._emit(Frame(src, stream_id, seq, latency_ms, payload))

    # edits / deletes / reactions / receipts / typing --------------------

    def _on_edit(self, src: NodeID, body: bytes) -> None:
        if len(body) < GROUP_ID_LEN + MSG_ID_LEN:
            return
        gid = _gid_or_none(body[:GROUP_ID_LEN])
        mid = body[GROUP_ID_LEN:GROUP_ID_LEN + MSG_ID_LEN]
        text = body[GROUP_ID_LEN + MSG_ID_LEN:GROUP_ID_LEN + MSG_ID_LEN + _MAX_TEXT]
        self._emit(Edited(src, gid, mid, text.decode("utf-8", "replace")))

    def _on_delete(self, src: NodeID, body: bytes) -> None:
        if len(body) != GROUP_ID_LEN + MSG_ID_LEN:
            return
        gid = _gid_or_none(body[:GROUP_ID_LEN])
        self._emit(Deleted(src, gid, body[GROUP_ID_LEN:]))

    def _on_reaction(self, src: NodeID, body: bytes) -> None:
        if len(body) < GROUP_ID_LEN + MSG_ID_LEN:
            return
        gid = _gid_or_none(body[:GROUP_ID_LEN])
        mid = body[GROUP_ID_LEN:GROUP_ID_LEN + MSG_ID_LEN]
        emoji = body[GROUP_ID_LEN + MSG_ID_LEN:GROUP_ID_LEN + MSG_ID_LEN + _MAX_EMOJI_BYTES]
        self._emit(Reaction(src, gid, mid, emoji.decode("utf-8", "replace")))

    def _on_receipt(self, src: NodeID, body: bytes) -> None:
        if len(body) < 1 + GROUP_ID_LEN + 2:
            return
        kind = body[0]
        if kind not in (_DELIVERED, _READ):
            return
        gid = _gid_or_none(body[1:1 + GROUP_ID_LEN])
        (count,) = struct.unpack_from("!H", body, 1 + GROUP_ID_LEN)
        off = 1 + GROUP_ID_LEN + 2
        if count > _MAX_RECEIPT_IDS or off + count * MSG_ID_LEN > len(body):
            return
        mids = [body[off + i * MSG_ID_LEN:off + (i + 1) * MSG_ID_LEN] for i in range(count)]
        self._emit(Receipt(src, kind, gid, mids))

    def _on_typing(self, src: NodeID, body: bytes) -> None:
        if len(body) != GROUP_ID_LEN + 1:
            return
        self._emit(Typing(src, _gid_or_none(body[:GROUP_ID_LEN]), body[GROUP_ID_LEN] == 1))

    # social-layer handlers (all validated & bounded; drop on malformed) --

    def _on_profile(self, src: NodeID, body: bytes) -> None:
        if len(body) < 2:
            return
        (pl,) = struct.unpack_from("!H", body, 0)
        off = 2
        if pl > _MAX_PSEUDO_BYTES or off + pl + 2 > len(body):
            return
        pseudo = body[off:off + pl].decode("utf-8", "replace").strip()
        off += pl
        (bl,) = struct.unpack_from("!H", body, off)
        off += 2
        if bl > _MAX_BIO_BYTES or off + bl > len(body):
            return
        bio = body[off:off + bl].decode("utf-8", "replace")
        avatar = body[off + bl:off + bl + _MAX_AVATAR_BYTES]
        if pseudo:
            self.state.learn_pseudo(src.raw.hex(), pseudo)
        self.state.learn_profile(src.raw.hex(), bio=bio, avatar=avatar)
        self._emit(ProfileReceived(src, pseudo, bio, avatar))

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
        if len(body) < GROUP_ID_LEN + MSG_ID_LEN + GROUP_ID_LEN:
            return
        gid = body[:GROUP_ID_LEN]
        off = GROUP_ID_LEN
        mid = body[off:off + MSG_ID_LEN]
        off += MSG_ID_LEN
        reply = _gid_or_none(body[off:off + GROUP_ID_LEN])
        off += GROUP_ID_LEN
        text = body[off:off + _MAX_TEXT]
        self._emit(GroupMessage(gid, src, text.decode("utf-8", "replace"), mid, reply))

    def _on_dir_query(self, src: NodeID, body: bytes) -> None:
        if len(body) < 4 or self.node_id is None:
            return
        (qid,) = struct.unpack_from("!I", body, 0)
        pseudo = body[4:4 + _MAX_PSEUDO_BYTES].decode("utf-8", "replace")
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


_HANDLERS = {
    _TEXT: ChatApp._on_text,
    _FILE_OFFER: ChatApp._on_offer,
    _FILE_CHUNK: ChatApp._on_chunk,
    _STREAM: ChatApp._on_frame,
    _PROFILE: ChatApp._on_profile,
    _GROUP_INVITE: ChatApp._on_group_invite,
    _GROUP_TEXT: ChatApp._on_group_text,
    _DIR_QUERY: ChatApp._on_dir_query,
    _DIR_REPLY: ChatApp._on_dir_reply,
    _RECEIPT: ChatApp._on_receipt,
    _TYPING: ChatApp._on_typing,
    _EDIT: ChatApp._on_edit,
    _DELETE: ChatApp._on_delete,
    _REACTION: ChatApp._on_reaction,
}
