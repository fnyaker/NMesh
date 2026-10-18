"""
Contacts — the address books of this node, and how they follow a person around.

Runs on the data connector like chat does: its own section of the mesh, its own
encrypted drawer, its own allowances per sender. What it adds is the one thing a
single node cannot do alone — keep an address book on **several nodes** in step,
so the contacts a person made on their laptop are on their phone.

**Sharing is an invitation, and an invitation is not trusted.** A node that
offers a book to another costs the second one a line in a queue until a human
accepts it; nothing a stranger sends reaches a book that was not accepted. A
contact called "Bank" planted in somebody's address book is a social-engineering
attack, so the only way into a book is a person saying yes.

**The owner numbers.** One node made the book and is the only one that gives
changes a sequence number; a member that may write sends its edits to the owner,
which orders them and passes them on. That keeps every replica settling on the
same entry (:func:`~src.apps.contacts_state.newer`) without a clock anyone has
to believe. If the owner is gone for good the copies stay readable and, for a
member that could write, editable — they stop following each other, nothing
more, and the owner can hand a member the book by letting it go (``revoke``
detaches the copy and it becomes that node's own).

Wire format inside each E2E DATA payload: a one-byte type, then a JSON object.
Every message is bounded and validated before it is looked at; a malformed one
is dropped, never fatal.
"""
from __future__ import annotations

import asyncio
import json
import time

from ..accusation import KIND_FLOOD as ABUSE_FLOOD
from ..app_guard import AppGuard, Limit
from ..node_id import NodeID
from . import contacts_state as cs
from .contacts_state import ContactsState

_OFFER = 0x01     # owner -> node: "here is a book, if you want it"
_ACCEPT = 0x02    # node -> owner: "yes"
_DECLINE = 0x03   # node -> owner: "no"
_LEAVE = 0x04     # member -> owner: "I no longer follow this book"
_PULL = 0x05      # member -> owner: "what changed since this sequence?"
_PUSH = 0x06      # either way: contacts, newest wins
_ACK = 0x07       # owner -> member: "I have these of yours"
_REVOKE = 0x08    # owner -> member: "this book is no longer shared with you"

MAX_MESSAGE = 40_000            # bytes, before parsing
PAGE_ENTRIES = 20               # contacts in one push
PAGE_BYTES = 30_000
SYNC_INTERVAL = 300.0           # seconds between rounds of pulls and resends
OFFER_RETRIES = 12              # times an unanswered invitation is sent again
NAMES_REFRESH = 60.0
MAX_NAMES = 5000
_MAX_JOBS = 32

# What one node may send us in ten seconds. Sized per kind like chat's: an
# invitation is the thing a stranger can send and a correct client sends
# rarely, a pull is a question that costs the owner a page of answers.
_LIMITS = {
    "invitations": Limit(4, 60.0, weight=3),
    "answers":     Limit(20, 10.0, weight=2),
    "pulls":       Limit(30, 10.0),
    "pushes":      Limit(60, 10.0),
}
_KINDS = {_OFFER: "invitations", _ACCEPT: "answers", _DECLINE: "answers",
          _LEAVE: "answers", _PULL: "pulls", _PUSH: "pushes", _ACK: "pushes",
          _REVOKE: "answers"}


def _encode(kind: int, body: dict) -> bytes:
    return bytes([kind]) + json.dumps(body, ensure_ascii=False,
                                      separators=(",", ":")).encode("utf-8")


class ContactsApp:
    """Books on this node, kept in step with the nodes they are shared with."""

    def __init__(self, client, *, node_id: NodeID | None = None,
                 state: ContactsState | None = None) -> None:
        self._client = client
        self.node_id = node_id
        self.state = state or ContactsState(me=node_id.raw.hex() if node_id else "")
        self._task: asyncio.Task | None = None
        self._sync_task: asyncio.Task | None = None
        self._jobs: set = set()
        self.names: dict[str, str] = {}      # node id -> the pseudo the node holds
        self._names_at = 0.0
        self._guard = AppGuard(client, _LIMITS, kind=ABUSE_FLOOD, spawn=self._spawn)

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        self.state.ensure_default()
        self._task = asyncio.create_task(self._loop())
        self._sync_task = asyncio.create_task(self._sync_loop())

    async def stop(self) -> None:
        for attr in ("_task", "_sync_task"):
            task = getattr(self, attr, None)
            if task is None:
                continue
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
            setattr(self, attr, None)
        jobs = list(self._jobs)
        self._jobs.clear()
        for job in jobs:
            job.cancel()
        if jobs:
            await asyncio.gather(*jobs, return_exceptions=True)
        await self._client.close()

    def _spawn(self, coro) -> None:
        """Run a short job off the receive loop, bounded, cancelled at stop."""
        if len(self._jobs) >= _MAX_JOBS:
            coro.close()
            return
        try:
            task = asyncio.create_task(coro)
        except RuntimeError:
            coro.close()
            return
        self._jobs.add(task)
        task.add_done_callback(self._jobs.discard)

    async def _loop(self) -> None:
        while True:
            try:
                src, payload = await self._client.recv()
            except (asyncio.IncompleteReadError, ConnectionError, OSError):
                return
            try:
                await self._dispatch(src, payload)
            except Exception:
                pass          # a malformed message is dropped, the loop goes on

    async def _sync_loop(self) -> None:
        await asyncio.sleep(3.0)
        while True:
            try:
                await self.sync_round()
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            await asyncio.sleep(SYNC_INTERVAL)

    # -- sending -----------------------------------------------------------

    async def _send(self, target: str, kind: int, body: dict) -> bool:
        if self.node_id is not None and target == self.node_id.raw.hex():
            return False
        payload = _encode(kind, body)
        if len(payload) > MAX_MESSAGE:
            return False
        try:
            await self._client.send(NodeID(bytes.fromhex(target)), payload)
            return True
        except Exception:
            return False

    def _pages(self, entries: list):
        """Split contacts into messages that fit one frame."""
        page, size = [], 0
        for entry in entries:
            blob = len(json.dumps(entry, ensure_ascii=False))
            if page and (len(page) >= PAGE_ENTRIES or size + blob > PAGE_BYTES):
                yield page
                page, size = [], 0
            page.append(entry)
            size += blob
        if page:
            yield page

    async def offer(self, book_id: str, node: str, role: str) -> bool:
        """Share ``book_id`` with ``node``: an invitation, not a transfer."""
        if not self.state.share(book_id, node, role):
            return False
        return await self._offer_to(book_id, node)

    async def _offer_to(self, book_id: str, node: str) -> bool:
        meta = self.state.book(book_id)
        member = meta["members"].get(node) if meta else None
        if meta is None or member is None:
            return False
        count = sum(1 for e in self.state.entries(book_id))
        return await self._send(node, _OFFER, {
            "book": book_id, "name": meta["name"], "color": meta["color"],
            "role": member["role"], "count": count})

    async def revoke(self, book_id: str, node: str) -> bool:
        """Stop sharing with ``node``; its copy stays with it, as its own."""
        if not self.state.unshare(book_id, node):
            return False
        await self._send(node, _REVOKE, {"book": book_id})
        return True

    async def remove_book(self, book_id: str) -> bool:
        """Delete a book. An owner lets every member go first; a member says it
        is leaving."""
        meta = self.state.delete_book(book_id)
        if meta is None:
            return False
        if meta["role"] == cs.OWNER:
            for node in meta["members"]:
                await self._send(node, _REVOKE, {"book": book_id})
        else:
            await self._send(meta["owner"], _LEAVE, {"book": book_id})
        return True

    async def respond(self, book_id: str, sender: str, accept: bool) -> bool:
        """A human's answer to an invitation."""
        offer = self.state.take_offer(book_id, sender)
        if offer is None:
            return False
        if not accept:
            await self._send(sender, _DECLINE, {"book": book_id})
            return True
        if not self.state.accept_offer(offer):
            await self._send(sender, _DECLINE, {"book": book_id})
            return False
        await self._send(sender, _ACCEPT, {"book": book_id})
        await self._pull(book_id)
        return True

    async def _pull(self, book_id: str) -> None:
        meta = self.state.book(book_id)
        if meta is None or meta["role"] == cs.OWNER:
            return
        await self._send(meta["owner"], _PULL, {"book": book_id, "since": meta["synced"]})

    async def after_change(self, book_id: str, cids=(), *, skip: str = "") -> None:
        """Tell the other side about an edit made here, best effort — the next
        sync round carries what this misses. ``skip`` is a member that sent the
        change and already has it."""
        meta = self.state.book(book_id)
        if meta is None:
            return
        if meta["role"] == cs.OWNER:
            rows = self.state.raw_entries(book_id, cids)
            for node, member in meta["members"].items():
                if member["state"] == "active" and rows and node != skip:
                    await self._push_to(node, book_id, rows)
        else:
            await self._push_dirty(book_id)

    async def _push_to(self, node: str, book_id: str, rows: list, *,
                       page: bool = False, top: int = 0, more: bool = False) -> None:
        pages = list(self._pages(rows)) or [[]]
        for i, chunk in enumerate(pages):
            last = i == len(pages) - 1
            body = {"book": book_id, "entries": chunk}
            if page:
                body.update(page=True, top=top, more=more and last)
            await self._send(node, _PUSH, body)

    async def _push_dirty(self, book_id: str) -> None:
        meta = self.state.book(book_id)
        if meta is None or meta["role"] != "write":
            return
        rows = self.state.dirty_entries(book_id, 200)
        if rows:
            await self._push_to(meta["owner"], book_id, rows)

    # -- one round of housekeeping ------------------------------------------

    async def sync_round(self) -> None:
        """Ask every owner for what changed, send what is still ours to send,
        and say again to anyone who has not answered an invitation."""
        for meta in self.state.books():
            book_id = meta["id"]
            if meta["role"] == cs.OWNER:
                for node, member in meta["members"].items():
                    if member["state"] == "offered" and member["tries"] < OFFER_RETRIES:
                        self.state.note_try(book_id, node)
                        await self._offer_to(book_id, node)
            else:
                await self._pull(book_id)
                await self._push_dirty(book_id)
        await self.refresh_names()

    async def refresh_names(self, force: bool = False) -> None:
        """Re-read what the node calls the nodes in these books."""
        now = time.monotonic()
        if not force and self._names_at and now - self._names_at < NAMES_REFRESH:
            return
        self._names_at = now
        resolve = getattr(self._client, "refresh_names", None)
        if resolve is None:
            return
        ids = sorted(self.state.node_ids())[:MAX_NAMES]
        if not ids:
            return
        try:
            found = await resolve(ids)
        except Exception:
            return
        for node in ids:
            if found.get(node):
                self.names[node] = str(found[node])[:64]
            else:
                self.names.pop(node, None)
        while len(self.names) > MAX_NAMES:
            self.names.pop(next(iter(self.names)))

    async def name_of(self, node: str) -> str:
        """What the node calls ``node``, asked now when it is not already known."""
        known = self.names.get(node)
        if known:
            return known
        resolve = getattr(self._client, "refresh_names", None)
        if resolve is None:
            return ""
        try:
            found = await resolve([node])
        except Exception:
            return ""
        name = found.get(node) if isinstance(found, dict) else None
        return str(name)[:64] if name else ""

    async def lookup(self, query: str, *, wide: bool = False) -> list:
        """The node's directory, asked for a name (whole or partial)."""
        fn = getattr(self._client, "lookup_pseudo", None)
        if fn is None:
            return []
        try:
            rows = await fn(query, wide=wide)
        except Exception:
            return []
        out = []
        for row in rows[:cs.MAX_RESULTS]:
            node, name = row.get("id"), row.get("pseudo")
            if cs.is_node(node) and isinstance(name, str):
                self.names.setdefault(node, name[:64])
                out.append({"id": node, "pseudo": name[:64],
                            "match": row.get("match", 3)})
        return out

    async def notify(self, key: str, summary: str) -> None:
        fn = getattr(self._client, "notify", None)
        if fn is None:
            return
        try:
            await fn(key, summary, level="warn")
        except Exception:
            pass

    # -- receiving ---------------------------------------------------------

    async def _dispatch(self, src: NodeID, payload: bytes) -> None:
        if not payload or len(payload) > MAX_MESSAGE:
            return
        kind = payload[0]
        handler = _HANDLERS.get(kind)
        if handler is None:
            return
        if not self._guard.allow(_KINDS[kind], src):
            return
        try:
            body = json.loads(payload[1:].decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            return
        if not isinstance(body, dict) or not cs.is_book_id(body.get("book")):
            return
        await handler(self, src.raw.hex(), body)

    async def _on_offer(self, src: str, body: dict) -> None:
        role, name = body.get("role"), body.get("name")
        if role not in cs.ROLES or not isinstance(name, str):
            return
        count = body.get("count")
        meta = self.state.book(body["book"])
        if meta is not None:
            # A book we already follow: the owner is telling us what we may do.
            if meta["role"] != cs.OWNER and meta["owner"] == src:
                self.state.set_role(body["book"], role)
            return
        if self.state.receive_offer(src, body["book"], name,
                                    body.get("color") if isinstance(body.get("color"), str) else "",
                                    role, count if isinstance(count, int) else 0):
            self._spawn(self.notify(
                "contacts-offer", "A contact book was shared with this node"))

    async def _on_accept(self, src: str, body: dict) -> None:
        self.state.activate_member(body["book"], src)

    async def _on_decline(self, src: str, body: dict) -> None:
        self.state.unshare(body["book"], src)

    async def _on_leave(self, src: str, body: dict) -> None:
        self.state.unshare(body["book"], src)

    async def _on_pull(self, src: str, body: dict) -> None:
        book_id = body["book"]
        member = self.state.member_state(book_id, src)
        if member is None:
            # It still thinks it follows a book we let go of (the revoke was
            # lost): say so, once per question, and it will stop asking.
            meta = self.state.book(book_id)
            if meta is not None and meta["role"] == cs.OWNER:
                await self._send(src, _REVOKE, {"book": book_id})
            return
        if member["state"] != "active":
            self.state.activate_member(book_id, src)
        since = body.get("since")
        since = since if isinstance(since, int) and not isinstance(since, bool) and since >= 0 else 0
        entries, top, more = self.state.changes_since(book_id, since, PAGE_ENTRIES)
        await self._push_to(src, book_id, entries, page=True, top=top, more=more)

    async def _on_push(self, src: str, body: dict) -> None:
        book_id = body["book"]
        entries = body.get("entries")
        if not isinstance(entries, list) or len(entries) > PAGE_ENTRIES * 2:
            return
        meta = self.state.book(book_id)
        if meta is None:
            return
        if meta["role"] == cs.OWNER:
            member = meta["members"].get(src)
            if member is None or member["state"] != "active" or member["role"] != "write":
                return
            taken = self.state.merge(book_id, entries, from_owner=False, writer=src)
            ids = [e.get("id") for e in entries if isinstance(e, dict) and cs.is_cid(e.get("id"))]
            await self._send(src, _ACK, {"book": book_id, "ids": ids})
            if taken:
                await self.after_change(book_id, taken, skip=src)
            return
        if meta["owner"] != src:
            return
        self.state.merge(book_id, entries, from_owner=True)
        if body.get("page") is True:
            top = body.get("top")
            top = top if isinstance(top, int) and not isinstance(top, bool) else 0
            seqs = [e.get("seq") for e in entries if isinstance(e, dict)
                    and isinstance(e.get("seq"), int) and not isinstance(e.get("seq"), bool)]
            if body.get("more") is True and seqs:
                self.state.mark_synced(book_id, max(seqs))
                await self._pull(book_id)
            else:
                self.state.mark_synced(book_id, max([top] + seqs))

    async def _on_ack(self, src: str, body: dict) -> None:
        meta = self.state.book(body["book"])
        if meta is None or meta["role"] == cs.OWNER or meta["owner"] != src:
            return
        ids = body.get("ids")
        if isinstance(ids, list):
            self.state.clear_dirty(body["book"], [i for i in ids if cs.is_cid(i)][:cs.MAX_ENTRIES])

    async def _on_revoke(self, src: str, body: dict) -> None:
        meta = self.state.book(body["book"])
        if meta is None or meta["role"] == cs.OWNER or meta["owner"] != src:
            return
        if self.state.detach(body["book"]):
            self._spawn(self.notify(
                "contacts-revoked", "A shared contact book is now only on this node"))


_HANDLERS = {
    _OFFER: ContactsApp._on_offer,
    _ACCEPT: ContactsApp._on_accept,
    _DECLINE: ContactsApp._on_decline,
    _LEAVE: ContactsApp._on_leave,
    _PULL: ContactsApp._on_pull,
    _PUSH: ContactsApp._on_push,
    _ACK: ContactsApp._on_ack,
    _REVOKE: ContactsApp._on_revoke,
}
