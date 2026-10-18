"""
Contacts state — address books, and the contacts in them.

A **book** is a named list of **contacts**; a contact is a name a person chose
and the nodes it answers to. A node keeps several books (family, work, the ones
other people shared), and every other app on the node asks for them through the
permission model (:mod:`src.app_perms`, ``contacts.read`` / ``contacts.write``)
rather than keeping a list of its own.

**A name here is somebody's own word.** What a node is called by *itself* is a
signed claim the node holds (:mod:`src.pseudo_dir`); what a contact is called is
what the person who owns the book wrote. The two are kept apart on purpose: the
second may be a nickname, and when it came from a shared book it is a stranger's
opinion that the owner of this node accepted once.

**A book can be shared.** The node that made it owns it; a book offered to
another node is a pending invitation until a human accepts, and then a
*mirror* — read-only, or writable when the owner said so — that the two keep in
step by the sync messages in :mod:`.contacts`. This module is only the data and
its rules: no sockets, no clock beyond a timestamp, no node.

Every collection is hard-bounded. A book is one value of the node's per-app
drawer (a quarter of a megabyte at most), so a book that no longer fits is
refused rather than truncated; tombstones are kept to carry a deletion to the
nodes that have not heard of it yet, and are the first thing to go when room is
needed.
"""
from __future__ import annotations

import json
import re
import secrets
import threading
import time

from .. import pseudo as pseudo_mod

BOOK_PREFIX = "book:"
_INDEX_KEY = "index"
_VALUE_MAX = 240 * 1024         # a drawer value is 256 KiB; keep clear of the edge

MAX_BOOKS = 32
MAX_ENTRIES = 1000              # per book, tombstones included
MAX_NODES = 8                   # nodes one contact answers to
MAX_NAME = 64
MAX_LABEL = 32
MAX_NOTE = 512
MAX_BOOK_NAME = 48
MAX_MEMBERS = 32                # nodes one book is shared with
MAX_OFFERS = 16                 # invitations waiting for a human, in all
MAX_OFFERS_PER_SENDER = 2
OFFER_TTL = 14 * 24 * 3600.0
TOMBSTONE_TTL = 90 * 24 * 3600.0
MAX_RESULTS = 200
MAX_COUNTER = 1 << 40           # an entry's version cannot be pushed past this

COLORS = ("blue", "green", "teal", "amber", "red", "purple", "pink", "gray")
ROLES = ("read", "write")
OWNER, LOCAL = "owner", "owner"   # my role in a book that is mine
MEMBER_STATES = ("offered", "active")

_ID_RE = re.compile(r"^[0-9a-f]{40}$")
_BOOK_RE = re.compile(r"^[0-9a-f]{32}$")
_CID_RE = re.compile(r"^[0-9a-f]{32}$")


def is_node(value) -> bool:
    return isinstance(value, str) and _ID_RE.match(value) is not None


def is_book_id(value) -> bool:
    return isinstance(value, str) and _BOOK_RE.match(value) is not None


def is_cid(value) -> bool:
    return isinstance(value, str) and _CID_RE.match(value) is not None


def _count(value) -> int:
    """A counter read back from storage or the wire: a whole number in range."""
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_COUNTER:
        return value
    return 0


def _line(value, limit: int) -> str:
    """One printable line, bounded — what a person typed or a peer sent."""
    if not isinstance(value, str):
        return ""
    clean = "".join(ch for ch in value if ch.isprintable())
    return " ".join(clean.split())[:limit]


def _text(value, limit: int) -> str:
    """A note: printable, newlines kept, bounded."""
    if not isinstance(value, str):
        return ""
    clean = "".join(ch for ch in value if ch.isprintable() or ch in "\n")
    return clean.strip()[:limit]


def clean_entry(raw, *, keep_version: bool = False):
    """A contact brought inside what is kept, or ``None`` when it is not one.

    Used on what a person typed *and* on what a peer sent: both are untrusted
    until they have been through here. ``keep_version`` is for the second —
    a sync message carries the version the entry was written under."""
    if not isinstance(raw, dict):
        return None
    cid = raw.get("id")
    if not is_cid(cid):
        return None
    nodes, seen = [], set()
    listed = raw.get("nodes")
    for item in (listed if isinstance(listed, list) else [])[:MAX_NODES]:
        if isinstance(item, str):
            item = {"id": item}
        if not isinstance(item, dict) or not is_node(item.get("id")):
            continue
        if item["id"] in seen:
            continue
        seen.add(item["id"])
        nodes.append({"id": item["id"], "label": _line(item.get("label"), MAX_LABEL)})
    entry = {"id": cid, "name": _line(raw.get("name"), MAX_NAME), "nodes": nodes,
             "note": _text(raw.get("note"), MAX_NOTE), "fav": raw.get("fav") is True,
             "del": raw.get("del") is True, "t": 0.0, "seq": 0, "v": [0, ""]}
    if not entry["del"] and not entry["name"] and not nodes:
        return None
    t = raw.get("t")
    entry["t"] = float(t) if isinstance(t, (int, float)) and 0 <= t < 1e11 else 0.0
    if keep_version:
        version = raw.get("v")
        if (not isinstance(version, list) or len(version) != 2
                or not isinstance(version[0], int) or isinstance(version[0], bool)
                or not 0 <= version[0] <= MAX_COUNTER
                or not (version[1] == "" or is_node(version[1]))):
            return None
        entry["v"] = [version[0], version[1]]
    entry["seq"] = _count(raw.get("seq"))
    if entry["del"]:
        # A tombstone says only that this contact is gone. What it used to hold
        # is not kept: the deletion is the whole message.
        entry.update(name="", nodes=[], note="", fav=False)
    return entry


def newer(candidate: dict, current: dict | None) -> bool:
    """Does ``candidate`` win over ``current``? Higher counter, then higher
    writer id — a total order, so every replica settles on the same entry."""
    if current is None:
        return True
    return tuple(candidate["v"]) > tuple(current["v"])


def search_key(entry: dict) -> str:
    parts = [entry.get("name", "")] + [n.get("label", "") for n in entry.get("nodes", ())]
    return pseudo_mod.fold(" ".join(p for p in parts if p))


class ContactsState:
    """The books of one node, thread-safe and persisted in an encrypted drawer.

    ``store`` is a :class:`~src.apps.chat_state.DrawerStore`; without one the
    state lives in memory (tests, demos). ``me`` is this node's id in hex — the
    writer stamped on what the person here changes, which is what makes two
    nodes' simultaneous edits of one contact settle the same way everywhere."""

    def __init__(self, store=None, me: str = "") -> None:
        self._store = store
        self.me = me if is_node(me) else ""
        self._lock = threading.RLock()
        self._books: dict[str, dict] = {}       # id -> meta (no entries)
        self._entries: dict[str, dict] = {}     # book id -> {cid -> entry}
        self._folded: dict[tuple, str] = {}     # (book, cid) -> search key
        self._offers: list[dict] = []
        self.default = ""
        self.version = 0                        # bumped by every change, read by pollers
        self._load()

    # -- persistence -------------------------------------------------------

    def _read(self, key: str):
        if self._store is None:
            return None
        try:
            blob = self._store.get(key)
            return json.loads(blob.decode("utf-8")) if blob else None
        except Exception:
            return None            # unreadable or corrupt: start empty, never crash

    def _write(self, key: str, doc) -> bool:
        if self._store is None:
            return True
        blob = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(blob) > _VALUE_MAX:
            return False
        try:
            return bool(self._store.put(key, blob))
        except Exception:
            return False

    def _load(self) -> None:
        index = self._read(_INDEX_KEY)
        if not isinstance(index, dict):
            return
        books = index.get("books")
        for book_id in (list(books) if isinstance(books, list) else [])[:MAX_BOOKS]:
            if not is_book_id(book_id):
                continue
            doc = self._read(BOOK_PREFIX + book_id)
            meta = self._clean_meta(doc.get("meta") if isinstance(doc, dict) else None, book_id)
            if meta is None:
                continue
            self._books[book_id] = meta
            entries = {}
            raw_entries = doc.get("entries")
            for raw in (list(raw_entries.values()) if isinstance(raw_entries, dict) else [])[:MAX_ENTRIES]:
                entry = clean_entry(raw, keep_version=True)
                if entry is not None:
                    entries[entry["id"]] = entry
            self._entries[book_id] = entries
            for cid, entry in entries.items():
                self._folded[(book_id, cid)] = search_key(entry)
        default = index.get("default")
        self.default = default if default in self._books else ""
        offers = index.get("offers")
        for raw in (offers if isinstance(offers, list) else [])[:MAX_OFFERS]:
            offer = self._clean_offer(raw)
            if offer is not None:
                self._offers.append(offer)

    def _clean_meta(self, raw, book_id: str):
        if not isinstance(raw, dict):
            return None
        owner = raw.get("owner")
        role = raw.get("role")
        if role not in (OWNER,) + ROLES:
            return None
        if role != OWNER and not is_node(owner):
            return None
        members = {}
        listed = raw.get("members")
        for node, row in (list(listed.items()) if isinstance(listed, dict) else [])[:MAX_MEMBERS]:
            if is_node(node) and isinstance(row, dict) and row.get("role") in ROLES:
                state = row.get("state") if row.get("state") in MEMBER_STATES else "offered"
                members[node] = {"role": row["role"], "state": state,
                                 "tries": min(_count(row.get("tries")), 99)}
        dirty = [c for c in (raw.get("dirty") if isinstance(raw.get("dirty"), list) else [])
                 if is_cid(c)][:MAX_ENTRIES]
        return {"id": book_id,
                "name": _line(raw.get("name"), MAX_BOOK_NAME) or "Contacts",
                "color": raw.get("color") if raw.get("color") in COLORS else "blue",
                "owner": owner if role != OWNER else self.me,
                "role": role, "members": members,
                "seq": _count(raw.get("seq")), "synced": _count(raw.get("synced")),
                "created": float(raw.get("created") or 0) if isinstance(raw.get("created"), (int, float)) else 0.0,
                "dirty": dirty}

    def _clean_offer(self, raw):
        if not isinstance(raw, dict):
            return None
        sender, book = raw.get("from"), raw.get("book")
        if not is_node(sender) or not is_book_id(book) or raw.get("role") not in ROLES:
            return None
        at = raw.get("at")
        return {"from": sender, "book": book,
                "name": _line(raw.get("name"), MAX_BOOK_NAME) or "Contacts",
                "color": raw.get("color") if raw.get("color") in COLORS else "blue",
                "role": raw["role"], "count": min(_count(raw.get("count")), MAX_ENTRIES),
                "at": float(at) if isinstance(at, (int, float)) else 0.0}

    def _persist_index(self) -> None:
        self._write(_INDEX_KEY, {"books": list(self._books), "default": self.default,
                                 "offers": self._offers})

    def _persist_book(self, book_id: str) -> bool:
        doc = {"meta": self._books[book_id], "entries": self._entries[book_id]}
        return self._write(BOOK_PREFIX + book_id, doc)

    def _changed(self) -> None:
        self.version += 1

    # -- books -------------------------------------------------------------

    def ensure_default(self) -> str:
        """The book new contacts go to, made on first use."""
        with self._lock:
            if self.default in self._books:
                return self.default
            for book_id, meta in self._books.items():
                if meta["role"] == OWNER:
                    self.default = book_id
                    self._persist_index()
                    return book_id
            book_id = self.create_book("Contacts", "blue")
            return book_id or ""

    def create_book(self, name: str, color: str = "blue") -> str:
        with self._lock:
            if len(self._books) >= MAX_BOOKS:
                return ""
            book_id = secrets.token_hex(16)
            meta = {"id": book_id, "name": _line(name, MAX_BOOK_NAME) or "Contacts",
                    "color": color if color in COLORS else "blue", "owner": self.me,
                    "role": OWNER, "members": {}, "seq": 0, "synced": 0,
                    "created": time.time(), "dirty": []}
            self._books[book_id] = meta
            self._entries[book_id] = {}
            if not self.default:
                self.default = book_id
            self._persist_book(book_id)
            self._persist_index()
            self._changed()
            return book_id

    def set_book(self, book_id: str, *, name=None, color=None) -> bool:
        with self._lock:
            meta = self._books.get(book_id)
            if meta is None or meta["role"] != OWNER:
                return False
            if isinstance(name, str) and _line(name, MAX_BOOK_NAME):
                meta["name"] = _line(name, MAX_BOOK_NAME)
            if color in COLORS:
                meta["color"] = color
            self._persist_book(book_id)
            self._changed()
            return True

    def set_default(self, book_id: str) -> bool:
        with self._lock:
            meta = self._books.get(book_id)
            if meta is None or meta["role"] not in (OWNER, "write"):
                return False
            self.default = book_id
            self._persist_index()
            self._changed()
            return True

    def delete_book(self, book_id: str) -> dict | None:
        """Remove a book from this node. Returns what it was (for the app to
        tell the other side), or ``None`` when there was no such book."""
        with self._lock:
            meta = self._books.pop(book_id, None)
            if meta is None:
                return None
            self._entries.pop(book_id, None)
            for key in [k for k in self._folded if k[0] == book_id]:
                del self._folded[key]
            if self.default == book_id:
                self.default = ""
                for other, row in self._books.items():
                    if row["role"] == OWNER:
                        self.default = other
                        break
            if self._store is not None:
                try:
                    self._store.delete(BOOK_PREFIX + book_id)
                except Exception:
                    pass
            self._persist_index()
            self._changed()
            return meta

    def book(self, book_id: str) -> dict | None:
        with self._lock:
            meta = self._books.get(book_id)
            return json.loads(json.dumps(meta)) if meta else None

    def books(self) -> list[dict]:
        """Every book, without its contacts, with how many it holds."""
        with self._lock:
            out = []
            for book_id, meta in self._books.items():
                live = sum(1 for e in self._entries[book_id].values() if not e["del"])
                row = json.loads(json.dumps(meta))
                row.update(count=live, default=(book_id == self.default),
                           writable=meta["role"] in (OWNER, "write"),
                           shared=bool(meta["members"]) or meta["role"] != OWNER)
                row.pop("dirty", None)
                out.append(row)
            out.sort(key=lambda r: (not r["default"], r["name"].casefold()))
            return out

    def can_write(self, book_id: str) -> bool:
        with self._lock:
            meta = self._books.get(book_id)
            return bool(meta and meta["role"] in (OWNER, "write"))

    # -- contacts ----------------------------------------------------------

    def _store_entry(self, book_id: str, entry: dict) -> bool:
        """Put ``entry`` in its book if it fits; the book is left as it was
        when it does not."""
        entries = self._entries[book_id]
        previous = entries.get(entry["id"])
        if previous is None and len(entries) >= MAX_ENTRIES:
            self._prune(book_id)
            if len(entries) >= MAX_ENTRIES:
                return False
        entries[entry["id"]] = entry
        if not self._persist_book(book_id):
            if previous is None:
                del entries[entry["id"]]
            else:
                entries[entry["id"]] = previous
            return False
        self._folded[(book_id, entry["id"])] = search_key(entry)
        self._changed()
        return True

    def _prune(self, book_id: str) -> None:
        """Make room: forget the tombstones that have had time to travel."""
        entries = self._entries[book_id]
        horizon = time.time() - TOMBSTONE_TTL
        for cid in [c for c, e in entries.items() if e["del"] and e["t"] < horizon]:
            del entries[cid]
            self._folded.pop((book_id, cid), None)

    def _stamp(self, book_id: str, entry: dict, previous: dict | None) -> dict:
        meta = self._books[book_id]
        counter = (previous["v"][0] if previous else 0) + 1
        entry["v"] = [min(counter, MAX_COUNTER), self.me]
        entry["t"] = time.time()
        if meta["role"] == OWNER:
            meta["seq"] += 1
            entry["seq"] = meta["seq"]
        else:
            entry["seq"] = previous["seq"] if previous else 0
            if entry["id"] not in meta["dirty"]:
                meta["dirty"].append(entry["id"])
        return entry

    def save(self, book_id: str, fields: dict, cid: str | None = None):
        """Create or change a contact. ``(True, contact)`` or ``(False, why)``.

        ``why`` is one of ``no_book``, ``read_only``, ``empty``, ``full``."""
        with self._lock:
            meta = self._books.get(book_id)
            if meta is None:
                return False, "no_book"
            if meta["role"] not in (OWNER, "write"):
                return False, "read_only"
            previous = self._entries[book_id].get(cid) if cid else None
            if cid and (previous is None or previous["del"]):
                return False, "no_contact"
            raw = dict(previous or {})
            raw.update({k: fields[k] for k in ("name", "nodes", "note", "fav") if k in fields})
            raw["id"] = cid or secrets.token_hex(16)
            raw["del"] = False
            entry = clean_entry(raw)
            if entry is None:
                return False, "empty"
            saved = (meta["seq"], list(meta["dirty"]))
            entry = self._stamp(book_id, entry, previous)
            if not self._store_entry(book_id, entry):
                meta["seq"], meta["dirty"] = saved
                return False, "full"
            return True, json.loads(json.dumps(entry))

    def remove(self, book_id: str, cid: str):
        with self._lock:
            meta = self._books.get(book_id)
            if meta is None:
                return False, "no_book"
            if meta["role"] not in (OWNER, "write"):
                return False, "read_only"
            previous = self._entries[book_id].get(cid)
            if previous is None or previous["del"]:
                return False, "no_contact"
            saved = (meta["seq"], list(meta["dirty"]))
            tomb = clean_entry({"id": cid, "del": True})
            tomb = self._stamp(book_id, tomb, previous)
            if not self._store_entry(book_id, tomb):
                meta["seq"], meta["dirty"] = saved
                return False, "full"
            return True, None

    def add_node(self, node: str, name: str = "", book_id: str = ""):
        """The one thing other apps ask: "this node is somebody I know".

        Idempotent per book: a node already in the book is not added twice."""
        if not is_node(node):
            return False, "bad_node"
        with self._lock:
            target = book_id or self.ensure_default()
            if not target or target not in self._books:
                return False, "no_book"
            for entry in self._entries[target].values():
                if not entry["del"] and any(n["id"] == node for n in entry["nodes"]):
                    if name and not entry["name"] and self.can_write(target):
                        return self.save(target, {"name": name}, entry["id"])
                    return True, json.loads(json.dumps(entry))
            return self.save(target, {"name": name or "", "nodes": [{"id": node}]})

    def remove_node(self, node: str, book_id: str = "") -> int:
        """Take a node out of the books it is in (one book, or every writable
        one). A contact left with no node and no name goes with it."""
        done = 0
        with self._lock:
            for target in ([book_id] if book_id else list(self._books)):
                if not self.can_write(target):
                    continue
                for entry in list(self._entries.get(target, {}).values()):
                    if entry["del"] or not any(n["id"] == node for n in entry["nodes"]):
                        continue
                    rest = [n for n in entry["nodes"] if n["id"] != node]
                    if rest or entry["name"]:
                        ok, _ = self.save(target, {"nodes": rest}, entry["id"])
                    else:
                        ok, _ = self.remove(target, entry["id"])
                    done += 1 if ok else 0
        return done

    def get(self, book_id: str, cid: str):
        with self._lock:
            entry = self._entries.get(book_id, {}).get(cid)
            return json.loads(json.dumps(entry)) if entry and not entry["del"] else None

    def entries(self, book_id: str | None = None, *, limit: int = MAX_ENTRIES * MAX_BOOKS) -> list[dict]:
        """Live contacts (never tombstones), a book's or every book's, by name."""
        with self._lock:
            out = []
            for target in ([book_id] if book_id else list(self._books)):
                for entry in self._entries.get(target, {}).values():
                    if not entry["del"]:
                        row = json.loads(json.dumps(entry))
                        row["book"] = target
                        out.append(row)
            out.sort(key=lambda r: (not r["fav"], (r["name"] or r["nodes"][0]["id"]).casefold()))
            return out[:limit]

    def raw_entries(self, book_id: str, cids) -> list[dict]:
        """The named entries as stored, tombstones included — what goes on the
        wire when something changed."""
        with self._lock:
            entries = self._entries.get(book_id, {})
            return [json.loads(json.dumps(entries[c])) for c in cids if c in entries]

    def find(self, node: str) -> list[dict]:
        """Every contact that answers to ``node``, my own books first."""
        with self._lock:
            out = []
            for book_id, entries in self._entries.items():
                for entry in entries.values():
                    if not entry["del"] and any(n["id"] == node for n in entry["nodes"]):
                        row = json.loads(json.dumps(entry))
                        row["book"] = book_id
                        row["book_name"] = self._books[book_id]["name"]
                        row["mine"] = self._books[book_id]["role"] == OWNER
                        out.append(row)
            out.sort(key=lambda r: (not r["mine"], r["book_name"].casefold()))
            return out

    def node_names(self) -> dict:
        """node id -> the name my own books give it, for every node known."""
        with self._lock:
            out: dict[str, str] = {}
            for book_id, entries in self._entries.items():
                mine = self._books[book_id]["role"] == OWNER
                for entry in entries.values():
                    if entry["del"] or not entry["name"]:
                        continue
                    for node in entry["nodes"]:
                        if mine or node["id"] not in out:
                            out[node["id"]] = entry["name"]
            return out

    def node_ids(self) -> set:
        """Every node a screen of this app can name: the ones in a contact, and
        the owner and members of each book."""
        with self._lock:
            out = {n["id"] for entries in self._entries.values()
                   for e in entries.values() if not e["del"] for n in e["nodes"]}
            for meta in self._books.values():
                out.update(meta["members"])
                if meta.get("owner") and meta["owner"] != self.me:
                    out.add(meta["owner"])
            return out

    def search(self, query: str, limit: int = 50) -> list[dict]:
        """Contacts matching what was typed: a name, a label, a note word or the
        start of a node id. Best match first; the same ranking the node's
        directory uses, so a name found here and a name found on the network
        sort alike."""
        needle = pseudo_mod.fold(query)
        raw = query.strip().lower() if isinstance(query, str) else ""
        limit = max(1, min(int(limit), MAX_RESULTS))
        if not needle:
            return []
        by_id = len(raw) >= 4 and re.fullmatch(r"[0-9a-f]+", raw) is not None
        scored = []
        with self._lock:
            for (book_id, cid), folded in self._folded.items():
                entry = self._entries[book_id].get(cid)
                if entry is None or entry["del"]:
                    continue
                rank = pseudo_mod.rank_folded(needle, folded)
                if rank is None and by_id and any(n["id"].startswith(raw) for n in entry["nodes"]):
                    rank = pseudo_mod.PREFIX
                if rank is None and len(needle) >= 3 and needle in pseudo_mod.fold(entry["note"]):
                    rank = pseudo_mod.CONTAINS + 1
                if rank is None:
                    continue
                row = json.loads(json.dumps(entry))
                row["book"] = book_id
                row["book_name"] = self._books[book_id]["name"]
                scored.append((rank, not entry["fav"], len(entry["name"]), row))
        scored.sort(key=lambda s: s[:3])
        return [row for *_, row in scored[:limit]]

    # -- sharing: the owner's side -----------------------------------------

    def share(self, book_id: str, node: str, role: str) -> bool:
        with self._lock:
            meta = self._books.get(book_id)
            if (meta is None or meta["role"] != OWNER or role not in ROLES
                    or not is_node(node) or node == self.me):
                return False
            if node not in meta["members"] and len(meta["members"]) >= MAX_MEMBERS:
                return False
            previous = meta["members"].get(node)
            meta["members"][node] = {"role": role,
                                     "state": previous["state"] if previous else "offered",
                                     "tries": 0 if not previous else previous.get("tries", 0)}
            self._persist_book(book_id)
            self._changed()
            return True

    def unshare(self, book_id: str, node: str) -> bool:
        with self._lock:
            meta = self._books.get(book_id)
            if meta is None or meta["role"] != OWNER or node not in meta["members"]:
                return False
            del meta["members"][node]
            self._persist_book(book_id)
            self._changed()
            return True

    def member_state(self, book_id: str, node: str):
        with self._lock:
            meta = self._books.get(book_id)
            return dict(meta["members"][node]) if meta and node in meta["members"] else None

    def activate_member(self, book_id: str, node: str) -> bool:
        with self._lock:
            meta = self._books.get(book_id)
            if meta is None or meta["role"] != OWNER or node not in meta["members"]:
                return False
            meta["members"][node]["state"] = "active"
            self._persist_book(book_id)
            self._changed()
            return True

    def note_try(self, book_id: str, node: str) -> int:
        with self._lock:
            meta = self._books.get(book_id)
            row = meta["members"].get(node) if meta else None
            if row is None:
                return 99
            row["tries"] = min(99, row.get("tries", 0) + 1)
            self._persist_book(book_id)
            return row["tries"]

    def changes_since(self, book_id: str, since: int, limit: int) -> tuple[list, int, bool]:
        """What the owner has that a member at ``since`` has not: up to
        ``limit`` entries by sequence, the owner's current sequence, and
        whether more remain."""
        with self._lock:
            meta = self._books.get(book_id)
            if meta is None:
                return [], 0, False
            newer_entries = sorted((e for e in self._entries[book_id].values() if e["seq"] > since),
                                   key=lambda e: e["seq"])
            page = newer_entries[:limit]
            return ([json.loads(json.dumps(e)) for e in page], meta["seq"],
                    len(newer_entries) > len(page))

    # -- sharing: the member's side ----------------------------------------

    def offers(self) -> list[dict]:
        with self._lock:
            self._expire_offers()
            return [dict(o) for o in self._offers]

    def _expire_offers(self) -> None:
        horizon = time.time() - OFFER_TTL
        kept = [o for o in self._offers if o["at"] >= horizon]
        if len(kept) != len(self._offers):
            self._offers = kept
            self._persist_index()

    def receive_offer(self, sender: str, book: str, name: str, color: str,
                      role: str, count: int) -> bool:
        """Keep an invitation until a human answers it. Bounded in all and per
        sender, and a repeat replaces itself rather than queueing."""
        offer = self._clean_offer({"from": sender, "book": book, "name": name,
                                   "color": color, "role": role, "count": count,
                                   "at": time.time()})
        if offer is None:
            return False
        with self._lock:
            self._expire_offers()
            if book in self._books:
                return False
            same = [o for o in self._offers if o["from"] == sender and o["book"] == book]
            if same:
                self._offers.remove(same[0])
            elif (len(self._offers) >= MAX_OFFERS
                  or sum(1 for o in self._offers if o["from"] == sender) >= MAX_OFFERS_PER_SENDER):
                return False
            self._offers.append(offer)
            self._persist_index()
            self._changed()
            return True

    def take_offer(self, book: str, sender: str) -> dict | None:
        with self._lock:
            for offer in self._offers:
                if offer["book"] == book and offer["from"] == sender:
                    self._offers.remove(offer)
                    self._persist_index()
                    self._changed()
                    return offer
            return None

    def accept_offer(self, offer: dict) -> bool:
        """Make the mirror an accepted invitation promised."""
        with self._lock:
            if len(self._books) >= MAX_BOOKS or offer["book"] in self._books:
                return False
            meta = {"id": offer["book"], "name": offer["name"], "color": offer["color"],
                    "owner": offer["from"], "role": offer["role"], "members": {},
                    "seq": 0, "synced": 0, "created": time.time(), "dirty": []}
            self._books[offer["book"]] = meta
            self._entries[offer["book"]] = {}
            self._persist_book(offer["book"])
            self._persist_index()
            self._changed()
            return True

    def detach(self, book_id: str) -> bool:
        """The owner let this node go: the copy stays, and becomes this node's."""
        with self._lock:
            meta = self._books.get(book_id)
            if meta is None or meta["role"] == OWNER:
                return False
            meta.update(role=OWNER, owner=self.me, members={}, dirty=[],
                        seq=max((e["seq"] for e in self._entries[book_id].values()), default=0))
            self._persist_book(book_id)
            self._changed()
            return True

    def set_role(self, book_id: str, role: str) -> bool:
        with self._lock:
            meta = self._books.get(book_id)
            if meta is None or meta["role"] == OWNER or role not in ROLES:
                return False
            meta["role"] = role
            self._persist_book(book_id)
            self._changed()
            return True

    def mirrors_of(self, owner: str) -> list[str]:
        with self._lock:
            return [b for b, m in self._books.items() if m["role"] != OWNER and m["owner"] == owner]

    def dirty_entries(self, book_id: str, limit: int) -> list[dict]:
        with self._lock:
            meta = self._books.get(book_id)
            if meta is None:
                return []
            rows = [self._entries[book_id][c] for c in meta["dirty"] if c in self._entries[book_id]]
            return [json.loads(json.dumps(e)) for e in rows[:limit]]

    def clear_dirty(self, book_id: str, cids) -> None:
        with self._lock:
            meta = self._books.get(book_id)
            if meta is None:
                return
            drop = set(cids)
            meta["dirty"] = [c for c in meta["dirty"] if c not in drop]
            self._persist_book(book_id)

    def mark_synced(self, book_id: str, seq: int) -> None:
        with self._lock:
            meta = self._books.get(book_id)
            if meta is not None and 0 <= seq <= MAX_COUNTER and seq > meta["synced"]:
                meta["synced"] = seq
                self._persist_book(book_id)

    # -- merging what a peer sent ------------------------------------------

    def merge(self, book_id: str, entries, *, from_owner: bool, writer: str = "") -> list[str]:
        """Fold peer entries into a book. Returns the ids that were taken.

        ``from_owner`` is the direction: an owner's entries arrive with the
        sequence the owner gave them; a member's are stamped here, with the
        next sequence, because the owner is the only one who numbers."""
        taken: list[str] = []
        with self._lock:
            meta = self._books.get(book_id)
            if meta is None:
                return taken
            for raw in entries[:MAX_ENTRIES] if isinstance(entries, list) else []:
                entry = clean_entry(raw, keep_version=True)
                if entry is None:
                    continue
                if not is_node(entry["v"][1]):
                    continue
                if not from_owner and entry["v"][1] != writer:
                    # A member writes under its own id and nobody else's.
                    continue
                current = self._entries[book_id].get(entry["id"])
                if not newer(entry, current):
                    continue
                if meta["role"] == OWNER:
                    meta["seq"] += 1
                    entry["seq"] = meta["seq"]
                if self._store_entry(book_id, entry):
                    taken.append(entry["id"])
                    if meta["role"] != OWNER and entry["id"] in meta["dirty"] and from_owner:
                        # The owner's word on this contact came back to us; ours
                        # either won (and the owner has it) or lost (and is gone).
                        meta["dirty"].remove(entry["id"])
                elif meta["role"] == OWNER:
                    meta["seq"] -= 1
            if taken:
                self._persist_book(book_id)
        return taken

    def stats(self) -> dict:
        with self._lock:
            return {"books": len(self._books), "offers": len(self._offers),
                    "contacts": sum(1 for es in self._entries.values()
                                    for e in es.values() if not e["del"])}
