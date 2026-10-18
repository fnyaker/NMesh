"""
The contacts bridge — what the console's page and the other apps ask of
:class:`~src.apps.contacts.ContactsApp`.

Two doors onto one set of books:

* **The page** (`/contacts`) is driven by a person, signed in to the console.
  Its calls arrive as :meth:`handle` with an operation name and a JSON object.
* **Other apps** reach the books through the app API (``API`` below), and every
  operation there names the permission it needs — ``contacts.read`` or
  ``contacts.write`` — which the plane checks against what a human granted that
  app. Chat is the first of them, and asks like any other app would.

The page is the owner at the keyboard, so it holds no permission; the API is for
somebody else, so it holds only what it was given.
"""
from __future__ import annotations

import asyncio
import re

from .. import app_api
from .. import console_feed
from . import contacts_state as cs

_CALL_TIMEOUT = 20.0
_SEARCH_TIMEOUT = 25.0
_NAME_TIMEOUT = 3.0
MAX_NAMES = 3000
MAX_IMPORT = 600_000            # bytes of vCard text
MAX_IMPORT_CARDS = 1000
_CHANGES = {"no_book": "That book does not exist.",
            "read_only": "This book is shared with you to read only.",
            "no_contact": "That contact does not exist.",
            "empty": "A contact needs a name or a node.",
            "full": "This book is full.",
            "bad_node": "That is not a node id.",
            "not_owner": "Only the node that made a book can share it.",
            "self": "That is this node.",
            "gone": "That invitation is gone."}


def _row(entry: dict) -> dict:
    """A contact as another app sees it: enough to show the person, never the
    note written beside them."""
    return {"id": entry["id"], "book": entry.get("book", ""),
            "name": entry["name"], "nodes": entry["nodes"], "fav": entry["fav"]}


class ContactsBridge:
    """Thread-safe front of the contacts app: a person's page, and the API."""

    API = (
        app_api.operation(
            "books", "The address books on this node",
            permission="contacts.read"),
        app_api.operation(
            "list", "The contacts in one book, or in all of them",
            [app_api.param("book", "text", required=False, default="")],
            permission="contacts.read"),
        app_api.operation(
            "names", "Every node in the books and the name it was given",
            permission="contacts.read"),
        app_api.operation(
            "search", "Find saved contacts by name or node id",
            [app_api.param("query", "text"),
             app_api.param("limit", "count", required=False, default=20)],
            permission="contacts.read"),
        app_api.operation(
            "find", "The contacts that answer to a node",
            [app_api.param("node", "node")],
            permission="contacts.read"),
        app_api.operation(
            "add", "Save a node as a contact",
            [app_api.param("node", "node"),
             app_api.param("name", "text", required=False, default=""),
             app_api.param("book", "text", required=False, default="")],
            changes=True, permission="contacts.write"),
        app_api.operation(
            "remove", "Take a node out of the contacts",
            [app_api.param("node", "node"),
             app_api.param("book", "text", required=False, default="")],
            changes=True, permission="contacts.write"),
    )

    def __init__(self, contacts_app, *, node_id=None) -> None:
        self._app = contacts_app
        self.state = contacts_app.state
        self._loop: asyncio.AbstractEventLoop | None = None
        self._names_memo: tuple = (-1, {})

    # -- lifecycle ----------------------------------------------------------

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def stop(self) -> None:
        self._loop = None

    def _run(self, coro, timeout: float = _CALL_TIMEOUT):
        if self._loop is None:
            coro.close()
            raise RuntimeError("bridge not started")
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout=timeout)

    def _later(self, coro) -> None:
        """Start something on the loop and do not wait for it: an edit is saved
        before the other nodes hear of it, and the next sync round makes up for
        a message that is lost."""
        loop = self._loop
        if loop is None:
            coro.close()
            return
        try:
            loop.call_soon_threadsafe(self._app._spawn, coro)
        except RuntimeError:
            coro.close()

    # -- the app API --------------------------------------------------------

    def api_books(self) -> dict:
        return {"books": [{"id": b["id"], "name": b["name"], "color": b["color"],
                           "count": b["count"], "default": b["default"],
                           "writable": b["writable"], "shared": b["shared"]}
                          for b in self.state.books()]}

    def api_names(self) -> dict:
        """Node id -> name, for every node in my books: what a chat screen
        needs to say "Ada" instead of forty hex digits. Recomputed only when a
        book changed, since a page asks for it on every refresh."""
        version = self.state.version
        if self._names_memo[0] != version:
            names = dict(list(self.state.node_names().items())[:MAX_NAMES])
            self._names_memo = (version, names)
        return {"names": dict(self._names_memo[1]), "version": version}

    def api_list(self, book: str = "") -> dict:
        if book and not cs.is_book_id(book):
            raise app_api.AppAPIError("not a book")
        rows = self.state.entries(book or None, limit=cs.MAX_RESULTS)
        return {"contacts": [_row(r) for r in rows]}

    def api_search(self, query: str, limit: int = 20) -> dict:
        rows = self.state.search(query, limit=limit)
        return {"contacts": [_row(r) for r in rows]}

    def api_find(self, node: str) -> dict:
        return {"contacts": [dict(_row(r), book_name=r["book_name"]) for r in self.state.find(node)]}

    def api_add(self, node: str, name: str = "", book: str = "") -> dict:
        if book and not cs.is_book_id(book):
            raise app_api.AppAPIError("not a book")
        if not name:
            try:
                name = self._run(self._app.name_of(node), timeout=_NAME_TIMEOUT)
            except Exception:
                name = ""
        ok, result = self.state.add_node(node, name, book)
        if not ok:
            raise app_api.AppAPIError(_CHANGES.get(result, "not added"))
        target = result["id"]
        for found in self.state.find(node):
            if found["id"] == target:
                self._later(self._app.after_change(found["book"], [target]))
                return {"added": True, "contact": target, "book": found["book"]}
        return {"added": True, "contact": target, "book": book}

    def api_remove(self, node: str, book: str = "") -> dict:
        if book and not cs.is_book_id(book):
            raise app_api.AppAPIError("not a book")
        touched = {f["book"]: f["id"] for f in self.state.find(node)
                   if not book or f["book"] == book}
        removed = self.state.remove_node(node, book)
        for book_id, cid in touched.items():
            self._later(self._app.after_change(book_id, [cid]))
        return {"removed": removed}

    # -- what the page reads ------------------------------------------------

    def snapshot(self, book: str = "", *, have=None, proto: int = 1) -> dict:
        """The books, the invitations waiting for an answer, and one book's
        contacts, in the shape the page asked for."""
        books = self.state.books()
        chosen = book if any(b["id"] == book for b in books) else (
            next((b["id"] for b in books if b["default"]), books[0]["id"] if books else ""))
        contacts = self.state.entries(chosen) if chosen else []
        names = self._names(contacts, next((b for b in books if b["id"] == chosen), None))
        sections = {
            "me": self._app.node_id.raw.hex() if self._app.node_id else "",
            "books": books,
            "offers": self.state.offers(),
            "contacts": contacts,
            "names": names,
        }
        return console_feed.build(sections, have=have, proto=proto, extra={
            "book": chosen, "version": self.state.version})

    def _names(self, contacts, book=None) -> dict:
        """What the node calls each node on this screen — its own word, shown
        beside the one the person chose, never in place of it. The nodes a book
        is shared with, and the one that owns it, are on screen too."""
        ids = [node["id"] for entry in contacts for node in entry["nodes"]]
        if book:
            ids += list(book.get("members") or {})
            ids.append(book.get("owner") or "")
        out = {}
        for node in ids:
            name = self._app.names.get(node)
            if name:
                out[node] = name
        return out

    def people(self, query: str, wide: bool = True) -> dict:
        """Everyone who answers to ``query``: saved contacts first, then the
        nodes the directory knows by that name — on a mesh of thousands, the
        way to find somebody who is not in any book yet."""
        query = (query or "").strip()[:cs.MAX_NAME]
        if not query:
            return {"results": []}
        saved = self.state.search(query, limit=30)
        known = set()
        results = []
        for row in saved:
            for node in row["nodes"] or [{"id": "", "label": ""}]:
                known.add(node["id"])
            results.append({"kind": "contact", "contact": row["id"], "book": row["book"],
                            "book_name": row["book_name"], "name": row["name"],
                            "nodes": row["nodes"]})
        try:
            found = self._run(self._app.lookup(query, wide=wide), timeout=_SEARCH_TIMEOUT)
        except Exception:
            found = []
        for row in found:
            results.append({"kind": "node", "node": row["id"], "pseudo": row["pseudo"],
                            "saved": row["id"] in known or bool(self.state.find(row["id"]))})
        return {"results": results}

    # -- what the page does -------------------------------------------------

    def handle(self, op: str, data: dict) -> tuple[int, dict]:
        """One call from the page. ``(status, document)``; never raises."""
        method = getattr(self, "do_" + re.sub(r"[^a-z_]", "", op or ""), None)
        if method is None or not isinstance(data, dict):
            return 404, {"error": "not found"}
        try:
            return method(data)
        except asyncio.TimeoutError:
            return 504, {"error": "the node did not answer in time"}
        except Exception as exc:       # noqa: BLE001 — a bad call must not be a crash
            return 400, {"error": str(exc)[:200] or type(exc).__name__}

    @staticmethod
    def _fail(why: str, status: int = 400) -> tuple[int, dict]:
        return status, {"ok": False, "error": _CHANGES.get(why, why), "why": why}

    def do_save(self, data: dict):
        book, cid = data.get("book", ""), data.get("id") or None
        if not cs.is_book_id(book) or (cid is not None and not cs.is_cid(cid)):
            return self._fail("no_book")
        ok, result = self.state.save(book, {k: data[k] for k in ("name", "nodes", "note", "fav")
                                            if k in data}, cid)
        if not ok:
            return self._fail(result)
        self._later(self._app.after_change(book, [result["id"]]))
        self._later(self._app.refresh_names(force=True))
        return 200, {"ok": True, "contact": result}

    def do_delete(self, data: dict):
        book, cid = data.get("book", ""), data.get("id", "")
        if not cs.is_book_id(book) or not cs.is_cid(cid):
            return self._fail("no_contact")
        ok, why = self.state.remove(book, cid)
        if not ok:
            return self._fail(why)
        self._later(self._app.after_change(book, [cid]))
        return 200, {"ok": True}

    def do_move(self, data: dict):
        """Copy a contact into another book of mine and take it out of the first."""
        source, target, cid = data.get("book", ""), data.get("to", ""), data.get("id", "")
        entry = self.state.get(source, cid) if cs.is_book_id(source) and cs.is_cid(cid) else None
        if entry is None or not cs.is_book_id(target):
            return self._fail("no_contact")
        ok, result = self.state.save(target, {k: entry[k] for k in ("name", "nodes", "note", "fav")})
        if not ok:
            return self._fail(result)
        ok, why = self.state.remove(source, cid)
        self._later(self._app.after_change(target, [result["id"]]))
        self._later(self._app.after_change(source, [cid]))
        return 200, {"ok": True, "contact": result}

    def do_book(self, data: dict):
        action = data.get("action", "create")
        book = data.get("book", "")
        if action == "create":
            created = self.state.create_book(str(data.get("name") or "Contacts"),
                                             str(data.get("color") or "blue"))
            return (200, {"ok": True, "book": created}) if created else self._fail("full")
        if not cs.is_book_id(book):
            return self._fail("no_book")
        if action == "rename":
            ok = self.state.set_book(book, name=data.get("name"), color=data.get("color"))
            if ok:
                self._later(self._app.after_change(book, []))
            return (200, {"ok": True}) if ok else self._fail("read_only")
        if action == "default":
            return (200, {"ok": True}) if self.state.set_default(book) else self._fail("read_only")
        if action == "delete":
            done = self._run(self._app.remove_book(book))
            return (200, {"ok": True}) if done else self._fail("no_book")
        return 400, {"error": "unknown action"}

    def do_share(self, data: dict):
        book, node, role = data.get("book", ""), data.get("node", ""), data.get("role", "read")
        if not cs.is_book_id(book):
            return self._fail("no_book")
        meta = self.state.book(book)
        if meta is None or meta["role"] != cs.OWNER:
            return self._fail("not_owner")
        if not cs.is_node(node) or role not in cs.ROLES:
            return self._fail("bad_node")
        if self._app.node_id is not None and node == self._app.node_id.raw.hex():
            return self._fail("self")
        ok = self._run(self._app.offer(book, node, role))
        # The invitation is kept when the first send fails: it goes again with
        # the next round, which is what a node that is offline needs.
        return 200, {"ok": True, "sent": bool(ok)}

    def do_unshare(self, data: dict):
        book, node = data.get("book", ""), data.get("node", "")
        if not cs.is_book_id(book) or not cs.is_node(node):
            return self._fail("no_book")
        done = self._run(self._app.revoke(book, node))
        return (200, {"ok": True}) if done else self._fail("no_book")

    def do_answer(self, data: dict):
        book, sender = data.get("book", ""), data.get("from", "")
        if not cs.is_book_id(book) or not cs.is_node(sender):
            return self._fail("no_book")
        done = self._run(self._app.respond(book, sender, data.get("accept") is True))
        return (200, {"ok": True}) if done else self._fail("gone")

    def do_people(self, data: dict):
        return 200, self.people(str(data.get("query", "")), wide=data.get("wide") is not False)

    def do_import(self, data: dict):
        book, text = data.get("book", ""), data.get("text", "")
        if not cs.is_book_id(book) or not isinstance(text, str):
            return self._fail("no_book")
        if len(text) > MAX_IMPORT:
            return 413, {"error": "that file is too large"}
        added = skipped = 0
        for fields in parse_vcards(text)[:MAX_IMPORT_CARDS]:
            ok, result = self.state.save(book, fields)
            if ok:
                added += 1
            else:
                skipped += 1
                if result in ("read_only", "no_book", "full"):
                    break
        if added:
            self._later(self._app.after_change(book, [r["id"] for r in self.state.entries(book)]))
        return 200, {"ok": True, "added": added, "skipped": skipped}

    def export(self, book: str) -> tuple[str, str] | None:
        """``(file name, vCard text)`` for one book, or ``None``."""
        meta = self.state.book(book) if cs.is_book_id(book) else None
        if meta is None:
            return None
        return (re.sub(r"[^A-Za-z0-9._-]+", "_", meta["name"]).strip("_") or "contacts") + ".vcf", \
            vcards(self.state.entries(book))


# ---------------------------------------------------------------------------
# vCard: the one format every address book can read
# ---------------------------------------------------------------------------

def _esc(text: str) -> str:
    return (text.replace("\\", "\\\\").replace("\n", "\\n")
            .replace(",", "\\,").replace(";", "\\;"))


def _unesc(text: str) -> str:
    out, i = [], 0
    while i < len(text):
        if text[i] == "\\" and i + 1 < len(text):
            out.append("\n" if text[i + 1] in "nN" else text[i + 1])
            i += 2
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def vcards(entries) -> str:
    lines = []
    for entry in entries:
        lines += ["BEGIN:VCARD", "VERSION:3.0",
                  "FN:" + _esc(entry["name"] or entry["nodes"][0]["id"][:12]),
                  "N:" + _esc(entry["name"]) + ";;;;"]
        if entry["note"]:
            lines.append("NOTE:" + _esc(entry["note"]))
        if entry["fav"]:
            lines.append("X-NMESH-FAVORITE:1")
        for node in entry["nodes"]:
            label = ";X-LABEL=" + _esc(node["label"]).replace(":", " ") if node["label"] else ""
            lines.append("X-NMESH-NODE" + label + ":" + node["id"])
        lines.append("END:VCARD")
    return "\r\n".join(lines) + ("\r\n" if lines else "")


def parse_vcards(text: str) -> list[dict]:
    """Contacts from vCard text. Lenient about what other address books write,
    strict about what is kept: only a name, a note and the nodes survive."""
    unfolded = re.sub(r"\r?\n[ \t]", "", text)
    cards, current = [], None
    for raw in unfolded.splitlines():
        line = raw.strip()
        upper = line.upper()
        if upper == "BEGIN:VCARD":
            current = {"name": "", "nodes": [], "note": "", "fav": False}
        elif upper == "END:VCARD":
            if current is not None and (current["name"] or current["nodes"]):
                cards.append(current)
            current = None
        elif current is not None and ":" in line:
            head, _, value = line.partition(":")
            key = head.split(";")[0].upper().split(".")[-1]
            if key == "FN":
                current["name"] = _unesc(value)
            elif key == "N" and not current["name"]:
                current["name"] = " ".join(p for p in reversed(
                    [_unesc(x) for x in value.split(";")[:2]]) if p)
            elif key == "NOTE":
                current["note"] = _unesc(value)
            elif key == "X-NMESH-FAVORITE":
                current["fav"] = value.strip() == "1"
            elif key == "X-NMESH-NODE" and cs.is_node(value.strip().lower()):
                label = re.search(r"X-LABEL=([^;:]*)", head, re.IGNORECASE)
                current["nodes"].append({"id": value.strip().lower(),
                                         "label": _unesc(label.group(1)) if label else ""})
        if len(cards) >= MAX_IMPORT_CARDS:
            break
    return cards
