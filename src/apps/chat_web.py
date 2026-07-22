"""
Web UI for the chat application.

This is an *option of the chat app*, not of the node: when enabled, it subscribes
to the ChatApp's event stream and surfaces messages to a browser, and sends
outgoing messages back through the ChatApp. Everything still flows through the
chat app — the node and the management console are untouched.

Stdlib-only, same pattern as the management console: a threaded HTTP server that
marshals sends onto the event loop. Loopback + bearer token by default; strict
CSP, same-origin assets, request-size cap.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import secrets
import threading
import time
from collections import deque, OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from ..node_id import NodeID
from .chat import (
    TextMessage, FileReceived, GroupMessage, DirResult, ProfileReceived,
    Receipt, Typing, Edited, Deleted, Reaction, GroupInvited,
    MSG_ID_LEN, _DELIVERED, _READ,
)

_MAX_BODY = 64 * 1024
_MESSAGES_MAX = 2000
_DIR_RESULTS_MAX = 200
_CALL_TIMEOUT = 10.0
_MESSAGES_KEY = "messages"        # drawer key holding the persisted feed
_MESSAGES_BUDGET = 220 * 1024     # serialised feed ceiling (under the drawer cap)
_TYPING_TTL = 6.0                 # seconds a typing indicator stays live
_FILES_MAX = 64                   # received/sent blobs cached for serving
_FILES_BYTES = 96 * 1024 * 1024   # total bytes of cached file blobs
_IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp")


def _is_image(name: str) -> bool:
    return name.lower().endswith(_IMAGE_EXTS)

_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'self'; object-src 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class ChatBridge:
    """Loop-thread-safe messaging state + actions bridging a ChatApp to an HTTP
    front-end. It subscribes to the app's event stream and keeps a rich, bounded
    message model — replies, edits, deletes, reactions, delivered/read receipts,
    typing, and file/media blobs — persisted (text metadata) in the encrypted
    drawer. File/media bytes stay in a bounded in-memory cache served on demand.

    A conversation is keyed by ``conv``: a peer id (hex) for 1:1, or
    ``"g:"+group_id`` for a group. Change tracking uses a monotonic ``version``:
    every new message OR mutation bumps it and stamps the record's ``seq``, so a
    front-end polling ``snapshot(since)`` sees edits/reactions/status too.

    Everything still flows through the chat app — the node and the management
    console core are untouched."""

    def __init__(self, chat_app, *, peer: NodeID | None = None, store=None) -> None:
        self._chat = chat_app
        self._peer = peer
        self._store = store        # DrawerStore | None — persists the feed if set
        self._loop: asyncio.AbstractEventLoop | None = None
        self._messages: list = []               # ordered records (trimmed manually)
        self._by_mid: dict[str, dict] = {}       # wire msg id (hex) -> record
        self._files: "OrderedDict[str, tuple]" = OrderedDict()  # mid -> (name, bytes)
        self._files_bytes = 0
        self._unread: dict[str, int] = {}        # conv -> unread count
        self._typing: dict[str, tuple] = {}      # conv -> (sender_hex, expiry)
        self._dir_results: deque = deque(maxlen=_DIR_RESULTS_MAX)
        self._msg_id = 0                          # stable per-message local id
        self._version = 0                         # change counter (drives polling)
        self._lock = threading.Lock()
        self._load_messages()

    # -- lifecycle (start binds the loop that sends are marshalled onto) ---

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._chat.add_listener(self._on_event)

    def stop(self) -> None:
        self._chat.remove_listener(self._on_event)

    @property
    def me(self) -> str | None:
        return self._chat.node_id.raw.hex() if self._chat.node_id else None

    # -- persistence (encrypted drawer; history survives a restart) --------

    def _load_messages(self) -> None:
        if self._store is None:
            return
        try:
            blob = self._store.get(_MESSAGES_KEY)
            doc = json.loads(blob.decode("utf-8")) if blob else None
        except Exception:
            return  # corrupt/unreadable → empty feed, never crash
        if not isinstance(doc, dict):
            return
        for m in doc.get("messages", []) if isinstance(doc.get("messages"), list) else []:
            if isinstance(m, dict) and isinstance(m.get("id"), int):
                self._messages.append(m)
                if m.get("mid"):
                    self._by_mid[m["mid"]] = m
        if isinstance(doc.get("unread"), dict):
            self._unread = {k: int(v) for k, v in doc["unread"].items()
                            if isinstance(v, int)}
        self._msg_id = max([m["id"] for m in self._messages], default=0)
        self._version = max([m.get("seq", 0) for m in self._messages], default=0)

    def _persist_locked(self) -> None:
        if self._store is None:
            return
        msgs = self._messages
        while True:
            blob = json.dumps({"messages": msgs, "unread": self._unread}).encode("utf-8")
            if len(blob) <= _MESSAGES_BUDGET or len(msgs) <= 1:
                break
            drop = msgs[:len(msgs) // 2]                 # shed the oldest half
            for m in drop:
                self._by_mid.pop(m.get("mid"), None)
            msgs = self._messages = msgs[len(msgs) // 2:]
        try:
            self._store.put(_MESSAGES_KEY, blob)
        except Exception:
            pass

    # -- record model -----------------------------------------------------

    def _add(self, conv: str, src: str, rec: dict) -> dict:
        """Append a new message record (caller holds the lock)."""
        self._msg_id += 1
        self._version += 1
        record = {**rec, "id": self._msg_id, "seq": self._version,
                  "conv": conv, "src": src, "t": time.time()}
        self._messages.append(record)
        if record.get("mid"):
            self._by_mid[record["mid"]] = record
        while len(self._messages) > _MESSAGES_MAX:
            old = self._messages.pop(0)
            self._by_mid.pop(old.get("mid"), None)
        if src != "me":
            self._unread[conv] = self._unread.get(conv, 0) + 1
        self._persist_locked()
        return record

    def _touch(self, record: dict) -> None:
        self._version += 1
        record["seq"] = self._version

    def _cache_file(self, mid_hex: str, name: str, data: bytes) -> None:
        if mid_hex in self._files:
            self._files_bytes -= len(self._files[mid_hex][1])
            self._files.pop(mid_hex)
        self._files[mid_hex] = (name, data)
        self._files_bytes += len(data)
        while self._files and (len(self._files) > _FILES_MAX
                               or self._files_bytes > _FILES_BYTES):
            _, (_, old) = self._files.popitem(last=False)
            self._files_bytes -= len(old)

    # -- ChatApp listener (runs on the event loop thread) -----------------

    def _on_event(self, ev) -> None:
        with self._lock:
            self._dispatch_event(ev)

    def _dispatch_event(self, ev) -> None:
        if isinstance(ev, TextMessage):
            conv = ("g:" + ev.group_id.hex()) if ev.group_id else ev.src.raw.hex()
            self._add(conv, ev.src.raw.hex(), self._text_rec(ev.mid, ev.text, ev.reply_to))
            self._auto_deliver(ev.src, ev.mid, ev.group_id)
        elif isinstance(ev, GroupMessage):
            gid = ev.group_id.hex()
            if any(g["id"] == gid for g in self._chat.state.snapshot()["groups"]):
                self._add("g:" + gid, ev.src.raw.hex(),
                          self._text_rec(ev.mid, ev.text, ev.reply_to))
        elif isinstance(ev, FileReceived):
            conv = ("g:" + ev.group_id.hex()) if ev.group_id else ev.src.raw.hex()
            self._cache_file(ev.mid.hex(), ev.name, ev.data)
            self._add(conv, ev.src.raw.hex(), self._file_rec(ev.mid, ev.name, len(ev.data), ev.reply_to))
            self._auto_deliver(ev.src, ev.mid, ev.group_id)
        elif isinstance(ev, Edited):
            self._apply_edit(ev.src.raw.hex(), ev.mid.hex(), ev.text)
        elif isinstance(ev, Deleted):
            self._apply_delete(ev.src.raw.hex(), ev.mid.hex())
        elif isinstance(ev, Reaction):
            self._apply_reaction(ev.src.raw.hex(), ev.mid.hex(), ev.emoji)
        elif isinstance(ev, Receipt):
            self._apply_receipt(ev.kind, ev.mids)
        elif isinstance(ev, Typing):
            conv = ("g:" + ev.group_id.hex()) if ev.group_id else ev.src.raw.hex()
            if ev.active:
                self._typing[conv] = (ev.src.raw.hex(), time.time() + _TYPING_TTL)
            else:
                self._typing.pop(conv, None)
        elif isinstance(ev, DirResult):
            self._dir_results.append(
                {"id": ev.node_id.raw.hex(), "pseudo": ev.pseudo, "t": time.time()})

    def _text_rec(self, mid: bytes, text: str, reply: bytes | None) -> dict:
        return {"mid": mid.hex(), "kind": "text", "text": text,
                "reply": reply.hex() if reply else None, "reactions": {}}

    def _file_rec(self, mid: bytes, name: str, size: int, reply: bytes | None) -> dict:
        return {"mid": mid.hex(), "kind": "image" if _is_image(name) else "file",
                "name": name, "size": size, "available": True,
                "reply": reply.hex() if reply else None, "reactions": {}}

    def _auto_deliver(self, src: NodeID, mid: bytes, group_id) -> None:
        # Acknowledge receipt of a 1:1 message so the sender sees a delivered tick.
        if group_id is not None or self._loop is None:
            return
        asyncio.ensure_future(self._safe(self._chat.send_receipt(src, _DELIVERED, [mid])),
                              loop=self._loop)

    def _apply_edit(self, src_hex: str, mid_hex: str, text: str) -> None:
        rec = self._by_mid.get(mid_hex)
        if rec is not None and rec["src"] == src_hex and rec.get("kind") == "text":
            rec["text"] = text
            rec["edited"] = True
            self._touch(rec)
            self._persist_locked()

    def _apply_delete(self, src_hex: str, mid_hex: str) -> None:
        rec = self._by_mid.get(mid_hex)
        if rec is not None and rec["src"] == src_hex:
            rec["deleted"] = True
            rec["text"] = ""
            rec["reactions"] = {}
            self._touch(rec)
            self._persist_locked()

    def _apply_reaction(self, reactor_hex: str, mid_hex: str, emoji: str) -> None:
        rec = self._by_mid.get(mid_hex)
        if rec is None:
            return
        reactions = rec.setdefault("reactions", {})
        for e in list(reactions):                        # one reaction per person
            reactions[e] = [r for r in reactions[e] if r != reactor_hex]
            if not reactions[e]:
                del reactions[e]
        if emoji:
            reactions.setdefault(emoji, []).append(reactor_hex)
        self._touch(rec)
        self._persist_locked()

    def _apply_receipt(self, kind: int, mids: list) -> None:
        rank = {"sent": 0, "delivered": 1, "read": 2}
        new = "read" if kind == _READ else "delivered"
        changed = False
        for m in mids:
            rec = self._by_mid.get(m.hex())
            if rec is not None and rec["src"] == "me":
                if rank.get(rec.get("status", "sent"), 0) < rank[new]:
                    rec["status"] = new
                    self._touch(rec)
                    changed = True
        if changed:
            self._persist_locked()

    # -- actions (called from the web thread; sends marshalled onto loop) --

    def _run(self, coro):
        if self._loop is None:
            raise RuntimeError("bridge not started")
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout=_CALL_TIMEOUT)

    async def _safe(self, coro):
        try:
            await coro
        except Exception:
            pass

    def _resolve_peer(self, peer_hex: str | None) -> NodeID:
        if peer_hex:
            return NodeID(bytes.fromhex(peer_hex))
        if self._peer is None:
            raise ValueError("no peer set")
        return self._peer

    def _group_id(self, conv: str) -> bytes | None:
        return bytes.fromhex(conv[2:]) if conv.startswith("g:") else None

    def _targets(self, conv: str) -> list:
        if conv.startswith("g:"):
            gid = bytes.fromhex(conv[2:])
            me = self._chat.node_id
            return [n for n in self._chat._roster_ids(gid) if me is None or n != me]
        return [NodeID(bytes.fromhex(conv))]

    def send_text(self, peer_hex: str | None, text: str, reply: str | None = None) -> None:
        conv = ("g:" + peer_hex[2:]) if (peer_hex or "").startswith("g:") else \
               (peer_hex or (self._peer.raw.hex() if self._peer else ""))
        reply_b = bytes.fromhex(reply) if reply else None
        gid = self._group_id(conv)
        if gid is not None:
            mid = self._run(self._chat.send_group_text(gid, text, reply_to=reply_b))
        else:
            peer = self._resolve_peer(peer_hex)
            conv = peer.raw.hex()
            mid = self._run(self._chat.send_text(peer, text, reply_to=reply_b))
        with self._lock:
            rec = self._text_rec(mid, text, reply_b)
            rec["status"] = "sent"
            self._add(conv, "me", rec)

    # kept for API compatibility; groups now go through send_text with "g:" conv
    def send_group(self, group_id_hex: str, text: str) -> None:
        self.send_text("g:" + group_id_hex, text)

    def send_file(self, peer_hex: str | None, name: str, data: bytes,
                  reply: str | None = None) -> None:
        conv = ("g:" + peer_hex[2:]) if (peer_hex or "").startswith("g:") else None
        reply_b = bytes.fromhex(reply) if reply else None
        if conv is not None:
            gid = bytes.fromhex(conv[2:])
            mid = None
            for t in self._targets(conv):
                mid = self._run(self._chat.send_file(t, name, data, reply_to=reply_b))
            mid = mid or b"\x00" * MSG_ID_LEN
        else:
            peer = self._resolve_peer(peer_hex)
            conv = peer.raw.hex()
            mid = self._run(self._chat.send_file(peer, name, data, reply_to=reply_b))
        with self._lock:
            self._cache_file(mid.hex(), name, data)
            rec = self._file_rec(mid, name, len(data), reply_b)
            rec["status"] = "sent"
            self._add(conv, "me", rec)

    def edit_message(self, conv: str, mid: str, text: str) -> bool:
        with self._lock:
            rec = self._by_mid.get(mid)
            if rec is None or rec["src"] != "me" or rec.get("kind") != "text":
                return False
        mid_b = bytes.fromhex(mid)
        gid = self._group_id(conv)
        for t in self._targets(conv):
            self._run(self._chat.send_edit(t, mid_b, text, group_id=gid))
        with self._lock:
            rec = self._by_mid.get(mid)
            if rec is not None:
                rec["text"] = text
                rec["edited"] = True
                self._touch(rec)
                self._persist_locked()
        return True

    def delete_message(self, conv: str, mid: str) -> bool:
        with self._lock:
            rec = self._by_mid.get(mid)
            if rec is None or rec["src"] != "me":
                return False
        mid_b = bytes.fromhex(mid)
        gid = self._group_id(conv)
        for t in self._targets(conv):
            self._run(self._chat.send_delete(t, mid_b, group_id=gid))
        with self._lock:
            self._apply_delete("me", mid)
        return True

    def react(self, conv: str, mid: str, emoji: str) -> bool:
        me = self.me or "me"
        with self._lock:
            rec = self._by_mid.get(mid)
            if rec is None:
                return False
            # Toggle: clicking my current reaction clears it.
            mine = next((e for e, rs in rec.get("reactions", {}).items() if me in rs), None)
            send_emoji = "" if mine == emoji else emoji
        mid_b = bytes.fromhex(mid)
        gid = self._group_id(conv)
        for t in self._targets(conv):
            self._run(self._chat.send_reaction(t, mid_b, send_emoji, group_id=gid))
        with self._lock:
            self._apply_reaction(me, mid, send_emoji)
        return True

    def mark_read(self, conv: str) -> None:
        with self._lock:
            self._unread[conv] = 0
            mids = [bytes.fromhex(m["mid"]) for m in self._messages
                    if m["conv"] == conv and m["src"] != "me" and m.get("mid")]
            self._persist_locked()
        if not mids:
            return
        gid = self._group_id(conv)
        for t in self._targets(conv):
            try:
                self._run(self._chat.send_receipt(t, _READ, mids, group_id=gid))
            except Exception:
                pass

    def set_typing(self, conv: str, active: bool) -> None:
        gid = self._group_id(conv)
        for t in self._targets(conv):
            try:
                self._run(self._chat.send_typing(t, active, group_id=gid))
            except Exception:
                pass

    def get_file(self, mid: str) -> tuple | None:
        with self._lock:
            return self._files.get(mid)

    def get_avatar(self, id_hex: str) -> bytes | None:
        return self._chat.state.get_avatar(id_hex)

    # -- profile / contacts / groups --------------------------------------

    def set_pseudo(self, pseudo: str) -> None:
        self._run(self._chat.set_pseudo(pseudo))

    def set_profile(self, *, pseudo=None, bio=None, avatar=None) -> None:
        self._run(self._chat.set_profile(pseudo=pseudo, bio=bio, avatar=avatar))

    def add_contact(self, id_hex: str, pseudo: str = "") -> bool:
        return self._run(self._chat.add_contact(NodeID(bytes.fromhex(id_hex)), pseudo))

    def remove_contact(self, id_hex: str) -> bool:
        return self._chat.state.remove_contact(id_hex)

    def remove_group(self, gid_hex: str) -> bool:
        return self._chat.state.remove_group(gid_hex)

    def create_group(self, name: str, member_hexes: list) -> str:
        members = [NodeID(bytes.fromhex(h)) for h in member_hexes]
        gid = self._run(self._chat.create_group(name, members))
        return gid.hex()

    def search_pseudo(self, pseudo: str) -> list:
        """Local directory + the network DHT directory (anyone who published
        their pseudo, no prior contact needed) + a 1-hop query to contacts."""
        hits = {h["id"]: h for h in self._chat.state.find_by_pseudo(pseudo)}
        try:
            for r in self._run(self._chat.lookup_pseudo_network(pseudo)):
                nid = r.get("id")
                if isinstance(nid, str):
                    hits.setdefault(nid, {"id": nid, "pseudo": r.get("pseudo", ""),
                                          "kind": "network"})
        except Exception:
            pass
        try:
            self._run(self._chat.dir_query(pseudo))
        except Exception:
            pass
        return list(hits.values())

    def snapshot(self, since: int) -> dict:
        state = self._chat.state.snapshot()
        now = time.time()
        with self._lock:
            msgs = [m for m in self._messages if m.get("seq", 0) > since]
            typing = {c: s for c, (s, exp) in self._typing.items() if exp > now}
            return {
                "version": self._version,
                "messages": msgs,
                "unread": dict(self._unread),
                "typing": typing,
                "peer": self._peer.raw.hex() if self._peer else None,
                "me": self.me,
                "pseudo": state["pseudo"],
                "bio": state.get("bio", ""),
                "has_avatar": state.get("has_avatar", False),
                "contacts": state["contacts"],
                "known": state["known"],
                "groups": state["groups"],
                "dir_results": list(self._dir_results),
            }


class ChatWebServer:
    """Standalone chat web UI: its own threaded HTTP server on its own port and
    bearer token, wrapping a :class:`ChatBridge`. The node console hosts the same
    bridge in-process instead (see :mod:`src.webconsole`)."""

    def __init__(self, chat_app, *, host: str = "127.0.0.1", port: int = 0,
                 token: str | None = None, peer: NodeID | None = None) -> None:
        self.host = host
        self.port = port
        self.token = token or secrets.token_urlsafe(18)
        self._token_bytes = self.token.encode("utf-8")
        self.bridge = ChatBridge(chat_app, peer=peer)
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- lifecycle --------------------------------------------------------

    def start(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        self.bridge.start(loop or asyncio.get_event_loop())
        self._server = ThreadingHTTPServer((self.host, self.port), _make_handler(self))
        self.port = self._server.server_address[1]
        # Poll the shutdown flag tightly (stdlib default is 0.5s) so stop()
        # returns near-instantly instead of blocking up to half a second.
        self._thread = threading.Thread(
            target=lambda: self._server.serve_forever(poll_interval=0.02),
            name="nmesh-chat-web", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.bridge.stop()
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/"

    # -- thin delegates the request handler drives ------------------------

    def send_text(self, peer_hex: str | None, text: str) -> None:
        self.bridge.send_text(peer_hex, text)

    def snapshot(self, since: int) -> dict:
        return self.bridge.snapshot(since)


def _make_handler(server: "ChatWebServer"):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "nmesh-chat"

        def log_message(self, *a):
            pass

        def _send(self, code, ctype, body: bytes):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in _HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, code, obj):
            self._send(code, "application/json; charset=utf-8",
                       json.dumps(obj).encode("utf-8"))

        def _authed(self) -> bool:
            auth = self.headers.get("Authorization", "")
            return (auth.startswith("Bearer ")
                    and hmac.compare_digest(auth[7:].encode("utf-8"), server._token_bytes))

        def _read_body(self) -> bytes | None:
            try:
                length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                self.close_connection = True
                return None
            if length < 0 or length > _MAX_BODY:
                self.close_connection = True
                return None
            return self.rfile.read(length) if length else b""

        def do_GET(self):
            path = urlparse(self.path).path
            if path in _ASSETS:
                ctype, text = _ASSETS[path]
                self._send(200, ctype, text.encode("utf-8"))
                return
            if path == "/api/messages":
                if not self._authed():
                    self._json(401, {"error": "unauthorized"})
                    return
                qs = parse_qs(urlparse(self.path).query)
                try:
                    since = int(qs.get("since", ["0"])[0])
                except ValueError:
                    since = 0
                self._json(200, server.snapshot(since))
                return
            self._json(404, {"error": "not found"})

        def do_HEAD(self):
            self.do_GET()

        def do_POST(self):
            path = urlparse(self.path).path
            body = self._read_body()
            if body is None:
                self._json(413, {"error": "body too large"})
                return
            if path == "/api/send":
                if not self._authed():
                    self._json(401, {"error": "unauthorized"})
                    return
                try:
                    data = json.loads(body.decode("utf-8"))
                    text = data.get("text", "")
                    if not isinstance(text, str) or not text:
                        raise ValueError("text required")
                    server.send_text(data.get("peer"), text)
                    self._json(200, {"ok": True})
                except Exception as exc:
                    self._json(400, {"ok": False, "error": str(exc)[:200]})
                return
            self._json(404, {"error": "not found"})

    return Handler


# ---------------------------------------------------------------------------
# Embedded UI (self-contained, same-origin, strict CSP)
# ---------------------------------------------------------------------------

_HTML = """<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>NMesh Chat</title><link rel="stylesheet" href="/chat.css"></head><body>
<div id="login" class="center"><form id="login-form" class="card">
<h1>NMesh<span>chat</span></h1>
<input id="token" type="password" placeholder="Chat token" autofocus>
<button type="submit">Enter</button><div id="err" class="err"></div></form></div>
<div id="app" class="hidden">
<header><b>NMesh<span>chat</span></b><span id="peer" class="muted mono"></span></header>
<div id="log"></div>
<form id="send-form"><input id="peer-in" class="mono" placeholder="peer id (hex, optional if preset)">
<input id="msg" placeholder="type a message…" autocomplete="off"><button>Send</button></form>
</div><script src="/chat.js"></script></body></html>"""

_CSS = """
:root{--bg:#0e1116;--card:#171b22;--line:#242a33;--fg:#e6e9ef;--muted:#8b93a1;--accent:#4da3ff;--bad:#f85149}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.hidden{display:none!important}.mono{font-family:ui-monospace,Menlo,monospace}.muted{color:var(--muted)}
.err{color:var(--bad);min-height:1.2em;margin-top:8px}
.center{display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;width:320px;text-align:center}
h1{margin:0 0 12px}h1 span,header span{color:var(--accent);margin-left:5px}
input,button{font:inherit}input{width:100%;background:#0e1116;border:1px solid var(--line);
color:var(--fg);border-radius:8px;padding:9px 11px;margin-top:8px}
button{background:var(--accent);color:#04122a;border:0;border-radius:8px;padding:9px 14px;font-weight:600;cursor:pointer}
#app{max-width:760px;margin:0 auto;height:100vh;display:flex;flex-direction:column;padding:12px}
header{display:flex;gap:10px;align-items:center;padding:8px 4px;border-bottom:1px solid var(--line)}
#log{flex:1;overflow-y:auto;padding:12px 4px;display:flex;flex-direction:column;gap:8px}
.bubble{max-width:75%;padding:8px 12px;border-radius:12px;background:var(--card);border:1px solid var(--line)}
.me{align-self:flex-end;background:#123;border-color:#245}
.who{font-size:11px;color:var(--muted);margin-bottom:2px}
#send-form{display:flex;gap:8px;padding-top:8px}#send-form #msg{flex:1;margin:0}
#peer-in{width:auto;flex:0 0 200px;margin:0}
"""

_JS = r"""
let TOKEN=null, cursor=0;
const $=(id)=>document.getElementById(id);
async function api(path, method="GET", body){
  const h={Authorization:"Bearer "+TOKEN}; if(body)h["Content-Type"]="application/json";
  const r=await fetch(path,{method,headers:h,body:body?JSON.stringify(body):undefined});
  if(r.status===401){logout();throw new Error("unauth");} return r;
}
function logout(){TOKEN=null;$("app").classList.add("hidden");$("login").classList.remove("hidden");}
$("login-form").addEventListener("submit",async(e)=>{
  e.preventDefault(); TOKEN=$("token").value; $("err").textContent="";
  try{ const r=await fetch("/api/messages?since=0",{headers:{Authorization:"Bearer "+TOKEN}});
    if(!r.ok){$("err").textContent="invalid token";return;}
    $("token").value=""; $("login").classList.add("hidden"); $("app").classList.remove("hidden");
    const s=await r.json(); if(s.peer)$("peer").textContent="peer "+s.peer.slice(0,12)+"…";
    render(s.messages); cursor=s.cursor; setInterval(poll,1000);
  }catch(_){$("err").textContent="error";}
});
async function poll(){ try{ const s=await(await api("/api/messages?since="+cursor)).json();
  render(s.messages); if(s.cursor)cursor=s.cursor; }catch(_){}}
function render(msgs){ const log=$("log");
  for(const m of msgs){ const d=document.createElement("div");
    d.className="bubble"+(m.src==="me"?" me":"");
    const who=m.src==="me"?"you":m.src.slice(0,12)+"…";
    let txt = m.type==="file" ? ("📎 "+m.name+" ("+m.size+" B)") : m.text;
    d.innerHTML='<div class="who"></div><div class="body"></div>';
    d.querySelector(".who").textContent=who; d.querySelector(".body").textContent=txt;
    log.appendChild(d);
  } if(msgs.length)log.scrollTop=log.scrollHeight;
}
$("send-form").addEventListener("submit",async(e)=>{
  e.preventDefault(); const text=$("msg").value; if(!text)return;
  const peer=$("peer-in").value.trim()||undefined;
  try{ const r=await api("/api/send","POST",{text,peer});
    if(r.ok){$("msg").value="";} else {const j=await r.json();alert("send failed: "+(j.error||""));}
  }catch(_){}
});
"""

_ASSETS = {
    "/": ("text/html; charset=utf-8", _HTML),
    "/chat.css": ("text/css; charset=utf-8", _CSS),
    "/chat.js": ("application/javascript; charset=utf-8", _JS),
}
