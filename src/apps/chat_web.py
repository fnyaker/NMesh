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
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from ..node_id import NodeID
from .chat import TextMessage, FileReceived

_MAX_BODY = 64 * 1024
_MESSAGES_MAX = 500
_CALL_TIMEOUT = 10.0

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
    """Loop-thread-safe message store + send actions bridging a ChatApp to an
    HTTP front-end. It runs no server of its own: it subscribes to the app's
    event stream, buffers a bounded feed, and marshals outgoing sends onto the
    event loop. Any front-end (the standalone :class:`ChatWebServer`, or the
    node's web console) drives it via :meth:`snapshot` / :meth:`send_text`.

    Everything still flows through the chat app — the node and the management
    console core are untouched."""

    def __init__(self, chat_app, *, peer: NodeID | None = None) -> None:
        self._chat = chat_app
        self._peer = peer
        self._loop: asyncio.AbstractEventLoop | None = None
        self._messages: deque = deque(maxlen=_MESSAGES_MAX)
        self._cursor = 0
        self._lock = threading.Lock()

    # -- lifecycle (start binds the loop that sends are marshalled onto) ---

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._chat.add_listener(self._on_event)

    def stop(self) -> None:
        self._chat.remove_listener(self._on_event)

    # -- ChatApp listener (runs on the event loop thread) -----------------

    def _on_event(self, ev) -> None:
        if isinstance(ev, TextMessage):
            rec = {"type": "text", "src": ev.src.raw.hex(), "text": ev.text}
        elif isinstance(ev, FileReceived):
            rec = {"type": "file", "src": ev.src.raw.hex(),
                   "name": ev.name, "size": len(ev.data)}
        else:
            return  # real-time frames aren't shown in the chat log
        with self._lock:
            self._cursor += 1
            rec["id"] = self._cursor
            rec["t"] = time.time()
            self._messages.append(rec)

    def record_outgoing(self, text: str) -> None:
        with self._lock:
            self._cursor += 1
            self._messages.append({"id": self._cursor, "type": "text",
                                   "src": "me", "text": text, "t": time.time()})

    # -- actions ----------------------------------------------------------

    def _resolve_peer(self, peer_hex: str | None) -> NodeID:
        if peer_hex:
            return NodeID(bytes.fromhex(peer_hex))
        if self._peer is None:
            raise ValueError("no peer set")
        return self._peer

    def send_text(self, peer_hex: str | None, text: str) -> None:
        if self._loop is None:
            raise RuntimeError("bridge not started")
        peer = self._resolve_peer(peer_hex)
        fut = asyncio.run_coroutine_threadsafe(
            self._chat.send_text(peer, text), self._loop)
        fut.result(timeout=_CALL_TIMEOUT)
        self.record_outgoing(text)

    def snapshot(self, since: int) -> dict:
        with self._lock:
            msgs = [m for m in self._messages if m["id"] > since]
            return {
                "cursor": self._cursor,
                "messages": msgs,
                "peer": self._peer.raw.hex() if self._peer else None,
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
