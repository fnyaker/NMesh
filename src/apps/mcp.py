"""
The MCP app: this node's operations, as tools an AI client can call.

`Model Context Protocol <https://modelcontextprotocol.io>`_ is how a model is
given tools: a server lists them with a name, a description and a JSON schema,
and answers calls to them. This app is such a server, and the point of it is
what it does **not** contain: there is no list of tools in it.

The tools are **generated from what the console's front end is sent** — the
control plane's catalogue (``control.catalogue``), the operations apps declare
(``apps.catalogue``) and, for an app that declares nothing, the routes its own
page calls (``web.routes``). A button the console grows is a tool the next time
a client lists them, and an operation this app may not call is not listed at
all, because the catalogue it reads is filtered by what *it* was granted.

It reaches the node the way any app does: through the data connector, under its
own app id and its own token, through the internal API (``CONTROL`` frames). So
what an AI client can do here is exactly what a human granted this app on the
Apps page — ``readstate`` to look, the parts of ``control`` to act — and every
call is answered, or refused, by the same code a page meets. Nothing is a
shortcut.

**Internal only by default.** The server listens on the loopback, behind a
bearer token kept in this app's drawer, and refuses a request whose ``Origin``
is a web page that is not on this machine (the protocol's own advice against
DNS rebinding). An operator can bind it elsewhere; the Apps page says what that
means when they do.

Transport: MCP's *Streamable HTTP*, answered as plain JSON — one POST, one
JSON-RPC message or batch in, its answer out. There is no server-initiated
stream, so ``GET`` is refused, as the transport allows. A client that only
speaks stdio uses ``scripts/nmesh_mcp_stdio.py``, which carries lines to this
endpoint and back.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .. import app_api, faults
from ..version import __version__

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8790
PATH = "/mcp"
# Protocol revisions this server speaks, newest first. A client asking for one
# of them gets it; any other is answered with the newest, as the spec says.
VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

# Bounds. A request comes from whatever reaches the port — the loopback by
# default, which is still every process on this machine.
MAX_BODY = 1024 * 1024          # one JSON-RPC message or batch
# A body over the bound is still read, up to this, so the client hears "too
# large" rather than a broken pipe; past this it is cut off.
_DRAIN_MAX = 4 * MAX_BODY
# A client that opens a connection and then sends nothing holds a thread.
_SOCKET_TIMEOUT = 30.0
# Requests answered at once. Each is a thread of this server, and a tool call
# may wait on a job for minutes: past this, a request is told to come back.
MAX_INFLIGHT = 16
MAX_BATCH = 32
MAX_TOOLS = 512
# How long one tool call may take. A job (an install, a lookup across the
# network) is polled to its end within this; a client that wants to wait less
# cancels its own request.
CALL_CEILING = 600.0
_POLL = 1.0
# How long the catalogue the tools come from is reused. Short: a permission
# taken back on the Apps page should stop being a tool within seconds.
_CATALOGUE_TTL = 5.0

_SETTINGS_KEY = "mcp.settings"
_TOKEN_KEY = "mcp.token"

# The operations that are machinery rather than tools: listing and polling are
# what this server does *for* the client, and an app operation or a page route
# is offered as its own tool rather than through the door that carries it.
_NOT_TOOLS = frozenset({"control.catalogue", "control.changes", "jobs.start",
                        "jobs.poll", "jobs.list", "jobs.forget", "apps.call",
                        "web.request", "web.routes", "apps.catalogue"})


class McpError(Exception):
    """A JSON-RPC error: a code from the spec and a sentence."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# From a declared parameter to a JSON schema
# ---------------------------------------------------------------------------

def schema_of(field: dict) -> dict:
    """One declared parameter as JSON Schema. The declaration stays the
    authority — the node checks every argument again — so this is a
    description for the model, never the validation."""
    kind = field.get("kind")
    out: dict
    if kind == "node":
        out = {"type": "string", "pattern": "^[0-9a-f]{40}$",
               "description": "a node id: 40 hex characters"}
    elif kind == "flag":
        out = {"type": "boolean"}
    elif kind == "count":
        out = {"type": "integer", "minimum": 0}
        if field.get("limit") is not None:
            out["maximum"] = int(field["limit"])
    elif kind == "tokens":
        out = {"type": "array", "items": {"type": "string"}}
    elif kind == "choice":
        out = {"type": "string", "enum": list(field.get("choices", ()))}
    elif kind in ("document", "payload"):
        out = {"type": "object"}
    elif kind == "hex":
        out = {"type": "string", "pattern": "^[0-9a-f]*$"}
    elif kind == "blob":
        out = {"type": "string", "description": "base64"}
    else:                                   # text, line, secret
        out = {"type": "string"}
    if field.get("help"):
        out["description"] = str(field["help"])[:200]
    if field.get("default") is not None:
        out["default"] = field["default"]
    return out


def input_schema(params) -> dict:
    properties, required = {}, []
    for field in params or ():
        name = field.get("name")
        if not isinstance(name, str):
            continue
        properties[name] = schema_of(field)
        if field.get("required"):
            required.append(name)
    schema = {"type": "object", "properties": properties,
              "additionalProperties": False}
    if required:
        schema["required"] = required
    return schema


def _annotations(title: str, changes: bool) -> dict:
    return {"title": title[:80], "readOnlyHint": not changes,
            "destructiveHint": bool(changes), "openWorldHint": True}


def build_tools(catalogue: list, apps: list, pages: list) -> dict:
    """``{tool name: (tool, how to call it)}`` from what the node lists.

    Three sources, one shape: a node operation (``node_state``), an app's
    declared operation (``app_chat_peer``), a route an app's page calls
    (``web_chat_post_send``)."""
    tools = {}
    for module in catalogue:
        for entry in module.get("operations", ()):
            op = f"{module.get('module')}.{entry.get('name')}"
            if op in _NOT_TOOLS:
                continue
            name = op.replace(".", "_")
            notes = []
            if entry.get("changes"):
                notes.append("changes this node's state")
            if entry.get("background"):
                notes.append("runs as a job; the call waits for it to finish")
            description = str(entry.get("summary") or op)
            if notes:
                description += " (" + "; ".join(notes) + ")"
            tools[name] = ({"name": name, "title": op,
                            "description": description,
                            "inputSchema": input_schema(entry.get("params")),
                            "annotations": _annotations(op, entry.get("changes"))},
                           {"kind": "op", "op": op,
                            "background": bool(entry.get("background")),
                            "timeout": float(entry.get("timeout") or 10.0)})
    for app in apps:
        for entry in app.get("operations", ()):
            op = f"{app.get('app')}.{entry.get('name')}"
            name = "app_" + op.replace(".", "_")
            tools[name] = ({"name": name, "title": op,
                            "description": f"[{app.get('app')}] " +
                                           str(entry.get("summary") or op),
                            "inputSchema": input_schema(entry.get("params")),
                            "annotations": _annotations(op, entry.get("changes"))},
                           {"kind": "app", "app": app.get("app"),
                            "op": entry.get("name")})
    for page in pages:
        for route in page.get("routes", ()):
            method, path = route.get("method", "GET"), route.get("path", "")
            stem = path.split("/api/", 1)[-1].replace("/", "_").replace("-", "_")
            name = f"web_{stem.split('_', 1)[0]}_{method.lower()}_" + \
                   (stem.split("_", 1)[1] if "_" in stem else "")
            name = name.rstrip("_")
            properties = {"query": {"type": "string",
                                    "description": "a query string, without the ?"}}
            if method == "POST":
                properties["body"] = {"type": "object",
                                      "description": "the JSON body the page sends"}
            tools[name] = ({"name": name, "title": f"{method} {path}",
                            "description": (f"[{page.get('title') or page.get('app')}] "
                                            f"{method} {path} — a route this app's own "
                                            f"page calls; the app declares no operation "
                                            f"for it"),
                            "inputSchema": {"type": "object", "properties": properties,
                                            "additionalProperties": False},
                            "annotations": _annotations(f"{method} {path}",
                                                        method != "GET")},
                           {"kind": "web", "app": page.get("app"), "method": method,
                            "path": path})
            if len(tools) >= MAX_TOOLS:
                break
    return dict(list(tools.items())[:MAX_TOOLS])


# ---------------------------------------------------------------------------
# The app
# ---------------------------------------------------------------------------

class McpApp:
    """The server, and the connector client it reaches the node through.

    ``start``/``stop`` on the node's loop, like every built-in app; the HTTP
    server runs on its own threads and hands each call to the loop."""

    def __init__(self, client, *, store=None, log=None) -> None:
        self._client = client
        self._store = store            # (get, put) over this app's drawer
        self._log = log
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._tools: dict = {}
        self._tools_at = 0.0
        self.host = DEFAULT_HOST
        self.port = DEFAULT_PORT
        self.token = ""
        self.error = ""
        self.calls = 0
        self._inflight = threading.BoundedSemaphore(MAX_INFLIGHT)

    # -- settings, kept in the drawer ---------------------------------------

    def _get(self, key: str):
        if self._store is None:
            return None
        try:
            raw = self._store[0](key)
            return raw.decode("utf-8") if raw else None
        except Exception:
            return None

    def _put(self, key: str, value: str) -> None:
        if self._store is not None:
            try:
                self._store[1](key, value.encode("utf-8"))
            except Exception as exc:            # noqa: BLE001
                faults.note("mcp settings", exc)

    def _load(self) -> None:
        raw = self._get(_SETTINGS_KEY)
        try:
            settings = json.loads(raw) if raw else {}
        except ValueError:
            settings = {}
        if isinstance(settings, dict):
            host = settings.get("host")
            port = settings.get("port")
            if isinstance(host, str) and _host_ok(host):
                self.host = host
            if isinstance(port, int) and 0 < port < 65536:
                self.port = port
        self.token = self._get(_TOKEN_KEY) or ""
        if not self.token:
            self.rotate()

    def rotate(self) -> str:
        self.token = "mcp-" + secrets.token_urlsafe(32)
        self._put(_TOKEN_KEY, self.token)
        return self.token

    def configure(self, host: str, port: int) -> None:
        if not _host_ok(host):
            raise app_api.AppAPIError("host: an address, like 127.0.0.1")
        if not 0 < int(port) < 65536:
            raise app_api.AppAPIError("port: 1 to 65535")
        self.host, self.port = host, int(port)
        self._put(_SETTINGS_KEY, json.dumps({"host": self.host, "port": self.port}))

    # -- lifecycle ------------------------------------------------------------

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        await asyncio.to_thread(self._load)
        await self._client.connect()
        await self._serve()

    async def stop(self) -> None:
        await asyncio.to_thread(self._close)
        try:
            await self._client.close()
        except Exception:
            pass

    async def restart_server(self) -> None:
        await asyncio.to_thread(self._close)
        await self._serve()

    async def _serve(self) -> None:
        try:
            server = await asyncio.to_thread(
                ThreadingHTTPServer, (self.host, self.port), _handler_for(self))
        except OSError as exc:
            # A port somebody else holds must not take the node down with it:
            # the app runs, says why it serves nothing, and can be pointed
            # elsewhere from the Apps page.
            self.error = f"cannot listen on {self.host}:{self.port}: {exc.strerror or exc}"
            faults.note("mcp listen", exc)
            return
        server.daemon_threads = True
        self._server = server
        self.port = server.server_address[1]
        self.error = ""
        self._thread = threading.Thread(target=server.serve_forever,
                                        name="mcp", daemon=True)
        self._thread.start()

    def _close(self) -> None:
        server, self._server = self._server, None
        if server is not None:
            try:
                server.shutdown()
                server.server_close()
            except Exception:
                pass

    @property
    def url(self) -> str:
        host = self.host if self.host not in ("0.0.0.0", "::") else "127.0.0.1"
        if ":" in host:
            host = f"[{host}]"
        return f"http://{host}:{self.port}{PATH}"

    def status(self) -> dict:
        return {"running": self._server is not None, "url": self.url,
                "host": self.host, "port": self.port, "error": self.error,
                "loopback": self.host in ("127.0.0.1", "::1", "localhost"),
                "tools": len(self._tools), "calls": self.calls,
                "versions": list(VERSIONS)}

    # -- talking to the node ----------------------------------------------------

    def _ask(self, op: str, params: dict | None = None, timeout: float = 30.0) -> dict:
        """One internal-API call, from a server thread. The reply document."""
        loop = self._loop
        if loop is None:
            raise McpError(-32603, "the server is not attached to a node")
        future = asyncio.run_coroutine_threadsafe(
            self._client.control(op, params or {}, timeout=timeout), loop)
        try:
            return future.result(timeout + 2.0)
        except Exception as exc:
            raise McpError(-32603, f"the node did not answer ({type(exc).__name__})") from None

    def tools(self, refresh: bool = False) -> dict:
        with self._lock:
            if not refresh and self._tools and time.monotonic() - self._tools_at < _CATALOGUE_TTL:
                return self._tools
        catalogue = self._ask("control.catalogue")
        modules = ((catalogue.get("result") or {}).get("modules", [])
                   if catalogue.get("ok") else [])
        reachable = {module.get("module") + "." + entry.get("name")
                     for module in modules for entry in module.get("operations", ())}
        apps = self._ask("apps.catalogue") if "apps.call" in reachable else {}
        # A page's routes are tools only for a server that may call them:
        # listing what it would be refused is a list of failures to try.
        pages = self._ask("web.routes") if "web.request" in reachable else {}
        tools = build_tools(
            modules,
            (apps.get("result") or {}).get("apps", []) if apps.get("ok") else [],
            (pages.get("result") or {}).get("apps", []) if pages.get("ok") else [])
        with self._lock:
            self._tools, self._tools_at = tools, time.monotonic()
        return tools

    def call_tool(self, name: str, arguments: dict) -> dict:
        """One tool call → an MCP ``CallToolResult``. A refusal is a result
        with ``isError`` rather than a protocol error: the model reads it and
        can do something about it — ask for a permission, pick another tool."""
        found = self.tools().get(name)
        if found is None:
            found = self.tools(refresh=True).get(name)
        if found is None:
            raise McpError(-32602, f"no tool called {name[:64]!r}")
        _tool, how = found
        arguments = arguments if isinstance(arguments, dict) else {}
        self.calls += 1
        if how["kind"] == "op":
            reply = (self._job(how["op"], arguments, how["timeout"]) if how["background"]
                     else self._ask(how["op"], arguments, max(10.0, how["timeout"] + 5.0)))
        elif how["kind"] == "app":
            reply = self._ask("apps.call", {"app": how["app"], "op": how["op"],
                                            "args": arguments})
            if reply.get("ok"):
                reply = {"ok": True, "result": (reply.get("result") or {}).get("result")}
        else:
            reply = self._ask("web.request", {
                "app": how["app"], "method": how["method"], "path": how["path"],
                "query": str(arguments.get("query") or ""),
                "body": arguments.get("body") if isinstance(arguments.get("body"), dict) else None})
        if self._log is not None:
            self._log(f"tool {name}: {'ok' if reply.get('ok') else reply.get('code', 'refused')}")
        return _result(reply)

    def _job(self, op: str, arguments: dict, timeout: float) -> dict:
        started = self._ask("jobs.start", {"op": op, "params": arguments})
        if not started.get("ok"):
            return started
        job = (started.get("result") or {}).get("job") or (started.get("result") or {}).get("id")
        deadline = time.monotonic() + min(CALL_CEILING, timeout + 30.0)
        while time.monotonic() < deadline:
            polled = self._ask("jobs.poll", {"job": job})
            if not polled.get("ok"):
                return polled
            state = polled.get("result") or {}
            if state.get("state") not in ("running", "queued"):
                if state.get("state") == "done":
                    return {"ok": True, "result": state.get("result")}
                return {"ok": False, "code": state.get("code") or "failed",
                        "error": state.get("error") or "the job did not finish"}
            time.sleep(_POLL)
        return {"ok": False, "code": "unavailable",
                "error": f"{op} is still running; poll job {job} with jobs.poll"}

    # -- JSON-RPC -----------------------------------------------------------------

    def handle(self, message):
        """One JSON-RPC message → its answer, or ``None`` for a notification."""
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _error(None, -32600, "not a JSON-RPC 2.0 request")
        ident = message.get("id")
        method = message.get("method")
        if not isinstance(method, str):
            if "result" in message or "error" in message:
                return None                 # a response to something we never asked
            return _error(ident, -32600, "no method")
        notification = "id" not in message
        params = message.get("params")
        params = params if isinstance(params, dict) else {}
        try:
            result = self._dispatch(method, params)
        except McpError as exc:
            return None if notification else _error(ident, exc.code, str(exc))
        except Exception as exc:                # noqa: BLE001 — never a trace
            faults.note(f"mcp {method}", exc)
            return None if notification else _error(ident, -32603, "internal error")
        if notification:
            return None
        return {"jsonrpc": "2.0", "id": ident, "result": result}

    def _dispatch(self, method: str, params: dict):
        if method == "initialize":
            asked = params.get("protocolVersion")
            return {"protocolVersion": asked if asked in VERSIONS else VERSIONS[0],
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "nmesh", "title": "NMesh node",
                                   "version": __version__},
                    "instructions": (
                        "Tools are this NMesh node's own operations — the ones its "
                        "web console performs — limited to what the node's operator "
                        "granted this server. Tools whose name starts with app_ are "
                        "operations of an app on the node; web_ tools call a route "
                        "an app's own page calls. A refused call says which "
                        "permission it needs.")}
        if method.startswith("notifications/"):
            return {}
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": [tool for tool, _how in self.tools(refresh=True).values()]}
        if method == "tools/call":
            name = params.get("name")
            if not isinstance(name, str):
                raise McpError(-32602, "tools/call needs a name")
            return self.call_tool(name, params.get("arguments") or {})
        if method in ("resources/list", "resources/templates/list"):
            return {"resources": [] if method == "resources/list" else [],
                    "resourceTemplates": []}
        if method == "prompts/list":
            return {"prompts": []}
        raise McpError(-32601, f"no method called {method[:64]!r}")


def _result(reply: dict) -> dict:
    if reply.get("ok"):
        result = reply.get("result")
        text = json.dumps(result, ensure_ascii=False, default=str)
        out = {"content": [{"type": "text", "text": text}], "isError": False}
        if isinstance(result, dict):
            out["structuredContent"] = result
        return out
    words = reply.get("error") or "refused"
    code = reply.get("code") or "refused"
    detail = reply.get("detail")
    text = f"{code}: {words}" + (f" {json.dumps(detail)}" if detail else "")
    return {"content": [{"type": "text", "text": text}], "isError": True}


def _error(ident, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": ident,
            "error": {"code": code, "message": str(message)[:300]}}


def _host_ok(host: str) -> bool:
    return (isinstance(host, str) and 0 < len(host) <= 64
            and all(ch.isalnum() or ch in ".:-" for ch in host))


def _local_origin(origin: str) -> bool:
    """Is this ``Origin`` header a page on this machine? A request from a web
    page elsewhere that a browser was tricked into sending (DNS rebinding) is
    refused before the token is even looked at."""
    try:
        host = urlparse(origin).hostname or ""
    except ValueError:
        return False
    return host in ("localhost", "127.0.0.1", "::1")


def _handler_for(app: McpApp):
    class Handler(BaseHTTPRequestHandler):
        server_version = "nmesh-mcp"
        sys_version = ""
        timeout = _SOCKET_TIMEOUT

        def log_message(self, *_args) -> None:     # quiet: the node keeps its own log
            pass

        def _send(self, status: int, document=None, extra=()) -> None:
            blob = b"" if document is None else json.dumps(document).encode("utf-8")
            self.send_response(status)
            if document is not None:
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(blob)))
            self.send_header("Cache-Control", "no-store")
            for name, value in extra:
                self.send_header(name, value)
            self.end_headers()
            if blob:
                self.wfile.write(blob)

        def _admitted(self) -> bool:
            origin = self.headers.get("Origin")
            if origin and not _local_origin(origin):
                self._send(403, {"error": "requests from web pages elsewhere are refused"})
                return False
            offered = self.headers.get("Authorization", "")
            token = offered[7:] if offered.startswith("Bearer ") else ""
            if not app.token or not hmac.compare_digest(token.encode("utf-8"),
                                                        app.token.encode("utf-8")):
                self._send(401, {"error": "a bearer token is required"},
                           extra=(("WWW-Authenticate", 'Bearer realm="nmesh-mcp"'),))
                return False
            return True

        def do_GET(self) -> None:
            if urlparse(self.path).path != PATH:
                self._send(404, {"error": "not found"})
                return
            # No stream is offered: every answer goes back on its POST.
            self._send(405, {"error": "this server answers POST only"},
                       extra=(("Allow", "POST"),))

        def do_DELETE(self) -> None:
            self.do_GET()

        def do_POST(self) -> None:
            if urlparse(self.path).path != PATH:
                self._send(404, {"error": "not found"})
                return
            if not self._admitted():
                return
            if not app._inflight.acquire(blocking=False):
                self._send(503, {"error": "too many requests at once"},
                           extra=(("Retry-After", "1"),))
                return
            try:
                self._answer()
            finally:
                app._inflight.release()

        def _answer(self) -> None:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if length < 0 or length > MAX_BODY:
                # Read what was sent first, within a bound: answering before the
                # body is read leaves the client writing into a closed socket,
                # and what it hears is a broken pipe instead of the reason.
                left = min(max(0, length), _DRAIN_MAX)
                while left > 0:
                    chunk = self.rfile.read(min(65536, left))
                    if not chunk:
                        break
                    left -= len(chunk)
                self.close_connection = True
                self._send(413, {"error": "request too large"})
                return
            raw = self.rfile.read(length)
            try:
                message = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError, RecursionError):
                self._send(400, _error(None, -32700, "not JSON"))
                return
            if isinstance(message, list):
                if not message or len(message) > MAX_BATCH:
                    self._send(400, _error(None, -32600, "a batch of 1 to 32"))
                    return
                answers = [answer for answer in (app.handle(item) for item in message)
                           if answer is not None]
                if answers:
                    self._send(200, answers)
                else:
                    self._send(202)
                return
            answer = app.handle(message)
            if answer is None:
                self._send(202)
            else:
                self._send(200, answer)

    return Handler


class McpBridge:
    """What the console asks of the MCP app, declared like any app's API.

    Three of its four operations are ``operator``: the token is the server's
    whole authority, and an app that could read it — or move the server, or
    mint a new one — would hold every permission this app holds."""

    API = (
        app_api.operation("status", "Where the MCP server listens, and how it is doing"),
        app_api.operation("token", "The bearer token an MCP client needs",
                          operator=True),
        app_api.operation("rotate", "Replace the bearer token; clients using the old one stop",
                          changes=True, operator=True),
        app_api.operation("configure", "Listen on another address or port",
                          [app_api.param("host", "text"),
                           app_api.param("port", "count")],
                          changes=True, operator=True),
    )

    def __init__(self, app: McpApp) -> None:
        self._app = app
        self._loop = None

    def start(self, loop) -> None:
        self._loop = loop

    def stop(self) -> None:
        self._loop = None

    def api_status(self) -> dict:
        return self._app.status()

    def api_token(self) -> dict:
        return {"token": self._app.token, "url": self._app.url}

    def api_rotate(self) -> dict:
        return {"token": self._app.rotate(), "url": self._app.url}

    def api_configure(self, host: str, port: int) -> dict:
        self._app.configure(host, port)
        loop = self._loop
        if loop is not None:
            asyncio.run_coroutine_threadsafe(self._app.restart_server(), loop).result(10.0)
        return self._app.status()
