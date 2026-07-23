"""
Local web console — a management plane for a MeshNode.

This is the most security-sensitive surface in the project: it can trust new
certificates and join networks, so a compromise here compromises the node.
It is therefore built defensively and with stdlib only (+ ``cryptography``,
already a dependency, for the TLS cert):

  - HTTPS with a self-signed cert whose fingerprint is printed at startup.
  - Password auth; the password is generated on first run and only ever stored
    as a salted scrypt hash.
  - Session auth by bearer token (Authorization header) *or* a session cookie.
    The cookie is ``HttpOnly`` (unreadable from JS, so XSS can't exfiltrate it),
    ``SameSite=Strict`` (never sent on a cross-site request, so it carries no
    CSRF surface — the property that once justified having no cookie at all),
    and ``Secure`` under TLS. Both auth paths validate the same session token;
    the cookie exists so a page refresh no longer forces a re-login.
  - Login lockout after repeated failures.
  - Binds to loopback by default; exposing it on the LAN is an explicit choice.
  - Strict CSP, same-origin assets only, no external resources, request-size cap.

The HTTP server runs in a daemon thread and marshals every node interaction onto
the asyncio event loop, so node state is only ever touched from the loop thread.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import ssl
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from .webassets import INDEX_HTML, APP_JS, STYLE_CSS, CHAT_HTML, CHAT_JS, CHAT_CSS

_MAX_BODY = 64 * 1024
_MAX_APP_BODY = 4 * 1024 * 1024   # larger cap for app publish uploads
_MAX_CHAT_UPLOAD = 64 * 1024 * 1024   # chat file/avatar uploads (base64)
_APP_CALL_TIMEOUT = 60.0          # DHT publish/fetch can touch several peers
_TOKEN_TTL = 3600.0            # session idle lifetime, seconds
_LOGIN_MAX_FAILURES = 5
_LOGIN_LOCKOUT = 60.0          # seconds locked after too many failures
_CALL_TIMEOUT = 10.0          # max seconds to wait on a loop-marshalled call
_LIST_DEFAULT_LIMIT = 20
_LIST_MAX_LIMIT = 100
_LIST_MAX_QUERY = 128
# serve_forever() only notices a shutdown() between polls; the stdlib default is
# 0.5s, which makes every stop() block that long. Poll tighter so teardown is
# near-instant (idle cost is one cheap select wakeup per interval).
_SHUTDOWN_POLL = 0.02
_SCRYPT = dict(n=16384, r=8, p=1, dklen=32)
_COOKIE_NAME = "nmesh_session"


def _set_cookie_header(token: str, secure: bool) -> tuple[str, str]:
    """A session cookie (no Max-Age → dropped when the browser closes). It
    survives a page refresh, which is the whole point; the server still enforces
    the sliding idle TTL on the token itself. SameSite=Strict is what keeps this
    free of CSRF surface; HttpOnly keeps it out of reach of page scripts."""
    parts = [f"{_COOKIE_NAME}={token}", "Path=/", "HttpOnly", "SameSite=Strict"]
    if secure:
        parts.append("Secure")
    return ("Set-Cookie", "; ".join(parts))


def _clear_cookie_header(secure: bool) -> tuple[str, str]:
    parts = [f"{_COOKIE_NAME}=", "Path=/", "Max-Age=0", "HttpOnly", "SameSite=Strict"]
    if secure:
        parts.append("Secure")
    return ("Set-Cookie", "; ".join(parts))


def _scrypt(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, **_SCRYPT)


class WebConsole:
    def __init__(self, node, *, host: str = "127.0.0.1", port: int = 8787,
                 state_dir: str | None = None, use_tls: bool = True,
                 password: str | None = None, chat_bridge=None) -> None:
        self._node = node
        self.host = host
        self.port = port
        self._state_dir = state_dir
        self._use_tls = use_tls
        # Optional in-process chat app surfaced at /chat (see src.apps.chat_web).
        self._chat = chat_bridge
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

        # Sessions: token -> expiry monotonic deadline.
        self._tokens: dict[str, float] = {}
        self._tokens_lock = threading.Lock()

        # Login throttling.
        self._fail_count = 0
        self._lockout_until = 0.0

        self.generated_password: str | None = None
        self._salt, self._pw_hash = self._load_or_create_credentials(password)
        self._ssl_ctx = self._build_ssl_context() if use_tls else None

    # -- credentials ------------------------------------------------------

    def _cred_path(self) -> str | None:
        return os.path.join(self._state_dir, "console.cred") if self._state_dir else None

    def _load_or_create_credentials(self, password: str | None):
        path = self._cred_path()
        if password is None and path and os.path.exists(path):
            try:
                with open(path) as f:
                    tag, salt_hex, hash_hex = f.read().strip().split("$")
                if tag == "scrypt":
                    return bytes.fromhex(salt_hex), bytes.fromhex(hash_hex)
            except Exception:
                pass  # unreadable/corrupt → regenerate below
        if password is None:
            password = secrets.token_urlsafe(18)
            self.generated_password = password
        salt = secrets.token_bytes(16)
        pw_hash = _scrypt(password, salt)
        if path:
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                f.write(f"scrypt${salt.hex()}${pw_hash.hex()}")
            os.replace(tmp, path)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        return salt, pw_hash

    def _check_password(self, password: str) -> bool:
        return hmac.compare_digest(_scrypt(password, self._salt), self._pw_hash)

    # -- TLS --------------------------------------------------------------

    def _build_ssl_context(self) -> ssl.SSLContext:
        cert_pem, key_pem = self._load_or_create_cert()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        # load_cert_chain needs files; use a temp dir only if we have no state dir.
        import tempfile
        d = self._state_dir or tempfile.mkdtemp(prefix="nmesh-console-")
        cert_path = os.path.join(d, "console_cert.pem")
        key_path = os.path.join(d, "console_key.pem")
        if not os.path.exists(cert_path):
            with open(cert_path, "wb") as f:
                f.write(cert_pem)
        if not os.path.exists(key_path):
            with open(key_path, "wb") as f:
                f.write(key_pem)
            try:
                os.chmod(key_path, 0o600)
            except OSError:
                pass
        ctx.load_cert_chain(cert_path, key_path)
        self.cert_fingerprint = hashlib.sha256(
            ssl.PEM_cert_to_DER_cert(cert_pem.decode())
        ).hexdigest()
        return ctx

    def _load_or_create_cert(self) -> tuple[bytes, bytes]:
        if self._state_dir:
            cp = os.path.join(self._state_dir, "console_cert.pem")
            kp = os.path.join(self._state_dir, "console_key.pem")
            if os.path.exists(cp) and os.path.exists(kp):
                with open(cp, "rb") as f:
                    cert_pem = f.read()
                with open(kp, "rb") as f:
                    key_pem = f.read()
                return cert_pem, key_pem
        return _generate_self_signed(self.host)

    # -- token sessions ---------------------------------------------------

    def _issue_token(self) -> str:
        token = secrets.token_urlsafe(32)
        with self._tokens_lock:
            self._tokens[token] = time.monotonic() + _TOKEN_TTL
            self._gc_tokens()
        return token

    def _valid_token(self, token: str | None) -> bool:
        if not token:
            return False
        now = time.monotonic()
        with self._tokens_lock:
            deadline = self._tokens.get(token)
            if deadline is None or deadline < now:
                self._tokens.pop(token, None)
                return False
            self._tokens[token] = now + _TOKEN_TTL  # sliding expiry
            return True

    def _revoke_token(self, token: str) -> None:
        with self._tokens_lock:
            self._tokens.pop(token, None)

    def _gc_tokens(self) -> None:
        now = time.monotonic()
        for t in [t for t, d in self._tokens.items() if d < now]:
            self._tokens.pop(t, None)

    # -- login throttle ---------------------------------------------------

    def _locked_out(self) -> bool:
        return time.monotonic() < self._lockout_until

    def _record_login_result(self, ok: bool) -> None:
        if ok:
            self._fail_count = 0
            return
        self._fail_count += 1
        if self._fail_count >= _LOGIN_MAX_FAILURES:
            self._lockout_until = time.monotonic() + _LOGIN_LOCKOUT
            self._fail_count = 0

    # -- loop marshalling -------------------------------------------------

    def _call(self, coro, timeout: float = _CALL_TIMEOUT):
        """Run a coroutine on the node's event loop from the server thread."""
        if self._loop is None:
            raise RuntimeError("console not started")
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result(timeout=timeout)

    # -- lifecycle --------------------------------------------------------

    def _apps(self) -> list:
        """Built-in apps hosted in-process by this console (for the Apps list)."""
        apps = []
        if self._chat is not None:
            apps.append({"id": "chat", "name": "Chat", "path": "/chat"})
        return apps

    def start(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        self._loop = loop or asyncio.get_event_loop()
        if self._chat is not None:
            self._chat.start(self._loop)
        handler = _make_handler(self)
        self._server = ThreadingHTTPServer((self.host, self.port), handler)
        if self._ssl_ctx is not None:
            self._server.socket = self._ssl_ctx.wrap_socket(
                self._server.socket, server_side=True
            )
        # If port was 0, capture the OS-assigned one.
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=lambda: self._server.serve_forever(poll_interval=_SHUTDOWN_POLL),
            name="nmesh-console", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        if self._chat is not None:
            self._chat.stop()

    @property
    def url(self) -> str:
        scheme = "https" if self._use_tls else "http"
        return f"{scheme}://{self.host}:{self.port}/"


# ---------------------------------------------------------------------------
# Self-signed cert (ECDSA P-256)
# ---------------------------------------------------------------------------

def _generate_self_signed(host: str) -> tuple[bytes, bytes]:
    from datetime import datetime, timedelta, timezone
    import ipaddress
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "nmesh-console")])
    alt_names: list[x509.GeneralName] = [x509.DNSName("localhost")]
    for candidate in {host, "127.0.0.1"}:
        try:
            alt_names.append(x509.IPAddress(ipaddress.ip_address(candidate)))
        except ValueError:
            if candidate != "localhost":
                alt_names.append(x509.DNSName(candidate))
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'self'; object-src 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

_STATIC = {
    "/": ("text/html; charset=utf-8", INDEX_HTML),
    "/app.js": ("application/javascript; charset=utf-8", APP_JS),
    "/style.css": ("text/css; charset=utf-8", STYLE_CSS),
}

# Chat sub-page assets, served only when a chat bridge is attached. Like the
# console shell, the page HTML/JS/CSS are public; the /api/chat/* endpoints
# below require the same bearer token as the rest of the console.
_CHAT_STATIC = {
    "/chat": ("text/html; charset=utf-8", CHAT_HTML),
    "/chat.js": ("application/javascript; charset=utf-8", CHAT_JS),
    "/chat.css": ("text/css; charset=utf-8", CHAT_CSS),
}


def _parse_list_query(path: str, *, nodes: bool = False) -> tuple[str | None, str, int, int]:
    raw_query = path.partition("?")[2]
    for index, char in enumerate(raw_query):
        if (char == "%" and (index + 2 >= len(raw_query)
                             or any(c not in "0123456789abcdefABCDEF"
                                    for c in raw_query[index + 1:index + 3]))):
            raise ValueError("invalid query")
    try:
        params = parse_qs(raw_query, keep_blank_values=True, strict_parsing=True,
                          max_num_fields=4, encoding="utf-8", errors="strict")
    except (UnicodeError, ValueError) as exc:
        raise ValueError("invalid query") from exc
    allowed = {"q", "limit", "offset"} | ({"scope"} if nodes else set())
    if set(params) - allowed or any(len(values) != 1 for values in params.values()):
        raise ValueError("invalid query")

    scope = params.get("scope", [None])[0]
    if nodes and scope not in ("active", "known"):
        raise ValueError("invalid scope")
    query = params.get("q", [""])[0]
    if len(query) > _LIST_MAX_QUERY:
        raise ValueError("query too long")

    def pagination_value(name: str, default: int) -> int:
        value = params.get(name, [str(default)])[0]
        if not value or not value.isascii() or not value.isdigit():
            raise ValueError(f"invalid {name}")
        try:
            return int(value)
        except ValueError as exc:
            raise ValueError(f"invalid {name}") from exc

    limit = pagination_value("limit", _LIST_DEFAULT_LIMIT)
    offset = pagination_value("offset", 0)
    if limit < 1 or limit > _LIST_MAX_LIMIT:
        raise ValueError("invalid limit")
    return scope, query.casefold(), limit, offset


def _matches_list_query(item: dict, query: str) -> bool:
    if not query:
        return True
    for value in item.values():
        if isinstance(value, str) and query in value.casefold():
            return True
        if isinstance(value, (list, tuple)):
            if any(isinstance(part, str) and query in part.casefold()
                   for part in value):
                return True
    return False


def _make_handler(console: WebConsole):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "nmesh-console"

        def log_message(self, *args) -> None:
            pass  # stay quiet; the node has its own logging

        # -- helpers --

        def _send(self, code: int, ctype: str, body: bytes,
                  extra_headers: list | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in _SECURITY_HEADERS.items():
                self.send_header(k, v)
            for k, v in (extra_headers or []):
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, code: int, obj, extra_headers: list | None = None) -> None:
            self._send(code, "application/json; charset=utf-8",
                       json.dumps(obj).encode("utf-8"), extra_headers)

        def _send_binary(self, data: bytes, name: str) -> None:
            # Images are served with their type so the UI can render them inline;
            # everything else is an opaque download. nosniff (in _SECURITY_HEADERS)
            # stops the browser from reinterpreting the bytes.
            ext = name.lower().rsplit(".", 1)[-1] if "." in name else ""
            ctype = {
                "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                "gif": "image/gif", "webp": "image/webp", "bmp": "image/bmp",
            }.get(ext, "application/octet-stream")
            self._send(200, ctype, data)

        def _read_body(self, max_len: int = _MAX_BODY) -> bytes | None:
            try:
                length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                self.close_connection = True
                return None
            if length < 0 or length > max_len:
                # Don't drain a hostile oversized body — cut the connection.
                self.close_connection = True
                return None
            return self.rfile.read(length) if length else b""

        def _cookie_token(self) -> str | None:
            raw = self.headers.get("Cookie")
            if not raw:
                return None
            try:
                jar = SimpleCookie(raw)
            except Exception:
                return None  # malformed Cookie header — treat as absent
            morsel = jar.get(_COOKIE_NAME)
            return morsel.value if morsel is not None else None

        def _session_token(self) -> str | None:
            # A bearer header wins (programmatic clients set it explicitly);
            # otherwise fall back to the session cookie the browser sends itself.
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                return auth[7:]
            return self._cookie_token()

        def _authed(self) -> bool:
            return console._valid_token(self._session_token())

        # -- routing --

        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path in _STATIC:
                ctype, text = _STATIC[path]
                self._send(200, ctype, text.encode("utf-8"))
                return
            if console._chat is not None and path in _CHAT_STATIC:
                ctype, text = _CHAT_STATIC[path]
                self._send(200, ctype, text.encode("utf-8"))
                return
            if path in ("/api/nodes", "/api/store/catalog",
                        "/api/store/installed"):
                self._handle_list_get(path)
                return
            if path == "/api/state":
                if not self._authed():
                    self._json(401, {"error": "unauthorized"})
                    return
                try:
                    snap = console._call(console._node.console_snapshot())
                    snap["server_time"] = time.time()
                    snap["apps"] = console._apps()
                    self._json(200, snap)
                except Exception:
                    self._json(503, {"error": "node unavailable"})
                return
            if path == "/api/chat/messages":
                if console._chat is None:
                    self._json(404, {"error": "not found"})
                    return
                if not self._authed():
                    self._json(401, {"error": "unauthorized"})
                    return
                qs = self.path.split("?", 1)
                since = 0
                if len(qs) == 2:
                    from urllib.parse import parse_qs
                    try:
                        since = int(parse_qs(qs[1]).get("since", ["0"])[0])
                    except ValueError:
                        since = 0
                self._json(200, console._chat.snapshot(since))
                return
            if path == "/api/chat/file":
                if console._chat is None or not self._authed():
                    self._json(404 if console._chat is None else 401, {"error": "no"})
                    return
                from urllib.parse import parse_qs
                mid = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "").get("mid", [""])[0]
                got = console._chat.get_file(mid)
                if got is None:
                    self._json(404, {"error": "not found"})
                    return
                name, data = got
                self._send_binary(data, name)
                return
            if path == "/api/chat/avatar":
                if console._chat is None or not self._authed():
                    self._json(404 if console._chat is None else 401, {"error": "no"})
                    return
                from urllib.parse import parse_qs
                aid = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "").get("id", ["self"])[0]
                data = console._chat.get_avatar(aid)
                if not data:
                    self._json(404, {"error": "not found"})
                    return
                self._send_binary(data, "avatar")
                return
            if path == "/api/rootcert":
                if not self._authed():
                    self._json(401, {"error": "unauthorized"})
                    return
                try:
                    hexcert = console._call(_wrap(console._node.console_root_cert_hex))
                    self._json(200, {"cert_hex": hexcert})
                except Exception:
                    self._json(503, {"error": "node unavailable"})
                return
            if path == "/api/store":
                if not self._authed():
                    self._json(401, {"error": "unauthorized"})
                    return
                try:
                    self._json(200, console._call(
                        _wrap(console._node.store_overview)))
                except Exception:
                    self._json(503, {"error": "node unavailable"})
                return
            self._json(404, {"error": "not found"})

        def _handle_list_get(self, path: str) -> None:
            if not self._authed():
                self._json(401, {"error": "unauthorized"})
                return
            try:
                scope, query, limit, offset = _parse_list_query(
                    self.path, nodes=path == "/api/nodes")
            except ValueError:
                self._json(400, {"error": "invalid query"})
                return
            try:
                if path == "/api/nodes":
                    items = console._call(
                        _wrap(console._node.console_nodes, scope))
                    if scope == "known":
                        items.sort(key=lambda item: (
                            item["seen_ago"], item["id"]))
                    else:
                        items.sort(key=lambda item: (
                            item["id"], item.get("transport") or "",
                            item.get("is_client_side", False),
                            tuple(item.get("addresses", ()))))
                elif path == "/api/store/catalog":
                    items = console._call(
                        _wrap(console._node.store_overview))["catalog"]
                    items.sort(key=lambda item: (-item["ts"], item["app_id"]))
                else:
                    items = console._call(
                        _wrap(console._node.installed_list))
                    items.sort(key=lambda item: (
                        str(item.get("name", "")).casefold(),
                        str(item.get("app_id", ""))))
                matched = [item for item in items
                           if _matches_list_query(item, query)]
                self._json(200, {
                    "items": matched[offset:offset + limit],
                    "total": len(matched),
                    "limit": limit,
                    "offset": offset,
                })
            except Exception:
                self._json(503, {"error": "node unavailable"})

        def do_HEAD(self) -> None:
            self.do_GET()

        def do_POST(self) -> None:
            path = self.path.split("?", 1)[0]
            if path in ("/api/app/publish", "/api/store/publish"):
                cap = _MAX_APP_BODY
            elif path in ("/api/chat/file", "/api/chat/profile"):
                cap = _MAX_CHAT_UPLOAD
            else:
                cap = _MAX_BODY
            body = self._read_body(cap)
            if body is None:
                self._json(413, {"error": "body too large or malformed"})
                return
            if path == "/api/login":
                self._handle_login(body)
                return
            # everything below requires auth
            if not self._authed():
                self._json(401, {"error": "unauthorized"})
                return
            if path == "/api/logout":
                tok = self._session_token()
                if tok:
                    console._revoke_token(tok)
                self._json(200, {"ok": True},
                           extra_headers=[_clear_cookie_header(console._use_tls)])
                return
            if path == "/api/invite":
                code = console._call(_wrap(console._node.generate_invite))
                self._json(200, {"code": code})
                return
            if path == "/api/trust":
                data = _parse_json(body)
                cert_hex = (data or {}).get("cert_hex", "")
                ok = console._call(_wrap(console._node.console_add_root, cert_hex))
                self._json(200 if ok else 400, {"ok": bool(ok)})
                return
            if path == "/api/join":
                data = _parse_json(body)
                if not data or "uri" not in data or "code" not in data:
                    self._json(400, {"error": "uri and code required"})
                    return
                try:
                    console._call(console._node.join(data["uri"], data["code"]))
                    self._json(200, {"ok": True})
                except Exception as exc:
                    self._json(502, {"ok": False, "error": str(exc)[:200]})
                return
            if path == "/api/reachability/probe":
                try:
                    sent = console._call(console._node.probe_reachability())
                    self._json(200, {"ok": True, "sent": sent})
                except Exception:
                    self._json(503, {"error": "node unavailable"})
                return
            if path == "/api/ping":
                try:
                    result = console._call(console._node.console_ping_peers())
                    self._json(200, {"ok": True, **result})
                except Exception:
                    self._json(503, {"error": "node unavailable"})
                return
            if path == "/api/ping/node":
                data = _parse_json(body)
                node_id = (data or {}).get("id", "")
                if not isinstance(node_id, str) or not node_id:
                    self._json(400, {"error": "id required"})
                    return
                try:
                    result = console._call(
                        console._node.console_ping_node(node_id), timeout=15.0)
                    self._json(200, result)
                except Exception:
                    self._json(503, {"error": "node unavailable"})
                return
            if path == "/api/lan/discovery":
                data = _parse_json(body)
                if not data or not isinstance(data.get("enabled"), bool):
                    self._json(400, {"error": "enabled (bool) required"})
                    return
                try:
                    if data["enabled"]:
                        console._call(console._node.start_lan_discovery())
                    else:
                        console._call(console._node.stop_lan_discovery())
                    self._json(200, {"ok": True, "enabled": data["enabled"]})
                except Exception as exc:
                    self._json(400, {"ok": False, "error": str(exc)[:200]})
                return
            if path == "/api/relay/invite":
                try:
                    block = console._call(_wrap(console._node.console_relay_invite))
                    self._json(200, {"block": block})
                except Exception:
                    self._json(503, {"error": "node unavailable"})
                return
            if path == "/api/relay/join":
                data = _parse_json(body)
                block = (data or {}).get("block", "")
                try:
                    result = console._call(
                        _wrap(console._node.console_relay_join, block))
                    self._json(200, {"ok": True, **result})
                except Exception as exc:
                    self._json(400, {"ok": False, "error": str(exc)[:200]})
                return
            if path == "/api/connect/request":
                try:
                    block = console._call(_wrap(console._node.console_connect_request))
                    self._json(200, {"block": block})
                except Exception:
                    self._json(503, {"error": "node unavailable"})
                return
            if path == "/api/connect/accept":
                data = _parse_json(body)
                block = (data or {}).get("block", "")
                try:
                    reply = console._call(
                        _wrap(console._node.console_connect_accept, block))
                    self._json(200, {"ok": True, "block": reply})
                except Exception as exc:
                    self._json(400, {"ok": False, "error": str(exc)[:200]})
                return
            if path == "/api/connect/complete":
                data = _parse_json(body)
                block = (data or {}).get("block", "")
                try:
                    result = console._call(
                        _wrap(console._node.console_connect_complete, block))
                    self._json(200, {"ok": True, **result})
                except Exception as exc:
                    self._json(400, {"ok": False, "error": str(exc)[:200]})
                return
            if path == "/api/invite/block":
                try:
                    block = console._call(_wrap(console._node.console_invite_block))
                    self._json(200, {"block": block})
                except Exception:
                    self._json(503, {"error": "node unavailable"})
                return
            if path == "/api/join/block":
                data = _parse_json(body)
                block = (data or {}).get("block", "")
                try:
                    result = console._call(
                        _wrap(console._node.console_join_block, block))
                    self._json(200, {"ok": True, **result})
                except Exception as exc:
                    self._json(400, {"ok": False, "error": str(exc)[:200]})
                return
            if path == "/api/punch":
                data = _parse_json(body)
                if not data or not isinstance(data.get("enabled"), bool):
                    self._json(400, {"error": "enabled (bool) required"})
                    return
                enabled = console._call(
                    _wrap(console._node.console_set_punch_enabled, data["enabled"]))
                self._json(200, {"ok": True, "enabled": enabled})
                return
            if path == "/api/punch/keepalive":
                data = _parse_json(body)
                if not data or not isinstance(data.get("enabled"), bool):
                    self._json(400, {"error": "enabled (bool) required"})
                    return
                enabled = console._call(
                    _wrap(console._node.console_set_punch_keepalive, data["enabled"]))
                self._json(200, {"ok": True, "keepalive": enabled})
                return
            if path == "/api/punch/open":
                data = _parse_json(body) or {}
                host = data.get("host")
                port = data.get("port")
                # allow "ip:port" in a single field for convenience
                if port is None and isinstance(data.get("endpoint"), str):
                    from .ip_utils import split_host_port
                    hp = split_host_port(data["endpoint"].strip())
                    if hp is not None:
                        host = hp[0]
                        try:
                            port = int(hp[1])
                        except ValueError:
                            port = None
                try:
                    result = console._call(
                        _wrap(console._node.console_open_hole, host, port))
                    self._json(200, {"ok": True, **result})
                except Exception as exc:
                    self._json(400, {"ok": False, "error": str(exc)[:200]})
                return
            if path == "/api/udp":
                data = _parse_json(body)
                action = (data or {}).get("action")
                try:
                    if action == "start":
                        console._call(
                            console._node.console_start_udp((data or {}).get("port")))
                    elif action == "stop":
                        console._call(console._node.console_stop_udp())
                    else:
                        self._json(400, {"error": "action must be start or stop"})
                        return
                    self._json(200, {"ok": True})
                except Exception as exc:
                    self._json(400, {"ok": False, "error": str(exc)[:200]})
                return
            if path == "/api/listen":
                data = _parse_json(body)
                try:
                    console._call(
                        console._node.console_add_listen((data or {}).get("uri", "")))
                    self._json(200, {"ok": True})
                except Exception as exc:
                    self._json(400, {"ok": False, "error": str(exc)[:200]})
                return
            if path == "/api/unlisten":
                data = _parse_json(body)
                try:
                    ok = console._call(
                        console._node.console_remove_listen((data or {}).get("uri", "")))
                    self._json(200 if ok else 404, {"ok": bool(ok)})
                except Exception as exc:
                    self._json(400, {"ok": False, "error": str(exc)[:200]})
                return
            if path == "/api/net/recheck":
                ok = console._call(_wrap(console._node.console_recheck_net))
                self._json(200, {"ok": bool(ok)})
                return
            if path.startswith("/api/chat/"):
                if console._chat is None:
                    self._json(404, {"error": "not found"})
                    return
                self._handle_chat_post(path, _parse_json(body))
                return
            if path == "/api/app/publish":
                self._handle_app_publish(body)
                return
            if path == "/api/app/fetch":
                self._handle_app_fetch(body)
                return
            if path == "/api/store/publish":
                self._handle_store_publish(body)
                return
            if path in ("/api/store/install", "/api/store/uninstall",
                        "/api/store/update"):
                self._handle_store_action(path.rsplit("/", 1)[1], _parse_json(body))
                return
            self._json(404, {"error": "not found"})

        def _handle_chat_post(self, path: str, data) -> None:
            chat = console._chat
            data = data or {}
            try:
                if path == "/api/chat/send":
                    text = data.get("text", "")
                    conv = _chat_conv(data)
                    if not isinstance(text, str) or not text:
                        self._json(400, {"error": "text required"})
                        return
                    reply = data.get("reply") if isinstance(data.get("reply"), str) else None
                    chat.send_text(conv, text, reply)
                    self._json(200, {"ok": True})
                elif path == "/api/chat/file":
                    conv = _chat_conv(data)
                    name = data.get("name", "")
                    b64 = data.get("data", "")
                    if not isinstance(name, str) or not name or not isinstance(b64, str):
                        self._json(400, {"error": "name and data required"})
                        return
                    raw = base64.b64decode(b64, validate=True)
                    reply = data.get("reply") if isinstance(data.get("reply"), str) else None
                    chat.send_file(conv, name, raw, reply)
                    self._json(200, {"ok": True})
                elif path == "/api/chat/edit":
                    ok = chat.edit_message(data.get("conv", ""), data.get("mid", ""),
                                           data.get("text", ""))
                    self._json(200 if ok else 400, {"ok": bool(ok)})
                elif path == "/api/chat/delete":
                    ok = chat.delete_message(data.get("conv", ""), data.get("mid", ""))
                    self._json(200 if ok else 400, {"ok": bool(ok)})
                elif path == "/api/chat/react":
                    ok = chat.react(data.get("conv", ""), data.get("mid", ""),
                                    str(data.get("emoji", "")))
                    self._json(200 if ok else 400, {"ok": bool(ok)})
                elif path == "/api/chat/read":
                    chat.mark_read(data.get("conv", ""))
                    self._json(200, {"ok": True})
                elif path == "/api/chat/typing":
                    chat.set_typing(data.get("conv", ""), bool(data.get("active")))
                    self._json(200, {"ok": True})
                elif path == "/api/chat/pseudo":
                    pseudo = data.get("pseudo", "")
                    if not isinstance(pseudo, str):
                        self._json(400, {"error": "pseudo required"})
                        return
                    chat.set_pseudo(pseudo)
                    self._json(200, {"ok": True})
                elif path == "/api/chat/profile":
                    pseudo = data["pseudo"] if isinstance(data.get("pseudo"), str) else None
                    bio = data["bio"] if isinstance(data.get("bio"), str) else None
                    avatar = None
                    if isinstance(data.get("avatar"), str):
                        avatar = base64.b64decode(data["avatar"], validate=True)
                    chat.set_profile(pseudo=pseudo, bio=bio, avatar=avatar)
                    self._json(200, {"ok": True})
                elif path == "/api/chat/contact":
                    op = data.get("op", "add")
                    if op == "remove":
                        ok = chat.remove_contact(data.get("id", ""))
                    else:
                        ok = chat.add_contact(data.get("id", ""), data.get("pseudo", ""))
                    self._json(200 if ok else 400, {"ok": bool(ok)})
                elif path == "/api/chat/group":
                    op = data.get("op", "create")
                    if op == "remove":
                        ok = chat.remove_group(data.get("id", ""))
                        self._json(200 if ok else 400, {"ok": bool(ok)})
                    else:
                        members = data.get("members", [])
                        if not isinstance(members, list):
                            self._json(400, {"error": "members must be a list"})
                            return
                        gid = chat.create_group(str(data.get("name", "")), members)
                        self._json(200, {"ok": True, "id": gid})
                elif path == "/api/chat/search":
                    pseudo = data.get("pseudo", "")
                    if not isinstance(pseudo, str) or not pseudo:
                        self._json(400, {"error": "pseudo required"})
                        return
                    self._json(200, {"results": chat.search_pseudo(pseudo)})
                else:
                    self._json(404, {"error": "not found"})
            except Exception as exc:
                self._json(400, {"ok": False, "error": str(exc)[:200]})

        def _handle_app_publish(self, body: bytes) -> None:
            data = _parse_json(body)
            if (not data or not isinstance(data.get("name"), str)
                    or not isinstance(data.get("version"), str)
                    or not isinstance(data.get("files"), dict)):
                self._json(400, {"error": "name, version, files required"})
                return
            try:
                files: dict[str, bytes] = {}
                total = 0
                for p, b64 in data["files"].items():
                    if not isinstance(p, str) or not isinstance(b64, str):
                        raise ValueError("bad file entry")
                    raw = base64.b64decode(b64, validate=True)
                    total += len(raw)
                    if total > _MAX_APP_BODY:
                        raise ValueError("app too large")
                    files[p] = raw
                app_id = console._call(
                    console._node.publish_app(data["name"], data["version"], files),
                    timeout=_APP_CALL_TIMEOUT)
                self._json(200, {"app_id": app_id.hex()})
            except Exception as exc:
                self._json(400, {"error": str(exc)[:200]})

        def _handle_app_fetch(self, body: bytes) -> None:
            data = _parse_json(body)
            try:
                app_id = bytes.fromhex((data or {}).get("app_id", ""))
            except (ValueError, TypeError):
                app_id = b""
            if len(app_id) != 20:
                self._json(400, {"error": "bad app_id"})
                return
            try:
                result = console._call(console._node.fetch_app(app_id),
                                       timeout=_APP_CALL_TIMEOUT)
            except Exception:
                self._json(503, {"error": "fetch failed"})
                return
            if result is None:
                self._json(404, {"found": False})
                return
            manifest, files = result
            self._json(200, {
                "found": True,
                "name": manifest.get("name"),
                "version": manifest.get("version"),
                "files": {p: base64.b64encode(d).decode("ascii")
                          for p, d in files.items()},
            })

        def _handle_store_publish(self, body: bytes) -> None:
            data = _parse_json(body)
            if (not data or not isinstance(data.get("name"), str)
                    or not isinstance(data.get("version"), str)
                    or not isinstance(data.get("files"), dict)):
                self._json(400, {"error": "name, version, files required"})
                return
            try:
                files: dict[str, bytes] = {}
                total = 0
                for p, b64 in data["files"].items():
                    if not isinstance(p, str) or not isinstance(b64, str):
                        raise ValueError("bad file entry")
                    raw = base64.b64decode(b64, validate=True)
                    total += len(raw)
                    if total > _MAX_APP_BODY:
                        raise ValueError("app too large")
                    files[p] = raw
                info = console._call(
                    console._node.publish_store_app(data["name"], data["version"], files),
                    timeout=_APP_CALL_TIMEOUT)
                self._json(200, {"ok": True, **info})
            except Exception as exc:
                self._json(400, {"ok": False, "error": str(exc)[:200]})

        def _handle_store_action(self, action: str, data) -> None:
            app_id = (data or {}).get("app_id")
            if not isinstance(app_id, str) or not app_id:
                self._json(400, {"error": "app_id required"})
                return
            try:
                if action == "install":
                    result = console._call(console._node.install_app(app_id),
                                           timeout=_APP_CALL_TIMEOUT)
                    self._json(200, {"ok": result is not None, "app": result})
                elif action == "update":
                    result = console._call(console._node.update_app(app_id),
                                           timeout=_APP_CALL_TIMEOUT)
                    self._json(200, {"ok": result is not None, "app": result})
                else:  # uninstall
                    ok = console._call(_wrap(console._node.uninstall_app, app_id))
                    self._json(200, {"ok": bool(ok)})
            except Exception as exc:
                self._json(400, {"ok": False, "error": str(exc)[:200]})

        def _handle_login(self, body: bytes) -> None:
            if console._locked_out():
                self._json(429, {"error": "too many attempts, locked out"})
                return
            data = _parse_json(body)
            password = (data or {}).get("password")
            ok = bool(password) and console._check_password(password)
            console._record_login_result(ok)
            if not ok:
                self._json(401, {"error": "invalid password"})
                return
            token = console._issue_token()
            self._json(200, {"token": token},
                       extra_headers=[_set_cookie_header(token, console._use_tls)])

    return Handler


def _chat_conv(data) -> str | None:
    """Resolve a conversation key from a chat request: an explicit ``conv``, a
    ``group`` id (prefixed ``g:``), or a direct ``peer`` id."""
    d = data or {}
    if isinstance(d.get("conv"), str) and d["conv"]:
        return d["conv"]
    if isinstance(d.get("group"), str) and d["group"]:
        return "g:" + d["group"]
    return d.get("peer")


def _parse_json(body: bytes):
    try:
        obj = json.loads(body.decode("utf-8"))
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


async def _wrap(fn, *args):
    """Adapt a sync node method into an awaitable run on the loop thread."""
    return fn(*args)
