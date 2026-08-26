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

from . import app_api
from . import updater
from . import config as node_config
from . import console_auth
from .core_release import ReleaseError
from . import join_ticket
from . import qr
from .node import MESSAGE_NAMES
from .webassets import (NODE_HTML, NODE_JS, NODE_CSS,
                        INDEX_HTML, APP_JS, STYLE_CSS, CHAT_HTML, CHAT_JS,
                        CHAT_CSS, FLEET_HTML, FLEET_JS, FLEET_CSS)
from .webassets.ui import FAVICON_SVG, THEME_JS
from .apps.fleet import console_path_refusal as fleet_console_refusal
from . import transport as transport_option

# The page names the node it is driving with this header. Absent (or naming us)
# means "this node", which is what a page that has never heard of contexts does.
_REMOTE_HEADER = "X-NMesh-Node"


def _field(manager, scheme: str, name: str) -> dict:
    """The declaration of one field, for writing its value back as text."""
    for entry in manager.options().get(scheme, []):
        if entry["name"] == name:
            return entry
    return {"kind": "text"}


def _is_node_hex(value) -> bool:
    return (isinstance(value, str) and len(value) == 40
            and all(c in "0123456789abcdef" for c in value))

_MAX_BODY = 64 * 1024
_MAX_APP_BODY = 4 * 1024 * 1024   # larger cap for app publish uploads
_MAX_CHAT_UPLOAD = 64 * 1024 * 1024   # chat file/avatar uploads (base64)
_MAX_KEY_UPLOAD = 128 * 1024          # one private key, generously bounded
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
                 password: str | None = None, chat_bridge=None,
                 app_host=None, config_path: str | None = None) -> None:
        self._node = node
        self.host = host
        self.port = port
        self._state_dir = state_dir
        self._use_tls = use_tls
        # The node's configuration file, when it was started from one. Without
        # it the settings page reports that there is nothing to edit rather than
        # inventing a path and writing somewhere nobody asked for.
        self._config_path = config_path
        # Built-in apps. With an ``app_host`` the console follows what is
        # actually running (apps can be enabled/disabled live from the Apps
        # page); ``chat_bridge`` remains the direct wiring for a runner that
        # hosts one app itself.
        self._app_host = app_host
        self._chat_bridge = chat_bridge
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
        return console_auth.path_for(self._state_dir)

    def _load_or_create_credentials(self, password: str | None):
        path = self._cred_path()
        if password is None:
            stored = console_auth.read(path)
            if stored is not None:
                return stored
            password = console_auth.generate()
            self.generated_password = password
        if path:
            return console_auth.write(path, password)
        # No state directory: the credential lives for this process only.
        salt = secrets.token_bytes(16)
        return salt, console_auth.hash_password(password, salt)

    def _check_password(self, password: str) -> bool:
        return console_auth.check(password, self._salt, self._pw_hash)

    def set_password(self, new_password: str) -> None:
        """Replace the console password. Raises ``CredentialError`` on a bad one.

        The stored hash is swapped only after the new file is written, so a
        failed write leaves the old password working rather than a node nobody
        can log into."""
        console_auth.validate(new_password)
        path = self._cred_path()
        if path:
            self._salt, self._pw_hash = console_auth.write(path, new_password)
        else:
            salt = secrets.token_bytes(16)
            self._salt = salt
            self._pw_hash = console_auth.hash_password(new_password, salt)

    def _revoke_all_tokens_except(self, keep: str | None) -> int:
        """Every other session dies with the old password.

        The caller's own session is kept: someone changing their password
        because they think a session was stolen must not be logged out by the
        very act of fixing it, and the stolen one is gone either way."""
        with self._tokens_lock:
            doomed = [token for token in self._tokens if token != keep]
            for token in doomed:
                self._tokens.pop(token, None)
        return len(doomed)

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

    @property
    def _chat(self):
        """The live chat bridge, or None when the app is disabled/absent."""
        if self._app_host is not None:
            return self._app_host.bridge("chat")
        return self._chat_bridge

    @property
    def _fleet(self):
        """The live fleet bridge, or None when the app is disabled/absent."""
        return self._app_host.bridge("fleet") if self._app_host else None

    def _apps(self) -> list:
        """Built-in apps and their state (for the Apps page).

        With an app host this is the registry's view — installed, enabled,
        running — so the page can toggle them. Without one, it degrades to
        naming whatever bridge was wired directly."""
        if self._app_host is not None:
            return self._app_host.overview()
        apps = []
        if self._chat_bridge is not None:
            apps.append({"id": "chat", "name": "Chat", "path": "/chat",
                         "installed": True, "enabled": True, "running": True,
                         "description": ""})
        return apps

    def _config_snapshot(self) -> dict:
        """The configuration as the settings page needs it: current values,
        which of them may be edited from here, and anything wrong with the file.

        Read from disk on every request rather than cached: the file can be
        edited by hand, and a page showing what the node was started with rather
        than what the file now says would be actively misleading."""
        if not self._config_path:
            return {"available": False,
                    "reason": "this node was not started from a configuration file"}
        values, problems = node_config.load(self._config_path)
        merged = node_config.defaults()
        merged.update(values)
        return {"available": True,
                "path": self._config_path,
                "settings": node_config.public(merged),
                "problems": problems[:16],
                "restart_required": False,
                "service_managed": updater.service_managed()}

    @property
    def _api(self) -> "app_api.AppAPI":
        """The app API surface, over whatever is running right now.

        Built per access rather than held: an app stopped a second ago must not
        still be reachable through a reference this object kept."""
        return app_api.AppAPI(self._app_host)

    def _persist_setting(self, name: str, value) -> bool:
        """Remember one live toggle in the configuration file.

        Best effort, exactly like the transport settings: a node with no file
        still applies the change to the running process, it just will not
        remember it. The toggle itself never depends on this working."""
        if not self._config_path:
            return False
        try:
            values, _problems = node_config.load(self._config_path)
            merged = node_config.defaults()
            merged.update(values)
            merged[name] = value
            node_config.save(self._config_path, merged)
            return True
        except (OSError, ValueError, KeyError):
            return False

    def _transport_options(self) -> dict:
        """What every registered transport says it takes.

        The console renders this without knowing a single transport: a medium
        added tomorrow gets a form for free, and one that declares nothing
        simply does not appear."""
        manager = self._node._transport_manager
        try:
            declared = manager.options()
        except Exception:
            declared = {}
        return {"transports": [{"scheme": scheme, "options": fields}
                               for scheme, fields in declared.items()],
                "persisted": bool(self._config_path)}

    def _persist_transports(self) -> tuple:
        """Write what is not at its default into the configuration file.

        Best effort by design: a node with no file still applies the change to
        the running process, it just will not remember it."""
        if not self._config_path:
            return False, "not stored — this node has no configuration file"
        try:
            values, _problems = node_config.load(self._config_path)
            merged = node_config.defaults()
            merged.update(values)
            manager = self._node._transport_manager
            merged["transports"] = {
                scheme: {name: transport_option.as_text(
                    _field(manager, scheme, name), value)
                    for name, value in fields.items()}
                for scheme, fields in manager.settings().items()}
            node_config.save(self._config_path, merged)
        except Exception as exc:
            return False, f"could not write the file: {type(exc).__name__}"
        return True, ""

    def start(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        self._loop = loop or asyncio.get_event_loop()
        if self._app_host is not None:
            self._app_host.bind_console(self._loop)
        elif self._chat_bridge is not None:
            self._chat_bridge.start(self._loop)
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

    # -- restarting onto freshly installed code ---------------------------
    #
    # Replacing the tree does not change the code already loaded in this
    # process: an update only takes effect when the node starts again. The
    # service manager is what starts it, so "restart" here means "exit, and let
    # it bring us back" — the same path a crash would take, which is why it is
    # only ever done when something is actually watching.

    _RESTART_DELAY = 1.0        # let the operator's response reach them first

    def _restart_worker(self) -> None:
        """Stop the node properly, then leave. Never returns."""
        time.sleep(self._RESTART_DELAY)
        try:
            if self._loop is not None and not self._loop.is_closed():
                # Bounded: a peer refusing to close must not keep the old code
                # running for ever, which is the thing we are here to end.
                asyncio.run_coroutine_threadsafe(
                    self._node.stop(), self._loop).result(timeout=20.0)
        except Exception:
            pass                # going down regardless; state writes are bounded
        os._exit(0)

    def restart_for_update(self) -> bool:
        """Exit so the service manager starts us again on the new code.

        Returns whether a restart was scheduled. Without a service manager
        (``NMESH_SERVICE_MANAGED``), exiting would simply stop the node — a
        worse outcome than running yesterday's code — so we stay up and the
        console tells the operator to restart it themselves."""
        if not updater.service_managed():
            return False
        threading.Thread(target=self._restart_worker, daemon=True,
                         name="nmesh-restart").start()
        return True

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        if self._app_host is None and self._chat_bridge is not None:
            self._chat_bridge.stop()

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
    # One node, described. The same view chat and fleet mount in place; this
    # page is what they open when the operator asked for a window or a tab.
    "/node": ("text/html; charset=utf-8", NODE_HTML),
    "/node.js": ("application/javascript; charset=utf-8", NODE_JS),
    "/node.css": ("text/css; charset=utf-8", NODE_CSS),
    "/app.js": ("application/javascript; charset=utf-8", APP_JS),
    "/style.css": ("text/css; charset=utf-8", STYLE_CSS),
    # Loaded blocking in <head> on every page: a stored theme choice has to be
    # on the element before the first paint, and the CSP forbids inline script.
    "/theme.js": ("application/javascript; charset=utf-8", THEME_JS),
    "/favicon.svg": ("image/svg+xml", FAVICON_SVG),
}

# Chat sub-page assets, served only when a chat bridge is attached. Like the
# console shell, the page HTML/JS/CSS are public; the /api/chat/* endpoints
# below require the same bearer token as the rest of the console.
_CHAT_STATIC = {
    "/chat": ("text/html; charset=utf-8", CHAT_HTML),
    "/chat.js": ("application/javascript; charset=utf-8", CHAT_JS),
    "/chat.css": ("text/css; charset=utf-8", CHAT_CSS),
}

# Fleet sub-page assets, served only when the fleet app is running. Same rule as
# chat: the page itself is public, every /api/fleet/* call needs the session.
_FLEET_STATIC = {
    "/fleet": ("text/html; charset=utf-8", FLEET_HTML),
    "/fleet.js": ("application/javascript; charset=utf-8", FLEET_JS),
    "/fleet.css": ("text/css; charset=utf-8", FLEET_CSS),
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


def _number(raw, default: int = 0) -> int:
    """A JSON scalar as an int, without trusting it to be one."""
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


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

        # -- remote context ----------------------------------------------
        # The page sends `X-NMesh-Node: <id>` when the operator has switched
        # context. Everything else about the request is unchanged, so the whole
        # console works against another node without a second front-end — and a
        # page that forgets the header simply drives the local node, which is
        # the safe way round.

        def _remote_node(self) -> str | None:
            raw = (self.headers.get(_REMOTE_HEADER) or "").strip().lower()
            if not raw or raw == console._node.id.raw.hex():
                return None
            return raw if _is_node_hex(raw) else ""

        def _proxy_remote(self, node_hex: str, path: str,
                          body: bytes | None) -> None:
            """Relay this request to ``node_hex`` and answer with what it said."""
            fleet = console._fleet
            if fleet is None:
                self._json(409, {"error": "the fleet app is not running"})
                return
            refusal = fleet_console_refusal(path)
            if refusal:
                self._json(403, {"error": refusal})
                return
            status, ctype, payload = fleet.remote_call(
                self._session_token() or "", node_hex, self.command, path, body)
            self._send(status, str(ctype)[:128], payload)

        # -- routing --

        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            remote = self._remote_node()
            if remote is not None:
                if not self._authed():
                    self._json(401, {"error": "unauthorized"})
                    return
                if not remote:
                    self._json(400, {"error": "bad node id"})
                    return
                self._proxy_remote(remote, self.path, None)
                return
            if path == "/api/remote/targets":
                self._handle_remote_targets()
                return
            if path in _STATIC:
                ctype, text = _STATIC[path]
                self._send(200, ctype, text.encode("utf-8"))
                return
            if console._chat is not None and path in _CHAT_STATIC:
                ctype, text = _CHAT_STATIC[path]
                self._send(200, ctype, text.encode("utf-8"))
                return
            if console._fleet is not None and path in _FLEET_STATIC:
                ctype, text = _FLEET_STATIC[path]
                self._send(200, ctype, text.encode("utf-8"))
                return
            if path.startswith("/api/fleet/"):
                self._handle_fleet_get(path)
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
                    snap["version"] = updater.__version__
                    self._json(200, snap)
                except Exception:
                    self._json(503, {"error": "node unavailable"})
                return
            if path == "/api/app-api":
                # What a page may offer. Authenticated like everything else:
                # the list of what an operator could do is itself worth
                # knowing, and this console does not answer strangers.
                if not self._authed():
                    self._json(401, {"error": "unauthorized"})
                    return
                self._json(200, {"apps": console._api.catalogue()})
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
            if path == "/api/update/check":
                if not self._authed():
                    self._json(401, {"error": "unauthorized"})
                    return
                try:
                    result = console._call(updater.check(), timeout=40.0)
                except updater.UpdateError as exc:
                    self._json(200, {"error": str(exc)[:256],
                                     "current": updater.__version__})
                    return
                except Exception:
                    self._json(503, {"error": "update check failed"})
                    return
                ok, reason = updater.updatable()
                result["can_apply"] = ok
                result["blocked"] = reason
                self._json(200, result)
                return
            if path == "/api/releases":
                if not self._authed():
                    self._json(401, {"error": "unauthorized"})
                    return
                # Marshalled onto the loop like every other node read: the
                # node's state is never touched from an HTTP thread.
                try:
                    self._json(200, console._call(
                        _wrap(console._node.release_overview)))
                except Exception:
                    self._json(503, {"error": "node unavailable"})
                return
            if path == "/api/config":
                if not self._authed():
                    self._json(401, {"error": "unauthorized"})
                    return
                self._json(200, console._config_snapshot())
                return
            if path == "/api/transports":
                if not self._authed():
                    self._json(401, {"error": "unauthorized"})
                    return
                self._json(200, console._transport_options())
                return
            if path == "/api/trace":
                if not self._authed():
                    self._json(401, {"error": "unauthorized"})
                    return
                trace = console._node.trace
                payload = {"status": trace.status(), "summary": trace.summary()}
                from urllib.parse import parse_qs
                query = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
                if query.get("events", ["0"])[0] == "1":
                    payload["events"] = trace.events(limit=400)
                self._json(200, payload)
                return
            if path == "/api/trace/export":
                if not self._authed():
                    self._json(401, {"error": "unauthorized"})
                    return
                import json as _json_mod
                # Served as an opaque download: a trace is routing metadata and
                # has no business being rendered inline by the browser.
                self._send_binary(
                    _json_mod.dumps(console._node.trace.export(), indent=1).encode(),
                    "nmesh-trace.json")
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
            elif path == "/api/fleet/keys":
                cap = _MAX_KEY_UPLOAD
            else:
                cap = _MAX_BODY
            body = self._read_body(cap)
            if body is None:
                self._json(413, {"error": "body too large or malformed"})
                return
            remote = self._remote_node()
            if path == "/api/login" and remote is None:
                self._handle_login(body)
                return
            # everything below requires auth
            if not self._authed():
                self._json(401, {"error": "unauthorized"})
                return
            if remote is not None:
                if not remote:
                    self._json(400, {"error": "bad node id"})
                    return
                self._proxy_remote(remote, self.path, body)
                return
            if path.startswith("/api/remote/"):
                self._handle_remote_post(path, _parse_json(body))
                return
            if path == "/api/logout":
                tok = self._session_token()
                if tok:
                    console._revoke_token(tok)
                    # A local session ending takes every remote console it held
                    # with it: nothing survives the sign-out that opened it.
                    if console._fleet is not None:
                        console._fleet.remote_drop_session(tok)
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
            if path == "/api/ticket":
                self._handle_ticket(_parse_json(body))
                return
            if path == "/api/join":
                data = _parse_json(body) or {}
                # A ticket is the same join, with the address and the code
                # travelling together instead of separately.
                if data.get("ticket"):
                    try:
                        parsed = join_ticket.decode(data["ticket"])
                    except join_ticket.TicketError as exc:
                        self._json(400, {"error": str(exc)[:200]})
                        return
                    data = {"uri": parsed["uri"], "code": parsed["code"]}
                if "uri" not in data or "code" not in data:
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
            if path == "/api/nodes/forget":
                data = _parse_json(body)
                node_id = (data or {}).get("id", "")
                if not isinstance(node_id, str) or not node_id:
                    self._json(400, {"error": "id required"})
                    return
                try:
                    ok = console._call(console._node.console_forget_node(node_id))
                    self._json(200 if ok else 404, {"ok": bool(ok)})
                except Exception as exc:
                    self._json(400, {"ok": False, "error": str(exc)[:200]})
                return
            if path == "/api/peers/retry":
                data = _parse_json(body) or {}
                node_id = data.get("id", "")
                uri = data.get("uri", "")
                if not isinstance(node_id, str) or not node_id:
                    self._json(400, {"error": "id required"})
                    return
                if not isinstance(uri, str):
                    self._json(400, {"error": "uri must be a string"})
                    return
                try:
                    # A dial per address, each bounded by the node — the whole
                    # walk can outlast the default call timeout on a node with
                    # several dead addresses, which is precisely the case the
                    # button is pressed in.
                    result = console._call(
                        console._node.console_retry_addresses(node_id, uri),
                        timeout=60.0)
                    self._json(200 if result.get("ok") else 400, result)
                except Exception:
                    self._json(503, {"error": "node unavailable"})
                return
            if path == "/api/addressing/balance":
                data = _parse_json(body) or {}
                try:
                    value = console._node.set_transport_balance(data.get("value"))
                except ValueError as exc:
                    self._json(400, {"error": str(exc)[:200]})
                    return
                console._persist_setting("transport_balance", value)
                self._json(200, {"ok": True, "value": value,
                                 "preference": console._node.transport_preference()})
                return
            if path == "/api/addressing/dynamic":
                data = _parse_json(body)
                if not data or not isinstance(data.get("enabled"), bool):
                    self._json(400, {"error": "enabled (bool) required"})
                    return
                try:
                    console._node.set_dynamic_address(data["enabled"])
                    console._persist_setting("dynamic_address", data["enabled"])
                    self._json(200, {"ok": True, "enabled": data["enabled"]})
                except Exception as exc:
                    self._json(400, {"ok": False, "error": str(exc)[:200]})
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
            if path == "/api/app-call":
                self._handle_app_call(_parse_json(body))
                return
            if path.startswith("/api/chat/"):
                if console._chat is None:
                    self._json(404, {"error": "not found"})
                    return
                self._handle_chat_post(path, _parse_json(body))
                return
            if path.startswith("/api/fleet/"):
                if console._fleet is None:
                    self._json(404, {"error": "not found"})
                    return
                self._handle_fleet_post(path, _parse_json(body))
                return
            if path.startswith("/api/apps/"):
                self._handle_apps_post(path, _parse_json(body))
                return
            if path == "/api/update/apply":
                self._handle_update_apply(_parse_json(body))
                return
            if path.startswith("/api/releases/"):
                self._handle_release_post(path, _parse_json(body))
                return
            if path == "/api/config":
                self._handle_config_save(_parse_json(body))
                return
            if path == "/api/transports":
                self._handle_transport_save(_parse_json(body))
                return
            if path == "/api/trace":
                self._handle_trace(_parse_json(body))
                return
            if path == "/api/password":
                self._handle_password(_parse_json(body))
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

        def _handle_ticket(self, data) -> None:
            """Mint a compact join ticket, with its QR code.

            The QR is rendered here, from the string we just made — there is no
            endpoint that turns arbitrary text into a QR code, because nothing
            would need one."""
            if not self._authed():
                self._json(401, {"error": "unauthorized"})
                return
            ttl = join_ticket.clamp_ttl((data or {}).get("ttl"))
            try:
                ticket = console._call(_wrap(console._node.issue_join_ticket, ttl))
            except ValueError as exc:
                # Not reachable from the open internet: say why, rather than
                # handing over a ticket that cannot work.
                self._json(409, {"error": str(exc)[:300]})
                return
            except Exception:
                self._json(500, {"error": "could not issue a ticket"})
                return
            # The code travels inside the ticket; repeating it in the response
            # would only put the same secret in one more place.
            ticket.pop("code", None)
            try:
                ticket["qr_svg"] = qr.svg_for(ticket["ticket"])
            except qr.QRError:
                ticket["qr_svg"] = ""
            self._json(200, ticket)

        def _handle_password(self, data) -> None:
            """Change the console password.

            A valid session is not enough: the **current password** must be in
            the request. A stolen session token must not be able to lock the
            owner out of their own node — that turns a session theft into a
            permanent takeover.

            A wrong current password counts toward the same lockout as a failed
            login, so this endpoint cannot be used to guess it faster."""
            if not self._authed():
                self._json(401, {"error": "unauthorized"})
                return
            if console._locked_out():
                self._json(429, {"error": "too many attempts — wait a minute"})
                return
            data = data or {}
            current = data.get("current")
            new = data.get("new")
            if not isinstance(current, str) or not console._check_password(current):
                console._record_login_result(False)
                self._json(403, {"error": "the current password is wrong"})
                return
            console._record_login_result(True)
            try:
                console.set_password(new)
            except console_auth.CredentialError as exc:
                self._json(400, {"error": str(exc)})
                return
            except OSError as exc:
                # The old password still works: set_password swaps the stored
                # hash only after the file is written.
                self._json(500, {"error": f"could not save the new password: "
                                          f"{exc.strerror or 'error'}"})
                return
            revoked = console._revoke_all_tokens_except(self._session_token())
            self._json(200, {"changed": True, "sessions_revoked": revoked})

        def _handle_trace(self, data) -> None:
            """Start or stop the protocol trace.

            Bounded on the way in as well as inside: an operator asking for a
            week-long trace of a million packets gets the largest one the node
            is willing to hold, not the one they typed."""
            if not self._authed():
                self._json(401, {"error": "unauthorized"})
                return
            data = data or {}
            action = data.get("action")
            trace = console._node.trace
            if action == "start":
                self._json(200, trace.start(seconds=_number(data.get("seconds")),
                                            events=_number(data.get("events")),
                                            names=MESSAGE_NAMES))
                return
            if action == "stop":
                self._json(200, trace.stop())
                return
            if action == "clear":
                trace.clear()
                self._json(200, trace.status())
                return
            self._json(400, {"error": "action must be start, stop or clear"})

        def _handle_release_post(self, path: str, data) -> None:
            """Publishing, pinning and installing mesh-native releases.

            The console decides nothing here: pinning a key, installing a
            release and turning automatic installation on all end in the node,
            which owns the gates. What this layer owns is that a signed-in
            operator asked."""
            if not self._authed():
                self._json(401, {"error": "unauthorized"})
                return
            data = data if isinstance(data, dict) else {}
            node = console._node
            try:
                if path == "/api/releases/publish":
                    notes = data.get("notes")
                    result = console._call(
                        node.publish_release(
                            notes=notes if isinstance(notes, str) else ""),
                        timeout=300.0)
                    self._json(200, {"ok": True, **result})
                    return
                if path == "/api/releases/install":
                    publisher = data.get("publisher_id")
                    if not isinstance(publisher, str):
                        self._json(400, {"error": "publisher_id required"})
                        return
                    if data.get("confirm") is not True:
                        self._json(400, {"error": "confirmation required"})
                        return
                    result = console._call(node.install_release(publisher),
                                           timeout=400.0)
                    # An operator pressed Install and is watching. The
                    # unattended path (the release loop) never restarts — that
                    # is where a bad release could become a restart loop.
                    restarting = console.restart_for_update()
                    self._json(200, {"ok": True, **result,
                                     "restarting": restarting})
                    return
                if path == "/api/releases/trust":
                    key = data.get("key")
                    if not isinstance(key, str):
                        self._json(400, {"error": "key required"})
                        return
                    name = data.get("name")
                    entry = console._call(_wrap(
                        node.trust_publisher, key.strip(),
                        name if isinstance(name, str) else "",
                        data.get("auto") is True))
                    self._json(200, {"ok": True, "publisher": entry})
                    return
                if path == "/api/releases/untrust":
                    publisher = data.get("publisher_id")
                    if not isinstance(publisher, str):
                        self._json(400, {"error": "publisher_id required"})
                        return
                    self._json(200, {"ok": console._call(
                        _wrap(node.untrust_publisher, publisher))})
                    return
                if path == "/api/releases/auto":
                    publisher = data.get("publisher_id")
                    if not isinstance(publisher, str):
                        self._json(400, {"error": "publisher_id required"})
                        return
                    ok = console._call(_wrap(node.set_publisher_auto, publisher,
                                             data.get("auto") is True))
                    self._json(200 if ok else 404, {"ok": ok})
                    return
            except ReleaseError as exc:
                self._json(400, {"error": str(exc)[:256]})
                return
            except updater.UpdateError as exc:
                self._json(502, {"error": str(exc)[:256]})
                return
            except Exception as exc:
                self._json(500, {"error": f"release failed: {type(exc).__name__}"})
                return
            self._json(404, {"error": "not found"})

        def _handle_app_call(self, data) -> None:
            """Invoke one declared operation on one running app.

            The single door: no route per action, and nothing reachable that an
            app did not write down. Authentication is the console's own — an
            operator signed in here — and it buys no authority beyond that: an
            operation that asks another node for rights still ends with a human
            over there agreeing."""
            if not self._authed():
                self._json(401, {"error": "unauthorized"})
                return
            data = data if isinstance(data, dict) else {}
            app = data.get("app")
            name = data.get("op")
            if not isinstance(app, str) or not isinstance(name, str):
                self._json(400, {"error": "app and op are required"})
                return
            args = data.get("args")
            try:
                result = console._api.call(app, name,
                                           args if isinstance(args, dict) else {})
            except app_api.AppAPIError as exc:
                self._json(400, {"ok": False, "error": str(exc)[:200]})
                return
            except Exception:
                self._json(503, {"ok": False, "error": "the app is unavailable"})
                return
            self._json(200, {"ok": True, "result": result})

        def _handle_config_save(self, data) -> None:
            """Write the node's configuration file.

            Every field is validated before anything is written: a rejected
            value leaves the stored one alone, so one bad entry in a form can
            never produce a file the node would refuse to start on. Nothing is
            applied live — the node reads this at startup, and the answer says
            so rather than letting the page imply otherwise."""
            if not self._authed():
                self._json(401, {"error": "unauthorized"})
                return
            if not console._config_path:
                self._json(409, {"error": "this node was not started from a "
                                          "configuration file"})
                return
            current, _problems = node_config.load(console._config_path)
            merged = node_config.defaults()
            merged.update(current)
            merged, rejected = node_config.apply_edits(
                merged, (data or {}).get("settings"))
            if rejected:
                self._json(400, {"error": "some settings were refused",
                                 "rejected": rejected[:16]})
                return
            try:
                node_config.save(console._config_path, merged)
            except OSError as exc:
                self._json(500, {"error": f"could not write the configuration: "
                                          f"{exc.strerror or 'error'}"})
                return
            self._json(200, {"saved": True,
                             "path": console._config_path,
                             "restart_required": True,
                             "service_managed": updater.service_managed()})

        def _handle_update_apply(self, data) -> None:
            """Install a release — only ever the one the operator confirmed.

            The request must name the version. If GitHub has moved on since the
            page was drawn, the mismatch is refused: a tab left open for an hour
            must not install something nobody looked at."""
            data = data or {}
            wanted = data.get("version")
            if not isinstance(wanted, str) or not wanted:
                self._json(400, {"error": "version required"})
                return
            if data.get("confirm") is not True:
                self._json(400, {"error": "confirmation required"})
                return
            ok, reason = updater.updatable()
            if not ok:
                self._json(409, {"error": reason})
                return
            try:
                latest = console._call(updater.check(), timeout=40.0)
            except updater.UpdateError as exc:
                self._json(502, {"error": str(exc)[:256]})
                return
            except Exception:
                self._json(503, {"error": "update check failed"})
                return
            if latest.get("latest") != wanted:
                self._json(409, {
                    "error": f"the latest release is now {latest.get('latest')}, "
                             f"not {wanted} — check again and re-confirm"})
                return
            if not latest.get("available"):
                self._json(409, {"error": "already up to date"})
                return
            try:
                result = console._call(updater.apply(wanted), timeout=400.0)
            except updater.UpdateError as exc:
                self._json(502, {"error": str(exc)[:256]})
                return
            except Exception as exc:
                self._json(500, {"error": f"update failed: {type(exc).__name__}"})
                return
            # The files are in place; this process is still running the old
            # ones. Answer first, then leave so the manager brings us back on
            # the new code — otherwise the page's "restarting" is a lie.
            restarting = console.restart_for_update()
            self._json(200, {"ok": True, **result, "restarting": restarting})

        # -- fleet (remote management) ------------------------------------
        #
        # Every route below is behind the same session as the rest of the
        # console. The node-side capability checks still apply on the far end:
        # this console can only ask, never grant itself anything.

        def _handle_fleet_get(self, path: str) -> None:
            if console._fleet is None:
                self._json(404, {"error": "not found"})
                return
            if not self._authed():
                self._json(401, {"error": "unauthorized"})
                return
            query = parse_qs(self.path.partition("?")[2])
            if path == "/api/fleet/state":
                since = _int_param(query, "since", 0)
                self._json(200, console._fleet.snapshot(since))
                return
            if path == "/api/fleet/shell":
                sid = (query.get("sid") or [""])[0]
                data = console._fleet.shell_data(sid, _int_param(query, "offset", 0))
                self._json(200 if data else 404, data or {"error": "no session"})
                return
            if path == "/api/fleet/keys":
                # Paths and comments of local SSH keys — never key material.
                self._json(200, {"keys": console._fleet.local_keys()})
                return
            self._json(404, {"error": "not found"})

        # -- remote consoles ---------------------------------------------

        def _handle_transport_save(self, data) -> None:
            """Apply one transport's settings, then write them to the file.

            Applied first, stored second: a value the transport refuses must
            never reach the file, or the next start would refuse it too — with
            nobody at the keyboard to read why."""
            data = data or {}
            scheme = str(data.get("scheme") or "")[:32]
            values = data.get("values")
            if not isinstance(values, dict):
                self._json(400, {"error": "no settings given"})
                return
            manager = console._node._transport_manager
            try:
                result = console._call(_wrap(manager.configure, scheme, values))
            except Exception as exc:
                self._json(400, {"error": str(exc)[:200]})
                return
            saved, note = console._persist_transports()
            self._json(200, {"ok": not result["rejected"],
                             "applied": {name: value for name, value
                                         in result["applied"].items()},
                             "rejected": result["rejected"],
                             "persisted": saved, "note": note})

        def _handle_remote_targets(self) -> None:
            if not self._authed():
                self._json(401, {"error": "unauthorized"})
                return
            fleet = console._fleet
            self._json(200, {
                "me": console._node.id.raw.hex(),
                "available": fleet is not None,
                "targets": fleet.remote_targets() if fleet is not None else [],
            })

        def _handle_remote_post(self, path: str, data) -> None:
            fleet = console._fleet
            if fleet is None:
                self._json(409, {"error": "the fleet app is not running"})
                return
            data = data or {}
            node = str(data.get("node") or "")
            session = self._session_token() or ""
            action = path.rsplit("/", 1)[1]
            if not _is_node_hex(node):
                self._json(400, {"error": "bad node id"})
                return
            if action == "connect":
                password = data.get("password")
                if not isinstance(password, str) or not password:
                    self._json(400, {"error": "the remote console password is required"})
                    return
                ok, detail = fleet.remote_connect(session, node, password)
                self._json(200 if ok else 403, {"ok": ok, "error": detail})
                return
            if action == "disconnect":
                self._json(200, {"ok": fleet.remote_disconnect(session, node)})
                return
            self._json(404, {"error": "not found"})

        def _handle_fleet_post(self, path: str, data) -> None:
            fleet = console._fleet
            data = data or {}
            node = data.get("node") or data.get("id") or ""
            action = path.rsplit("/", 1)[1]
            try:
                if action == "enrol":
                    ok = fleet.enrol(node, data.get("caps"), data.get("label", ""))
                    self._json(200 if ok else 400, {"ok": bool(ok)})
                elif action == "approve":
                    ok = fleet.approve(node, data.get("caps"))
                    self._json(200 if ok else 400, {"ok": bool(ok)})
                elif action == "deny":
                    ok = fleet.deny(node, data.get("reason", ""))
                    self._json(200 if ok else 400, {"ok": bool(ok)})
                elif action == "revoke":
                    ok = fleet.revoke(node)
                    self._json(200 if ok else 404, {"ok": bool(ok)})
                elif action == "caps-request":
                    # Asking a node we manage for more: it parks the request
                    # for a human over there, exactly like a first enrolment.
                    ok = fleet.request_caps(node, data.get("caps"))
                    self._json(200 if ok else 400, {"ok": bool(ok)})
                elif action == "caps-drop":
                    ok = fleet.drop_caps(node, data.get("caps"))
                    self._json(200 if ok else 400, {"ok": bool(ok)})
                elif action == "caps-set":
                    # What an operator may do to *this* node, decided here.
                    ok = fleet.set_operator_caps(node, data.get("caps"))
                    self._json(200 if ok else 400, {"ok": bool(ok)})
                elif action == "status":
                    self._json(200, {"rid": fleet.status(node)})
                elif action == "update":
                    self._json(200, {"rid": fleet.update(node)})
                elif action == "scan":
                    # ``targets`` mixes subnets and precise machines; ``subnets``
                    # is accepted as the older spelling of the same field.
                    targets = data.get("targets") or data.get("subnets")
                    if node and node != fleet.me:
                        self._json(200, {"rid": fleet.scan(node, targets)})
                    else:
                        self._json(200, fleet.scan_local(targets))
                elif action == "shell":
                    self._json(200, {"rid": fleet.open_shell(
                        node, _dim_param(data.get("cols"), 80),
                        _dim_param(data.get("rows"), 24))})
                elif action == "input":
                    raw = _b64_field(data.get("data"))
                    ok = raw is not None and fleet.shell_input(
                        node, data.get("sid", ""), raw)
                    self._json(200 if ok else 400, {"ok": bool(ok)})
                elif action == "resize":
                    ok = fleet.shell_resize(node, data.get("sid", ""),
                                            _dim_param(data.get("cols"), 80),
                                            _dim_param(data.get("rows"), 24))
                    self._json(200 if ok else 400, {"ok": bool(ok)})
                elif action == "close":
                    ok = fleet.close_shell(node, data.get("sid", ""))
                    self._json(200 if ok else 400, {"ok": bool(ok)})
                elif action == "keys":
                    # Uploading a private key: it goes straight into the node's
                    # encrypted drawer and is never echoed back.
                    material = data.get("data")
                    if isinstance(material, str) and material.startswith("b64:"):
                        decoded = _b64_field(material[4:])
                        material = decoded.decode("utf-8", "replace") if decoded else None
                    entry = fleet.add_key(data.get("name", ""), material) \
                        if isinstance(material, str) else None
                    self._json(200 if entry else 400,
                               {"ok": bool(entry), "key": entry,
                                "keys": fleet.local_keys()})
                elif action == "keys-remove":
                    ok = fleet.remove_key(data.get("id", ""))
                    self._json(200 if ok else 404,
                               {"ok": bool(ok), "keys": fleet.local_keys()})
                elif action == "provision":
                    self._handle_provision(fleet, node, data)
                else:
                    self._json(404, {"error": "not found"})
            except ValueError:
                self._json(400, {"error": "bad request"})
            except Exception as exc:
                self._json(503, {"error": str(exc)[:200]})

        def _handle_provision(self, fleet, node: str, data) -> None:
            """Start a provisioning run.

            The credential arrives in this request body and is passed straight
            through to the app. It is never written to the console's state, its
            log, or its session — and the response never echoes it back."""
            targets = data.get("targets")
            if not isinstance(targets, list) or not targets:
                self._json(400, {"error": "targets required"})
                return
            username = data.get("username")
            if not isinstance(username, str) or not username:
                self._json(400, {"error": "username required"})
                return
            kwargs = dict(
                username=username,
                password=data.get("password") or None,
                key_path=data.get("key_path") or None,
                key_id=data.get("key_id") or None,
                key_passphrase=data.get("key_passphrase") or None,
                # Escalation is stated, never guessed: probing for sudo means
                # failed attempts in the target's auth log.
                can_sudo=bool(data.get("can_sudo", True)),
                sudo_user=data.get("sudo_user") or None,
                sudo_password=data.get("sudo_password") or None,
                mode="user" if data.get("mode") == "user" else "system",
                caps=data.get("caps"),
                join_uris=data.get("join_uris"),
                join_code=data.get("join_code"),
            )
            if node and node != fleet.me:
                self._json(200, {"rid": fleet.provision(node, targets, **kwargs)})
            else:
                self._json(200, {"results": fleet.provision_local(targets, **kwargs)})

        # -- built-in apps (install / enable) -----------------------------

        def _handle_apps_post(self, path: str, data) -> None:
            host = console._app_host
            if host is None:
                self._json(404, {"error": "not found"})
                return
            # ``id`` is the registry key; ``name`` is accepted as the older
            # spelling so a caller written against either keeps working.
            data = data or {}
            name = data.get("id") or data.get("name")
            action = path.rsplit("/", 1)[1]
            if not isinstance(name, str) or action not in (
                    "enable", "disable", "install", "uninstall"):
                self._json(400, {"error": "bad request"})
                return
            try:
                ok = console._call(getattr(host, action)(name), timeout=30.0)
            except Exception as exc:
                self._json(503, {"error": str(exc)[:200]})
                return
            self._json(200 if ok else 400, {"ok": bool(ok),
                                            "apps": console._apps()})

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


def _int_param(query: dict, name: str, default: int) -> int:
    try:
        return max(0, int((query.get(name) or [str(default)])[0]))
    except (ValueError, TypeError):
        return default


def _dim_param(value, default: int) -> int:
    """Clamp a terminal dimension coming from the browser."""
    try:
        return max(1, min(int(value), 1000))
    except (TypeError, ValueError):
        return default


def _b64_field(value) -> bytes | None:
    """Decode a base64 field from a request body. Terminal input is bytes, not
    text, so it travels base64-encoded; anything undecodable is refused."""
    if not isinstance(value, str) or len(value) > _MAX_BODY:
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        return None


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
