"""
Local web console — a management plane for a MeshNode.

This is the most security-sensitive surface in the project: it can trust new
certificates and join networks, so a compromise here compromises the node.
It is therefore built defensively and with stdlib only (+ ``cryptography``,
already a dependency, for the TLS cert):

  - HTTPS with a self-signed cert whose fingerprint is printed at startup.
  - Password auth; the password is generated on first run and only ever stored
    as a salted scrypt hash.
  - Bearer tokens (Authorization header), never cookies → no CSRF surface.
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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .webassets import INDEX_HTML, APP_JS, STYLE_CSS

_MAX_BODY = 64 * 1024
_MAX_APP_BODY = 4 * 1024 * 1024   # larger cap for app publish uploads
_APP_CALL_TIMEOUT = 60.0          # DHT publish/fetch can touch several peers
_TOKEN_TTL = 3600.0            # session idle lifetime, seconds
_LOGIN_MAX_FAILURES = 5
_LOGIN_LOCKOUT = 60.0          # seconds locked after too many failures
_CALL_TIMEOUT = 10.0          # max seconds to wait on a loop-marshalled call
_SCRYPT = dict(n=16384, r=8, p=1, dklen=32)


def _scrypt(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, **_SCRYPT)


class WebConsole:
    def __init__(self, node, *, host: str = "127.0.0.1", port: int = 8787,
                 state_dir: str | None = None, use_tls: bool = True,
                 password: str | None = None) -> None:
        self._node = node
        self.host = host
        self.port = port
        self._state_dir = state_dir
        self._use_tls = use_tls
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

    def start(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        self._loop = loop or asyncio.get_event_loop()
        handler = _make_handler(self)
        self._server = ThreadingHTTPServer((self.host, self.port), handler)
        if self._ssl_ctx is not None:
            self._server.socket = self._ssl_ctx.wrap_socket(
                self._server.socket, server_side=True
            )
        # If port was 0, capture the OS-assigned one.
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever,
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


def _make_handler(console: WebConsole):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "nmesh-console"

        def log_message(self, *args) -> None:
            pass  # stay quiet; the node has its own logging

        # -- helpers --

        def _send(self, code: int, ctype: str, body: bytes) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in _SECURITY_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, code: int, obj) -> None:
            self._send(code, "application/json; charset=utf-8",
                       json.dumps(obj).encode("utf-8"))

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

        def _authed(self) -> bool:
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return False
            return console._valid_token(auth[7:])

        # -- routing --

        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path in _STATIC:
                ctype, text = _STATIC[path]
                self._send(200, ctype, text.encode("utf-8"))
                return
            if path == "/api/state":
                if not self._authed():
                    self._json(401, {"error": "unauthorized"})
                    return
                try:
                    snap = console._call(console._node.console_snapshot())
                    snap["server_time"] = time.time()
                    self._json(200, snap)
                except Exception:
                    self._json(503, {"error": "node unavailable"})
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
            self._json(404, {"error": "not found"})

        def do_HEAD(self) -> None:
            self.do_GET()

        def do_POST(self) -> None:
            path = self.path.split("?", 1)[0]
            cap = _MAX_APP_BODY if path == "/api/app/publish" else _MAX_BODY
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
                auth = self.headers.get("Authorization", "")
                console._revoke_token(auth[7:])
                self._json(200, {"ok": True})
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
            if path == "/api/app/publish":
                self._handle_app_publish(body)
                return
            if path == "/api/app/fetch":
                self._handle_app_fetch(body)
                return
            self._json(404, {"error": "not found"})

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
            self._json(200, {"token": console._issue_token()})

    return Handler


def _parse_json(body: bytes):
    try:
        obj = json.loads(body.decode("utf-8"))
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


async def _wrap(fn, *args):
    """Adapt a sync node method into an awaitable run on the loop thread."""
    return fn(*args)
