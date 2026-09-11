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
from collections import OrderedDict
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from . import app_api
from . import control
from .control import listing
from . import updater
from . import console_auth
from .control.modules.settings import write_settings
from .webassets import (NODE_HTML, NODE_JS, NODE_CSS,
                        PKG_HTML, PKG_JS, PKG_CSS,
                        INDEX_HTML, APP_JS, STYLE_CSS, CHAT_HTML, CHAT_JS,
                        CHAT_CSS, FLEET_HTML, FLEET_JS, FLEET_CSS,
                        TERM_HTML, TERM_JS, TERM_CSS)
from .webassets.ui import FAVICON_SVG, THEME_JS
from .apps.fleet import (console_path_refusal as fleet_console_refusal,
                         FileTransferError as FleetFileError)
from .apps.fleet_console import REPLAY_HEADER

# The page names the node it is driving with this header. Absent (or naming us)
# means "this node", which is what a page that has never heard of contexts does.
_REMOTE_HEADER = "X-NMesh-Node"

# The control channel's one route. Everything the management plane carries goes
# through here as a frame (`src/control/frame.py`), whichever node it is for:
# the header above decides whether this console answers it or relays it, and
# that is the only difference between managing this machine and managing
# another. The routes beside it are what has not moved onto the plane yet —
# `Docs/Architecture/control-plane.md` keeps the ledger.
CONTROL_PATH = "/api/control"

# A refusal's code, in HTTP. The plane speaks codes because it is reached over
# more than one channel (a page here, a peer through the fleet relay), and a
# status number is this channel's word for what happened — so the translation
# lives at this door and nowhere else.
_STATUS_BY_CODE = {
    "bad_request": 400,
    "unauthorized": 401,
    "refused": 403,
    "not_found": 404,
    "conflict": 409,
    "unavailable": 503,
    "failed": 500,
}
# And back, for the one caller that has a status and needs a code: the relay to
# another node, when what came back was not a frame at all (no session there, a
# node that never answered) and has to be phrased as a refusal anyway.
_CODE_BY_STATUS = {status: code for code, status in _STATUS_BY_CODE.items()}
# The relay's own failures, which have no forward mapping because nothing here
# ever *answers* a gateway status — it only ever reads one. A node that never
# answered comes back as 502, and calling that `failed` told a page "something
# went wrong over there" when what happened is that there is no over there:
# a console driving a machine that has gone stayed pointed at it, looking alive
# and showing nothing.
_CODE_BY_STATUS.update({502: "unavailable", 504: "unavailable"})


def _is_node_hex(value) -> bool:
    return (isinstance(value, str) and len(value) == 40
            and all(c in "0123456789abcdef" for c in value))


def _safe_filename(name) -> str:
    """A name fit for a ``Content-Disposition`` header.

    It comes off a machine somebody else runs, so it decides nothing here: a
    quote or a newline in it would end the header and start writing whatever
    followed as another one. Kept to plain characters, and never empty."""
    cleaned = "".join(ch for ch in str(name)[:100]
                      if ch.isalnum() or ch in "._- ()[]").strip()
    return cleaned or "download"

_MAX_BODY = 64 * 1024
_MAX_APP_BODY = 4 * 1024 * 1024   # larger cap for app publish uploads
_MAX_CHAT_UPLOAD = 64 * 1024 * 1024   # chat file/avatar uploads (base64)
_MAX_KEY_UPLOAD = 128 * 1024          # one private key, generously bounded
# One file pushed to a managed node. `fleet_files.MAX_TRANSFER` (32 MiB) is what
# actually crosses the mesh; this is that, base64-encoded, plus the JSON around
# it — so an oversized body is refused by the socket rather than after a decode.
_MAX_FILE_UPLOAD = 46 * 1024 * 1024
_APP_CALL_TIMEOUT = 60.0          # DHT publish/fetch can touch several peers
_TOKEN_TTL = 3600.0            # session idle lifetime, seconds
_LOGIN_MAX_FAILURES = 5
_LOGIN_LOCKOUT = 60.0          # seconds locked after too many failures
# Password checks allowed to run at once. One scrypt is 16 MiB and a slice of
# CPU by design, so a burst of parallel logins costs the node far more than it
# costs whoever sent them.
_LOGIN_MAX_INFLIGHT = 4
_CALL_TIMEOUT = 10.0          # max seconds to wait on a loop-marshalled call
# Asking the directory is a Kademlia lookup plus a query to every target, and
# the node bounds the whole round itself — this only has to be the larger of the
# two, or the console would give up on an answer the node was about to hand it.
_PKG_LOOKUP_TIMEOUT = 30.0
# What a list may be asked for, from the one place that decides it
# (`src/control/listing.py`) — this door parses a query string, it does not get
# to have its own opinion about how long a query may be.
_LIST_DEFAULT_LIMIT = listing.DEFAULT_LIMIT
_LIST_MAX_LIMIT = listing.MAX_LIMIT
_LIST_MAX_QUERY = listing.MAX_QUERY
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


# ---------------------------------------------------------------------------
# Changes, coalesced
# ---------------------------------------------------------------------------

class _Changes:
    """What moved, and a way to wait for the next thing that does.

    The node calls :meth:`note` on its receive loop, the moment a link comes up
    or goes down. So this side has to cost a set and a notify — never a
    snapshot, never a socket: whoever is streaming reads the state afterwards,
    on its own thread.

    A sequence number rather than a queue per listener. A listener remembers
    where it was and asks for what has changed since; a burst of forty link
    events between two reads is one answer naming one topic, which is exactly
    what a page wants — it is going to re-read the same list either way.
    """

    # Topics are a closed set from one file (`MeshNode._note_change`), but the
    # dictionary is bounded anyway: an unbounded map keyed by something another
    # module chooses is the shape of the bug, whoever writes the keys today.
    MAX_TOPICS = 32

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._seq = 0
        self._at: "OrderedDict[str, int]" = OrderedDict()
        self._closed = False

    @property
    def seq(self) -> int:
        with self._cond:
            return self._seq

    def note(self, topic) -> None:
        topic = str(topic)[:32]
        with self._cond:
            if self._closed:
                return
            self._seq += 1
            self._at.pop(topic, None)
            self._at[topic] = self._seq
            while len(self._at) > self.MAX_TOPICS:
                self._at.popitem(last=False)
            self._cond.notify_all()

    def since(self, seq: int, timeout: float):
        """``(topics, seq)`` — what changed after ``seq``, waiting up to
        ``timeout`` seconds for the first of it. Empty on timeout, and on
        close, so a caller's loop ends rather than spinning."""
        deadline = time.monotonic() + max(0.0, timeout)
        with self._cond:
            while self._seq <= seq and not self._closed:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return [], self._seq
                self._cond.wait(remaining)
            if self._closed:
                return [], self._seq
            return (sorted(name for name, at in self._at.items() if at > seq),
                    self._seq)

    @property
    def closed(self) -> bool:
        with self._cond:
            return self._closed

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()


# One stream wakes at most this often, however many changes arrive in between:
# ten repaints a second reads as instant, and a hundred is a page that fights
# the pointer while saying nothing new.
_STREAM_FRAME = 0.1
# Nothing happened for this long → a comment down the wire. It keeps a proxy
# from reaping an idle connection, and it is how a stream notices the client
# went away without ever telling us: a page that reloaded is a socket nobody
# closed on this side, and it is the *write* that finds out. Short enough that
# a few reloads in a row do not park several dead streams against the ceiling.
_STREAM_PING = 10.0
# Streams held at once. Each one is a thread of the console's server for as
# long as a page is open, so it is bounded like everything else here — with
# room for the pages of a couple of browsers plus whatever a reload left
# behind for a ping or two.
_MAX_STREAMS = 16


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
        # What the node says has moved, and the streams reading it. The console
        # subscribes on start() and unsubscribes on stop(): a listener left
        # hooked to a node whose console is gone is a reference nothing drops.
        self._changes = _Changes()
        self._streams = 0
        self._streams_lock = threading.Lock()

        # The management plane, and the context the modules on it act through.
        # Built here rather than at the first request: what this node can be
        # asked to do must not depend on whether anybody has asked yet, and a
        # module whose declaration is wrong should fail to *start* the console
        # rather than to answer one call (`src/control/plane.py`).
        self._control_context = control.Context(
            node=node, config_path=config_path, apps=self._apps,
            changes=self._changes, api=lambda: self._api,
            host=lambda: self._app_host, restart=self.restart)
        self._plane = control.build(self._control_context)

        # Sessions: token -> expiry monotonic deadline.
        self._tokens: dict[str, float] = {}
        self._tokens_lock = threading.Lock()

        # Login throttling. Under its own lock: the HTTP server is threaded, so
        # without one every concurrent attempt passes `_locked_out()` before any
        # of them records a failure, and `+= 1` loses increments — turning "5
        # failures then 60 s" into "as many parallel attempts as the attacker
        # opens". Each of those attempts is one scrypt (16 MiB and a slice of
        # CPU), so it is a work lever as much as a throttle bypass.
        self._fail_count = 0
        self._lockout_until = 0.0
        self._login_lock = threading.Lock()
        # Password checks running right now. scrypt is deliberately expensive,
        # so the count of them in flight is its own bound: without it a burst of
        # parallel logins is a memory and CPU lever regardless of the lockout.
        self._attempts_in_flight = 0

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
        cert_pem, key_pem, loaded = self._load_or_create_cert()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        # load_cert_chain needs files; use a temp dir only if we have no state dir.
        import tempfile
        d = self._state_dir or tempfile.mkdtemp(prefix="nmesh-console-")
        cert_path = os.path.join(d, "console_cert.pem")
        key_path = os.path.join(d, "console_key.pem")
        if not loaded:
            # Both, or neither. Writing each only "if it does not exist" meant a
            # state directory with the certificate but no key kept the stale
            # certificate and wrote a fresh key beside it — a mismatched pair,
            # and a console that fails to start with an opaque TLS error.
            self._write_private(cert_path, cert_pem)
            self._write_private(key_path, key_pem)
        ctx.load_cert_chain(cert_path, key_path)
        self.cert_fingerprint = hashlib.sha256(
            ssl.PEM_cert_to_DER_cert(cert_pem.decode())
        ).hexdigest()
        return ctx

    @staticmethod
    def _write_private(path: str, data: bytes) -> None:
        """Create 0600 at open time, not by a chmod afterwards — the private
        half of a TLS pair must never exist world-readable, however briefly
        (the rule CLAUDE.md states for the identity file)."""
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)

    def _load_or_create_cert(self) -> tuple[bytes, bytes, bool]:
        """``(cert, key, loaded_from_disk)``."""
        if self._state_dir:
            cp = os.path.join(self._state_dir, "console_cert.pem")
            kp = os.path.join(self._state_dir, "console_key.pem")
            if os.path.exists(cp) and os.path.exists(kp):
                with open(cp, "rb") as f:
                    cert_pem = f.read()
                with open(kp, "rb") as f:
                    key_pem = f.read()
                return cert_pem, key_pem, True
        cert_pem, key_pem = _generate_self_signed(self.host)
        return cert_pem, key_pem, False

    # -- token sessions ---------------------------------------------------

    def _issue_token(self) -> str:
        token = secrets.token_urlsafe(32)
        with self._tokens_lock:
            self._tokens[token] = time.monotonic() + _TOKEN_TTL
            self._gc_tokens()
        return token

    def issue_session_for_grant(self) -> str:
        """Mint a session for an operator the *fleet ledger* already authorised.

        The only place a console session is created without a password, and it
        exists because of a machine nobody can type one on: a node this operator
        provisioned generated its password on first start and printed it to a
        log the operator never read. The password is not the authority here —
        the grant is, and it was given by a human on this machine (capability
        ``passwordless``, see :mod:`src.apps.fleet_state`).

        This is deliberately **not** reachable over HTTP: the caller is the
        fleet app running in this process, which has already verified the mesh
        session, the ledger entry and a fresh signature over the request. A
        route would turn all three into one bearer token on a socket."""
        return self._issue_token()

    def revoke_session_for_grant(self, token: str) -> None:
        """End a session issued above, when the grant behind it is taken back."""
        if isinstance(token, str) and token:
            self._revoke_token(token)

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

    def _begin_login(self) -> bool:
        """Claim one attempt, or refuse. Deciding and counting happen under the
        same lock, so parallel attempts cannot all slip through the gap between
        them."""
        with self._login_lock:
            if time.monotonic() < self._lockout_until:
                return False
            self._attempts_in_flight += 1
            if self._attempts_in_flight > _LOGIN_MAX_INFLIGHT:
                self._attempts_in_flight -= 1
                return False
            return True

    def _locked_out(self) -> bool:
        with self._login_lock:
            return time.monotonic() < self._lockout_until

    def _record_login_result(self, ok: bool) -> None:
        with self._login_lock:
            self._attempts_in_flight = max(0, self._attempts_in_flight - 1)
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

    def _note_awake(self, source: str) -> None:
        """Tell the node somebody is here, from the server thread.

        Handed over rather than written here: the awake book is the node's and
        is only ever touched on its loop. Fire-and-forget and never raises — a
        page must not fail because the node is on its way down."""
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        try:
            loop.call_soon_threadsafe(self._node.note_awake, source)
        except RuntimeError:
            pass

    @property
    def open_streams(self) -> int:
        """Change streams held open right now — one per page listening.

        A page with its interval turned off asks for nothing until something
        moves, so the requests alone would have it stop counting as somebody
        after `_MLO_AWAKE_TTL`. The connection it is holding is the state that
        says otherwise."""
        with self._streams_lock:
            return self._streams

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

    def _update_branch(self) -> str:
        """Which branch *this* node follows for updates, or "" for releases.

        Read from this console's own configuration file rather than from
        wherever the default would be: a node started with ``--config``
        elsewhere must not be told what some other file says."""
        return updater.update_branch(self._config_path)

    @property
    def _api(self) -> "app_api.AppAPI":
        """The app API surface, over whatever is running right now.

        Built per access rather than held: an app stopped a second ago must not
        still be reachable through a reference this object kept."""
        return app_api.AppAPI(self._app_host)

    def _persist_setting(self, name: str, value) -> bool:
        """Remember one live toggle in the configuration file.

        Best effort: a node with no file still applies the change to the
        running process, it just will not remember it — the toggle never
        depends on this working. The write itself is the config module's, so
        this file has one fewer copy of "load, merge, save"."""
        return write_settings(self._config_path, {name: value})[0]

    def start(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        self._loop = loop or asyncio.get_event_loop()
        self._control_context.bind_loop(self._loop)
        # A page holding the change stream open is somebody here for as long as
        # it holds it — the *state* half of what the node's awake book takes,
        # the requests below being the moments. See `MeshNode.hold_awake`.
        hold = getattr(self._node, "hold_awake", None)
        if hold is not None:
            hold("console stream", lambda: self.open_streams > 0)
        if self._app_host is not None:
            self._app_host.bind_console(self._loop)
        elif self._chat_bridge is not None:
            self._chat_bridge.start(self._loop)
        self._node.set_change_listener(self._changes.note)
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

    # -- the control channel ----------------------------------------------
    #
    # Two channels, one plane, and the choice between them is the whole of what
    # "managing another node" means here. Nothing above this decides anything:
    # a page asks for `node.state`, and which machine answers is which channel
    # carried the frame (`Docs/Architecture/control-plane.md`).

    def local_channel(self, origin: str = control.Origin.LOCAL):
        """This node's plane. ``origin`` is never the caller's to choose — the
        request handler knows where the frame came from and says so."""
        return control.LocalChannel(self._plane, origin)

    def remote_channel(self, session: str, node_hex: str):
        """The same channel, pointed at a node this operator manages."""
        return control.RemoteChannel(node_hex, self._control_relay(session))

    def _control_relay(self, session: str):
        """How a frame reaches another node: the fleet's ``manage`` capability,
        replaying it against that node's console exactly as a browser there
        would (:mod:`src.apps.fleet_console`).

        The relay is a pipe and translates only failures *of the pipe*: an
        answer that came back is the far node's plane speaking for itself, and
        is handed on untouched."""
        def relay(node_hex: str, frame: bytes) -> bytes:
            fleet = self._fleet
            if fleet is None:
                raise control.ControlError("conflict",
                                           "the fleet app is not running")
            status, _ctype, payload = fleet.remote_call(
                session, node_hex, "POST", CONTROL_PATH, frame)
            if 200 <= int(status) < 300:
                return payload
            # Not a frame: the relay itself refused (no session on that node,
            # a node that never answered). Phrased as one, with the code the
            # status meant, so a page reads one shape of answer whatever went
            # wrong. `unauthorized` here is *that* node's session, never ours —
            # which is why this never travels as an HTTP 401 to the page.
            note = _parse_json(payload) or {}
            message = note.get("error") if isinstance(note.get("error"), str) else ""
            return control.encode({
                "v": 1, "id": "", "ok": False,
                "code": _CODE_BY_STATUS.get(int(status), "failed"),
                "error": message or "that node could not be reached"})
        return relay

    # -- restarting --------------------------------------------------------
    #
    # Two callers, one mechanism: an update, which only takes effect when the
    # node starts again on the tree that was just written, and an operator who
    # asked for a restart outright.
    #
    # Two ways back, and `updater.restart_plan` picks between them. With a
    # supervisor (`NMESH_SERVICE_MANAGED`) the node exits and is started again —
    # the whole process image goes, which is the cleanest thing an update can
    # ask for. Without one it **re-execs itself**: `os.execv` is not an exit, it
    # replaces this process with a fresh interpreter on the same command line,
    # keeping the pid and the terminal. That is what a phone needs — Android has
    # no init a package can reach, so a node under Termux with no
    # `termux-services` used to install an update and then sit on it until
    # somebody reopened the app and typed the command again.

    _RESTART_DELAY = 1.0        # let the operator's response reach them first

    def _restart_worker(self, mode: str) -> None:
        """Stop the node properly, then come back. Never returns on success."""
        time.sleep(self._RESTART_DELAY)
        try:
            if self._loop is not None and not self._loop.is_closed():
                # Bounded: a peer refusing to close must not keep the old code
                # running for ever, which is the thing we are here to end.
                asyncio.run_coroutine_threadsafe(
                    self._node.stop(), self._loop).result(timeout=20.0)
        except Exception:
            pass                # going down regardless; state writes are bounded
        if mode == updater.RESTART_REEXEC:
            try:
                updater.reexec()
            except Exception:
                # The exec failed and this image is still here — with a node
                # that has been stopped. Leaving is then the honest outcome:
                # staying up would serve a console attached to nothing.
                pass
        os._exit(0)

    def restart(self) -> bool:
        """Come back running the code that is on disk now.

        Returns whether a restart was scheduled. When neither route is
        available — no supervisor, and nothing this process can re-exec — the
        node stays up and the console says so, rather than leaving an operator
        with a node that never came back."""
        mode, _launch, _reason = updater.restart_plan()
        if not mode:
            return False
        threading.Thread(target=self._restart_worker, args=(mode,), daemon=True,
                         name="nmesh-restart").start()
        return True

    def stop(self) -> None:
        # Before the socket: a stream waiting on the condition would otherwise
        # sit there until its next ping, holding a thread against a console that
        # has already gone.
        try:
            self._node.set_change_listener(None)
        except Exception:
            pass
        self._changes.close()
        drop = getattr(self._node, "drop_awake", None)
        if drop is not None:
            drop("console stream")   # a console that has stopped holds nothing
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
    # One package, described — the same rule: a view before it is a page.
    "/package": ("text/html; charset=utf-8", PKG_HTML),
    "/package.js": ("application/javascript; charset=utf-8", PKG_JS),
    "/package.css": ("text/css; charset=utf-8", PKG_CSS),
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
    # The terminal with the whole screen. Same session, same right, opened in a
    # tab of its own because that is what a terminal on a phone needs.
    "/term": ("text/html; charset=utf-8", TERM_HTML),
    "/term.js": ("application/javascript; charset=utf-8", TERM_JS),
    "/term.css": ("text/css; charset=utf-8", TERM_CSS),
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

        def _query(self, name: str):
            """One query-string value, or None when it was not given."""
            if "?" not in self.path:
                return None
            values = parse_qs(self.path.split("?", 1)[1]).get(name)
            return values[0] if values else None

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
            if not console._valid_token(self._session_token()):
                return False
            # A request carrying this console's session is a page open, and
            # that — not `/api/state` alone — is what "somebody is using this
            # node" means: the chat and fleet pages never ask for the node's
            # state, so waking on that one route left a console open on chat
            # looking like an empty room.
            #
            # Except a call a peer is replaying through the fleet's `manage`
            # right: that is a page on *their* machine, and waking this node
            # must not be something the network can do to it. The marker can
            # only ever ask for less, so nothing that can set it gains
            # anything by lying (`fleet_console.REPLAY_HEADER`).
            if not self.headers.get(REPLAY_HEADER):
                console._note_awake("console")
            return True

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

        # -- the control channel -------------------------------------------
        #
        # One route for the whole management plane, and one decision in it:
        # which channel the frame goes down. Everything else — what the
        # operation is, what it may be given, whether a remote console may ask
        # for it at all — belongs to the plane, declared next to the module
        # that answers it (`Docs/Architecture/control-plane.md`).

        def _control_channel(self):
            """The channel this request is for, and the origin it speaks as."""
            remote = self._remote_node()
            if remote:
                return console.remote_channel(self._session_token() or "", remote)
            # A call a peer is replaying through the fleet's `manage` right is a
            # page on *their* machine, so it reaches the plane as a remote
            # origin — which is what turns "what may the network ask of this
            # node?" into one `remote=True` per operation, in a list this node
            # keeps about itself (`fleet_console.REPLAY_HEADER`).
            origin = (control.Origin.REMOTE if self.headers.get(REPLAY_HEADER)
                      else control.Origin.LOCAL)
            return console.local_channel(origin)

        def _handle_control(self, body) -> None:
            """One frame in, one frame out.

            **The status describes the console you asked; the frame describes
            the node you asked about.** So a refusal from a *managed* node comes
            back as a 200 carrying a refusal: that node's session expiring must
            not read to this page as its own session expiring, which is what an
            HTTP 401 means to every client we have — and what used to sign an
            operator out of their own console when a remote one dropped them."""
            channel = self._control_channel()
            answer = channel.send(body or b"")
            if channel.target:
                self._send(200, "application/json; charset=utf-8", answer)
                return
            reply = control.decode_reply(answer)
            self._send(200 if reply.ok
                       else _STATUS_BY_CODE.get(reply.code, 500),
                       "application/json; charset=utf-8", answer)

        def _from_plane(self, op: str, params=None) -> None:
            """Answer one of the older routes from the plane.

            The route stays because things call it — a page nobody has
            rewritten, a script, a `curl` in a runbook — but it is not a second
            implementation: it asks the plane exactly what a frame would and
            unwraps the answer into the shape that route always had."""
            if not self._authed():
                self._json(401, {"error": "unauthorized"})
                return
            reply = self._control_channel().call(op, params or {})
            if reply.ok:
                self._json(200, reply.result)
                return
            # A refusal's structured half travels under the keys the module
            # chose, beside the sentence — which is the shape these routes
            # always had (`{"error": …, "rejected": […]}`).
            self._json(_STATUS_BY_CODE.get(reply.code, 500),
                       {"error": reply.error, **reply.detail})

        # -- routing --

        def do_GET(self) -> None:
            self._answering(self._get)

        def do_POST(self) -> None:
            self._answering(self._post)

        def _answering(self, handler) -> None:
            """Run a request handler, and **always answer**.

            An unhandled exception here does not become a 500 on its own: it
            unwinds through `handle_one_request`, which sends nothing and closes
            the socket. A page that asked sees a connection drop, not an error —
            so a skeleton stays on screen for ever and the bug reads as "it
            loads infinitely", which says nothing about where it is.

            That is exactly what happened: a value that was not JSON-serialisable
            reached `_json`, `json.dumps` raised, and the package page spun. The
            answer is a floor under every route rather than a `try` around the
            one that failed."""
            try:
                handler()
            except Exception:
                # Nothing about the failure travels: an exception's text is our
                # internals, and this is answered before anybody has proved
                # anything on some routes.
                try:
                    self._json(500, {"error": "the console could not answer"})
                except Exception:
                    self.close_connection = True

        def _get(self) -> None:
            path = self.path.split("?", 1)[0]
            remote = self._remote_node()
            if remote is not None:
                if not self._authed():
                    self._json(401, {"error": "unauthorized"})
                    return
                if not remote:
                    self._json(400, {"error": "bad node id"})
                    return
                if path == "/api/events":
                    # A connection held open is not a thing the relay carries:
                    # it moves one bounded request and its answer. Saying so is
                    # what lets a page fall back to its cadence rather than
                    # waiting on a stream that will never speak.
                    self._json(409, {"error": "a change stream is local to the "
                                              "console serving it"})
                    return
                self._proxy_remote(remote, self.path, None)
                return
            if path == "/api/remote/targets":
                self._handle_remote_targets()
                return
            if path == "/api/events":
                self._stream_changes()
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
                self._from_plane("node.state")
                return
            if path == "/api/app-api":
                # What a page may offer. Authenticated like everything else:
                # the list of what an operator could do is itself worth
                # knowing, and this console does not answer strangers.
                self._from_plane("apps.catalogue")
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
                self._from_plane("releases.check")
                return
            if path == "/api/releases":
                self._from_plane("releases.overview")
                return
            if path == "/api/pseudo":
                # `q` searches; without it, this is "what am I called?". And
                # `wide` is a different question rather than a louder one — it
                # asks the directory, which costs a Kademlia round, so it is a
                # named operation with its own ceiling (`pseudo.lookup`).
                query = self._query("q")
                if query is None:
                    self._from_plane("pseudo.get")
                elif self._query("wide") == "1":
                    self._from_plane("pseudo.lookup", {"query": query})
                else:
                    self._from_plane("pseudo.search", {"query": query})
                return
            if path == "/api/config":
                self._from_plane("config.get")
                return
            if path == "/api/transports":
                self._from_plane("transports.options")
                return
            if path == "/api/trace":
                self._from_plane("trace.status",
                                 {"events": self._query("events") == "1"})
                return
            if path == "/api/trace/export":
                self._handle_trace_export()
                return
            if path == "/api/rootcert":
                self._from_plane("node.rootcert")
                return
            if path == "/api/store":
                self._from_plane("store.overview")
                return
            if path == "/api/keys":
                self._from_plane("keys.overview")
                return
            if path == "/api/packages":
                self._handle_packages_get()
                return
            if path.startswith("/api/packages/"):
                self._handle_package_get(path[len("/api/packages/"):])
                return
            self._json(404, {"error": "not found"})

        # -- the package directory ----------------------------------------
        #
        # There is no catalogue to list, which is the point: an unlisted
        # directory is one nobody can flood with entries nobody asked for. You
        # ask it a question — this name, or this node — and it answers.

        def _handle_packages_get(self) -> None:
            """Ask the directory: by name, or about one node.

            `wide` is a different question rather than a louder one — it costs a
            Kademlia round plus a query to every target — so it is its own
            operation with its own ceiling, and a keystroke never triggers it.
            """
            node = self._query("node")
            query = self._query("q")
            if self._query("wide") == "1":
                self._from_plane("packages.lookup",
                                 {"query": query or "", "node": node or ""})
            elif node is not None:
                self._from_plane("packages.held", {"node": node})
            elif query:
                self._from_plane("packages.search", {"query": query})
            else:
                self._json(400, {"error": "q or node required"})

        def _handle_package_get(self, rest: str) -> None:
            if not self._authed():
                self._json(401, {"error": "unauthorized"})
                return
            record_id, _, action = rest.partition("/")
            if action not in ("", "download"):
                self._json(404, {"error": "not found"})
                return
            if action == "download":
                # The bytes an operator wants to open by hand before trusting
                # anything: every one of them checked against a hash the author
                # signed, and served as an opaque download (nosniff) rather than
                # anything a browser might decide to render.
                try:
                    fetched = console._call(
                        console._node.fetch_package(record_id),
                        timeout=_APP_CALL_TIMEOUT)
                except Exception:
                    self._json(503, {"error": "the package could not be fetched"})
                    return
                if fetched is None:
                    self._json(404, {"error": "not found"})
                    return
                _entry, blob, name = fetched
                self._send_binary(blob, name)
                return
            self._from_plane(
                "packages.describe" if self._query("fetch") == "1"
                else "packages.entry", {"record": record_id})

        def _handle_list_get(self, path: str) -> None:
            """The older paged lists, in their query-string spelling.

            The parsing is this door's — a query string is HTTP's idea, not the
            plane's — and everything after it belongs to the operation that
            answers: the sort, the filter, the page and the bounds
            (`src/control/listing.py`)."""
            try:
                scope, query, limit, offset = _parse_list_query(
                    self.path, nodes=path == "/api/nodes")
            except ValueError:
                self._json(400, {"error": "invalid query"})
                return
            params = {"query": query, "limit": limit, "offset": offset}
            if path == "/api/nodes":
                self._from_plane("node.list", {"scope": scope, **params})
            else:
                self._from_plane("store.list", {
                    "scope": "catalog" if path.endswith("/catalog")
                    else "installed", **params})

        def do_HEAD(self) -> None:
            self.do_GET()

        def _post(self) -> None:
            path = self.path.split("?", 1)[0]
            if path in ("/api/app/publish", "/api/store/publish"):
                cap = _MAX_APP_BODY
            elif path in ("/api/chat/file", "/api/chat/profile"):
                cap = _MAX_CHAT_UPLOAD
            elif path == "/api/fleet/upload":
                cap = _MAX_FILE_UPLOAD
            elif path == "/api/fleet/keys":
                cap = _MAX_KEY_UPLOAD
            else:
                cap = _MAX_BODY
            remote = self._remote_node()
            # The session is checked before a large body is read into memory.
            # The upload caps are generous — 64 MiB for a chat file — and the
            # server is threaded with no ceiling on connections, so reading
            # first meant any stranger who could reach the port could hold that
            # much per request. /api/login is the one route that must read its
            # (small) body before it can possibly be authorised.
            if path != "/api/login" or remote is not None:
                if not self._authed():
                    self.close_connection = True
                    self._json(401, {"error": "unauthorized"})
                    return
            elif cap > _MAX_BODY:
                cap = _MAX_BODY
            body = self._read_body(cap)
            if body is None:
                self._json(413, {"error": "body too large or malformed"})
                return
            if path == "/api/login" and remote is None:
                self._handle_login(body)
                return
            if path == CONTROL_PATH:
                # Before the relay below, deliberately: a control frame is not
                # proxied *by path* like the older routes — the channel itself
                # decides whether it answers here or travels, which is what
                # makes remote management one decision instead of a denylist of
                # prefixes.
                self._handle_control(body)
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
                self._from_plane("join.invite")
                return
            if path == "/api/trust":
                data = _parse_json(body) or {}
                self._from_plane("trust.add", {"cert": data.get("cert_hex", "")})
                return
            if path.startswith("/api/trust/"):
                data = _parse_json(body) or {}
                # One name per route, and the plane spells the middle one with
                # an underscore like every other operation.
                action = path.rsplit("/", 1)[1].replace("-", "_")
                params = {"node": data.get("node", "")}
                if action == "revoke":
                    params["reason"] = _number(data.get("reason"))
                if action == "witness":
                    params["remove"] = bool(data.get("remove"))
                self._from_plane("trust." + action, params)
                return
            if path == "/api/ticket":
                data = _parse_json(body) or {}
                self._from_plane("join.ticket", {"ttl": _number(data.get("ttl"))})
                return
            if path == "/api/join":
                data = _parse_json(body) or {}
                # A ticket is the same join, with the address and the code
                # travelling together; the operation decodes it.
                self._from_plane("join.network", {
                    "uri": data.get("uri") or "",
                    "code": data.get("code") or "",
                    "ticket": data.get("ticket") or ""})
                return
            if path == "/api/reachability/probe":
                self._from_plane("network.probe")
                return
            if path == "/api/ping":
                self._from_plane("node.ping")
                return
            if path == "/api/ping/node":
                # These routes name the node `id`; the plane calls it what it
                # is everywhere else. One translation, at the door.
                self._from_plane("node.ping_node",
                                 {"node": (_parse_json(body) or {}).get("id", "")})
                return
            if path == "/api/nodes/forget":
                self._from_plane("node.forget",
                                 {"node": (_parse_json(body) or {}).get("id", "")})
                return
            if path == "/api/peers/retry":
                data = _parse_json(body) or {}
                self._from_plane("node.retry", {"node": data.get("id", ""),
                                                "uri": data.get("uri", "")})
                return
            if path == "/api/addressing/balance":
                data = _parse_json(body) or {}
                self._from_plane("network.balance",
                                 {"value": data.get("value")})
                return
            if path == "/api/addressing/dynamic":
                data = _parse_json(body) or {}
                self._from_plane("network.dynamic",
                                 {"enabled": data.get("enabled")})
                return
            if path == "/api/mlo":
                # Two settings and two shapes on purpose: "always on" is a
                # yes/no an operator flips, the other two are numbers a bundle
                # is judged on. Which *media* may be bundled is not here at all
                # — that is the transport's own `mlo` option, because only the
                # medium knows what a probe ten times a second costs on it.
                data = _parse_json(body)
                if not isinstance(data, dict):
                    self._json(400, {"error": "object required"})
                    return
                self._from_plane("network.mlo", {
                    name: data[name] for name in
                    ("always", "skew_ms", "drop_percent", "keepalive_fast_min",
                     "keepalive_fast_max", "keepalive_slow_min",
                     "keepalive_slow_max") if name in data})
                return
            if path == "/api/lan/discovery":
                data = _parse_json(body) or {}
                self._from_plane("network.discovery",
                                 {"enabled": data.get("enabled")})
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
                self._from_plane("join.block")
                return
            if path == "/api/join/block":
                data = _parse_json(body) or {}
                self._from_plane("join.use_block",
                                 {"block": data.get("block") or ""})
                return
            if path == "/api/punch":
                data = _parse_json(body) or {}
                self._from_plane("network.punch",
                                 {"enabled": data.get("enabled")})
                return
            if path == "/api/punch/keepalive":
                data = _parse_json(body) or {}
                self._from_plane("network.punch_keepalive",
                                 {"enabled": data.get("enabled")})
                return
            if path == "/api/punch/open":
                data = _parse_json(body) or {}
                host, port = data.get("host"), data.get("port")
                # "ip:port" in a single field is accepted here, where the form
                # that offers it lives — the operation takes the two it needs.
                if port is None and isinstance(data.get("endpoint"), str):
                    from .ip_utils import split_host_port
                    pair = split_host_port(data["endpoint"].strip())
                    if pair is not None:
                        host, port = pair[0], _number(pair[1])
                self._from_plane("network.punch_open",
                                 {"host": host if host is not None else "",
                                  "port": port if port is not None else 0})
                return
            if path == "/api/udp":
                data = _parse_json(body) or {}
                params = {"action": data.get("action") or ""}
                if data.get("port") is not None:
                    params["port"] = data["port"]
                self._from_plane("network.udp", params)
                return
            if path == "/api/listen":
                data = _parse_json(body) or {}
                self._from_plane("network.listen", {"uri": data.get("uri", "")})
                return
            if path == "/api/unlisten":
                data = _parse_json(body) or {}
                self._from_plane("network.unlisten", {"uri": data.get("uri", "")})
                return
            if path == "/api/net/recheck":
                self._from_plane("network.recheck")
                return
            if path == "/api/app-call":
                data = _parse_json(body) or {}
                self._from_plane("apps.call", {"app": data.get("app") or "",
                                               "op": data.get("op") or "",
                                               "args": data.get("args") or {}})
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
                data = _parse_json(body) or {}
                # ``id`` is the registry key; ``name`` is accepted as the older
                # spelling so a caller written against either keeps working.
                self._from_plane("apps.set",
                                 {"app": data.get("id") or data.get("name") or "",
                                  "action": path.rsplit("/", 1)[1]})
                return
            if path == "/api/update/apply":
                data = _parse_json(body) or {}
                self._from_plane("releases.apply",
                                 {"version": data.get("version") or "",
                                  "confirm": data.get("confirm") is True})
                return
            if path == "/api/restart":
                data = _parse_json(body) or {}
                self._from_plane("node.restart",
                                 {"confirm": data.get("confirm") is True})
                return
            if path.startswith("/api/releases/"):
                self._handle_release_post(path, _parse_json(body))
                return

            if path.startswith("/api/packages/"):
                self._handle_package_post(path, _parse_json(body))
                return
            if path.startswith("/api/keys/"):
                self._handle_key_post(path, _parse_json(body))
                return
            if path == "/api/pseudo":
                data = _parse_json(body) or {}
                self._from_plane("pseudo.save", {"pseudo": data.get("pseudo", "")})
                return
            if path == "/api/config":
                data = _parse_json(body) or {}
                self._from_plane("config.save",
                                 {"settings": data.get("settings") or {}})
                return
            if path == "/api/transports":
                data = _parse_json(body) or {}
                self._from_plane("transports.save",
                                 {"scheme": data.get("scheme") or "",
                                  "values": data.get("values") or {}})
                return
            if path == "/api/trace":
                data = _parse_json(body) or {}
                self._from_plane("trace.set", {
                    "action": data.get("action") or "",
                    "seconds": _number(data.get("seconds")),
                    "events": _number(data.get("events"))})
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
                data = _parse_json(body) or {}
                self._from_plane("store." + path.rsplit("/", 1)[1],
                                 {"app": data.get("app_id") or ""})
                return
            self._json(404, {"error": "not found"})

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

        def _handle_trace_export(self) -> None:
            """The trace as a file.

            The one migrated route that is not a plain unwrap: the *answer* is
            the same document the plane returns, but it is served as an opaque
            download rather than as JSON a page reads — a trace is routing
            metadata and has no business being rendered inline by the browser."""
            if not self._authed():
                self._json(401, {"error": "unauthorized"})
                return
            reply = self._control_channel().call("trace.export")
            if not reply.ok:
                self._json(_STATUS_BY_CODE.get(reply.code, 500),
                           {"error": reply.error})
                return
            self._send_binary(
                json.dumps(reply.result, indent=1).encode("utf-8"),
                "nmesh-trace.json")

        def _handle_key_post(self, path: str, data) -> None:
            """Making, offering, accepting and forgetting a publisher key.

            One translation per route. The rule the operations carry is the one
            these had to repeat: a passphrase is typed at the machine that will
            hold the key, so none of this is reachable from a console managing
            this node — only the overview is
            (`src/control/modules/keys.py`)."""
            data = data if isinstance(data, dict) else {}
            action = path.rsplit("/", 1)[1]
            label = data.get("label")
            label = label if isinstance(label, str) else ""

            def secret(name):
                """A passphrase passed through exactly as typed, or not at all:
                the field is never trimmed, and a `null` is not an empty one."""
                value = data.get(name)
                return {name: value} if isinstance(value, str) else {}

            if action == "create":
                self._from_plane("keys.create",
                                 {"label": label, **secret("passphrase")})
            elif action == "import":
                self._from_plane("keys.adopt",
                                 {"path": data.get("path") or "",
                                  "label": label, **secret("passphrase")})
            elif action == "offer":
                self._from_plane("keys.offer", {
                    "node": data.get("node") or "",
                    "key": data.get("key_id") or "",
                    "confirm": data.get("confirm") is True,
                    "label": label, **secret("passphrase")})
            elif action == "accept":
                self._from_plane("keys.accept", {
                    "offer": data.get("offer_id") or "",
                    "confirm": data.get("confirm") is True,
                    **secret("passphrase")})
            elif action == "refuse":
                self._from_plane("keys.refuse",
                                 {"offer": data.get("offer_id") or ""})
            elif action == "forget":
                self._from_plane("keys.forget",
                                 {"key": data.get("key_id") or "",
                                  "confirm": data.get("confirm") is True})
            else:
                self._json(404, {"error": "not found"})

        def _handle_package_post(self, path: str, data) -> None:
            """Installing, pinning and subscribing from a package record.

            One translation per route. What the operations own — and what this
            used to spell out three times — is that the publisher key comes from
            *inside the record*, checked against the signature it made, so
            pinning is a confirmation of a record rather than a hex string
            copied from a channel nobody could vouch for."""
            data = data if isinstance(data, dict) else {}
            record = data.get("id")
            record = record if isinstance(record, str) else ""
            action = path.rsplit("/", 1)[1]
            if action == "install":
                self._from_plane("packages.install",
                                 {"record": record,
                                  "confirm": data.get("confirm") is True})
            elif action == "trust":
                self._from_plane("packages.trust", {
                    "record": record, "confirm": data.get("confirm") is True,
                    "auto": data.get("auto") is True,
                    "endorsed": data.get("endorsed") is True})
            elif action == "subscribe":
                quorum = data.get("quorum")
                self._from_plane("packages.subscribe", {
                    "record": record,
                    "on": data.get("on") is not False,
                    "auto": data.get("auto") is True,
                    "quorum": quorum if isinstance(quorum, int)
                    and not isinstance(quorum, bool) else 1})
            else:
                self._json(404, {"error": "not found"})

        def _handle_release_post(self, path: str, data) -> None:
            """Publishing, pinning and installing mesh-native releases.

            One translation per route and nothing else: these carried their own
            validation, their own error mapping and their own idea of what a
            publisher id is. The operations own all three now
            (`src/control/modules/releases.py`); what is left here is the older
            spelling of each argument."""
            data = data if isinstance(data, dict) else {}
            action = path.rsplit("/", 1)[1]
            if action == "publish":
                params = {"notes": data.get("notes") or "",
                          "key_id": data.get("key_id") or ""}
                # Absent rather than null: naming a field is saying you meant
                # to set it, so `{"passphrase": null}` is a value the field
                # cannot take — while *not* sending one is "there is no
                # passphrase", which is what an unlocked key means.
                if data.get("passphrase") is not None:
                    params["passphrase"] = data["passphrase"]
                self._from_plane("releases.publish", params)
            elif action == "install":
                self._from_plane("releases.install", {
                    "release": data.get("release") or "",
                    "confirm": data.get("confirm") is True})
            elif action == "trust":
                self._from_plane("releases.trust", {
                    "key": str(data.get("key") or "").strip(),
                    "name": data.get("name") or "",
                    "auto": data.get("auto") is True,
                    "endorsed": data.get("endorsed") is True})
            elif action == "untrust":
                self._from_plane("releases.untrust",
                                 {"publisher": data.get("publisher_id") or ""})
            elif action == "auto":
                self._from_plane("releases.auto", {
                    "publisher": data.get("publisher_id") or "",
                    "auto": data.get("auto") is True})
            elif action == "endorse":
                self._from_plane("releases.endorse", {
                    "publisher": data.get("publisher_id") or "",
                    "endorsed": data.get("endorsed") is True})
            else:
                self._json(404, {"error": "not found"})

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
                node = (query.get("node") or [""])[0]
                # A page that has just asked for a shell knows the node, not the
                # session: the open answers asynchronously. Naming the node is
                # how a terminal draws itself without polling the whole ledger.
                if not sid and node:
                    sid = console._fleet.newest_shell(node)
                    if not sid:
                        self._json(404, {"error": "no session"})
                        return
                data = console._fleet.shell_data(sid, _int_param(query, "offset", 0))
                self._json(200 if data else 404, data or {"error": "no session"})
                return
            if path in ("/api/fleet/files", "/api/fleet/file"):
                self._handle_files_get(path, query)
                return
            if path == "/api/fleet/keys":
                # Paths and comments of local SSH keys — never key material.
                self._json(200, {"keys": console._fleet.local_keys()})
                return
            self._json(404, {"error": "not found"})

        def _handle_files_get(self, path: str, query: dict) -> None:
            """Browsing and downloading, under the ``shell`` right.

            Two routes and one reason for the split: a listing is JSON a page
            redraws, a file is bytes a browser saves. Serving both from one
            route would mean guessing which one the caller wanted."""
            node = (query.get("node") or [""])[0]
            if not _is_node_hex(node):
                self._json(400, {"error": "bad node id"})
                return
            target = (query.get("path") or [""])[0]
            try:
                if path == "/api/fleet/files":
                    self._json(200, console._fleet.files_list(node, target))
                    return
                name, data = console._fleet.files_download(node, target)
            except FleetFileError as exc:
                self._json(502, {"error": str(exc)[:200]})
                return
            except TimeoutError:
                self._json(504, {"error": "that node did not answer in time"})
                return
            except Exception as exc:            # noqa: BLE001 — never leak a trace
                self._json(500, {"error": f"that failed ({type(exc).__name__})"})
                return
            # Named on the way out, and only ever as an attachment: a file from
            # somebody else's machine is not something this page should render.
            self._send(200, "application/octet-stream", data, [
                ("Content-Disposition",
                 "attachment; filename=\"%s\"" % _safe_filename(name))])

        # -- remote consoles ---------------------------------------------

        # -- the change stream ---------------------------------------------
        #
        # The console used to ask "has anything changed?" on a timer. At two
        # seconds a link that came up was invisible for two seconds; at a tenth
        # of a second it was two hundred questions a minute answered "no". This
        # inverts it: the node says when something moved and the page reads only
        # then, so a link appears the moment it does.
        #
        # Only *that* something moved is sent — never what it is. The page reads
        # the state it already knows how to read; a second description of a node
        # travelling down a second channel is two things to keep in step.
        #
        # This one is local by construction. It is a connection held open, and
        # the fleet console relay is a bounded request and its answer, not a
        # stream; a page driving another node keeps its cadence instead, and
        # says so.

        def _stream_changes(self) -> None:
            if not self._authed():
                self._json(401, {"error": "unauthorized"})
                return
            with console._streams_lock:
                if console._streams >= _MAX_STREAMS:
                    self._json(503, {"error": "too many open streams"})
                    return
                console._streams += 1
            try:
                self._run_stream()
            finally:
                with console._streams_lock:
                    console._streams -= 1

        def _run_stream(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            # No length, so the body ends when the connection does. Announcing
            # that here is what makes it legal under HTTP/1.1 — and it is what
            # tells this handler not to try to read a second request off a
            # socket that is going to stay busy for hours.
            self.send_header("Connection", "close")
            for key, value in _SECURITY_HEADERS.items():
                self.send_header(key, value)
            self.end_headers()
            seq = console._changes.seq
            try:
                # Says the stream is live before anything has moved, so a page
                # can stop its timer on evidence rather than on hope.
                self._emit("ready", {"at": time.time()})
                while console._server is not None:
                    topics, seq = console._changes.since(seq, _STREAM_PING)
                    if not topics:
                        if console._changes.closed:
                            return
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                        continue
                    self._emit("change", {"topics": topics, "at": time.time()})
                    # Hold the frame open rather than answering each event: the
                    # next pass picks up everything that piled up meanwhile, in
                    # one message. Ten a second, whatever the mesh is doing.
                    time.sleep(_STREAM_FRAME)
            except (BrokenPipeError, ConnectionResetError, OSError, ValueError):
                return          # the page went away; nothing to report

        def _emit(self, name: str, document: dict) -> None:
            self.wfile.write(
                f"event: {name}\ndata: {json.dumps(document)}\n\n".encode("utf-8"))
            self.wfile.flush()

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
                if password is not None and not isinstance(password, str):
                    self._json(400, {"error": "the password must be text"})
                    return
                # No password is a request, not an omission: the bridge checks
                # that the node actually granted `passwordless` and refuses
                # otherwise, so an empty field cannot become a way in.
                ok, detail = fleet.remote_connect(session, node, password or None)
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
                elif action == "invite":
                    # The answer *is* the invitation, so this one waits for it
                    # rather than handing back a request id and leaving the
                    # page to poll for a secret it must show once.
                    result = fleet.api_invite(node, data.get("ttl") or 0,
                                              data.get("ticket") is True)
                    self._json(200 if not result.get("error") else 502, result)
                elif action == "scan":
                    # ``targets`` mixes subnets and precise machines; ``subnets``
                    # is accepted as the older spelling of the same field.
                    targets = data.get("targets") or data.get("subnets")
                    if node and node != fleet.me:
                        self._json(200, {"rid": fleet.scan(node, targets)})
                    else:
                        self._json(200, fleet.scan_local(targets))
                elif action == "mkdir":
                    self._json(200, fleet.files_mkdir(
                        node, str(data.get("path") or "")[:4096],
                        str(data.get("name") or "")[:255]))
                elif action == "upload":
                    self._handle_file_upload(fleet, node, data)
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
            except FleetFileError as exc:
                # The far node refused, or never answered. Not this console
                # failing, and an operator has to be able to tell them apart.
                self._json(502, {"error": str(exc)[:200]})
            except ValueError:
                self._json(400, {"error": "bad request"})
            except Exception as exc:
                self._json(503, {"error": str(exc)[:200]})

        def _handle_file_upload(self, fleet, node: str, data) -> None:
            """Push one file onto a node that granted ``shell``.

            The bytes arrive base64-encoded in the request body, like a chat
            attachment: one request, one file, and a cap on it, because the
            console holds the whole thing while it slices it onto the mesh."""
            raw = _b64_field(data.get("data"), _MAX_FILE_UPLOAD)
            if raw is None:
                self._json(400, {"error": "no file in that request"})
                return
            name = str(data.get("name") or "")[:255]
            if not name:
                self._json(400, {"error": "a name is required"})
                return
            self._json(200, fleet.files_upload(
                node, str(data.get("path") or "")[:4096], name, raw))

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
                # On unless the operator turned it off: a machine nobody will
                # log into again is a machine that has to be able to update
                # itself, and it can only be told whose code to take now.
                auto_update=data.get("auto_update", True) is not False,
                join_uris=data.get("join_uris"),
                join_code=data.get("join_code"),
            )
            if node and node != fleet.me:
                self._json(200, {"rid": fleet.provision(node, targets, **kwargs)})
            else:
                self._json(200, {"results": fleet.provision_local(targets, **kwargs)})

        # -- built-in apps (install / enable) -----------------------------

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
                elif path == "/api/chat/profile":
                    bio = data["bio"] if isinstance(data.get("bio"), str) else None
                    avatar = None
                    if isinstance(data.get("avatar"), str):
                        avatar = base64.b64decode(data["avatar"], validate=True)
                    chat.set_profile(bio=bio, avatar=avatar)
                    self._json(200, {"ok": True})
                elif path == "/api/chat/contact":
                    op = data.get("op", "add")
                    if op == "remove":
                        ok = chat.remove_contact(data.get("id", ""))
                    else:
                        ok = chat.add_contact(data.get("id", ""))
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
                notes = data.get("notes")
                info = console._call(
                    console._node.publish_store_app(
                        data["name"], data["version"], files,
                        notes=notes if isinstance(notes, str) else ""),
                    timeout=_APP_CALL_TIMEOUT)
                self._json(200, {"ok": True, **info})
            except Exception as exc:
                self._json(400, {"ok": False, "error": str(exc)[:200]})

        def _handle_login(self, body: bytes) -> None:
            if not console._begin_login():
                self._json(429, {"error": "too many attempts, locked out"})
                return
            try:
                data = _parse_json(body)
                password = (data or {}).get("password")
                ok = bool(password) and console._check_password(password)
            except BaseException:
                console._record_login_result(False)
                raise
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


def _b64_field(value, limit: int = _MAX_BODY) -> bytes | None:
    """Decode a base64 field from a request body. Terminal input is bytes, not
    text, so it travels base64-encoded; anything undecodable is refused.

    ``limit`` is the encoded length this field may have. It defaults to the
    ordinary body cap — a field that may be a whole file passes its own, and
    passing it here rather than after the decode is what keeps a hostile field
    from being expanded before it is refused."""
    if not isinstance(value, str) or len(value) > limit:
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


# Adapting a sync node method into an awaitable run on the loop thread. The
# plane's modules need exactly this and defined it first, so this is that one
# rather than a second spelling of it (`src/control/context.py`).
_wrap = control.on_loop
