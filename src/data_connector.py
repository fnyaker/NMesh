"""
Data connector — plug local applications into the mesh's DATA flow.

An external program (on the same host, or a Docker container sharing the socket)
connects, authenticates with a token, declares the **app id** of the section it
speaks on, and then exchanges end-to-end mesh messages:

    → AUTH   <app_id:APP_ID_LEN><token>
    ← AUTH_OK
    → SEND   <target_id:20><payload>      (node.send_data, framed with app_id)
    → WHOAMI
    ← WHOAMI <our_node_id:20>
    ← RECV   <src_id:20><payload>          (only for this client's app section)

This is the *data* plane (distinct from the web console, which is the management
plane). It is fully asyncio and lives on the node's event loop, so it talks to
the node directly — no threads.

Application multiplexing (see :mod:`src.app_channel`): a client's app id names a
section of the E2E DATA plane. Outgoing payloads are framed ``app_id ‖ payload``
before ``node.send_data``; inbound DATA is demultiplexed by that prefix so a
client only ever sees its own section's traffic. Management traffic never rides
the DATA plane, so it is structurally outside every app section.

Security (see CLAUDE.md): a token (constant-time compare) gates every action;
nothing is accepted before AUTH. Frames are size-capped and the client count is
bounded. A message whose section header is missing/short is dropped, never
delivered. Bind to loopback by default, or to a Unix socket (chmod 0600) for
container IPC; an ``ssl_context`` may be supplied to wrap the TCP listener.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import os
import secrets
import struct

from .app_auth import CTX_LEN, MAX_PURPOSE_LEN
from .app_channel import APP_ID_LEN, GENERIC_APP_ID, frame as _frame, unframe as _unframe
from .node_id import NodeID

_LEN = struct.Struct("!I")
_MAX_FRAME = 70_000        # 1 type byte + 20-byte id + up to ~60 KiB payload
_MAX_CLIENTS = 64
# Connections accepted but not yet authenticated. `_clients` only counts a
# client *after* AUTH, so counting that alone meant a process that never sent
# its first frame was never counted at all — and there is no deadline on a read
# that has not arrived. The socket is loopback or a Unix socket, but a container
# sharing it is an explicitly supported deployment.
_MAX_PENDING_CLIENTS = 16
_AUTH_DEADLINE = 10.0      # seconds a connection has to send its AUTH frame
# Frames queued for one client. A client that stops reading must not be able to
# hold the pump — and with it every other app's inbound delivery.
_MAX_CLIENT_QUEUE = 64

_KLEN = struct.Struct("!H")   # key-length prefix for STORE_PUT
_MAX_LIST = 60_000            # cap on a serialised key list reply
_ASSERT_HEAD = struct.Struct("!20s32sI")     # audience, ctx, ttl
_VERIFY_HEAD = struct.Struct("!B32sH")       # flags, ctx, purpose length

# client → server
_AUTH = 0x01
_SEND = 0x02
_WHOAMI = 0x03
_STORE_GET = 0x04     # body = key(utf-8)
_STORE_PUT = 0x05     # body = keylen(2) ‖ key(utf-8) ‖ value
_STORE_DEL = 0x06     # body = key(utf-8)
_STORE_LIST = 0x07    # body = empty
_APP_DHT_PUT = 0x08   # body = flag(1) ‖ keylen(2) ‖ enc_key ‖ content
_APP_DHT_GET = 0x09   # body = keylen(2) ‖ dec_key ‖ content_key(20)
_PSEUDO_MINE = 0x0A   # body = empty            — what is this node called?
_PSEUDO_LOOKUP = 0x0B # body = flags(1) ‖ query(utf-8) — find nodes by pseudo
_PSEUDO_OF = 0x0E     # body = node_id(20)*n     — what are these nodes called?
_ID_LEN = 20
_MAX_NAME_IDS = 512   # ids one resolve call may ask about (bounded, like everything)
_AUTH_ASSERT = 0x0C   # body = audience(20) ‖ ctx(32) ‖ ttl(4) ‖ purpose(utf-8)
_AUTH_VERIFY = 0x0D   # body = flags(1) ‖ ctx(32) ‖ plen(2) ‖ purpose ‖ assertion
# server → client
_AUTH_OK = 0x81
_AUTH_FAIL = 0x82
_RECV = 0x83
_WHOAMI_RESP = 0x84
_STORE_VALUE = 0x85   # body = present(1) ‖ value   (GET reply)
_STORE_OK = 0x86      # body = ok(1)                (PUT / DEL reply)
_STORE_KEYS = 0x87    # body = JSON array of keys   (LIST reply)
_APP_DHT_KEY = 0x88   # body = content_key(20) or empty on error  (PUT reply)
_APP_DHT_VALUE = 0x89 # body = present(1) ‖ content                (GET reply)
_PSEUDO_MINE_RESP = 0x8A  # body = pseudo(utf-8), empty when unnamed  (MINE reply)
_PSEUDO_RESULTS = 0x8B # body = JSON [{id, pseudo, ts, match}]     (LOOKUP reply)
_PSEUDO_NAMES = 0x8E  # body = JSON {id_hex: pseudo}              (OF reply)
_AUTH_ASSERTION = 0x8C # body = the signed assertion, or empty on refusal
_AUTH_PRINCIPAL = 0x8D # body = JSON principal, or JSON null when it fails


async def _read_frame(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    header = await reader.readexactly(_LEN.size)
    (length,) = _LEN.unpack(header)
    if length < 1 or length > _MAX_FRAME:
        raise ValueError("frame length out of bounds")
    body = await reader.readexactly(length)
    return body[0], body[1:]


async def _write_frame(writer: asyncio.StreamWriter, ftype: int, body: bytes) -> None:
    payload = bytes([ftype]) + body
    writer.write(_LEN.pack(len(payload)) + payload)
    await writer.drain()


class DataConnector:
    def __init__(self, node, *, host: str = "127.0.0.1", port: int = 0,
                 unix_path: str | None = None, token: str | None = None,
                 ssl_context=None) -> None:
        self._node = node
        self._host = host
        self.port = port
        self._unix_path = unix_path
        self._ssl = ssl_context
        self.token = token or secrets.token_urlsafe(24)
        self._token_bytes = self.token.encode("utf-8")
        # writer -> app_id: each client is bound to one app section.
        self._clients: dict[asyncio.StreamWriter, bytes] = {}
        # app_id -> AppAuth. One per section, kept so its replay cache persists
        # across frames and across a client reconnecting.
        self._auths: dict[bytes, object] = {}
        self._server: asyncio.AbstractServer | None = None
        self._pump_task: asyncio.Task | None = None
        # writer -> outbound queue + its pump task. One slow app must not stall
        # the others, so each client drains at its own pace and is dropped if it
        # falls too far behind.
        self._outbox: dict[asyncio.StreamWriter, asyncio.Queue] = {}
        self._writers: dict[asyncio.StreamWriter, asyncio.Task] = {}
        self._pending: int = 0

    @property
    def host(self) -> str:
        return self._host

    async def start(self) -> None:
        if self._unix_path:
            # 0600 from the moment it exists, not by a chmod afterwards: the
            # same window CLAUDE.md rejects for the identity file. A umask
            # around the bind is the only way to get it — a socket's mode is set
            # when it is created.
            previous = os.umask(0o177)
            try:
                self._server = await asyncio.start_unix_server(
                    self._handle_client, path=self._unix_path)
            finally:
                os.umask(previous)
            try:
                os.chmod(self._unix_path, 0o600)   # belt and braces
            except OSError:
                pass
        else:
            self._server = await asyncio.start_server(
                self._handle_client, self._host, self.port, ssl=self._ssl)
            self.port = self._server.sockets[0].getsockname()[1]
        self._pump_task = asyncio.create_task(self._pump())

    async def stop(self) -> None:
        if self._pump_task is not None:
            self._pump_task.cancel()
            try:
                await self._pump_task
            except (asyncio.CancelledError, Exception):
                pass
            self._pump_task = None
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
            self._server = None
        for task in list(self._writers.values()):
            task.cancel()
        self._writers.clear()
        self._outbox.clear()
        for w in list(self._clients):
            try:
                w.close()
            except Exception:
                pass
        self._clients.clear()
        if self._unix_path and os.path.exists(self._unix_path):
            try:
                os.unlink(self._unix_path)
            except OSError:
                pass

    async def _pump(self) -> None:
        """Demultiplex inbound mesh messages by app section to matching clients.

        Never writes to a socket itself. Writing here meant one client that had
        stopped reading blocked `drain()` and with it **every** app's inbound
        delivery, while `_data_queue` kept filling behind it. Each client has its
        own bounded queue and its own writer; a client that falls behind loses
        frames, alone.

        Never raises out, either: this task dying stopped inbound app data for
        good, with nothing to restart it."""
        while True:
            try:
                src, framed = await self._node.receive_data()
                parsed = _unframe(framed)
                if parsed is None:
                    continue  # no section header — drop (reject by default)
                app_id, payload = parsed
                body = src.raw + payload
                for w, w_app in list(self._clients.items()):
                    if w_app != app_id:
                        continue  # not this client's section
                    queue = self._outbox.get(w)
                    if queue is None:
                        continue
                    try:
                        queue.put_nowait(body)
                    except asyncio.QueueFull:
                        pass      # this client is behind; the others are not
            except asyncio.CancelledError:
                raise
            except Exception:
                continue

    async def _drain_client(self, writer: asyncio.StreamWriter,
                            queue: asyncio.Queue) -> None:
        """Write one client's frames, at that client's own pace."""
        try:
            while True:
                body = await queue.get()
                await _write_frame(writer, _RECV, body)
        except asyncio.CancelledError:
            raise
        except Exception:
            self._clients.pop(writer, None)

    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter) -> None:
        # Counted from accept, not from AUTH: a connection that never sends its
        # first frame is still a connection, and nothing else was counting it.
        if (len(self._clients) >= _MAX_CLIENTS
                or self._pending >= _MAX_PENDING_CLIENTS):
            writer.close()
            return
        self._pending += 1
        try:
            # …and it has a deadline to use it. There is no timeout on a read
            # that never arrives.
            async with asyncio.timeout(_AUTH_DEADLINE):
                ftype, body = await _read_frame(reader)
            # AUTH body = app_id(APP_ID_LEN) ‖ token. The token is compared in
            # constant time; the app id names this client's section.
            if ftype != _AUTH or len(body) < APP_ID_LEN or not hmac.compare_digest(
                    body[APP_ID_LEN:], self._token_bytes):
                await _write_frame(writer, _AUTH_FAIL, b"")
                writer.close()
                return
            app_id = body[:APP_ID_LEN]
            await _write_frame(writer, _AUTH_OK, b"")
            self._clients[writer] = app_id
            queue: asyncio.Queue = asyncio.Queue(_MAX_CLIENT_QUEUE)
            self._outbox[writer] = queue
            self._writers[writer] = asyncio.create_task(
                self._drain_client(writer, queue))
            self._pending -= 1
            while True:
                ftype, body = await _read_frame(reader)
                if ftype == _SEND:
                    if len(body) < 20:
                        continue
                    target = NodeID(body[:20])
                    try:
                        await self._node.send_data(target, _frame(app_id, body[20:]))
                    except Exception:
                        pass  # bad target / self-send — ignore, keep serving
                elif ftype == _WHOAMI:
                    await _write_frame(writer, _WHOAMI_RESP, self._node.id.raw)
                elif ftype in (_STORE_GET, _STORE_PUT, _STORE_DEL, _STORE_LIST):
                    # Local secure store. The drawer is this client's app section
                    # (app_id bound at AUTH): an app can never touch another's.
                    await self._handle_store(writer, app_id, ftype, body)
                elif ftype in (_APP_DHT_PUT, _APP_DHT_GET):
                    # Per-app DHT: same session-bound app_id names the namespace.
                    await self._handle_app_dht(writer, app_id, ftype, body)
                elif ftype in (_PSEUDO_MINE, _PSEUDO_LOOKUP, _PSEUDO_OF):
                    # Pseudos are the node's, not the app's — read-only here.
                    await self._handle_pseudo(writer, ftype, body)
                elif ftype in (_AUTH_ASSERT, _AUTH_VERIFY):
                    # App-level identity. Same rule as the drawer and the app
                    # DHT: the app id comes from the AUTH session, never the
                    # frame, so an app can only ever speak for its own section.
                    await self._handle_app_auth(writer, app_id, ftype, body)
                # unknown types are ignored
        except (asyncio.IncompleteReadError, ConnectionError, ValueError,
                OSError, asyncio.TimeoutError):
            pass
        except asyncio.CancelledError:
            raise
        finally:
            if writer not in self._outbox:
                self._pending = max(0, self._pending - 1)
            self._clients.pop(writer, None)
            self._outbox.pop(writer, None)
            task = self._writers.pop(writer, None)
            if task is not None:
                task.cancel()
            try:
                writer.close()
            except Exception:
                pass

    async def _handle_store(self, writer: asyncio.StreamWriter, app_id: bytes,
                            ftype: int, body: bytes) -> None:
        """Serve one local-store request against this client's drawer. Every
        malformed frame is dropped silently (reject by default); the node's
        AppStorage enforces all bounds and returns False on any breach."""
        if ftype == _STORE_GET:
            try:
                key = body.decode("utf-8")
            except UnicodeDecodeError:
                return
            value = self._node.app_store_get(app_id, key)
            present = b"\x01" if value is not None else b"\x00"
            await _write_frame(writer, _STORE_VALUE, present + (value or b""))
        elif ftype == _STORE_PUT:
            if len(body) < _KLEN.size:
                return
            (klen,) = _KLEN.unpack(body[:_KLEN.size])
            off = _KLEN.size
            if len(body) < off + klen:
                return
            try:
                key = body[off:off + klen].decode("utf-8")
            except UnicodeDecodeError:
                return
            ok = self._node.app_store_put(app_id, key, body[off + klen:])
            await _write_frame(writer, _STORE_OK, b"\x01" if ok else b"\x00")
        elif ftype == _STORE_DEL:
            try:
                key = body.decode("utf-8")
            except UnicodeDecodeError:
                return
            ok = self._node.app_store_delete(app_id, key)
            await _write_frame(writer, _STORE_OK, b"\x01" if ok else b"\x00")
        elif ftype == _STORE_LIST:
            keys = self._node.app_store_list(app_id)
            blob = json.dumps(keys).encode("utf-8")
            # The reply must fit one frame; hand back as many keys as fit. Apps
            # with huge key spaces should keep their own index in a value.
            while len(blob) > _MAX_LIST and keys:
                keys = keys[:len(keys) // 2]
                blob = json.dumps(keys).encode("utf-8")
            await _write_frame(writer, _STORE_KEYS, blob)

    async def _handle_app_dht(self, writer: asyncio.StreamWriter, app_id: bytes,
                              ftype: int, body: bytes) -> None:
        """Serve one per-app DHT request in this client's namespace. The app id
        comes from the session, never the frame. Any malformed frame or DHT
        error yields an empty/absent reply (reject by default), never a crash."""
        if ftype == _APP_DHT_PUT:
            if len(body) < 1 + _KLEN.size:
                return
            flag = body[0]
            (klen,) = _KLEN.unpack(body[1:1 + _KLEN.size])
            off = 1 + _KLEN.size
            if len(body) < off + klen:
                return
            enc_key = body[off:off + klen] if flag else None
            content = body[off + klen:]
            try:
                key = await self._node.app_dht_put(app_id, content, enc_key)
            except Exception:
                key = b""   # oversized / bad key — signal failure with empty key
            await _write_frame(writer, _APP_DHT_KEY, key)
        elif ftype == _APP_DHT_GET:
            if len(body) < _KLEN.size:
                return
            (klen,) = _KLEN.unpack(body[:_KLEN.size])
            off = _KLEN.size
            if len(body) < off + klen + 20:
                return
            dec_key = body[off:off + klen] if klen else None
            content_key = body[off + klen:off + klen + 20]
            try:
                content = await self._node.app_dht_get(app_id, content_key, dec_key)
            except Exception:
                content = None
            present = b"\x01" if content is not None else b"\x00"
            await _write_frame(writer, _APP_DHT_VALUE, present + (content or b""))

    def _auth_for(self, app_id: bytes):
        """The app-auth service for this section, created once and kept.

        Keeping it matters: the replay cache lives inside it, so a fresh one per
        frame would make every assertion verifiable twice."""
        auth = self._auths.get(app_id)
        if auth is None:
            auth = self._node.app_auth(app_id)
            if len(self._auths) >= _MAX_CLIENTS:
                self._auths.pop(next(iter(self._auths)), None)
            self._auths[app_id] = auth
        return auth

    async def _handle_app_auth(self, writer: asyncio.StreamWriter, app_id: bytes,
                               ftype: int, body: bytes) -> None:
        """Mint or verify an app-auth assertion for this client's section.

        The node signs only a structured statement in the app-auth domain (see
        :mod:`src.app_auth`) — never bytes the app chose — so this is an identity
        service, not a signing oracle. Every malformed frame is answered with an
        empty/negative reply rather than an error (reject by default)."""
        auth = self._auth_for(app_id)
        if ftype == _AUTH_ASSERT:
            if len(body) < _ASSERT_HEAD.size:
                await _write_frame(writer, _AUTH_ASSERTION, b"")
                return
            audience, ctx, ttl = _ASSERT_HEAD.unpack_from(body, 0)
            purpose_raw = body[_ASSERT_HEAD.size:]
            if len(purpose_raw) > MAX_PURPOSE_LEN:
                await _write_frame(writer, _AUTH_ASSERTION, b"")
                return
            try:
                blob = auth.assert_to(audience, purpose_raw.decode("utf-8"),
                                      ctx, ttl)
            except Exception:
                blob = b""      # bad purpose / ttl / audience — refuse, don't raise
            await _write_frame(writer, _AUTH_ASSERTION, blob)
        elif ftype == _AUTH_VERIFY:
            if len(body) < _VERIFY_HEAD.size:
                await _write_frame(writer, _AUTH_PRINCIPAL, b"null")
                return
            flags, ctx, plen = _VERIFY_HEAD.unpack_from(body, 0)
            off = _VERIFY_HEAD.size
            if len(body) < off + plen or plen > MAX_PURPOSE_LEN:
                await _write_frame(writer, _AUTH_PRINCIPAL, b"null")
                return
            try:
                purpose = body[off:off + plen].decode("utf-8") if plen else None
            except UnicodeDecodeError:
                await _write_frame(writer, _AUTH_PRINCIPAL, b"null")
                return
            principal = auth.verify(body[off + plen:], purpose=purpose,
                                    ctx=ctx if flags & 1 else None)
            document = None if principal is None else {
                "id": principal.node_id.raw.hex(),
                "purpose": principal.purpose,
                "ctx": principal.ctx.hex(),
                "issued_at": principal.issued_at,
                "expires_at": principal.expires_at,
            }
            await _write_frame(writer, _AUTH_PRINCIPAL,
                               json.dumps(document).encode("utf-8"))

    async def _handle_pseudo(self, writer: asyncio.StreamWriter,
                             ftype: int, body: bytes) -> None:
        """Read this node's pseudo, or search for other nodes' pseudos.

        Deliberately read-only. The pseudo is the *node's* name, shown in the
        console and used by every app, so choosing it belongs to whoever runs
        the node — not to any app that happens to hold a connector token. There
        is no frame here that renames the node, and that is the point."""
        if ftype == _PSEUDO_MINE:
            await _write_frame(writer, _PSEUDO_MINE_RESP,
                               self._node.pseudo.encode("utf-8"))
            return
        if ftype == _PSEUDO_OF:
            names = {}
            if len(body) % _ID_LEN == 0:
                for off in range(0, min(len(body), _ID_LEN * _MAX_NAME_IDS), _ID_LEN):
                    raw = body[off:off + _ID_LEN]
                    pseudo = self._node.pseudo_of(raw)
                    if pseudo:
                        names[raw.hex()] = pseudo
            await _write_frame(writer, _PSEUDO_NAMES,
                               json.dumps(names).encode("utf-8"))
            return
        # LOOKUP: flags(1) ‖ query. Bit 0 asks the network as well as the book.
        if not body:
            await _write_frame(writer, _PSEUDO_RESULTS, b"[]")
            return
        wide = bool(body[0] & 1)
        try:
            query = body[1:].decode("utf-8")
        except UnicodeDecodeError:
            await _write_frame(writer, _PSEUDO_RESULTS, b"[]")
            return
        try:
            results = (await self._node.search_pseudo(query) if wide
                       else self._node.find_pseudo(query))
        except Exception:
            results = []
        await _write_frame(writer, _PSEUDO_RESULTS,
                           json.dumps(results).encode("utf-8"))


# ---------------------------------------------------------------------------
# Client library — what an application uses to talk to the connector.
# ---------------------------------------------------------------------------

class ConnectorClient:
    """Async client for the data connector. An app connects, authenticates, and
    then sends/receives end-to-end mesh messages.

    Typically constructed with :meth:`from_env` when the node's process launcher
    started the app and injected the connection coordinates.
    """

    def __init__(self, host: str, port: int, token: str,
                 app_id: bytes = GENERIC_APP_ID) -> None:
        if len(app_id) != APP_ID_LEN:
            raise ValueError("app_id must be APP_ID_LEN bytes")
        self._host = host
        self._port = port
        self._token = token
        self._app_id = app_id
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._inbox: list[tuple[NodeID, bytes]] = []
        # One task reads the socket; everything else waits to be handed a frame.
        # See :meth:`_pump` for why there is no second reader.
        self._pump_task: asyncio.Task | None = None
        self._waiting: dict[int, list] = {}       # response type -> [futures]
        self._arrived: asyncio.Event | None = None
        self._asking: asyncio.Lock | None = None
        self._dead: Exception | None = None
        self._names: dict[str, str] = {}    # node id (hex) -> pseudo, bounded

    @classmethod
    def from_env(cls, environ=None, app_id: bytes | None = None) -> "ConnectorClient":
        e = environ if environ is not None else os.environ
        # Explicit app_id wins; else NMESH_APP_ID (hex); else the generic section.
        if app_id is None:
            app_hex = e.get("NMESH_APP_ID") if hasattr(e, "get") else None
            app_id = bytes.fromhex(app_hex) if app_hex else GENERIC_APP_ID
        return cls(e["NMESH_CONNECTOR_HOST"],
                   int(e["NMESH_CONNECTOR_PORT"]),
                   e["NMESH_CONNECTOR_TOKEN"],
                   app_id)

    async def connect(self) -> None:
        self._reader, self._writer = await asyncio.open_connection(self._host, self._port)
        await _write_frame(self._writer, _AUTH, self._app_id + self._token.encode("utf-8"))
        ftype, _ = await _read_frame(self._reader)
        if ftype != _AUTH_OK:
            raise ConnectionError("connector authentication failed")
        self._arrived = asyncio.Event()
        self._asking = asyncio.Lock()
        self._dead = None
        self._pump_task = asyncio.create_task(self._pump())

    async def _pump(self) -> None:
        """The only reader of the socket.

        Two coroutines reading one stream is a lost frame waiting to happen: an
        app sitting in :meth:`recv` would swallow the reply to a request made
        from somewhere else, and that request would then wait for a frame that
        had already been thrown away — a hang, not an error. So a single task
        reads, and hands each frame to whoever is owed it."""
        try:
            while True:
                ftype, body = await _read_frame(self._reader)
                if ftype == _RECV and len(body) >= 20:
                    self._inbox.append((NodeID(body[:20]), body[20:]))
                    self._arrived.set()
                    continue
                waiters = self._waiting.get(ftype)
                if waiters:
                    future = waiters.pop(0)
                    if not future.done():
                        future.set_result(body)
        except (asyncio.IncompleteReadError, ConnectionError, OSError, EOFError) as exc:
            self._fail(exc)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._fail(exc)

    def _fail(self, exc: Exception) -> None:
        """The link is gone: wake everyone waiting rather than leave them there."""
        self._dead = exc if isinstance(exc, Exception) else ConnectionError("connector closed")
        for waiters in self._waiting.values():
            for future in waiters:
                if not future.done():
                    future.set_exception(self._dead)
        self._waiting.clear()
        if self._arrived is not None:
            self._arrived.set()

    async def whoami(self) -> NodeID:
        return NodeID(await self._roundtrip(_WHOAMI, b"", _WHOAMI_RESP))

    async def send(self, target: NodeID, payload: bytes) -> None:
        await _write_frame(self._writer, _SEND, target.raw + payload)

    # -- local secure store (this app's drawer) ---------------------------
    #
    # The drawer is keyed by the app id this client authenticated with; the node
    # supplies it, so these calls never name another app's section.

    async def _roundtrip(self, req_type: int, req_body: bytes,
                         resp_type: int) -> bytes:
        """Ask the connector one question and wait for its answer.

        Replies carry no request id, so they can only be matched by order: the
        lock keeps one question in flight at a time, and the pump hands the
        answer to the future registered here."""
        if self._dead is not None:
            raise self._dead
        if self._asking is None:
            raise ConnectionError("connector client is not connected")
        async with self._asking:
            if self._dead is not None:
                raise self._dead
            future = asyncio.get_event_loop().create_future()
            self._waiting.setdefault(resp_type, []).append(future)
            try:
                await _write_frame(self._writer, req_type, req_body)
                return await future
            finally:
                waiters = self._waiting.get(resp_type)
                if waiters and future in waiters:
                    waiters.remove(future)

    async def store_put(self, key: str, value: bytes) -> bool:
        kb = key.encode("utf-8")
        body = _KLEN.pack(len(kb)) + kb + value
        resp = await self._roundtrip(_STORE_PUT, body, _STORE_OK)
        return bool(resp) and resp[0] == 1

    async def store_get(self, key: str) -> bytes | None:
        resp = await self._roundtrip(_STORE_GET, key.encode("utf-8"), _STORE_VALUE)
        if not resp or resp[0] != 1:
            return None
        return resp[1:]

    async def store_delete(self, key: str) -> bool:
        resp = await self._roundtrip(_STORE_DEL, key.encode("utf-8"), _STORE_OK)
        return bool(resp) and resp[0] == 1

    async def store_list(self) -> list[str]:
        resp = await self._roundtrip(_STORE_LIST, b"", _STORE_KEYS)
        try:
            keys = json.loads(resp.decode("utf-8"))
        except Exception:
            return []
        return [k for k in keys if isinstance(k, str)] if isinstance(keys, list) else []

    # -- per-app DHT (this app's shared namespace) ------------------------
    #
    # The app supplies content and, for private entries, the encryption key; the
    # node namespaces by this client's app id and does the DHT-level crypto.

    async def dht_put(self, content: bytes, enc_key: bytes | None = None) -> bytes | None:
        """Publish an entry on the app's DHT. ``enc_key`` present → private.
        Returns the 20-byte content key, or None if the node refused it."""
        flag = 1 if enc_key is not None else 0
        key = enc_key or b""
        body = bytes([flag]) + _KLEN.pack(len(key)) + key + content
        resp = await self._roundtrip(_APP_DHT_PUT, body, _APP_DHT_KEY)
        return resp if len(resp) == 20 else None

    async def dht_get(self, content_key: bytes, dec_key: bytes | None = None) -> bytes | None:
        """Fetch an app DHT entry by its content key. ``dec_key`` is required for
        private entries. Returns the content, or None if absent/undecryptable."""
        key = dec_key or b""
        body = _KLEN.pack(len(key)) + key + content_key
        resp = await self._roundtrip(_APP_DHT_GET, body, _APP_DHT_VALUE)
        if not resp or resp[0] != 1:
            return None
        return resp[1:]

    # -- pseudos (read-only: the node's name is the operator's to choose) --

    async def my_pseudo(self) -> str:
        """What our own node is called, or "" when it has no pseudo."""
        resp = await self._roundtrip(_PSEUDO_MINE, b"", _PSEUDO_MINE_RESP)
        try:
            return resp.decode("utf-8")
        except UnicodeDecodeError:
            return ""

    async def pseudos_of(self, ids) -> dict:
        """The pseudos of a set of node ids (hex strings or bytes), as
        ``{id_hex: pseudo}``. Ids with no known name are simply absent — a
        caller shows the id, which is what it should show anyway."""
        body = bytearray()
        for one in list(ids)[:_MAX_NAME_IDS]:
            raw = bytes.fromhex(one) if isinstance(one, str) else bytes(one)
            if len(raw) == _ID_LEN:
                body += raw
        resp = await self._roundtrip(_PSEUDO_OF, bytes(body), _PSEUDO_NAMES)
        try:
            out = json.loads(resp.decode("utf-8"))
        except Exception:
            return {}
        return {k: v for k, v in out.items()
                if isinstance(k, str) and isinstance(v, str)} if isinstance(out, dict) else {}

    def name_of(self, id_hex) -> str:
        """The last name we read for a node id, or "". Synchronous on purpose:
        this is what a UI thread calls while rendering a list, and a round trip
        per row would be absurd."""
        if isinstance(id_hex, (bytes, bytearray)):
            id_hex = bytes(id_hex).hex()
        return self._names.get(id_hex, "")

    async def refresh_names(self, ids) -> dict:
        """Re-read the names of ``ids`` from the node and cache them.

        One cache, filled from one place, shared by every app on this client:
        the alternative is each app keeping its own idea of what a node is
        called, which is the thing pseudos exist to stop."""
        wanted = [i.hex() if isinstance(i, (bytes, bytearray)) else str(i)
                  for i in ids][:_MAX_NAME_IDS]
        if not wanted:
            return {}
        names = await self.pseudos_of(wanted)
        for id_hex in wanted:
            found = names.get(id_hex)
            if found:
                self._names[id_hex] = found
            else:
                self._names.pop(id_hex, None)   # renamed to nothing, or gone
        while len(self._names) > _MAX_NAME_IDS:
            self._names.pop(next(iter(self._names)))
        return names

    async def lookup_pseudo(self, query: str, *, wide: bool = False) -> list[dict]:
        """Find nodes by pseudo, whole or partial, best match first.

        Returns ``[{"id": hex, "pseudo": str, "ts": int, "match": int}, …]`` —
        several, because pseudos are not unique; ``id`` is the real identity.
        ``wide`` also asks the network for an exact match, which costs a round
        of queries: leave it off for search-as-you-type."""
        body = bytes([1 if wide else 0]) + query.encode("utf-8")
        resp = await self._roundtrip(_PSEUDO_LOOKUP, body, _PSEUDO_RESULTS)
        try:
            out = json.loads(resp.decode("utf-8"))
        except Exception:
            return []
        return [x for x in out if isinstance(x, dict)] if isinstance(out, list) else []

    # -- app identity (this app's section) --------------------------------
    #
    # The node signs a structured statement in the app-auth domain, bound to the
    # app id this client authenticated with. An app therefore proves "this node,
    # inside *this* app, to *that* audience, for *this* purpose" — and can never
    # mint a statement for another section, nor get arbitrary bytes signed.
    # See Docs/AppAuth/guide.

    async def assert_to(self, audience: NodeID | bytes, purpose: str,
                        ctx: bytes = b"\x00" * CTX_LEN,
                        ttl: int = 120) -> bytes | None:
        """Mint a signed assertion naming our node. None if the node refused it
        (bad purpose, ttl or audience)."""
        raw = audience.raw if isinstance(audience, NodeID) else bytes(audience)
        body = (_ASSERT_HEAD.pack(raw, bytes(ctx), int(ttl))
                + purpose.encode("utf-8"))
        blob = await self._roundtrip(_AUTH_ASSERT, body, _AUTH_ASSERTION)
        return blob or None

    async def verify_assertion(self, blob: bytes, *, purpose: str | None = None,
                               ctx: bytes | None = None) -> dict | None:
        """Verify a peer's assertion addressed to us. Returns the principal
        (``{id, purpose, ctx, issued_at, expires_at}``) or None on any failure —
        wrong app, wrong audience, wrong purpose, stale, replayed, or forged."""
        encoded = purpose.encode("utf-8") if purpose else b""
        body = (_VERIFY_HEAD.pack(1 if ctx is not None else 0,
                                  bytes(ctx) if ctx is not None else b"\x00" * CTX_LEN,
                                  len(encoded))
                + encoded + blob)
        resp = await self._roundtrip(_AUTH_VERIFY, body, _AUTH_PRINCIPAL)
        try:
            document = json.loads(resp.decode("utf-8"))
        except Exception:
            return None
        return document if isinstance(document, dict) else None

    async def recv(self) -> tuple[NodeID, bytes]:
        while True:
            if self._inbox:
                return self._inbox.pop(0)
            if self._dead is not None:
                raise self._dead
            self._arrived.clear()
            await self._arrived.wait()

    async def close(self) -> None:
        if self._pump_task is not None:
            self._pump_task.cancel()
            try:
                await self._pump_task
            except (asyncio.CancelledError, Exception):
                pass
            self._pump_task = None
        self._fail(ConnectionError("connector client closed"))
        if self._writer is not None:
            try:
                self._writer.close()
            except Exception:
                pass
            self._writer = None
