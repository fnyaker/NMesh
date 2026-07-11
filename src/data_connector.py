"""
Data connector — plug local applications into the mesh's DATA flow.

An external program (on the same host, or a Docker container sharing the socket)
connects, authenticates with a token, and then speaks a tiny length-prefixed
protocol to send and receive end-to-end mesh messages:

    → AUTH   token
    ← AUTH_OK
    → SEND   <target_id:20><payload>      (node.send_data)
    → WHOAMI
    ← WHOAMI <our_node_id:20>
    ← RECV   <src_id:20><payload>          (node.receive_data, pushed)

This is the *data* plane (distinct from the web console, which is the management
plane). It is fully asyncio and lives on the node's event loop, so it talks to
the node directly — no threads.

Security (see CLAUDE.md): a token (constant-time compare) gates every action;
nothing is accepted before AUTH. Frames are size-capped and the client count is
bounded. Bind to loopback by default, or to a Unix socket (chmod 0600) for
container IPC; an ``ssl_context`` may be supplied to wrap the TCP listener.
"""
from __future__ import annotations

import asyncio
import hmac
import os
import secrets
import struct

from .node_id import NodeID

_LEN = struct.Struct("!I")
_MAX_FRAME = 70_000        # 1 type byte + 20-byte id + up to ~60 KiB payload
_MAX_CLIENTS = 64

# client → server
_AUTH = 0x01
_SEND = 0x02
_WHOAMI = 0x03
# server → client
_AUTH_OK = 0x81
_AUTH_FAIL = 0x82
_RECV = 0x83
_WHOAMI_RESP = 0x84


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
        self._clients: set[asyncio.StreamWriter] = set()
        self._server: asyncio.AbstractServer | None = None
        self._pump_task: asyncio.Task | None = None

    @property
    def host(self) -> str:
        return self._host

    async def start(self) -> None:
        if self._unix_path:
            self._server = await asyncio.start_unix_server(
                self._handle_client, path=self._unix_path)
            try:
                os.chmod(self._unix_path, 0o600)
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
        """Deliver inbound mesh messages to every authenticated client."""
        while True:
            src, payload = await self._node.receive_data()
            body = src.raw + payload
            for w in list(self._clients):
                try:
                    await _write_frame(w, _RECV, body)
                except Exception:
                    self._clients.discard(w)

    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter) -> None:
        if len(self._clients) >= _MAX_CLIENTS:
            writer.close()
            return
        try:
            ftype, body = await _read_frame(reader)
            if ftype != _AUTH or not hmac.compare_digest(body, self._token_bytes):
                await _write_frame(writer, _AUTH_FAIL, b"")
                writer.close()
                return
            await _write_frame(writer, _AUTH_OK, b"")
            self._clients.add(writer)
            while True:
                ftype, body = await _read_frame(reader)
                if ftype == _SEND:
                    if len(body) < 20:
                        continue
                    target = NodeID(body[:20])
                    try:
                        await self._node.send_data(target, body[20:])
                    except Exception:
                        pass  # bad target / self-send — ignore, keep serving
                elif ftype == _WHOAMI:
                    await _write_frame(writer, _WHOAMI_RESP, self._node.id.raw)
                # unknown types are ignored
        except (asyncio.IncompleteReadError, ConnectionError, ValueError, OSError):
            pass
        except asyncio.CancelledError:
            raise
        finally:
            self._clients.discard(writer)
            try:
                writer.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Client library — what an application uses to talk to the connector.
# ---------------------------------------------------------------------------

class ConnectorClient:
    """Async client for the data connector. An app connects, authenticates, and
    then sends/receives end-to-end mesh messages.

    Typically constructed with :meth:`from_env` when the node's process launcher
    started the app and injected the connection coordinates.
    """

    def __init__(self, host: str, port: int, token: str) -> None:
        self._host = host
        self._port = port
        self._token = token
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._inbox: list[tuple[NodeID, bytes]] = []

    @classmethod
    def from_env(cls, environ=None) -> "ConnectorClient":
        e = environ if environ is not None else os.environ
        return cls(e["NMESH_CONNECTOR_HOST"],
                   int(e["NMESH_CONNECTOR_PORT"]),
                   e["NMESH_CONNECTOR_TOKEN"])

    async def connect(self) -> None:
        self._reader, self._writer = await asyncio.open_connection(self._host, self._port)
        await _write_frame(self._writer, _AUTH, self._token.encode("utf-8"))
        ftype, _ = await _read_frame(self._reader)
        if ftype != _AUTH_OK:
            raise ConnectionError("connector authentication failed")

    async def whoami(self) -> NodeID:
        await _write_frame(self._writer, _WHOAMI, b"")
        while True:
            ftype, body = await _read_frame(self._reader)
            if ftype == _WHOAMI_RESP:
                return NodeID(body)
            if ftype == _RECV and len(body) >= 20:
                self._inbox.append((NodeID(body[:20]), body[20:]))  # buffer data

    async def send(self, target: NodeID, payload: bytes) -> None:
        await _write_frame(self._writer, _SEND, target.raw + payload)

    async def recv(self) -> tuple[NodeID, bytes]:
        if self._inbox:
            return self._inbox.pop(0)
        while True:
            ftype, body = await _read_frame(self._reader)
            if ftype == _RECV and len(body) >= 20:
                return NodeID(body[:20]), body[20:]

    async def close(self) -> None:
        if self._writer is not None:
            try:
                self._writer.close()
            except Exception:
                pass
            self._writer = None
