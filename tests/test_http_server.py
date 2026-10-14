"""
A client that connects and says nothing must not be able to stop the console.

The console listens on a socket wrapped for TLS, and a wrapped listening socket
handshakes inside ``accept()``: one silent connection held the only accepting
thread, and every other request waited behind it for as long as it stayed. These
tests are written from what an unauthenticated client can do, not from the code
that handles it — connect and be silent, connect in numbers, hang up mid-request.
"""
import asyncio
import pathlib
import re
import socket

import pytest

import src.http_server as http_server
import src.webconsole as webconsole
from src.http_server import HardenedServer
from src.node import MeshNode
from src.webconsole import WebConsole
from tests.conftest import make_manager
from tests.test_webconsole import PW, _request


async def _tls_console():
    node = MeshNode(transport_manager=make_manager())
    console = WebConsole(node, host="127.0.0.1", port=0, use_tls=True, password=PW)
    console.start(loop=asyncio.get_running_loop())
    return node, console


async def _page(console, wait: float = 5.0):
    return await asyncio.wait_for(
        asyncio.to_thread(_request, console, "GET", "/", None, tls=True), wait)


def _silent(console) -> socket.socket:
    return socket.create_connection(("127.0.0.1", console.port), timeout=5)


def _closed_within(sock: socket.socket, seconds: float) -> bool:
    sock.settimeout(seconds)
    try:
        return sock.recv(1) == b""
    except ConnectionError:
        return True
    except OSError:
        return False


class TestASilentClient:
    async def test_does_not_stop_anybody_else_being_served(self):
        node, console = await _tls_console()
        held = [_silent(console) for _ in range(3)]
        try:
            status, *_ = await _page(console)
            assert status == 200
        finally:
            for sock in held:
                sock.close()
            console.stop()
            await node.stop()

    async def test_is_let_go_after_the_timeout(self, monkeypatch):
        monkeypatch.setattr(webconsole, "CONNECTION_TIMEOUT", 0.4)
        node, console = await _tls_console()
        sock = _silent(console)
        try:
            assert await asyncio.to_thread(_closed_within, sock, 5.0)
        finally:
            sock.close()
            console.stop()
            await node.stop()


class TestManyClients:
    async def test_past_the_ceiling_a_new_connection_is_closed_unserved(self, monkeypatch):
        monkeypatch.setattr(http_server, "MAX_CONNECTIONS", 3)
        node, console = await _tls_console()
        held = [_silent(console) for _ in range(3)]
        try:
            await asyncio.sleep(0.3)             # let each one take its slot
            extra = _silent(console)
            assert await asyncio.to_thread(_closed_within, extra, 3.0)
            extra.close()
        finally:
            for sock in held:
                sock.close()
        try:
            await asyncio.sleep(0.5)             # their slots come back
            status, *_ = await _page(console)
            assert status == 200
        finally:
            console.stop()
            await node.stop()


class TestOneClientCannotTakeEverySlot:
    async def test_the_others_are_still_served(self, monkeypatch):
        """The whole point of a per-address bound: the total ceiling alone turns
        one client's unfinished requests into the console being down."""
        import http.client
        import ssl
        monkeypatch.setattr(http_server, "MAX_PER_ADDRESS", 3)
        node, console = await _tls_console()
        held = [_silent(console) for _ in range(3)]
        try:
            await asyncio.sleep(0.3)
            extra = _silent(console)             # a fourth from the same address
            assert await asyncio.to_thread(_closed_within, extra, 3.0)
            extra.close()

            def from_another_address():
                ctx = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(
                    "127.0.0.1", console.port, timeout=5, context=ctx,
                    source_address=("127.0.0.2", 0))
                conn.request("GET", "/")
                return conn.getresponse().status
            status = await asyncio.wait_for(asyncio.to_thread(from_another_address), 6)
            assert status == 200
        finally:
            for sock in held:
                sock.close()
            console.stop()
            await node.stop()


class TestAClientThatHangsUp:
    def _raise(self, server, exc):
        try:
            raise exc
        except Exception:
            server.handle_error(None, ("127.0.0.1", 1))

    def test_is_not_written_to_stderr(self, capsys):
        server = HardenedServer(("127.0.0.1", 0), webconsole.BaseHTTPRequestHandler)
        try:
            for exc in (ConnectionResetError(), BrokenPipeError(), TimeoutError(),
                        EOFError()):
                self._raise(server, exc)
        finally:
            server.server_close()
        assert capsys.readouterr().err == ""

    def test_a_real_fault_still_is(self, capsys):
        server = HardenedServer(("127.0.0.1", 0), webconsole.BaseHTTPRequestHandler)
        try:
            self._raise(server, ValueError("a bug"))
        finally:
            server.server_close()
        assert "ValueError" in capsys.readouterr().err


def test_every_http_server_in_the_tree_is_the_hardened_one():
    """The three servers share what is above. A fourth, or a return to the bare
    class, would bring the silent client back."""
    root = pathlib.Path(__file__).resolve().parent.parent / "src"
    offenders = []
    for path in root.rglob("*.py"):
        if path.name == "http_server.py":
            continue
        text = path.read_text(encoding="utf-8")
        if re.search(r"ThreadingHTTPServer\s*\(|ThreadingHTTPServer,", text) \
                or re.search(r"import[^\n]*ThreadingHTTPServer", text):
            offenders.append(str(path.relative_to(root)))
    assert offenders == []


def test_every_handler_sets_a_timeout():
    root = pathlib.Path(__file__).resolve().parent.parent / "src"
    for name in ("webconsole.py", "apps/chat_web.py", "apps/mcp.py"):
        text = (root / name).read_text(encoding="utf-8")
        assert "timeout = CONNECTION_TIMEOUT" in text, name


class TestTheCiphersOffered:
    async def _handshake(self, console, version, ciphers):
        import ssl

        def connect():
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = version
            if ciphers:
                ctx.set_ciphers(ciphers)
            with socket.create_connection(("127.0.0.1", console.port), timeout=5) as raw:
                with ctx.wrap_socket(raw) as tls:
                    return tls.cipher()[0]
        return await asyncio.to_thread(connect)

    async def test_tls_1_2_offers_forward_secrecy_with_an_aead_and_nothing_else(self):
        import ssl
        node, console = await _tls_console()
        try:
            assert "GCM" in await self._handshake(console, ssl.TLSVersion.TLSv1_2,
                                                  "ECDHE+AESGCM")
            for weak in ("AES256-SHA", "ECDHE+AES256+SHA", "AES128-SHA256", "AES256-GCM-SHA384"):
                with pytest.raises(ssl.SSLError):
                    await self._handshake(console, ssl.TLSVersion.TLSv1_2,
                                          weak + ":@SECLEVEL=0")
        finally:
            console.stop()
            await node.stop()

    async def test_tls_1_3_is_still_served(self):
        import ssl
        node, console = await _tls_console()
        try:
            assert await self._handshake(console, ssl.TLSVersion.TLSv1_3, None)
        finally:
            console.stop()
            await node.stop()
