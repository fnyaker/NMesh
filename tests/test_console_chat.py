"""
Console-hosted chat sub-page.

The built-in chat app is surfaced by the web console at /chat, reusing the
console's bearer-token auth. These check that the page is served, that the
chat API sits behind auth, that sends flow through the chat app, and that the
Apps list advertises it — and that with no bridge attached, none of it exists.
"""
import asyncio

import pytest

from src.node import MeshNode
from src.webconsole import WebConsole
from src.apps.chat import ChatApp, TextMessage
from src.apps.chat_web import ChatBridge
from src.node_id import NodeID
from tests.conftest import make_manager
from tests.test_webconsole import _request, _login, PW

PEER = NodeID(bytes(range(20)))


class _StubClient:
    def __init__(self):
        self.sent = []
    async def send(self, target, payload):
        self.sent.append((target, payload))
    async def recv(self):
        await asyncio.Event().wait()
    async def close(self):
        pass


async def _make_console_with_chat():
    node = MeshNode(transport_manager=make_manager())
    app = ChatApp(_StubClient())
    bridge = ChatBridge(app, peer=PEER)
    console = WebConsole(node, host="127.0.0.1", port=0, use_tls=False,
                         password=PW, chat_bridge=bridge)
    console.start(loop=asyncio.get_running_loop())
    return node, console, app


class TestConsoleChat:
    async def test_page_and_assets_served(self):
        node, console, _ = await _make_console_with_chat()
        try:
            for path, needle in (("/chat", b"NMesh"),
                                 ("/chat.js", b"api"),
                                 ("/chat.css", b"bubble")):
                status, _, body, _ = await asyncio.to_thread(
                    _request, console, "GET", path)
                assert status == 200 and needle in body
        finally:
            console.stop(); await node.stop()

    async def test_messages_require_auth(self):
        node, console, _ = await _make_console_with_chat()
        try:
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "GET", "/api/chat/messages")
            assert status == 401
        finally:
            console.stop(); await node.stop()

    async def test_incoming_message_surfaced(self):
        node, console, app = await _make_console_with_chat()
        try:
            _, token = await _login(console)
            app._emit(TextMessage(PEER, "hello via console"))
            status, _, _, j = await asyncio.to_thread(
                _request, console, "GET", "/api/chat/messages?since=0", token)
            assert status == 200
            texts = [m["text"] for m in j["messages"] if m["type"] == "text"]
            assert "hello via console" in texts
            assert j["peer"] == PEER.raw.hex()
        finally:
            console.stop(); await node.stop()

    async def test_send_routes_through_app(self):
        node, console, app = await _make_console_with_chat()
        try:
            _, token = await _login(console)
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/chat/send", token, {"text": "yo"})
            assert status == 200 and j["ok"] is True
            assert app._client.sent[-1][0] == PEER
            assert app._client.sent[-1][1] == bytes([0x01]) + b"yo"
        finally:
            console.stop(); await node.stop()

    async def test_send_requires_auth(self):
        node, console, _ = await _make_console_with_chat()
        try:
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/chat/send", None, {"text": "x"})
            assert status == 401
        finally:
            console.stop(); await node.stop()

    async def test_apps_list_advertises_chat(self):
        node, console, _ = await _make_console_with_chat()
        try:
            _, token = await _login(console)
            status, _, _, j = await asyncio.to_thread(
                _request, console, "GET", "/api/state", token)
            assert status == 200
            ids = [a["id"] for a in j.get("apps", [])]
            assert "chat" in ids
            chat = next(a for a in j["apps"] if a["id"] == "chat")
            assert chat["path"] == "/chat"
        finally:
            console.stop(); await node.stop()


class TestNoChatBridge:
    """With no bridge attached, the chat surface must not exist at all."""

    async def _make_plain(self):
        node = MeshNode(transport_manager=make_manager())
        console = WebConsole(node, host="127.0.0.1", port=0, use_tls=False,
                             password=PW)
        console.start(loop=asyncio.get_running_loop())
        return node, console

    async def test_chat_page_absent(self):
        node, console = await self._make_plain()
        try:
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "GET", "/chat")
            assert status == 404
        finally:
            console.stop(); await node.stop()

    async def test_chat_api_absent(self):
        node, console = await self._make_plain()
        try:
            _, token = await _login(console)
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "GET", "/api/chat/messages", token)
            assert status == 404
            status2, _, _, j = await asyncio.to_thread(
                _request, console, "GET", "/api/state", token)
            assert status2 == 200 and j.get("apps") == []
        finally:
            console.stop(); await node.stop()
