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


ME = NodeID(bytes([0x01]) * 20)
CONTACT = NodeID(bytes([0x02]) * 20)


async def _make_console_social():
    node = MeshNode(transport_manager=make_manager())
    app = ChatApp(_StubClient(), node_id=ME)
    bridge = ChatBridge(app)
    console = WebConsole(node, host="127.0.0.1", port=0, use_tls=False,
                         password=PW, chat_bridge=bridge)
    console.start(loop=asyncio.get_running_loop())
    return node, console, app


def _post(console, token, path, body):
    return _request(console, "POST", path, token, body)


class TestConsoleSocial:
    async def test_set_pseudo(self):
        node, console, app = await _make_console_social()
        try:
            _, token = await _login(console)
            st, _, _, j = await asyncio.to_thread(
                _post, console, token, "/api/chat/pseudo", {"pseudo": "alice"})
            assert st == 200 and j["ok"] is True
            assert app.state.pseudo == "alice"
            _, _, _, snap = await asyncio.to_thread(
                _request, console, "GET", "/api/chat/messages?since=0", token)
            assert snap["pseudo"] == "alice" and snap["me"] == ME.raw.hex()
        finally:
            console.stop(); await node.stop()

    async def test_add_and_remove_contact(self):
        node, console, app = await _make_console_social()
        try:
            _, token = await _login(console)
            st, _, _, j = await asyncio.to_thread(
                _post, console, token, "/api/chat/contact",
                {"op": "add", "id": CONTACT.raw.hex(), "pseudo": "bob"})
            assert st == 200 and j["ok"] is True
            assert CONTACT.raw.hex() in app.state.contacts
            st2, _, _, j2 = await asyncio.to_thread(
                _post, console, token, "/api/chat/contact",
                {"op": "remove", "id": CONTACT.raw.hex()})
            assert st2 == 200 and j2["ok"] is True
            assert CONTACT.raw.hex() not in app.state.contacts
        finally:
            console.stop(); await node.stop()

    async def test_create_group_and_send(self):
        node, console, app = await _make_console_social()
        try:
            _, token = await _login(console)
            app.state.add_contact(CONTACT.raw.hex(), "bob")
            st, _, _, j = await asyncio.to_thread(
                _post, console, token, "/api/chat/group",
                {"op": "create", "name": "team", "members": [CONTACT.raw.hex()]})
            assert st == 200 and j["ok"] is True
            gid = j["id"]
            assert gid in app.state.groups
            assert ME.raw.hex() in app.state.group_members(gid)
            # Sending to the group fans out to the member (not us).
            st2, _, _, j2 = await asyncio.to_thread(
                _post, console, token, "/api/chat/send", {"group": gid, "text": "hello team"})
            assert st2 == 200 and j2["ok"] is True
            assert any(t == CONTACT for t, _ in app._client.sent)
        finally:
            console.stop(); await node.stop()

    async def test_search_returns_local_hits(self):
        node, console, app = await _make_console_social()
        try:
            _, token = await _login(console)
            app.state.add_contact(CONTACT.raw.hex(), "Alice")
            st, _, _, j = await asyncio.to_thread(
                _post, console, token, "/api/chat/search", {"pseudo": "ali"})
            assert st == 200
            assert any(r["id"] == CONTACT.raw.hex() for r in j["results"])
        finally:
            console.stop(); await node.stop()

    async def test_social_requires_auth(self):
        node, console, _ = await _make_console_social()
        try:
            st, _, _, _ = await asyncio.to_thread(
                _post, console, None, "/api/chat/pseudo", {"pseudo": "x"})
            assert st == 401
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
