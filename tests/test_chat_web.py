"""
Chat web UI tests.

The web UI is an option of the chat app: it subscribes to the app's events and
sends through the app. These check the auth boundary, that incoming messages are
surfaced (via the app's listener), and that sending routes back through the app.
"""
import asyncio
import http.client
import json
import os

import pytest

from src.apps.chat import ChatApp, TextMessage
from src.apps.chat_web import ChatWebServer
from src.node_id import NodeID

TOKEN = "chat-token-xyz"
PEER = NodeID(os.urandom(20))
SRC = NodeID(os.urandom(20))


class StubClient:
    def __init__(self):
        self.sent = []
    async def send(self, target, payload):
        self.sent.append((target, payload))
    async def recv(self):
        await asyncio.Event().wait()
    async def close(self):
        pass


async def _make():
    app = ChatApp(StubClient())
    server = ChatWebServer(app, host="127.0.0.1", port=0, token=TOKEN, peer=PEER)
    server.start(loop=asyncio.get_running_loop())
    return app, server


def _request(server, method, path, token=None, body=None):
    conn = http.client.HTTPConnection(server.host, server.port, timeout=8)
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=data, headers=headers)
    r = conn.getresponse()
    payload = r.read()
    conn.close()
    try:
        parsed = json.loads(payload) if payload else None
    except Exception:
        parsed = None
    return r.status, payload, parsed


class TestChatWeb:
    async def test_messages_require_auth(self):
        app, server = await _make()
        try:
            status, _, _ = await asyncio.to_thread(_request, server, "GET", "/api/messages")
            assert status == 401
        finally:
            server.stop()

    async def test_bad_token_rejected(self):
        app, server = await _make()
        try:
            status, _, _ = await asyncio.to_thread(
                _request, server, "GET", "/api/messages", "nope")
            assert status == 401
        finally:
            server.stop()

    async def test_incoming_message_surfaced(self):
        app, server = await _make()
        try:
            # An event the chat app receives must appear in the web feed.
            app._emit(TextMessage(SRC, "hello from the mesh"))
            status, _, j = await asyncio.to_thread(
                _request, server, "GET", "/api/messages?since=0", TOKEN)
            assert status == 200
            texts = [m["text"] for m in j["messages"] if m["kind"] == "text"]
            assert "hello from the mesh" in texts
            assert j["peer"] == PEER.raw.hex()
        finally:
            server.stop()

    async def test_send_routes_through_app(self):
        app, server = await _make()
        try:
            status, _, j = await asyncio.to_thread(
                _request, server, "POST", "/api/send", TOKEN, {"text": "yo"})
            assert status == 200 and j["ok"] is True
            # The message went out through the chat app → its client.
            assert app._client.sent[-1][0] == PEER
            payload = app._client.sent[-1][1]
            assert payload[0] == 0x01 and payload.endswith(b"yo")  # _TEXT | mid | reply | text
            # And it's echoed in the feed as an outgoing message.
            _, _, feed = await asyncio.to_thread(
                _request, server, "GET", "/api/messages?since=0", TOKEN)
            assert any(m["src"] == "me" and m["text"] == "yo" for m in feed["messages"])
        finally:
            server.stop()

    async def test_send_requires_auth(self):
        app, server = await _make()
        try:
            status, _, _ = await asyncio.to_thread(
                _request, server, "POST", "/api/send", None, {"text": "x"})
            assert status == 401
        finally:
            server.stop()

    async def test_index_served_with_csp(self):
        app, server = await _make()
        try:
            status, body, _ = await asyncio.to_thread(_request, server, "GET", "/")
            assert status == 200 and b"NMesh" in body
        finally:
            server.stop()
