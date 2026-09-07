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

from src.apps.chat import (ChatApp, Deleted, Edited, Reaction,
                           TextMessage)
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


class TestArrivingOutOfOrder:
    """An app on a mesh cannot assume order, and chat's answer is to wait.

    A routed reply has never been obliged to arrive after the one before it,
    and multi-link operation makes the overtaking deliberate and a few
    milliseconds wide (`src/mlo.py`). An edit that outran its own message used
    to be dropped in silence — the message then stayed unedited for ever with
    nothing anywhere saying why."""

    def _bridge(self):
        return ChatWebServer(ChatApp(StubClient()), host="127.0.0.1", port=0,
                             token=TOKEN, peer=PEER).bridge

    async def test_an_edit_that_arrives_first_is_applied_when_it_can_be(self):
        bridge = self._bridge()
        mid = os.urandom(8)
        bridge._on_event(Edited(SRC, None, mid, "corrected"))
        bridge._on_event(TextMessage(SRC, "original", mid))
        held = [m for m in bridge.snapshot(0)["messages"]]
        assert [m["text"] for m in held] == ["corrected"]
        assert held[0]["edited"] is True

    async def test_a_reaction_that_arrives_first_lands_on_the_message(self):
        bridge = self._bridge()
        mid = os.urandom(8)
        bridge._on_event(Reaction(SRC, None, mid, "\N{PARTY POPPER}"))
        bridge._on_event(TextMessage(SRC, "hello", mid))
        message = bridge.snapshot(0)["messages"][0]
        assert list(message["reactions"]) == ["\N{PARTY POPPER}"]

    async def test_a_deletion_that_arrives_first_still_deletes(self):
        bridge = self._bridge()
        mid = os.urandom(8)
        bridge._on_event(Deleted(SRC, None, mid))
        bridge._on_event(TextMessage(SRC, "oops", mid))
        message = bridge.snapshot(0)["messages"][0]
        assert message["deleted"] is True and message["text"] == ""

    async def test_waiting_is_bounded_in_number(self):
        bridge = self._bridge()
        for _ in range(500):
            bridge._on_event(Edited(SRC, None, os.urandom(8), "x"))
        assert len(bridge._orphans) <= 128

    async def test_waiting_is_bounded_in_time(self):
        """An operation whose message never comes is a message nobody sent us."""
        bridge = self._bridge()
        mid = os.urandom(8)
        bridge._on_event(Edited(SRC, None, mid, "corrected"))
        at, operations = bridge._orphans[mid.hex()]
        bridge._orphans[mid.hex()] = (at - 10_000, operations)
        bridge._on_event(Edited(SRC, None, os.urandom(8), "y"))   # any later one
        assert mid.hex() not in bridge._orphans

    async def test_a_replay_does_not_park_itself_again(self):
        """The record is registered before the replay runs, or the operation
        would land back on the very message it was waiting for."""
        bridge = self._bridge()
        mid = os.urandom(8)
        bridge._on_event(Edited(SRC, None, mid, "corrected"))
        bridge._on_event(TextMessage(SRC, "original", mid))
        assert bridge._orphans == {}
