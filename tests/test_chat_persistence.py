"""
Chat persistence in the encrypted per-app drawer.

The built-in chat keeps its social state (pseudo/contacts/groups) and its message
feed in the node's encrypted drawer, so nothing sits in the clear and history
survives a restart. These tests drive ChatState and ChatBridge against a real
AppStorage and check: round-trip across reopen, encryption at rest, and that a
corrupt drawer never crashes (empty start).
"""
import asyncio
import os
import tempfile

import pytest

from src.crypto import CryptoIdentity
from src.app_storage import AppStorage
from src.app_channel import CHAT_APP_ID
from src.apps.chat import ChatApp, TextMessage
from src.apps.chat_state import ChatState, DrawerStore
from src.apps.chat_web import ChatBridge
from src.node_id import NodeID

ID_A = NodeID(os.urandom(20)).raw.hex()


class StubClient:
    def __init__(self):
        self.sent = []
    async def send(self, target, payload):
        self.sent.append((target, payload))
    async def recv(self):
        await asyncio.Event().wait()
    async def close(self):
        pass


def _store(d, ident):
    return DrawerStore(AppStorage(d, ident), CHAT_APP_ID)


class TestChatStatePersistence:
    def test_state_survives_reopen(self):
        with tempfile.TemporaryDirectory() as d:
            ident = CryptoIdentity()
            s = ChatState(store=_store(d, ident))
            s.set_pseudo("alice")
            s.add_contact(ID_A, "bob")
            # A fresh instance on the same drawer reloads it.
            s2 = ChatState(store=_store(d, ident))
            assert s2.pseudo == "alice"
            assert any(c["pseudo"] == "bob" for c in s2.snapshot()["contacts"])

    def test_state_encrypted_at_rest(self):
        with tempfile.TemporaryDirectory() as d:
            ident = CryptoIdentity()
            ChatState(store=_store(d, ident)).set_pseudo("topsecret-pseudo")
            blob = open(os.path.join(d, CHAT_APP_ID.hex() + ".drawer"), "rb").read()
            assert b"topsecret-pseudo" not in blob

    def test_corrupt_drawer_starts_empty(self):
        with tempfile.TemporaryDirectory() as d:
            ident = CryptoIdentity()
            ChatState(store=_store(d, ident)).set_pseudo("alice")
            path = os.path.join(d, CHAT_APP_ID.hex() + ".drawer")
            open(path, "wb").write(os.urandom(200))   # clobber
            assert ChatState(store=_store(d, ident)).pseudo == ""


class TestMessageFeedPersistence:
    def test_feed_survives_reopen(self):
        with tempfile.TemporaryDirectory() as d:
            ident = CryptoIdentity()
            app = ChatApp(StubClient())
            b1 = ChatBridge(app, store=_store(d, ident))
            b1._on_event(TextMessage(NodeID(bytes.fromhex(ID_A)), "hello world"))
            b1.record_outgoing(ID_A, "my reply")
            # A new bridge on the same drawer reloads the history.
            b2 = ChatBridge(ChatApp(StubClient()), store=_store(d, ident))
            texts = [m["text"] for m in b2.snapshot(0)["messages"]]
            assert "hello world" in texts and "my reply" in texts

    def test_cursor_preserved_so_since_still_works(self):
        with tempfile.TemporaryDirectory() as d:
            ident = CryptoIdentity()
            b1 = ChatBridge(ChatApp(StubClient()), store=_store(d, ident))
            b1.record_outgoing(ID_A, "one")
            b1.record_outgoing(ID_A, "two")
            last = b1.snapshot(0)["cursor"]
            b2 = ChatBridge(ChatApp(StubClient()), store=_store(d, ident))
            # New messages get ids strictly after the restored cursor.
            b2.record_outgoing(ID_A, "three")
            assert b2.snapshot(last)["messages"][-1]["text"] == "three"
            assert b2.snapshot(last)["messages"][-1]["id"] > last

    def test_no_store_is_ram_only(self):
        with tempfile.TemporaryDirectory() as d:
            b = ChatBridge(ChatApp(StubClient()))   # no store
            b.record_outgoing(ID_A, "ephemeral")
            assert os.listdir(d) == []

    def test_corrupt_feed_starts_empty(self):
        with tempfile.TemporaryDirectory() as d:
            ident = CryptoIdentity()
            b1 = ChatBridge(ChatApp(StubClient()), store=_store(d, ident))
            b1.record_outgoing(ID_A, "hi")
            open(os.path.join(d, CHAT_APP_ID.hex() + ".drawer"), "wb").write(os.urandom(150))
            b2 = ChatBridge(ChatApp(StubClient()), store=_store(d, ident))
            assert b2.snapshot(0)["messages"] == []
