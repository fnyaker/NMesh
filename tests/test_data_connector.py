"""
Data connector tests — the app-facing DATA plane.

Focus on the auth boundary (token required before anything), the send/receive
round-trip against a live node, and framing hardening.
"""
import asyncio

import pytest

from src.data_connector import (
    DataConnector, _read_frame, _write_frame, _LEN,
    _AUTH, _SEND, _WHOAMI, _AUTH_OK, _AUTH_FAIL, _RECV, _WHOAMI_RESP,
)
from src.node_id import NodeID
from tests.conftest import make_node
import os

TOKEN = "test-token-abc"


async def _make():
    node, fake = await make_node()
    conn = DataConnector(node, host="127.0.0.1", port=0, token=TOKEN)
    await conn.start()
    return node, fake, conn


async def _open(conn):
    return await asyncio.open_connection(conn._host, conn.port)


async def _auth(reader, writer, token=TOKEN):
    await _write_frame(writer, _AUTH, token.encode())
    ftype, _ = await _read_frame(reader)
    return ftype


class TestAuth:
    async def test_wrong_token_rejected(self):
        node, _, conn = await _make()
        try:
            reader, writer = await _open(conn)
            assert await _auth(reader, writer, "wrong") == _AUTH_FAIL
            assert await reader.read(1) == b""   # server closed us
            writer.close()
        finally:
            await conn.stop(); await node.stop()

    async def test_correct_token_accepted(self):
        node, _, conn = await _make()
        try:
            reader, writer = await _open(conn)
            assert await _auth(reader, writer) == _AUTH_OK
            writer.close()
        finally:
            await conn.stop(); await node.stop()

    async def test_send_before_auth_ignored(self):
        # First frame isn't AUTH → treated as failed auth, connection closed.
        node, _, conn = await _make()
        try:
            reader, writer = await _open(conn)
            await _write_frame(writer, _SEND, os.urandom(20) + b"hi")
            ftype, _ = await _read_frame(reader)
            assert ftype == _AUTH_FAIL
            writer.close()
        finally:
            await conn.stop(); await node.stop()


class TestSendReceive:
    async def test_send_reaches_node(self):
        node, _, conn = await _make()
        try:
            reader, writer = await _open(conn)
            assert await _auth(reader, writer) == _AUTH_OK
            target = NodeID(os.urandom(20))
            await _write_frame(writer, _SEND, target.raw + b"payload-out")
            # No route → node buffers it as pending E2E data.
            for _ in range(50):
                if target in node._e2e_pending_data:
                    break
                await asyncio.sleep(0.02)
            assert node._e2e_pending_data.get(target) == [b"payload-out"]
            writer.close()
        finally:
            await conn.stop(); await node.stop()

    async def test_whoami(self):
        node, _, conn = await _make()
        try:
            reader, writer = await _open(conn)
            await _auth(reader, writer)
            await _write_frame(writer, _WHOAMI, b"")
            ftype, body = await _read_frame(reader)
            assert ftype == _WHOAMI_RESP
            assert body == node.id.raw
            writer.close()
        finally:
            await conn.stop(); await node.stop()

    async def test_inbound_message_pushed(self):
        node, _, conn = await _make()
        try:
            reader, writer = await _open(conn)
            await _auth(reader, writer)
            src = NodeID(os.urandom(20))
            node._data_queue.put_nowait((src, b"incoming"))
            ftype, body = await asyncio.wait_for(_read_frame(reader), timeout=2.0)
            assert ftype == _RECV
            assert body[:20] == src.raw
            assert body[20:] == b"incoming"
            writer.close()
        finally:
            await conn.stop(); await node.stop()


class TestHardening:
    async def test_oversized_frame_closes(self):
        node, _, conn = await _make()
        try:
            reader, writer = await _open(conn)
            writer.write(_LEN.pack(10 ** 7))   # absurd length prefix
            await writer.drain()
            assert await reader.read(1) == b""  # server rejected + closed
            writer.close()
        finally:
            await conn.stop(); await node.stop()

    async def test_token_is_generated_when_absent(self):
        node, _ = await make_node()
        conn = DataConnector(node)
        assert conn.token and len(conn.token) >= 16
        await node.stop()
