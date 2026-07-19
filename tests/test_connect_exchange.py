"""
Two-step connect exchange tests.

The simple invite flow: joiner B makes a request block → host A accepts it and
returns an invite block → B completes and joins. Each side opens NAT holes
toward the other during the exchange, so it works with no shared relay. The
blocks are hostile input — validation is covered here alongside a full
end-to-end connect between two UDP nodes.
"""
import asyncio
import base64
import json
import socket

import pytest

from src.node import (
    MeshNode, _encode_conn_block, _decode_conn_block, _CONN_BLOCK_VERSION,
)
from src.udp_transport import UDPTransport, UDPServer
from src.transport_manager import TransportManager
from tests.conftest import make_manager, make_node


def _udp_manager() -> TransportManager:
    m = TransportManager()
    m.register("udp", UDPTransport, UDPServer)
    return m


def _free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


async def _udp_authed(node, other):
    return any(p.authenticated_id == other and p.session is not None
               and isinstance(p.transport, UDPTransport) for p in node._peers)


class TestBlockCodec:
    def test_roundtrip(self):
        block = _encode_conn_block("req", uris=["udp://1.2.3.4:9000"])
        data = _decode_conn_block(block, "req")
        assert data["v"] == _CONN_BLOCK_VERSION
        assert data["kind"] == "req"
        assert data["uris"] == ["udp://1.2.3.4:9000"]

    def test_wrong_kind_rejected(self):
        block = _encode_conn_block("inv", code="x", uris=[])
        with pytest.raises(ValueError):
            _decode_conn_block(block, "req")

    def test_hostile_blocks_rejected(self):
        bad = [
            None, 42, "", "x" * 9000, "not-base64!!!",
            base64.b64encode(b"[1,2]").decode(),                       # not a dict
            base64.b64encode(b'{"v":1,"kind":"req"}').decode(),        # wrong version
            base64.b64encode(b'{"v":2,"kind":"other"}').decode(),      # wrong kind
        ]
        for block in bad:
            with pytest.raises(ValueError):
                _decode_conn_block(block, "req")


class TestConnectFlow:
    async def test_request_block_lists_our_uris(self):
        node = MeshNode(transport_manager=_udp_manager())
        await node.start_udp(0, "127.0.0.1")
        node._addresses = ["udp://127.0.0.1:9001"]
        try:
            block = node.console_connect_request()
            data = _decode_conn_block(block, "req")
            assert "udp://127.0.0.1:9001" in data["uris"]
        finally:
            await node.stop_udp()

    async def test_accept_opens_holes_and_returns_invite(self):
        A = MeshNode(transport_manager=_udp_manager())
        await A.start_udp(0, "127.0.0.1")
        A._addresses = [f"udp://127.0.0.1:{A.udp_port()}"]
        A._udp_server._sock.sendto = lambda *a: None  # no real datagrams
        try:
            req = _encode_conn_block("req", uris=["udp://198.51.100.9:40001"])
            inv = A.console_connect_accept(req)
            data = _decode_conn_block(inv, "inv")
            assert isinstance(data["code"], str) and len(data["code"]) == 10
            assert data["code"] in A._invite._codes          # code is live
            assert ("198.51.100.9", 40001) in A._manual_holes  # hole opened toward B
        finally:
            A._cancel_manual_holes()
            await A.stop_udp()

    async def test_accept_rejects_a_non_request_block(self):
        A = MeshNode(transport_manager=_udp_manager())
        await A.start_udp(0, "127.0.0.1")
        try:
            inv = _encode_conn_block("inv", code="x", uris=["udp://1.2.3.4:9000"])
            with pytest.raises(ValueError):
                A.console_connect_accept(inv)
        finally:
            await A.stop_udp()

    async def test_complete_rejects_a_non_invite_block(self):
        B = MeshNode(transport_manager=_udp_manager())
        await B.start_udp(0, "127.0.0.1")
        try:
            req = _encode_conn_block("req", uris=["udp://1.2.3.4:9000"])
            with pytest.raises(ValueError):
                B.console_connect_complete(req)
        finally:
            await B.stop_udp()

    async def test_complete_rejects_unsupported_schemes(self):
        B = MeshNode(transport_manager=_udp_manager())  # only udp registered
        await B.start_udp(0, "127.0.0.1")
        try:
            inv = _encode_conn_block("inv", code="abc1234567",
                                     uris=["tcp://1.2.3.4:9000"])
            with pytest.raises(ValueError):
                B.console_connect_complete(inv)
        finally:
            await B.stop_udp()


class TestConnectEndToEnd:
    async def test_two_step_connect_no_relay(self):
        """B joins A with two copy-pastes and no shared relay."""
        pa, pb = _free_udp_port(), _free_udp_port()
        A = MeshNode(transport_manager=_udp_manager())
        B = MeshNode(transport_manager=_udp_manager())
        await A.start_udp(pa, "127.0.0.1")
        await B.start_udp(pb, "127.0.0.1")
        A._addresses = [f"udp://127.0.0.1:{pa}"]
        B._addresses = [f"udp://127.0.0.1:{pb}"]
        try:
            # 1. B creates a request; 2. A accepts → invite; 3. B completes
            req = B.console_connect_request()
            inv = A.console_connect_accept(req)
            B.console_connect_complete(inv)

            async with asyncio.timeout(15):
                while B._join_status["running"]:
                    await asyncio.sleep(0.05)
            assert B._join_status["connected"] == f"udp://127.0.0.1:{pa}"
            assert await _udp_authed(B, A.id)
            assert await _udp_authed(A, B.id)
        finally:
            await A.stop()
            await B.stop()
