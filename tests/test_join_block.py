"""
Invite-block tests (base64 join bundles) and transport control tests.

The invite block is pasted by an operator but *crafted* by whoever produced
it — it is hostile input. These tests cover the validation boundary (size,
types, version, URI caps, scheme filtering), the multi-URI fallback logic
(dead address → next address), and the runtime hole-punching switch.
"""
import asyncio
import base64
import json

import pytest

from src.node import MeshNode, _encode_punch_relay, PUNCH_RELAY
from src.node_id import NodeID
from src.packet import Packet
from tests.conftest import (
    make_manager, make_node, ConnectableFakeTransportManager,
)


def _make_block(code, uris, v=1) -> str:
    return base64.b64encode(
        json.dumps({"v": v, "code": code, "uris": uris}).encode()).decode()


async def _wait_join_done(node: MeshNode, timeout: float = 5.0) -> dict:
    async with asyncio.timeout(timeout):
        while node._join_status is None or node._join_status["running"]:
            await asyncio.sleep(0.02)
    return node._join_status


class TestInviteBlock:
    async def test_block_roundtrip(self):
        node = MeshNode(transport_manager=make_manager())
        node._addresses = ["fake://a:1"]
        block = node.console_invite_block()
        data = json.loads(base64.b64decode(block))
        assert data["v"] == 1
        assert "fake://a:1" in data["uris"]
        assert len(data["code"]) == 10
        assert node._invite.has_code()  # the code in the block is live

    async def test_hostile_blocks_rejected(self):
        node = MeshNode(transport_manager=make_manager())
        bad = [
            None, 42, "",                       # not a usable string
            "x" * 9000,                          # oversized
            "not-base64!!!",                     # invalid base64
            base64.b64encode(b"[1,2]").decode(),      # not a dict
            _make_block("c" * 10, ["fake://a:1"], v=2),   # wrong version
            _make_block("", ["fake://a:1"]),              # empty code
            _make_block("c" * 100, ["fake://a:1"]),       # oversized code
            _make_block("c" * 10, "fake://a:1"),          # uris not a list
            _make_block("c" * 10, []),                    # no addresses
            _make_block("c" * 10, [123, None]),           # non-string uris
            _make_block("c" * 10, ["tcp://a:1"]),         # unsupported scheme
            _make_block("c" * 10, ["garbage"]),           # invalid URI
        ]
        for block in bad:
            with pytest.raises(ValueError):
                node.console_join_block(block)
        assert node._join_task is None  # nothing ever started

    async def test_uri_count_is_capped(self):
        node = MeshNode(transport_manager=make_manager())
        node._join_try_timeout = 0.05
        uris = [f"fake://host{i}:1" for i in range(100)]
        result = node.console_join_block(_make_block("c" * 10, uris))
        assert result["candidates"] == 16
        status = await _wait_join_done(node, timeout=15.0)
        assert len(status["tried"]) == 16

    async def test_second_join_while_running_is_rejected(self):
        node = MeshNode(transport_manager=make_manager())
        node._join_try_timeout = 1.0
        node.console_join_block(_make_block("c" * 10, ["fake://a:1"]))
        with pytest.raises(ValueError):
            node.console_join_block(_make_block("c" * 10, ["fake://b:1"]))
        await _wait_join_done(node)


class TestJoinBlockEndToEnd:
    async def _host_and_joiner(self):
        host = MeshNode(transport_manager=make_manager())
        mgr = ConnectableFakeTransportManager()
        joiner = MeshNode(transport_manager=mgr)
        return host, joiner, mgr

    async def test_join_succeeds_on_first_uri(self):
        host, joiner, mgr = await self._host_and_joiner()
        mgr.register_target("fake://host:9000", host)
        code = host.generate_invite()

        joiner.console_join_block(_make_block(code, ["fake://host:9000"]))
        status = await _wait_join_done(joiner)
        assert status["connected"] == "fake://host:9000"
        assert status["tried"] == []
        assert any(p.session is not None for p in joiner._peers)
        assert any(p.session is not None for p in host._peers)

    async def test_join_falls_back_to_next_uri(self):
        host, joiner, mgr = await self._host_and_joiner()
        mgr.register_target("fake://dead:9000", None)   # connects, never answers
        mgr.register_target("fake://host:9000", host)
        code = host.generate_invite()
        joiner._join_try_timeout = 0.5

        joiner.console_join_block(
            _make_block(code, ["fake://dead:9000", "fake://host:9000"]))
        status = await _wait_join_done(joiner)
        assert status["connected"] == "fake://host:9000"
        assert [t["uri"] for t in status["tried"]] == ["fake://dead:9000"]
        assert status["tried"][0]["error"]
        # The dead attempt's peer was cleaned up — only the live link remains
        assert len(joiner._peers) == 1

    async def test_all_uris_dead_reports_failure(self):
        host, joiner, mgr = await self._host_and_joiner()
        mgr.register_target("fake://dead1:1", None)
        mgr.register_target("fake://dead2:1", None)
        joiner._join_try_timeout = 0.3

        joiner.console_join_block(
            _make_block("c" * 10, ["fake://dead1:1", "fake://dead2:1"]))
        status = await _wait_join_done(joiner)
        assert status["connected"] is None
        assert len(status["tried"]) == 2
        assert joiner._peers == []

    async def test_snapshot_exposes_join_status(self):
        host, joiner, mgr = await self._host_and_joiner()
        mgr.register_target("fake://host:9000", host)
        code = host.generate_invite()
        joiner.console_join_block(_make_block(code, ["fake://host:9000"]))
        await _wait_join_done(joiner)
        # ConnectableFakeTransportManager is not a full TransportManager —
        # only check the join_status field, not the whole snapshot.
        assert joiner._join_status["connected"] == "fake://host:9000"
        json.dumps(joiner._join_status)


class TestPunchControl:
    async def test_punching_enabled_by_default(self):
        node = MeshNode(transport_manager=make_manager())
        assert node._punch_enabled is True
        snap = await node.console_snapshot()
        assert snap["punch_enabled"] is True

    async def test_disable_ignores_punch_relay(self):
        node, fake = await make_node()
        node.console_set_punch_enabled(False)

        class _FakeUDPServer:
            _sock = None
        node._udp_server = _FakeUDPServer()
        payload = _encode_punch_relay(b"\x01" * 20, "198.51.100.9:40001",
                                      "203.0.113.7")
        pkt = Packet.create(PUNCH_RELAY, b"\x02" * 20, node.id.raw, payload)
        await node._handle_punch_relay(node._peers[0], pkt)
        assert node._punch_pending == {}

    async def test_disable_ignores_raw_punch_datagrams(self):
        node = MeshNode(transport_manager=make_manager())
        node.console_set_punch_enabled(False)
        # Must be a silent no-op, even with no UDP server at all
        node.handle_udp_datagram(b"NPPB" + b"\x00" * 100, ("198.51.100.9", 1))

    async def test_disable_clears_pending_attempts(self):
        from src.node import _PunchState
        node = MeshNode(transport_manager=make_manager())
        target = NodeID(b"\x03" * 20)
        node._punch_pending[target] = _PunchState(target, "1.2.3.4:1", "1.2.3.4")
        node.console_set_punch_enabled(False)
        assert node._punch_pending == {}
        node.console_set_punch_enabled(True)
        assert node._punch_enabled is True
