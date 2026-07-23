"""
Integration: reach a node by id when it's only reachable through a relay.

A and C never connect directly (only the relay R listens; no hole punch), so a
liveness probe from A to C must travel A→R→C and back. This exercises the routed
ECHO_REQUEST/ECHO_REPLY path — reaching an id remotely, not just a direct peer.

Excluded from the default suite (see pyproject addopts).
"""
import asyncio

import pytest

from src import MeshNode
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer


def make_node() -> MeshNode:
    mgr = TransportManager()
    mgr.register("tcp", TCPTransport, TCPServer)
    return MeshNode(mgr)


class TestRoutedPing:
    async def test_ping_node_through_relay(self):
        relay = make_node()
        a = make_node()
        c = make_node()
        await relay.start(["tcp://127.0.0.1:19272"])   # only the relay listens
        await a.join("tcp://127.0.0.1:19272", relay.generate_invite())
        await a.wait_for_session(timeout=15.0)
        await c.join("tcp://127.0.0.1:19272", relay.generate_invite())
        await c.wait_for_session(timeout=15.0)
        # No direct link and no hole punch: A and C only reach each other via R.
        a._punch_enabled = False
        c._punch_enabled = False
        relay._punch_enabled = False
        await a.bootstrap()
        await c.bootstrap()
        try:
            assert not any(p.authenticated_id == c.id for p in a._peers)  # not direct
            res = await asyncio.wait_for(
                a.console_ping_node(c.id.raw.hex()), timeout=15.0)
            assert res["reachable"] is True and res["via"] == "route"
            assert isinstance(res["rtt_ms"], (int, float))
        finally:
            await a.stop()
            await c.stop()
            await relay.stop()

    async def test_ping_unreachable_id_reports_unreachable(self):
        node = make_node()
        await node.start(["tcp://127.0.0.1:19273"])
        try:
            # A random id we have no path to → reachable False, no crash.
            res = await asyncio.wait_for(
                node.console_ping_node("ab" * 20), timeout=12.0)
            assert res["ok"] is True and res["reachable"] is False
        finally:
            await node.stop()
