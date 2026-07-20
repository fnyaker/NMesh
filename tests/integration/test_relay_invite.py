"""
Relayed invitation — end-to-end (étape 3).

The point of the whole feature: a node brings in a peer with NO direct link,
through a relay. Real TCP on loopback; A and B never connect to each other —
only both to R. The invite handshake tunnels A↔B through R, then E2E data
flows both ways over the relayed path.

Excluded from the default suite (see pyproject addopts); run explicitly:

    pytest tests/integration/test_relay_invite.py -q
"""
import asyncio
import random

import pytest

from src import MeshNode
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer


def _mgr() -> TransportManager:
    m = TransportManager()
    m.register("tcp", TCPTransport, TCPServer)
    return m


def _authed_relayed(node, other):
    return any(p.authenticated_id == other and p.session is not None
               for p in node._peers)


class TestRelayedInvitation:
    async def test_join_via_relay_no_direct_link(self):
        base = random.randint(20000, 40000)
        R, A, B = MeshNode(_mgr()), MeshNode(_mgr()), MeshNode(_mgr())
        await R.start([f"tcp://127.0.0.1:{base}"])
        # A joins the network through R (A dials R → R becomes a usable relay)
        await A.join(f"tcp://127.0.0.1:{base}", R.generate_invite())
        await asyncio.wait_for(A.wait_for_session(10), 15)
        try:
            # A invites B with a single relay block; B ingests it and joins
            # A THROUGH R — A and B never share a direct link.
            block = A.console_relay_invite()
            assert f"tcp://127.0.0.1:{base}" in __import__("json").loads(
                __import__("base64").b64decode(block))["relays"]
            B.console_relay_join(block)

            async with asyncio.timeout(20):
                while B._join_status["running"]:
                    await asyncio.sleep(0.05)
            assert B._join_status["connected"] == f"tcp://127.0.0.1:{base}"
            assert _authed_relayed(B, A.id)   # B ↔ A authenticated (via relay)
            assert _authed_relayed(A, B.id)

            # E2E data flows both ways over the relayed path
            await B.send_data(A.id, b"hello A via relay")
            async with asyncio.timeout(15):
                while True:
                    src, data = await A.receive_data()
                    if data == b"hello A via relay" and src == B.id:
                        break
            await A.send_data(B.id, b"reply to B")
            async with asyncio.timeout(15):
                while True:
                    src, data = await B.receive_data()
                    if data == b"reply to B" and src == A.id:
                        break
        finally:
            await A.stop()
            await B.stop()
            await R.stop()

    async def test_join_falls_back_to_next_relay(self):
        base = random.randint(20000, 40000)
        R, A, B = MeshNode(_mgr()), MeshNode(_mgr()), MeshNode(_mgr())
        await R.start([f"tcp://127.0.0.1:{base}"])
        await A.join(f"tcp://127.0.0.1:{base}", R.generate_invite())
        await asyncio.wait_for(A.wait_for_session(10), 15)
        try:
            B._relay_join_timeout = 3.0
            # first relay is dead (nothing listening), second is R
            import base64, json
            block = A.console_relay_invite()
            data = json.loads(base64.b64decode(block))
            data["relays"] = [f"tcp://127.0.0.1:{base + 1}"] + data["relays"]
            block2 = base64.b64encode(json.dumps(data).encode()).decode()
            B.console_relay_join(block2)
            async with asyncio.timeout(30):
                while B._join_status["running"]:
                    await asyncio.sleep(0.05)
            assert B._join_status["connected"] == f"tcp://127.0.0.1:{base}"
            assert _authed_relayed(B, A.id)
        finally:
            await A.stop()
            await B.stop()
            await R.stop()
