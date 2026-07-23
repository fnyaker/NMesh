"""
Integration: a stalled E2E handshake self-heals.

The reported bug: A sends to B before B is reachable (or an ACK is lost). The
handshake was armed once and never retried, so the queued message stayed stuck
until a reboot or until B happened to message A. This checks that the periodic
retry re-drives the handshake once B becomes reachable and the message lands.

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


async def _recv(node, timeout):
    try:
        return await asyncio.wait_for(node.receive_data(), timeout)
    except asyncio.TimeoutError:
        return None


class TestE2ERetry:
    async def test_message_to_offline_peer_delivers_when_it_joins(self):
        relay = make_node()
        a = make_node()
        b = make_node()
        await relay.start(["tcp://127.0.0.1:19262"])
        await a.join("tcp://127.0.0.1:19262", relay.generate_invite())
        await a.wait_for_session(timeout=15)
        a._punch_enabled = False

        # A sends to B while B is not on the network yet: the handshake is armed
        # but goes nowhere, and the payload sits in the pending queue.
        await a.send_data(b.id, b"queued while offline")
        assert a._e2e_pending_data.get(b.id)

        # B comes online on the same relay.
        await b.join("tcp://127.0.0.1:19262", relay.generate_invite())
        await b.wait_for_session(timeout=15)
        b._punch_enabled = False

        # The retry loop (cadence ~5s) must re-drive the handshake and flush.
        got = await _recv(b, 20)
        assert got is not None and got[1] == b"queued while offline"
        assert not a._e2e_pending_data.get(b.id)

        for n in (a, b, relay):
            await n.stop()
