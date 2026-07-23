"""
Integration: everything routes end to end over a multi-hop chain.

Five nodes in a line A-B-C-D-E — each knows only its neighbours (no hole punch,
no shortcut links). The far ends must reach each other through the middle for
data, a liveness ping, the content-addressed DHT, and the pseudo directory.
This is the "A→X through the whole alphabet" case.

Excluded from the default suite (see pyproject addopts).
"""
import asyncio

import pytest

from src import MeshNode
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer
from src.app_channel import CHAT_APP_ID


def make_node() -> MeshNode:
    mgr = TransportManager()
    mgr.register("tcp", TCPTransport, TCPServer)
    return MeshNode(mgr)


async def _line(n: int, base: int):
    nodes = [make_node() for _ in range(n)]
    for i, nd in enumerate(nodes):
        await nd.start([f"tcp://127.0.0.1:{base + i}"])
    for i in range(n - 1):
        await nodes[i].join(f"tcp://127.0.0.1:{base + i + 1}", nodes[i + 1].generate_invite())
        await nodes[i].wait_for_session(timeout=15.0)
    for nd in nodes:
        nd._punch_enabled = False
    # One trust anchor for the whole line so E2E can authenticate end to end
    # (routing reaches the far end regardless; E2E additionally needs trust).
    for x in nodes:
        for y in nodes:
            if x is not y:
                y._cert_store.add(x._identity.self_signed_cert())
                y._cert_store.add_root(x.id)
    await asyncio.sleep(0.3)
    return nodes


class TestChainRouting:
    async def test_everything_over_a_five_node_line(self):
        nodes = await _line(5, 19290)
        a, x = nodes[0], nodes[-1]
        try:
            # A and X are not direct peers.
            assert not any(p.authenticated_id == x.id for p in a._peers)

            # 1) DATA A→X routes through B, C, D.
            await a.send_data(x.id, b"across the chain")
            got = await asyncio.wait_for(x.receive_data(), timeout=15.0)
            assert got[1] == b"across the chain"

            # 2) routed liveness ping A→X.
            res = await asyncio.wait_for(a.console_ping_node(x.id.raw.hex()), timeout=15.0)
            assert res["reachable"] is True and res["via"] == "route"

            # 3) content-addressed DHT: A stores, X (far end) fetches it routed.
            key = await a.dht_put(b"chain dht payload")
            val = await asyncio.wait_for(x.dht_get(key), timeout=20.0)
            assert val == b"chain dht payload"

            # 4) pseudo directory: X publishes, A resolves it across the chain.
            await x.publish_pseudo(CHAT_APP_ID, "xavier")
            hits = await asyncio.wait_for(
                a.lookup_pseudo(CHAT_APP_ID, "xavier"), timeout=20.0)
            assert any(h["id"] == x.id.raw.hex() for h in hits)
        finally:
            for nd in nodes:
                await nd.stop()
