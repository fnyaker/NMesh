"""
Integration: the full mesh running over the spool (directory) transport — no
sockets at all. Real post-quantum crypto, real invite/handshake/E2E, but the
only medium is files in a shared directory.

Excluded from the default suite (see pyproject addopts); run explicitly:
    pytest tests/integration/test_spool_transport.py -q
"""
import asyncio
import os
import tempfile

import pytest

from src import MeshNode
from src.transport_manager import TransportManager
from src.spool_transport import SpoolTransport, SpoolServer


def make_node() -> MeshNode:
    mgr = TransportManager()
    mgr.register("spool", SpoolTransport, SpoolServer)
    return MeshNode(mgr)


class TestSpoolMesh:
    async def test_session_and_data_over_directory(self):
        with tempfile.TemporaryDirectory() as d:
            link = os.path.join(d, "link")
            host = make_node()
            guest = make_node()
            code = host.generate_invite()

            await host.start([f"spool://{link}"])
            await guest.join(f"spool://{link}", code)
            await guest.wait_for_session(timeout=25.0)
            await host.wait_for_session(timeout=25.0)

            await guest.send_data(host.id, b"hello via files")
            src, data = await asyncio.wait_for(host.receive_data(), timeout=25.0)
            assert data == b"hello via files"
            assert src == guest.id

            await guest.stop()
            await host.stop()

    async def test_bidirectional_over_directory(self):
        with tempfile.TemporaryDirectory() as d:
            link = os.path.join(d, "link")
            host = make_node()
            guest = make_node()
            code = host.generate_invite()

            await host.start([f"spool://{link}"])
            await guest.join(f"spool://{link}", code)
            await guest.wait_for_session(timeout=25.0)
            await host.wait_for_session(timeout=25.0)

            await guest.send_data(host.id, b"g2h")
            await host.send_data(guest.id, b"h2g")
            got_h = (await asyncio.wait_for(host.receive_data(), timeout=25.0))[1]
            got_g = (await asyncio.wait_for(guest.receive_data(), timeout=25.0))[1]
            assert got_h == b"g2h"
            assert got_g == b"h2g"

            await guest.stop()
            await host.stop()

    async def test_multi_hop_over_directory(self):
        # A and C both join hub B on the same directory link (SpoolServer gives
        # each its own session subdir). A and C never share a link, so A→C must
        # route through B — entirely over a file medium.
        with tempfile.TemporaryDirectory() as d:
            link = os.path.join(d, "hub")
            b = make_node()
            a = make_node()
            c = make_node()
            code_a = b.generate_invite()
            code_c = b.generate_invite()

            await b.start([f"spool://{link}"])
            await a.join(f"spool://{link}", code_a)
            await c.join(f"spool://{link}", code_c)
            await a.wait_for_session(timeout=25.0)
            await c.wait_for_session(timeout=25.0)

            await a.send_data(c.id, b"through B on disk")
            src, data = await asyncio.wait_for(c.receive_data(), timeout=30.0)
            assert data == b"through B on disk"
            assert src == a.id

            for n in (a, b, c):
                await n.stop()
