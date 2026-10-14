"""
Integration: two real nodes whose only medium is ``veil://``. The key is the
medium's own setting; the invitation, the handshake and the end-to-end session
run inside the keyed stream exactly as they do over TCP.
"""
import asyncio

import pytest

from src import MeshNode
from src.transports.manager import TransportManager
from src.transports.veil import VeilServer, VeilTransport
from tests.integration import free_port


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setattr(VeilTransport, "SETTINGS", {"key": "a circle's shared phrase"})


def make_node() -> MeshNode:
    mgr = TransportManager()
    mgr.register("veil", VeilTransport, VeilServer)
    return MeshNode(mgr)


class TestVeilMesh:
    async def test_session_and_data_over_a_keyed_stream(self):
        port = free_port()
        host, guest = make_node(), make_node()
        code = host.generate_invite()
        await host.start([f"veil://127.0.0.1:{port}"])
        try:
            await guest.join(f"veil://127.0.0.1:{port}", code)
            await guest.wait_for_session(timeout=25.0)
            await host.wait_for_session(timeout=25.0)
            await guest.send_data(host.id, b"through the veil")
            src, data = await asyncio.wait_for(host.receive_data(), timeout=25.0)
            assert (src, data) == (guest.id, b"through the veil")
            await host.send_data(guest.id, b"and back")
            assert (await asyncio.wait_for(guest.receive_data(), timeout=25.0))[1] == b"and back"
        finally:
            await guest.stop()
            await host.stop()

    async def test_a_guest_without_the_key_never_gets_a_session(self, monkeypatch):
        class Other(VeilTransport):
            SETTINGS = {"key": "some other long phrase"}
            _DEFAULTS = None

        port = free_port()
        host = make_node()
        mgr = TransportManager()
        mgr.register("veil", Other, VeilServer)
        stranger = MeshNode(mgr)
        code = host.generate_invite()
        await host.start([f"veil://127.0.0.1:{port}"])
        try:
            with pytest.raises(Exception):
                await asyncio.wait_for(
                    stranger.join(f"veil://127.0.0.1:{port}", code), timeout=15.0)
            assert not host._authenticated_peers()
        finally:
            await stranger.stop()
            await host.stop()
