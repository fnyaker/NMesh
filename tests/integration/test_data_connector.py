"""
Integration: two apps talk through the mesh via data connectors.

app_g → guest connector → mesh (E2E over TCP) → host connector → app_h.
This is the app-to-app data plane working end to end with real crypto.

Excluded from the default suite (see pyproject addopts).
"""
import asyncio

import pytest

from src import MeshNode
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer
from src.data_connector import (
    DataConnector, _read_frame, _write_frame,
    _AUTH, _SEND, _WHOAMI, _AUTH_OK, _RECV, _WHOAMI_RESP,
)

TOKEN = "integration-token"


def make_node() -> MeshNode:
    mgr = TransportManager()
    mgr.register("tcp", TCPTransport, TCPServer)
    return MeshNode(mgr)


async def _app(conn):
    reader, writer = await asyncio.open_connection(conn._host, conn.port)
    await _write_frame(writer, _AUTH, TOKEN.encode())
    ftype, _ = await _read_frame(reader)
    assert ftype == _AUTH_OK
    return reader, writer


class TestAppToApp:
    async def test_message_flows_app_to_app(self):
        host = make_node()
        guest = make_node()
        code = host.generate_invite()
        await host.start(["tcp://127.0.0.1:19140"])
        await guest.join("tcp://127.0.0.1:19140", code)
        await guest.wait_for_session(timeout=15.0)
        await host.wait_for_session(timeout=15.0)

        host_conn = DataConnector(host, port=0, token=TOKEN)
        guest_conn = DataConnector(guest, port=0, token=TOKEN)
        await host_conn.start()
        await guest_conn.start()

        try:
            hr, hw = await _app(host_conn)      # receiving app, on the host
            gr, gw = await _app(guest_conn)     # sending app, on the guest

            # The host app discovers its own node id via WHOAMI.
            await _write_frame(hw, _WHOAMI, b"")
            ftype, host_id = await _read_frame(hr)
            assert ftype == _WHOAMI_RESP

            # The guest app sends to the host node; it arrives at the host app.
            await _write_frame(gw, _SEND, host_id + b"hi from the guest app")
            ftype, body = await asyncio.wait_for(_read_frame(hr), timeout=15.0)
            assert ftype == _RECV
            assert body[20:] == b"hi from the guest app"

            hw.close()
            gw.close()
        finally:
            await host_conn.stop()
            await guest_conn.stop()
            await guest.stop()
            await host.stop()
