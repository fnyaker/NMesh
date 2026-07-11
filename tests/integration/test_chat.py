"""
Integration: the chat app running end to end over the mesh — text, a file
transfer, and a real-time frame stream — between two real nodes on TCP.

Excluded from the default suite (see pyproject addopts).
"""
import asyncio
import os
import statistics

import pytest

from src import MeshNode
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer
from src.data_connector import DataConnector, ConnectorClient
from src.apps.chat import ChatApp, TextMessage, FileReceived, Frame


def make_node() -> MeshNode:
    mgr = TransportManager()
    mgr.register("tcp", TCPTransport, TCPServer)
    return MeshNode(mgr)


async def _chat_for(node) -> tuple[DataConnector, ChatApp]:
    conn = DataConnector(node, host="127.0.0.1", port=0, token="tok")
    await conn.start()
    client = ConnectorClient(conn.host, conn.port, "tok")
    await client.connect()
    app = ChatApp(client)
    await app.start()
    return conn, app


async def _next(app, kind, timeout=20.0):
    ev = await asyncio.wait_for(app.next_event(), timeout=timeout)
    assert isinstance(ev, kind), f"expected {kind.__name__}, got {ev}"
    return ev


class TestChatOverMesh:
    async def test_text_file_and_stream(self):
        host = make_node()
        guest = make_node()
        code = host.generate_invite()
        await host.start(["tcp://127.0.0.1:19170"])
        await guest.join("tcp://127.0.0.1:19170", code)
        await guest.wait_for_session(timeout=15.0)
        await host.wait_for_session(timeout=15.0)

        host_conn, host_app = await _chat_for(host)
        guest_conn, guest_app = await _chat_for(guest)
        try:
            # --- text ---
            await guest_app.send_text(host.id, "salut, mesh !")
            msg = await _next(host_app, TextMessage)
            assert msg.text == "salut, mesh !" and msg.src == guest.id

            # --- file transfer ---
            blob = os.urandom(200_000)
            await guest_app.send_file(host.id, "photo.bin", blob)
            fr = await _next(host_app, FileReceived)
            assert fr.name == "photo.bin" and fr.data == blob and fr.src == guest.id

            # --- real-time stream (the "call" primitive) ---
            N = 30
            for seq in range(N):
                await guest_app.send_frame(host.id, stream_id=1, seq=seq,
                                           payload=b"frame-%d" % seq)
                await asyncio.sleep(0.01)   # ~100 fps
            latencies = []
            seqs = []
            for _ in range(N):
                fr = await _next(host_app, Frame)
                latencies.append(fr.latency_ms)
                seqs.append(fr.seq)
            assert sorted(seqs) == list(range(N))     # every frame arrived
            assert min(latencies) >= 0
            assert statistics.median(latencies) < 500  # near-real-time locally
        finally:
            await host_app.stop()
            await guest_app.stop()
            await host_conn.stop()
            await guest_conn.stop()
            await guest.stop()
            await host.stop()
