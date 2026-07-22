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
from src.app_channel import CHAT_APP_ID
from src.apps.chat import (
    ChatApp, TextMessage, FileReceived, Frame,
    ProfileReceived, GroupInvited, GroupMessage, DirResult,
    Edited, Deleted, Reaction, Receipt, _READ,
)


def make_node() -> MeshNode:
    mgr = TransportManager()
    mgr.register("tcp", TCPTransport, TCPServer)
    return MeshNode(mgr)


async def _chat_for(node) -> tuple[DataConnector, ChatApp]:
    conn = DataConnector(node, host="127.0.0.1", port=0, token="tok")
    await conn.start()
    client = ConnectorClient(conn.host, conn.port, "tok", CHAT_APP_ID)
    await client.connect()
    app = ChatApp(client, node_id=node.id)
    await app.start()
    return conn, app


async def _next(app, kind, timeout=20.0):
    ev = await asyncio.wait_for(app.next_event(), timeout=timeout)
    assert isinstance(ev, kind), f"expected {kind.__name__}, got {ev}"
    return ev


async def _wait_for(app, kind, timeout=20.0):
    """Drain events until one of ``kind`` arrives (others are skipped)."""
    async def _pump():
        while True:
            ev = await app.next_event()
            if isinstance(ev, kind):
                return ev
    return await asyncio.wait_for(_pump(), timeout=timeout)


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


class TestRichChatOverMesh:
    async def test_reaction_edit_receipt_and_profile(self):
        host = make_node()
        guest = make_node()
        code = host.generate_invite()
        await host.start(["tcp://127.0.0.1:19172"])
        await guest.join("tcp://127.0.0.1:19172", code)
        await guest.wait_for_session(timeout=15.0)
        await host.wait_for_session(timeout=15.0)

        host_conn, host_app = await _chat_for(host)
        guest_conn, guest_app = await _chat_for(guest)
        try:
            # Guest sends a message; host gets it with the sender-minted msg id.
            mid = await guest_app.send_text(host.id, "first")
            m = await _wait_for(host_app, TextMessage)
            assert m.mid == mid and m.text == "first"

            # Guest reacts to it → host sees the reaction on that mid.
            await guest_app.send_reaction(host.id, mid, "👍")
            r = await _wait_for(host_app, Reaction)
            assert r.mid == mid and r.emoji == "👍"

            # Guest edits it → host sees the new text for the same mid.
            await guest_app.send_edit(host.id, mid, "first (edited)")
            e = await _wait_for(host_app, Edited)
            assert e.mid == mid and e.text == "first (edited)"

            # Host marks it read → guest receives a READ receipt for that mid.
            await host_app.send_receipt(guest.id, _READ, [mid])
            rc = await _wait_for(guest_app, Receipt)
            assert rc.kind == _READ and mid in rc.mids

            # Guest publishes a rich profile (bio + avatar) → host learns it.
            await guest_app.add_contact(host.id, announce=False)
            await guest_app.set_profile(pseudo="guesty", bio="on the mesh",
                                        avatar=b"AVATARBYTES", announce=True)
            prof = await _wait_for(host_app, ProfileReceived)
            assert prof.pseudo == "guesty" and prof.bio == "on the mesh"
            assert prof.avatar == b"AVATARBYTES"
            assert host_app.state.get_avatar(guest.id.raw.hex()) == b"AVATARBYTES"
        finally:
            await host_app.stop()
            await guest_app.stop()
            await host_conn.stop()
            await guest_conn.stop()
            await guest.stop()
            await host.stop()


class TestSocialOverMesh:
    async def test_profile_group_and_pseudo_lookup(self):
        host = make_node()
        guest = make_node()
        code = host.generate_invite()
        await host.start(["tcp://127.0.0.1:19171"])
        await guest.join("tcp://127.0.0.1:19171", code)
        await guest.wait_for_session(timeout=15.0)
        await host.wait_for_session(timeout=15.0)

        host_conn, host_app = await _chat_for(host)
        guest_conn, guest_app = await _chat_for(guest)
        try:
            # Guest adds host as a contact and announces its pseudo → host learns it.
            await guest_app.set_pseudo("guesty", announce=False)
            await guest_app.add_contact(host.id, announce=True)
            prof = await _wait_for(host_app, ProfileReceived)
            assert prof.src == guest.id and prof.pseudo == "guesty"
            assert host_app.state.known[guest.id.raw.hex()]["pseudo"] == "guesty"

            # Guest creates a group with host and messages it.
            gid = await guest_app.create_group("team", [host.id])
            inv = await _wait_for(host_app, GroupInvited)
            assert inv.group_id == gid and host.id in inv.members
            await guest_app.send_group_text(gid, "hey team")
            gm = await _wait_for(host_app, GroupMessage)
            assert gm.group_id == gid and gm.src == guest.id and gm.text == "hey team"

            # Host sets a pseudo; guest (host is its contact) resolves it by pseudo.
            await host_app.set_pseudo("hosty", announce=False)
            await guest_app.dir_query("hosty")
            res = await _wait_for(guest_app, DirResult)
            assert res.node_id == host.id and res.pseudo == "hosty"
            # host is already a contact of guest, so the learned pseudo lands there.
            assert guest_app.state.contacts[host.id.raw.hex()]["pseudo"] == "hosty"
        finally:
            await host_app.stop()
            await guest_app.stop()
            await host_conn.stop()
            await guest_conn.stop()
            await guest.stop()
            await host.stop()
