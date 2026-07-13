"""
Tests d'intégration locaux — nœuds réels sur TCP localhost.

Plus lents que les tests unitaires : vraie crypto post-quantique + vraie pile
réseau. Ils valident le chemin complet invite → handshake → session E2E → data,
et le routage multi-hop A→B→C où A et C ne se parlent qu'à travers B.

Exclus de la suite par défaut (voir pyproject addopts) ; lancer explicitement :
    pytest tests/integration -q
"""
import asyncio
import os
import tempfile

import pytest

from src import MeshNode
from src.node_id import NodeID
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer


def _mgr() -> TransportManager:
    mgr = TransportManager()
    mgr.register("tcp", TCPTransport, TCPServer)
    return mgr


def make_node() -> MeshNode:
    return MeshNode(_mgr())


def persistent_node(state_dir: str, name: str) -> MeshNode:
    return MeshNode(
        _mgr(),
        identity_path=os.path.join(state_dir, f"{name}.key"),
        cert_store_path=os.path.join(state_dir, f"{name}.certs"),
        session_store_path=os.path.join(state_dir, f"{name}.sessions"),
    )


async def establish_session(host_addr: str, guest_addr: str) -> tuple[MeshNode, MeshNode]:
    host = make_node()
    guest = make_node()
    code = host.generate_invite()

    await host.start([f"tcp://{host_addr}"])
    await guest.join(f"tcp://{host_addr}", code)

    await guest.wait_for_session(timeout=15.0)
    await host.wait_for_session(timeout=15.0)
    return host, guest


async def _recv(node: MeshNode, timeout: float = 10.0) -> tuple[NodeID, bytes]:
    return await asyncio.wait_for(node.receive_data(), timeout=timeout)


# ---------------------------------------------------------------------------
# Invite + handshake over real TCP
# ---------------------------------------------------------------------------

class TestInviteAndHandshake:
    async def test_guest_gets_session_after_join(self):
        host, guest = await establish_session("127.0.0.1:19100", "127.0.0.1:19101")
        assert guest.session is not None
        await guest.stop()
        await host.stop()

    async def test_host_gets_session_after_join(self):
        host, guest = await establish_session("127.0.0.1:19102", "127.0.0.1:19103")
        assert host.session is not None
        await guest.stop()
        await host.stop()

    async def test_wrong_code_no_session(self):
        host = make_node()
        guest = make_node()
        host.generate_invite()

        await host.start(["tcp://127.0.0.1:19104"])
        await guest.join("tcp://127.0.0.1:19104", "wrongcode1")

        with pytest.raises(TimeoutError):
            await guest.wait_for_session(timeout=3.0)
        await guest.stop()
        await host.stop()

    async def test_invite_code_single_use(self):
        host = make_node()
        guest1 = make_node()
        guest2 = make_node()
        code = host.generate_invite()

        await host.start(["tcp://127.0.0.1:19105"])
        await guest1.join("tcp://127.0.0.1:19105", code)
        await guest1.wait_for_session(timeout=15.0)

        await guest2.join("tcp://127.0.0.1:19105", code)
        with pytest.raises(TimeoutError):
            await guest2.wait_for_session(timeout=3.0)

        await guest1.stop()
        await guest2.stop()
        await host.stop()


# ---------------------------------------------------------------------------
# End-to-end encrypted data over a single hop
# ---------------------------------------------------------------------------

class TestDataExchange:
    async def test_guest_to_host(self):
        host, guest = await establish_session("127.0.0.1:19110", "127.0.0.1:19111")
        await guest.send_data(host.id, b"hello host")
        src, data = await _recv(host)
        assert data == b"hello host"
        assert src == guest.id
        await guest.stop()
        await host.stop()

    async def test_host_to_guest(self):
        host, guest = await establish_session("127.0.0.1:19112", "127.0.0.1:19113")
        await host.send_data(guest.id, b"hello guest")
        src, data = await _recv(guest)
        assert data == b"hello guest"
        assert src == host.id
        await guest.stop()
        await host.stop()

    async def test_multiple_messages_ordered(self):
        host, guest = await establish_session("127.0.0.1:19114", "127.0.0.1:19115")
        messages = [f"msg{i}".encode() for i in range(20)]
        for msg in messages:
            await guest.send_data(host.id, msg)
        received = [(await _recv(host))[1] for _ in messages]
        assert received == messages
        await guest.stop()
        await host.stop()

    async def test_large_payload(self):
        host, guest = await establish_session("127.0.0.1:19116", "127.0.0.1:19117")
        blob = bytes(i % 256 for i in range(50_000))
        await guest.send_data(host.id, blob)
        src, data = await _recv(host)
        assert data == blob
        await guest.stop()
        await host.stop()


# ---------------------------------------------------------------------------
# Multi-hop routing: A —— B —— C, with A and C reachable only through B.
# This is the core "route A→C via B" guarantee.
# ---------------------------------------------------------------------------

class TestMultiHopRouting:
    async def _star(self, b_addr: str) -> tuple[MeshNode, MeshNode, MeshNode]:
        b = make_node()        # hub
        a = make_node()        # leaf
        c = make_node()        # leaf
        code_a = b.generate_invite()
        code_c = b.generate_invite()

        await b.start([f"tcp://{b_addr}"])
        await a.join(f"tcp://{b_addr}", code_a)
        await c.join(f"tcp://{b_addr}", code_c)
        await a.wait_for_session(timeout=15.0)
        await c.wait_for_session(timeout=15.0)
        return a, b, c

    async def test_a_to_c_through_b(self):
        a, b, c = await self._star("127.0.0.1:19120")
        # A and C never connected directly — the E2E handshake and data must
        # ride through B.
        await a.send_data(c.id, b"through the hub")
        src, data = await _recv(c, timeout=15.0)
        assert data == b"through the hub"
        assert src == a.id
        for n in (a, b, c):
            await n.stop()

    async def test_bidirectional_through_b(self):
        a, b, c = await self._star("127.0.0.1:19121")
        await a.send_data(c.id, b"a to c")
        await c.send_data(a.id, b"c to a")
        got_c = (await _recv(c, timeout=15.0))[1]
        got_a = (await _recv(a, timeout=15.0))[1]
        assert got_c == b"a to c"
        assert got_a == b"c to a"
        for n in (a, b, c):
            await n.stop()


# ---------------------------------------------------------------------------
# Self-healing: a peer whose socket dies is pruned from the mesh automatically.
# ---------------------------------------------------------------------------

class TestSelfHealing:
    async def test_dead_peer_is_pruned(self):
        host, guest = await establish_session("127.0.0.1:19130", "127.0.0.1:19131")
        assert len(host._peers) == 1
        # Kill the guest's socket hard; the host must reap the dead link.
        await guest.stop()

        loop = asyncio.get_event_loop()
        deadline = loop.time() + 10.0
        while loop.time() < deadline and host._peers:
            await asyncio.sleep(0.05)
        assert host._peers == []
        await host.stop()


# ---------------------------------------------------------------------------
# Direct-link persistence: a restarted node resumes its links and its E2E
# sessions from disk, with no re-invitation.
# ---------------------------------------------------------------------------

class TestRestartRecovery:
    async def test_resume_after_restart_without_reinvite(self):
        with tempfile.TemporaryDirectory() as d:
            addr = "127.0.0.1:19150"
            host = persistent_node(d, "host")
            guest = persistent_node(d, "guest")
            guest_id = guest.id

            code = host.generate_invite()
            await host.start([f"tcp://{addr}"])
            await guest.join(f"tcp://{addr}", code)
            await guest.wait_for_session(timeout=15.0)
            await host.wait_for_session(timeout=15.0)

            await guest.send_data(host.id, b"before restart")
            src, data = await asyncio.wait_for(host.receive_data(), timeout=15.0)
            assert data == b"before restart"

            # Restart the guest process: brand-new instance, same state dir,
            # no invite, no join call — everything comes from disk.
            await guest.stop()
            guest2 = persistent_node(d, "guest")
            assert guest2.id == guest_id
            assert guest2._routing.contains(host.id)          # link restored
            assert host.id in guest2._e2e_sessions            # E2E restored

            await guest2.send_data(host.id, b"after restart")
            src, data = await asyncio.wait_for(host.receive_data(), timeout=20.0)
            assert data == b"after restart"
            assert src == guest_id

            await guest2.stop()
            await host.stop()


# ---------------------------------------------------------------------------
# IP transport: multiple ports, runtime add/remove, advertised URIs.
# ---------------------------------------------------------------------------

class TestMultiPort:
    async def test_listen_multiple_ports_and_runtime_change(self):
        host = make_node()
        await host.start(["tcp://127.0.0.1:19200"])
        await host.add_listen("tcp://127.0.0.1:19201")

        gA, gB = make_node(), make_node()
        await gA.join("tcp://127.0.0.1:19200", host.generate_invite())
        await gB.join("tcp://127.0.0.1:19201", host.generate_invite())
        await gA.wait_for_session(timeout=15.0)
        await gB.wait_for_session(timeout=15.0)

        adv = host.advertised_uris()
        assert "tcp://127.0.0.1:19200" in adv
        assert "tcp://127.0.0.1:19201" in adv
        assert "tcp://127.0.0.1:19201" in host._transport_manager.listening_uris()

        # Drop the second port at runtime; new joins to it must fail.
        assert await host.remove_listen("tcp://127.0.0.1:19201")
        assert "tcp://127.0.0.1:19201" not in host.advertised_uris()
        gC = make_node()
        with pytest.raises(Exception):
            await gC.join("tcp://127.0.0.1:19201", host.generate_invite())

        await gA.stop(); await gB.stop(); await gC.stop(); await host.stop()
