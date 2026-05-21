"""
Tests d'intégration locaux — deux nœuds réels sur TCP localhost.
Plus lents que les tests unitaires (crypto réelle + réseau réel).
"""
import asyncio
import pytest
from src import MeshNode

HOST_ADDR   = "127.0.0.1:19100"
GUEST_ADDR  = "127.0.0.1:19101"
HOST_ADDR2  = "127.0.0.1:19110"
GUEST_ADDR2 = "127.0.0.1:19111"
HOST_ADDR3  = "127.0.0.1:19120"
GUEST_ADDR3 = "127.0.0.1:19121"
GUEST2_ADDR = "127.0.0.1:19122"


async def establish_session(host_addr: str, guest_addr: str) -> tuple[MeshNode, MeshNode]:
    host = MeshNode()
    guest = MeshNode()
    code = host.generate_invite()

    async def _start_host():
        await host.start(host_addr)

    async def _join_guest():
        await asyncio.sleep(0.1)
        await guest.join(host_addr, code)

    await asyncio.gather(_start_host(), _join_guest())
    await guest.wait_for_session(timeout=15.0)
    await host.wait_for_session(timeout=15.0)
    return host, guest


class TestInviteAndHandshake:
    async def test_guest_gets_session_after_join(self):
        host, guest = await establish_session(HOST_ADDR, GUEST_ADDR)
        assert guest.session is not None
        await guest.stop()
        await host.stop()

    async def test_host_gets_session_after_join(self):
        host, guest = await establish_session(HOST_ADDR, GUEST_ADDR)
        assert host.session is not None
        await guest.stop()
        await host.stop()

    async def test_wrong_code_no_session(self):
        host = MeshNode()
        guest = MeshNode()
        host.generate_invite()

        async def _start():
            await host.start(HOST_ADDR2)

        async def _join():
            await asyncio.sleep(0.1)
            await guest.join(HOST_ADDR2, "wrongcode1")

        await asyncio.gather(_start(), _join())
        with pytest.raises(TimeoutError):
            await guest.wait_for_session(timeout=3.0)
        await guest.stop()
        await host.stop()


class TestDataExchange:
    async def test_guest_to_host(self):
        host, guest = await establish_session(HOST_ADDR, GUEST_ADDR)
        await guest.send_data(b"hello host")
        data = await asyncio.wait_for(host.receive_data(), timeout=5.0)
        await guest.stop()
        await host.stop()
        assert data == b"hello host"

    async def test_host_to_guest(self):
        host, guest = await establish_session(HOST_ADDR2, GUEST_ADDR2)
        await host.send_data(b"hello guest")
        data = await asyncio.wait_for(guest.receive_data(), timeout=5.0)
        await guest.stop()
        await host.stop()
        assert data == b"hello guest"

    async def test_multiple_messages(self):
        host, guest = await establish_session(HOST_ADDR3, GUEST_ADDR3)
        messages = [f"msg{i}".encode() for i in range(5)]
        for msg in messages:
            await guest.send_data(msg)
        received = []
        for _ in messages:
            received.append(await asyncio.wait_for(host.receive_data(), timeout=5.0))
        await guest.stop()
        await host.stop()
        assert received == messages

    async def test_invite_code_single_use(self):
        host = MeshNode()
        guest1 = MeshNode()
        guest2 = MeshNode()
        code = host.generate_invite()

        async def _start():
            await host.start(HOST_ADDR3)

        async def _join1():
            await asyncio.sleep(0.1)
            await guest1.join(HOST_ADDR3, code)

        await asyncio.gather(_start(), _join1())
        await guest1.wait_for_session(timeout=15.0)
        await guest2.join(HOST_ADDR3, code)
        with pytest.raises(TimeoutError):
            await guest2.wait_for_session(timeout=3.0)
        await guest1.stop()
        await guest2.stop()
        await host.stop()
