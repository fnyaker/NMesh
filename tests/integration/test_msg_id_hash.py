"""Two real nodes agree on the `msg_id` hash, and data still flows.

The unit tests (`tests/test_msg_id_hash.py`) decide each rule on its own: what a
silent peer is sent, what a receiver accepts, how a relay re-heads a packet.
This proves the rules add up over sockets — the records cross a real link at
their own pace, both ends end up sending BLAKE2b ids, and the gap between the
two records arriving loses nothing.
"""
import asyncio

from src import MeshNode
from src.packet import MSG_ID_BLAKE2B
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer
from src.udp_transport import UDPTransport, UDPServer


def make_node() -> MeshNode:
    manager = TransportManager()
    manager.register("tcp", TCPTransport, TCPServer)
    manager.register("udp", UDPTransport, UDPServer)
    return MeshNode(manager)


async def _agree_and_carry(address: str) -> None:
    host, guest = make_node(), make_node()
    await host.start([address])
    try:
        await guest.join(address, host.generate_invite())
        await asyncio.wait_for(guest.wait_for_session(10), 15)
        await asyncio.wait_for(host.wait_for_session(10), 15)
        async with asyncio.timeout(10):
            while not all(peer.msg_id_algorithm() == MSG_ID_BLAKE2B
                          for node in (host, guest) for peer in node._peers):
                await asyncio.sleep(0.02)
        sent = [b"first", b"x" * 50000, b"last"]
        for data in sent:
            await guest.send_data(host.id, data)
        got = []
        async with asyncio.timeout(15):
            while len(got) < len(sent):
                src, data = await host.receive_data()
                if src == guest.id:
                    got.append(data)
        assert got == sent
    finally:
        await guest.stop()
        await host.stop()


async def test_over_tcp():
    await _agree_and_carry("tcp://127.0.0.1:19480")


async def test_over_udp():
    await _agree_and_carry("udp://127.0.0.1:19481")
