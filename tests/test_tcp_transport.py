import asyncio
import pytest
from src.tcp_transport import TCPTransport
from src.packet import Packet, PacketError

SRC     = bytes(range(20))
DST     = bytes(range(20, 40))
NONCE   = bytes(range(12))
GCM_TAG = bytes(range(16))

def make_packet(payload: bytes = b"hello") -> Packet:
    return Packet(
        version=1, type=0x01, ttl=64,
        src_id=SRC, dst_id=DST, msg_id=0,
        nonce=NONCE, gcm_tag=GCM_TAG,
        payload=payload,
    )


@pytest.fixture
async def transport_pair():
    server = TCPTransport()
    client = TCPTransport()

    # Ephemeral port (":0") so parallel workers never collide on a fixed number;
    # read it back once the server socket is bound (set before listen() blocks).
    server_task = asyncio.create_task(server.listen("127.0.0.1:0"))
    while server._server is None:
        await asyncio.sleep(0.001)
    port = server._server.sockets[0].getsockname()[1]
    await client.connect(f"127.0.0.1:{port}")
    await server_task

    yield server, client

    await client.close()
    await server.close()


class TestTCPTransport:
    async def test_send_receive(self, transport_pair):
        server, client = transport_pair
        packet = make_packet(b"hello mesh")
        await client.send(packet)
        received = await server.receive()
        assert received.pack() == packet.pack()

    async def test_bidirectional(self, transport_pair):
        server, client = transport_pair
        p1 = make_packet(b"client to server")
        p2 = make_packet(b"server to client")
        await client.send(p1)
        await server.send(p2)
        assert (await server.receive()).pack() == p1.pack()
        assert (await client.receive()).pack() == p2.pack()

    async def test_multiple_packets(self, transport_pair):
        server, client = transport_pair
        packets = [make_packet(f"msg{i}".encode()) for i in range(5)]
        for p in packets:
            await client.send(p)
        for p in packets:
            received = await server.receive()
            assert received.pack() == p.pack()

    async def test_send_not_connected(self):
        t = TCPTransport()
        with pytest.raises(ConnectionError):
            await t.send(make_packet())

    async def test_receive_not_connected(self):
        t = TCPTransport()
        with pytest.raises(ConnectionError):
            await t.receive()
