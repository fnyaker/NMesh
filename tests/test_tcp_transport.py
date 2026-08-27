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

    async def test_send_to_a_non_draining_peer_times_out(self):
        """A peer that accepts the connection but never drains wedges the sender
        forever: the write buffer fills and drain() never returns. The send must
        give up, not hang the loop."""
        class _NonDrainingWriter:
            def writelines(self, chunks):
                pass
            async def drain(self):
                await asyncio.sleep(3600)

        t = TCPTransport()
        t._writer = _NonDrainingWriter()
        # A tiny value, set directly: the 5 s floor is for operators, not for a
        # test that must fail fast.
        old = TCPTransport.SETTINGS.get("write_timeout")
        TCPTransport.SETTINGS["write_timeout"] = 0.01
        try:
            with pytest.raises(ConnectionError, match="write timeout"):
                await t.send(make_packet())
        finally:
            if old is None:
                TCPTransport.SETTINGS.pop("write_timeout", None)
            else:
                TCPTransport.SETTINGS["write_timeout"] = old
