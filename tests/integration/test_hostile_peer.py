"""
An authenticated peer turned adversary, on real TCP links.

The unit tests drive the reputation book and the tarpit through fakes; this is
the same threat model with real nodes, real post-quantum handshakes and real
sockets. A member the victim admitted itself floods it, replays what it sent,
and speaks in another member's name, and the victim has to hold the charter's
line through all of it: the adversary is muted without being told, its count
follows its identity across reconnections, nothing it replays or forges is
delivered, and an honest member beside it notices nothing.
"""
import asyncio
import os
import time

import pytest

from src.node import DATA
from src.packet import Packet
from src.transports.tcp import _FRAME
from tests.integration import free_port
from tests.integration.test_local import make_node


async def _member(victim, port):
    node = make_node()
    await node.join(f"tcp://127.0.0.1:{port}", victim.generate_invite())
    await node.wait_for_session(timeout=20.0)
    return node


async def _warm(sender, receiver):
    """One message through, so the end-to-end session exists and what comes
    next leaves as a single DATA packet."""
    await sender.send_data(receiver.id, b"warm")
    assert (await asyncio.wait_for(receiver.receive_data(), timeout=10.0))[1] == b"warm"


def _link_to(node, other):
    return next(p for p in node._peers
                if p.authenticated_id == other.id and p.session is not None)


async def _until(predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.05)
    return predicate()


async def _junk(link, count):
    """Frames the far side cannot even decode, on a link that is otherwise
    perfectly authenticated."""
    writer = link.transport._writer
    for _ in range(count):
        junk = os.urandom(40)
        writer.writelines((_FRAME.pack(len(junk)), junk))
    await writer.drain()


# Where the sender sits in the clear header (`src/packet.py`, HEADER_FORMAT):
# version, type and TTL, one byte each, then the 20-byte source id.
_SRC = slice(3, 23)


@pytest.fixture
async def mesh():
    port = free_port()
    victim = make_node()
    await victim.start([f"tcp://127.0.0.1:{port}"])
    hostile = await _member(victim, port)
    honest = await _member(victim, port)
    await victim.wait_for_session(timeout=20.0)
    try:
        yield victim, hostile, honest, port
    finally:
        for node in (honest, hostile, victim):
            await node.stop()


class TestAFlooder:
    async def test_is_muted_without_being_told(self, mesh):
        victim, hostile, _honest, _port = mesh
        link = _link_to(hostile, victim)
        await _junk(link, 60)
        assert await _until(lambda: victim._reputation.is_suspect(hostile.id))
        held = [p for p in victim._peers if p.authenticated_id == hostile.id]
        assert held and all(p.tarpit_until for p in held)
        # Long after the cut would have landed, the flooder still holds an
        # open link it believes in: no close, no error, nothing to react to.
        await asyncio.sleep(2.0)
        assert link in hostile._peers
        assert not link.transport.is_closed()

    async def test_is_no_longer_served(self, mesh):
        victim, hostile, _honest, _port = mesh
        await hostile.send_data(victim.id, b"before")
        assert (await asyncio.wait_for(victim.receive_data(), timeout=10.0))[1] == b"before"
        await _junk(_link_to(hostile, victim), 60)
        assert await _until(lambda: victim._reputation.is_suspect(hostile.id))
        await hostile.send_data(victim.id, b"from the flooder")
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(victim.receive_data(), timeout=3.0)

    async def test_an_honest_member_beside_it_notices_nothing(self, mesh):
        victim, hostile, honest, _port = mesh
        flood = asyncio.ensure_future(_junk(_link_to(hostile, victim), 500))
        await honest.send_data(victim.id, b"still here")
        src, data = await asyncio.wait_for(victim.receive_data(), timeout=10.0)
        assert (src, data) == (honest.id, b"still here")
        await victim.send_data(honest.id, b"and so am I")
        src, data = await asyncio.wait_for(honest.receive_data(), timeout=10.0)
        assert (src, data) == (victim.id, b"and so am I")
        await flood

    async def test_reconnecting_does_not_shed_the_count(self, mesh):
        """Counted per identity: a fresh link is the same adversary."""
        victim, hostile, _honest, port = mesh
        await _junk(_link_to(hostile, victim), 60)
        assert await _until(lambda: victim._reputation.is_suspect(hostile.id))
        for peer in list(hostile._peers):
            await peer.stop()
        await hostile.join(f"tcp://127.0.0.1:{port}", victim.generate_invite())
        await asyncio.sleep(2.0)
        assert victim._reputation.is_suspect(hostile.id)
        await hostile.send_data(victim.id, b"a fresh start")
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(victim.receive_data(), timeout=3.0)


class TestWhatItSends:
    async def test_a_replayed_message_is_delivered_once(self, mesh):
        victim, hostile, _honest, _port = mesh
        await _warm(hostile, victim)
        link = _link_to(hostile, victim)
        sent = []
        original = link.transport.send

        async def capture(packet):
            sent.append(packet)
            await original(packet)
        link.transport.send = capture
        await hostile.send_data(victim.id, b"once")
        assert (await asyncio.wait_for(victim.receive_data(), timeout=10.0))[1] == b"once"
        data_packets = [p for p in sent if p.type == DATA]
        assert data_packets
        for _ in range(20):
            for packet in data_packets:
                await original(packet)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(victim.receive_data(), timeout=3.0)

    async def test_a_message_in_another_member_s_name_is_not_delivered(self, mesh):
        """A real message of the adversary's, with only its sender changed to
        another member's: the header is the cipher's associated data, so the
        lie breaks it. The untouched original, sent after, is the control."""
        victim, hostile, honest, _port = mesh
        await _warm(hostile, victim)
        link = _link_to(hostile, victim)
        held = []
        original = link.transport.send

        async def hold(packet):
            held.append(packet)
        link.transport.send = hold
        await hostile.send_data(victim.id, b"whose is this")
        link.transport.send = original
        real = [p for p in held if p.type == DATA]
        assert real
        for packet in real:
            wire = bytearray(packet.pack())
            wire[_SRC] = honest.id.raw
            await original(Packet.unpack(bytes(wire)))
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(victim.receive_data(), timeout=3.0)
        for packet in real:
            await original(packet)
        src, data = await asyncio.wait_for(victim.receive_data(), timeout=10.0)
        assert (src, data) == (hostile.id, b"whose is this")
