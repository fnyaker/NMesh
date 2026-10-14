"""
A routed packet that comes back to a relay round a cycle is sent another way.

The relay forwards to its XOR-nearest neighbour except the link a packet arrived
on, so on a mesh that has not learned the destination a packet can go
A → B → C → A, where the replay table used to drop the only copy alive. The
first handshake to a node nobody links to was lost to exactly that.

What must still hold is the charter's bound: a copy over a link it already used
here is a replay and dies, a packet leaves a node by at most
`_ROUTE_SEND_FANOUT` neighbours, and the book that remembers is bounded.
"""
import asyncio
import os

from src.crypto import SessionKey
from src.node import DATA, MeshNode, _ROUTE_SEND_FANOUT
from src.node_id import NodeID
from src.packet import Packet
from tests.conftest import FakeTransport, make_manager

_TARGET = NodeID(b"\x00" * 20)
_SOURCE = b"\xee" * 20


async def _relay(count: int) -> tuple[MeshNode, list[FakeTransport]]:
    """A node holding `count` authenticated links whose ids sit at strictly
    increasing XOR distance from `_TARGET`: link 0 is the nearest."""
    node = MeshNode(transport_manager=make_manager())
    fakes = []
    for i in range(count):
        fake = FakeTransport()
        await node._inject_peer(fake)
        peer = node._peers[-1]
        peer.authenticated_id = NodeID(bytes([i + 1]) + b"\x00" * 19)
        peer.session = SessionKey(os.urandom(32))
        fakes.append(fake)
    return node, fakes


def _packet(dst: bytes = _TARGET.raw) -> Packet:
    return Packet.create(DATA, _SOURCE, dst, os.urandom(16))


def _carried(fake: FakeTransport) -> int:
    return sum(1 for p in fake.sent if p.type == DATA)


async def _quiet() -> None:
    await asyncio.sleep(0.1)


class TestACopyThatCameRoundIsSentAnotherWay:
    async def test_the_second_copy_leaves_by_a_neighbour_the_first_did_not_take(self):
        node, fakes = await _relay(4)
        pkt = _packet()
        fakes[3].inject(pkt)                  # arrives from the farthest link
        await _quiet()
        assert _carried(fakes[0]) == 1        # nearest other than the sender

        fakes[1].inject(pkt)                  # the same packet, back round a cycle
        await _quiet()
        assert _carried(fakes[2]) == 1        # not 0 (tried), not 1 (it came from there)
        assert _carried(fakes[0]) == 1
        assert _carried(fakes[3]) == 0        # never back to where it started
        await node.stop()

    async def test_a_copy_from_a_link_it_already_used_here_is_a_replay(self):
        """The line between a cycle and an attack: the same link twice."""
        node, fakes = await _relay(4)
        pkt = _packet()
        fakes[3].inject(pkt)
        await _quiet()
        for _ in range(20):
            fakes[3].inject(pkt)
        await _quiet()
        assert sum(_carried(f) for f in fakes) == 1
        await node.stop()

    async def test_a_packet_leaves_by_no_more_neighbours_than_the_fanout(self):
        node, fakes = await _relay(_ROUTE_SEND_FANOUT + 4)
        pkt = _packet()
        fakes[-1].inject(pkt)
        await _quiet()
        for fake in fakes[:-1]:               # every other link sends it back once
            fake.inject(pkt)
            await _quiet()
        leaving = sum(_carried(f) for f in fakes)
        assert 1 < leaving <= _ROUTE_SEND_FANOUT
        await node.stop()

    async def test_a_copy_with_nowhere_left_to_go_is_dropped_quietly(self):
        node, fakes = await _relay(3)
        pkt = _packet()
        fakes[2].inject(pkt)
        await _quiet()
        fakes[0].inject(pkt)
        await _quiet()
        fakes[1].inject(pkt)
        await _quiet()
        assert sum(_carried(f) for f in fakes) == 2       # 0 then 1; 2 is the source
        await node.stop()

    async def test_a_copy_to_this_node_is_still_dropped_as_a_duplicate(self):
        node, fakes = await _relay(3)
        pkt = _packet(dst=node.id.raw)
        fakes[2].inject(pkt)
        fakes[1].inject(pkt)
        await _quiet()
        assert sum(_carried(f) for f in fakes) == 0
        await node.stop()

    async def test_a_copy_on_its_last_hop_is_not_sent_on(self):
        node, fakes = await _relay(3)
        pkt = Packet.create(DATA, _SOURCE, _TARGET.raw, os.urandom(16), ttl=2)
        fakes[2].inject(pkt)
        await _quiet()
        before = sum(_carried(f) for f in fakes)
        fakes[1].inject(pkt)
        await _quiet()
        assert sum(_carried(f) for f in fakes) == before
        await node.stop()


class TestWhatIsRememberedIsBounded:
    async def test_the_book_never_outgrows_its_ceiling(self, monkeypatch):
        monkeypatch.setattr("src.node._FWD_BOOK_MAX", 3)
        node, fakes = await _relay(3)
        for _ in range(12):
            fakes[2].inject(_packet())
        await _quiet()
        assert 0 < len(node._fwd_book) <= 3
        await node.stop()

    async def test_each_entry_holds_no_more_than_the_fanout_plus_one(self):
        node, fakes = await _relay(_ROUTE_SEND_FANOUT + 6)
        pkt = _packet()
        fakes[-1].inject(pkt)
        for fake in fakes[:-1]:
            fake.inject(pkt)
        await _quiet()
        for arrived, tried in node._fwd_book.values():
            assert len(arrived) <= _ROUTE_SEND_FANOUT + 2
            assert len(tried) <= _ROUTE_SEND_FANOUT + 1
        await node.stop()
