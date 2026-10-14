"""
Links nobody needs are closed, and the far end is told it was on purpose.

A link stays open for ever unless something closes it, and each open link costs
a probe each way every twenty seconds: that was the whole traffic of an idle
node. What a node holds for good is its structure (the nearest nodes, a link or
two per band of distance); the rest goes after a while without a conversation.
Closing one must not start a chase on the other side, hence LINK_RELEASE.
"""
import asyncio
import os
import time

import pytest

import src.node as nodemod
from src import features
from src.node import MeshNode, LINK_RELEASE
from src.node_id import NodeID
from src.packet import Packet
from tests.conftest import FakeTransport, make_manager


def _at(node: MeshNode, band: int, low: int = 0) -> NodeID:
    value = int.from_bytes(node.id.raw, "big") ^ ((1 << (band - 1)) | low)
    return NodeID(value.to_bytes(20, "big"))


async def _link(node, node_id, *, idle=True, announces=False):
    fake = FakeTransport()
    peer = await node._inject_peer(fake)
    peer.authenticated_id = node_id
    peer.session = object()
    peer.last_used = time.monotonic() - (10_000 if idle else 0)
    if announces:
        peer.agreed = frozenset({features.LINK_RELEASE})
    return peer, fake


async def _node(links=12, leaf=2):
    """A node holding ``links`` links in distinct bands, all idle, with a leaf
    set of its two nearest and nothing known that would make it somebody's
    leaf."""
    node = MeshNode(transport_manager=make_manager())
    node._link_idle = 60.0
    node._leaf_size = leaf
    node._finger_links = 1
    made = []
    for band in range(20, 20 + links):
        made.append(await _link(node, _at(node, band)))
    node._leaf_last = [made[-1][0].authenticated_id, made[-2][0].authenticated_id]
    # With an empty table every node looks as if it had us among its nearest,
    # which is the one rule tested on its own below.
    node._likely_in_their_leaf = lambda _id: False
    return node, made


def _open(node):
    return {p.authenticated_id for p in node._peers if p.session is not None}


class TestWhatIsClosed:
    async def test_an_idle_link_nobody_needs_is_closed(self):
        node, made = await _node()
        # two links in one band: the second is not structure
        extra, _ = await _link(node, _at(node, 20, 5))
        node._prune_idle_links()
        assert extra not in node._peers
        await node.stop()

    async def test_the_structure_is_kept(self):
        node, made = await _node()
        before = _open(node)
        node._prune_idle_links()
        assert _open(node) == before, "one per band and the leaf set: nothing is extra"
        await node.stop()

    async def test_a_link_in_use_is_kept(self):
        node, made = await _node()
        busy, _ = await _link(node, _at(node, 20, 5), idle=False)
        node._prune_idle_links()
        assert busy in node._peers
        await node.stop()

    async def test_a_node_that_redialled_after_we_closed_is_not_closed_again(self):
        node, made = await _node()
        wanted, _ = await _link(node, _at(node, 20, 5))
        wanted.peer_wants = True
        node._prune_idle_links()
        assert wanted in node._peers
        await node.stop()

    @pytest.mark.parametrize("flag", ["relay_only", "probation"])
    async def test_a_relay_link_or_a_probe_is_left_alone(self, flag):
        node, made = await _node()
        odd, _ = await _link(node, _at(node, 20, 5))
        setattr(odd, flag, True)
        node._prune_idle_links()
        assert odd in node._peers
        await node.stop()

    async def test_a_node_we_hold_two_links_to_is_left_alone(self):
        node, made = await _node()
        twin_id = _at(node, 20, 5)
        first, _ = await _link(node, twin_id)
        second, _ = await _link(node, twin_id)
        node._prune_idle_links()
        assert first in node._peers and second in node._peers
        await node.stop()

    async def test_a_node_whose_leaf_we_probably_are_is_left_alone(self):
        node, made = await _node()
        other = _at(node, 20, 5)
        extra, _ = await _link(node, other)
        del node._likely_in_their_leaf          # the real rule
        node._leaf_size = 3
        # fewer than three known nodes nearer to it than we are
        node._routing.add(NodeID((int.from_bytes(other.raw, "big") ^ 1).to_bytes(20, "big")),
                          ["fake://a"], b"k")
        node._prune_idle_links()
        assert extra in node._peers
        await node.stop()

    async def test_a_node_that_is_not_near_us_is_closed(self):
        node, made = await _node()
        other = _at(node, 20, 5)
        extra, _ = await _link(node, other)
        del node._likely_in_their_leaf          # the real rule
        for low in (1, 2, 3):
            node._routing.add(NodeID((int.from_bytes(other.raw, "big") ^ low).to_bytes(20, "big")),
                              [f"fake://n{low}"], b"k")
        node._prune_idle_links()
        assert extra not in node._peers
        await node.stop()

    async def test_few_links_are_never_pruned(self):
        node, made = await _node(links=3)
        node._leaf_size = 8
        extra, _ = await _link(node, _at(node, 5))
        node._prune_idle_links()
        assert extra in node._peers
        await node.stop()

    async def test_zero_minutes_means_never(self):
        node, made = await _node()
        node._link_idle = 0.0
        extra, _ = await _link(node, _at(node, 20, 5))
        node._prune_idle_links()
        assert extra in node._peers
        await node.stop()

    async def test_a_sweep_closes_a_bounded_number(self):
        node, made = await _node(links=4)
        node._leaf_size = 2
        for low in range(1, 9):
            await _link(node, _at(node, 22, low))
        before = len(node._peers)
        for low in (1, 2, 3):          # make them all "not near" for the other end
            pass
        node._leaf_size = 2
        node._prune_idle_links()
        assert before - len(node._peers) <= nodemod._PRUNE_PER_SWEEP
        await node.stop()


class TestClosingOnPurpose:
    async def test_a_peer_that_understands_is_told_and_one_that_does_not_is_not(self):
        node, made = await _node()
        told, told_fake = await _link(node, _at(node, 20, 5), announces=True)
        silent, silent_fake = await _link(node, _at(node, 20, 6), announces=False)
        node._prune_idle_links()
        await asyncio.sleep(0.2)
        assert [p.type for p in told_fake.sent].count(LINK_RELEASE) == 1
        assert LINK_RELEASE not in [p.type for p in silent_fake.sent]
        await node.stop()

    async def test_it_is_not_chased_by_the_node_that_closed_it(self):
        node, made = await _node()
        extra, _ = await _link(node, _at(node, 20, 5))
        node._prune_idle_links()
        assert extra.authenticated_id not in node._reconnect
        assert extra.authenticated_id in node._idle_closed
        await node.stop()

    async def test_the_book_of_closed_links_is_bounded(self):
        node, made = await _node()
        for _ in range(nodemod._IDLE_CLOSED_MAX + 50):
            node._idle_closed[NodeID(os.urandom(20))] = time.monotonic()
            while len(node._idle_closed) > nodemod._IDLE_CLOSED_MAX:
                node._idle_closed.popitem(last=False)
        extra, _ = await _link(node, _at(node, 20, 5))
        node._prune_idle_links()
        assert len(node._idle_closed) <= nodemod._IDLE_CLOSED_MAX
        await node.stop()

    async def test_a_link_that_comes_back_is_not_ours_to_close(self):
        node = MeshNode(transport_manager=make_manager())
        other = NodeID(os.urandom(20))
        node._idle_closed[other] = time.monotonic()
        peer, _ = await _link(node, other)
        node._log_link_up(peer, "x")
        assert peer.peer_wants is True and other not in node._idle_closed
        stranger, _ = await _link(node, NodeID(os.urandom(20)))
        node._log_link_up(stranger, "x")
        assert stranger.peer_wants is False
        await node.stop()

    async def test_a_long_ago_closed_link_is_forgotten(self):
        node = MeshNode(transport_manager=make_manager())
        other = NodeID(os.urandom(20))
        node._idle_closed[other] = time.monotonic() - nodemod._PEER_WANTS_TTL - 1
        peer, _ = await _link(node, other)
        node._log_link_up(peer, "x")
        assert peer.peer_wants is False
        await node.stop()


class TestBeingToldItWasOnPurpose:
    async def test_a_release_marks_the_link(self):
        node = MeshNode(transport_manager=make_manager())
        peer, _ = await _link(node, NodeID(os.urandom(20)))
        await node._handle_link_release(peer, Packet.create(
            LINK_RELEASE, peer.authenticated_id.raw, node.id.raw, b""))
        assert peer.released is True
        await node.stop()

    async def test_a_release_that_carries_something_is_charged_and_ignored(self):
        node = MeshNode(transport_manager=make_manager())
        peer, _ = await _link(node, NodeID(os.urandom(20)))
        await node._handle_link_release(peer, Packet.create(
            LINK_RELEASE, peer.authenticated_id.raw, node.id.raw, b"x" * 10))
        assert peer.released is False
        await node.stop()

    async def test_a_release_before_authentication_is_ignored(self):
        node = MeshNode(transport_manager=make_manager())
        fake = FakeTransport()
        peer = await node._inject_peer(fake)
        await node._handle_link_release(peer, Packet.create(
            LINK_RELEASE, os.urandom(20), node.id.raw, b""))
        assert peer.released is False
        await node.stop()

    async def test_a_released_link_that_ends_is_not_chased(self):
        node = MeshNode(transport_manager=make_manager())
        other = NodeID(os.urandom(20))
        node._running = True
        gone, _ = await _link(node, other)
        gone.released = True
        node._peers.remove(gone)
        node._note_node_lost(gone)
        assert other not in node._reconnect
        lost, _ = await _link(node, NodeID(os.urandom(20)))
        node._peers.remove(lost)
        node._note_node_lost(lost)
        assert lost.authenticated_id in node._reconnect, "a loss is still chased"
        node._running = False
        await node.stop()


class TestTheBudget:
    async def test_it_is_bounded(self):
        node = MeshNode(transport_manager=make_manager())
        for bad in ({"leaf_size": 1}, {"leaf_size": 33}, {"finger_links": 0},
                    {"finger_links": 5}, {"idle_minutes": -1}, {"idle_minutes": 1441}):
            args = {"leaf_size": 8, "finger_links": 2, "idle_minutes": 10, **bad}
            with pytest.raises(ValueError):
                node.set_link_budget(**args)
        assert node.set_link_budget(leaf_size=4, finger_links=1, idle_minutes=0) == {
            "leaf_size": 4, "finger_links": 1, "idle_minutes": 0}
        assert node._link_idle == 0.0
        await node.stop()
