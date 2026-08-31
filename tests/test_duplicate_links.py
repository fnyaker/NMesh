"""
One node, one link per medium.

Two nodes that dial each other at the same moment used to end up with two links
each — same pair, same transport, both authenticated, both kept, because nothing
ever looked. The console showed one node twice on one port and half the traffic
went down a link the other end was not using.

What is proved here is the rule that settles it without an exchange: the
canonical link is the one dialled by the **larger** node id, so both ends reach
the same answer from the same two numbers, and neither drops the link the other
kept.
"""
import asyncio

import pytest

from src.node import MeshNode, _Peer
from src.node_id import NodeID
from tests.conftest import FakeTransport, make_manager


def _node() -> MeshNode:
    return MeshNode(transport_manager=make_manager())


def _link(node: MeshNode, target: NodeID, *, outbound: bool,
          uri: str = "fake://a:1", at: float | None = None) -> _Peer:
    """An authenticated link to ``target``, as the handshake would leave it."""
    peer = _Peer(FakeTransport(), is_client_side=outbound)
    peer.authenticated_id = target
    peer.session = object()
    peer.remote_addr = uri
    if at is not None:
        peer.connected_at = at
    node._peers.append(peer)
    return peer


def _bigger_than(node: MeshNode) -> NodeID:
    return NodeID(b"\xff" * 20) if node.id.raw < b"\xff" * 20 else NodeID(b"\x00" * 20)


def _smaller_than(node: MeshNode) -> NodeID:
    return NodeID(b"\x00" * 20) if node.id.raw > b"\x00" * 20 else NodeID(b"\xff" * 20)


class TestWhichLinkSurvives:
    def test_one_link_is_never_redundant(self):
        node = _node()
        peer = _link(node, _bigger_than(node), outbound=True)
        assert node._redundant_links(peer) == []

    def test_the_larger_id_dials(self):
        """We are the smaller one, so the link *they* dialled is the keeper —
        which on this side is the inbound one."""
        node = _node()
        target = _bigger_than(node)
        mine = _link(node, target, outbound=True)
        theirs = _link(node, target, outbound=False, uri="fake://b:2")
        assert node._redundant_links(theirs) == [mine]

    def test_the_smaller_id_answers(self):
        node = _node()
        target = _smaller_than(node)
        mine = _link(node, target, outbound=True)
        theirs = _link(node, target, outbound=False, uri="fake://b:2")
        assert node._redundant_links(mine) == [theirs]

    def test_both_ends_agree(self):
        """The whole point. One pair, two physical links, each seen from both
        sides — and the two nodes must name the same survivor, or the pair ends
        up with none."""
        left, right = _node(), _node()
        # "L" is the link left dialled, "R" the one right dialled. Each is
        # outbound on the side that opened it and inbound on the other.
        left_L = _link(left, right.id, outbound=True, uri="L")
        _link(left, right.id, outbound=False, uri="R")
        right_L = _link(right, left.id, outbound=False, uri="L")
        _link(right, left.id, outbound=True, uri="R")
        dropped_left = _uris(left._redundant_links(left_L))
        dropped_right = _uris(right._redundant_links(right_L))
        assert dropped_left == dropped_right
        assert len(dropped_left) == 1
        # And the survivor is the one the larger id dialled.
        assert dropped_left == ["R" if left.id.raw > right.id.raw else "L"]

    def test_two_links_the_same_way_round_keep_the_older_one(self):
        """We dialled twice. Nothing distinguishes them by direction, so the
        one that was up first wins — an order the far end sees too."""
        node = _node()
        target = _smaller_than(node)          # we are the dialler, both outbound
        _link(node, target, outbound=True, uri="fake://a:1", at=100.0)
        newer = _link(node, target, outbound=True, uri="fake://b:2", at=200.0)
        assert node._redundant_links(newer) == [newer]

    def test_a_second_medium_is_not_a_duplicate(self):
        """A node reached over two transports holds one link on each, and that
        is the design rather than an accident."""
        node = _node()
        target = _bigger_than(node)
        _link(node, target, outbound=True, uri="fake://a:1")
        other = _link(node, target, outbound=False, uri="udp://a:1")
        assert node._redundant_links(other) == []

    def test_a_different_node_is_not_a_duplicate(self):
        node = _node()
        _link(node, NodeID(b"\x01" * 20), outbound=True)
        peer = _link(node, NodeID(b"\x02" * 20), outbound=False)
        assert node._redundant_links(peer) == []

    def test_an_unauthenticated_link_counts_for_nothing(self):
        node = _node()
        target = _bigger_than(node)
        half = _link(node, target, outbound=True)
        half.session = None                     # handshake still in flight
        peer = _link(node, target, outbound=False, uri="fake://b:2")
        assert node._redundant_links(peer) == []

    def test_a_link_under_measurement_is_left_alone(self):
        """Address steering opens a second link on purpose and closes the loser
        itself; choosing for it would break the measurement."""
        node = _node()
        target = _bigger_than(node)
        _link(node, target, outbound=False)
        candidate = _link(node, target, outbound=True, uri="fake://b:2")
        candidate.probation = True
        assert node._redundant_links(candidate) == []
        incumbent = node._peers[0]
        assert node._redundant_links(incumbent) == []

    def test_a_relayed_link_is_never_collapsed(self):
        """A tunnelled peer is not a link on a medium; it has no scheme and no
        port to be a duplicate on."""
        node = _node()
        target = _bigger_than(node)
        _link(node, target, outbound=False)
        virtual = _link(node, target, outbound=True, uri="fake://b:2")
        virtual.relay_only = True
        assert node._redundant_links(node._peers[0]) == []
        assert node._redundant_links(virtual) == []


class TestCollapsing:
    async def test_the_loser_is_closed_and_dropped(self):
        node = _node()
        target = _bigger_than(node)
        mine = _link(node, target, outbound=True)
        theirs = _link(node, target, outbound=False, uri="fake://b:2")
        node._collapse_redundant_links(theirs)
        for _ in range(50):
            if mine not in node._peers:
                break
            await asyncio.sleep(0)
        assert mine not in node._peers
        assert theirs in node._peers

    async def test_collapsing_keeps_the_route_hints_of_the_node(self):
        """The node is still reachable — only one of two links to it went. A
        teardown that forgot the routes through it would cost real traffic."""
        node = _node()
        target = _bigger_than(node)
        via = NodeID(b"\x07" * 20)
        node._route_hints[via] = (target, 0.0)
        mine = _link(node, target, outbound=True)
        theirs = _link(node, target, outbound=False, uri="fake://b:2")
        node._collapse_redundant_links(theirs)
        for _ in range(50):
            if mine not in node._peers:
                break
            await asyncio.sleep(0)
        assert via in node._route_hints


def _uris(peers):
    return sorted(peer.remote_addr for peer in peers)
