"""
Which of a node's links carries the traffic.

A node may be reached over several media at once, and they are not equally
good: one of them may be losing every probe. Every place that had to pick one
wrote ``next(p for p in self._peers if p.authenticated_id == …)`` — *the first
one opened*, which with two links is a coin toss, and half the traffic went
down the dead one.

What is proved here is the rule that replaced it: one score, loss multiplying
rather than shifting, and a link nothing comes back from never chosen while
anything else exists.
"""
import pytest

from src.metrics import LinkQuality
from src.node import MeshNode, _Peer, _LOSS_PENALTY_EXP
from src.node_id import NodeID
from tests.conftest import FakeTransport, make_manager


def _node() -> MeshNode:
    return MeshNode(transport_manager=make_manager())


def _link(node: MeshNode, target: NodeID, uri: str, *,
          rtt_ms: float | None = None, pings: int = 0, pongs: int = 0) -> _Peer:
    """An authenticated link, with the probe history a real one would have."""
    peer = _Peer(FakeTransport(), is_client_side=True)
    peer.authenticated_id = target
    peer.session = object()
    peer.remote_addr = uri
    quality = LinkQuality()
    for _ in range(pings):
        quality.on_ping()
    for _ in range(pongs):
        quality.on_pong((rtt_ms or 10.0) / 1000.0)
    peer.quality = quality
    peer.last_rtt = None if rtt_ms is None else rtt_ms / 1000.0
    node._peers.append(peer)
    return peer


TARGET = NodeID(b"\x11" * 20)


class TestLossIsPenalising:
    def test_an_unproven_link_is_neither_rewarded_nor_punished(self):
        """Fewer than two probes is not "no loss" and not "all of it"."""
        node = _node()
        peer = _link(node, TARGET, "fake://a:1", rtt_ms=10, pings=1, pongs=1)
        assert node._loss_factor(peer) == 1.0

    def test_a_clean_link_pays_nothing(self):
        node = _node()
        peer = _link(node, TARGET, "fake://a:1", rtt_ms=10, pings=10, pongs=10)
        assert node._loss_factor(peer) == 1.0

    def test_losing_everything_scores_zero(self):
        node = _node()
        peer = _link(node, TARGET, "fake://a:1", pings=10, pongs=0)
        assert node._loss_factor(peer) == 0.0
        assert node._link_score(peer) == 0.0

    def test_loss_multiplies_rather_than_shifts(self):
        """One probe in ten lost has to cost more than any latency difference a
        real network produces, or a fast lossy link keeps winning."""
        node = _node()
        peer = _link(node, TARGET, "fake://a:1", rtt_ms=10, pings=10, pongs=9)
        assert node._loss_factor(peer) == pytest.approx(0.9 ** _LOSS_PENALTY_EXP)
        # A tenth lost costs about a third of the score…
        assert node._loss_factor(peer) < 0.7
        # …and the cost keeps growing, never flattening out.
        worse = _link(node, TARGET, "fake://b:2", rtt_ms=10, pings=10, pongs=5)
        assert node._loss_factor(worse) < node._loss_factor(peer) / 5


class TestPickingTheLink:
    def test_a_dead_link_is_never_chosen_over_a_live_one(self):
        """The case from the console: tcp healthy, udp at 100% loss, both up."""
        node = _node()
        dead = _link(node, TARGET, "udp://host:2", pings=12, pongs=0)
        alive = _link(node, TARGET, "fake://host:1", rtt_ms=40, pings=12, pongs=12)
        assert node._link_to(TARGET) is alive
        assert node._authenticated_peers() == [alive]
        assert dead in node._peers          # still there, still shown

    def test_the_dead_one_first_in_the_list_changes_nothing(self):
        """It used to be whichever was opened first."""
        node = _node()
        _link(node, TARGET, "udp://host:2", pings=12, pongs=0)
        alive = _link(node, TARGET, "fake://host:1", rtt_ms=200, pings=12, pongs=12)
        assert node._link_to(TARGET) is alive

    def test_a_slower_clean_link_beats_a_fast_lossy_one(self):
        node = _node()
        lossy = _link(node, TARGET, "fake://a:1", rtt_ms=5, pings=20, pongs=14)
        clean = _link(node, TARGET, "fake://b:2", rtt_ms=90, pings=20, pongs=20)
        assert node._link_score(clean) > node._link_score(lossy)
        assert node._link_to(TARGET) is clean

    def test_latency_still_decides_between_two_clean_links(self):
        node = _node()
        _link(node, TARGET, "fake://slow:1", rtt_ms=200, pings=20, pongs=20)
        quick = _link(node, TARGET, "fake://quick:2", rtt_ms=5, pings=20, pongs=20)
        assert node._link_to(TARGET) is quick

    def test_excluding_the_best_falls_back_to_the_next(self):
        node = _node()
        best = _link(node, TARGET, "fake://a:1", rtt_ms=5, pings=9, pongs=9)
        other = _link(node, TARGET, "fake://b:2", rtt_ms=50, pings=9, pongs=9)
        assert node._link_to(TARGET, exclude=best) is other

    def test_an_unauthenticated_link_is_not_a_candidate(self):
        node = _node()
        half = _link(node, TARGET, "fake://a:1", rtt_ms=1, pings=9, pongs=9)
        half.session = None
        alive = _link(node, TARGET, "fake://b:2", rtt_ms=90, pings=9, pongs=9)
        assert node._link_to(TARGET) is alive

    def test_no_link_is_no_answer(self):
        assert _node()._link_to(TARGET) is None

    def test_one_entry_per_node_and_the_order_is_stable(self):
        """A list on a screen must not reshuffle because two links swapped
        rank, so identities keep the order they were first seen in."""
        node = _node()
        first, second = NodeID(b"\x01" * 20), NodeID(b"\x02" * 20)
        _link(node, first, "fake://a:1", rtt_ms=90, pings=9, pongs=9)
        _link(node, second, "fake://b:1", rtt_ms=5, pings=9, pongs=9)
        _link(node, first, "fake://a:2", rtt_ms=5, pings=9, pongs=9)
        chosen = node._authenticated_peers()
        assert [peer.authenticated_id for peer in chosen] == [first, second]
        assert chosen[0].remote_addr == "fake://a:2"    # the better of the two


class TestSteering:
    def test_a_lossy_incumbent_is_worth_leaving(self):
        """Steering exists to move off a bad link; if loss did not count there,
        the one link it most needs to leave is the one it never would."""
        node = _node()
        lossy = _link(node, TARGET, "fake://a:1", rtt_ms=10, pings=20, pongs=10)
        candidate = _link(node, TARGET, "fake://b:2", rtt_ms=12, pings=4, pongs=4)
        gain = (node._address_score("fake://b:2", 12) * node._loss_factor(candidate)
                - node._address_score("fake://a:1", 10) * node._loss_factor(lossy))
        from src.node import _ADDR_STEER_MIN_GAIN
        assert gain >= _ADDR_STEER_MIN_GAIN
