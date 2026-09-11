"""
Replacing a link that is losing too much to still be one.

The gap this closes sits between two things that already worked. Scoring loss
keeps a rotten link out of the traffic (`test_link_choice.py`), and
`_reap_silent_links` cuts one that answers **nothing** (`test_reconnect.py`).
Neither touches the link an operator actually complains about: it answers four
probes in five, so it is never cut — and when it is the only link to that node,
a score has nothing to prefer over it. Nothing dialled anything, and getting a
working link back meant pressing "retry every address" by hand, again and
again.

What is proved here: the threshold is read off the *recent* window and never
off the lifetime share; an identity reached by a second, working link is not
rescued; the rescue dials that identity's addresses — the one in use included,
because a half-open connection is repaired by a new connection and not by a
different address — keeps whichever link `_link_score` prefers, and never
leaves two standing; and every bound holds, because this is a loop that a
peer's behaviour starts.
"""
import asyncio
import time

import pytest

from src.metrics import LinkQuality
from src.node import (MeshNode, _Peer, _LOSS_RESCUE_PROBES, _LOSS_RESCUE_SHARE,
                      _RESCUE_MAX, _RESCUE_MIN, _RESCUE_TRACKED)
from src.node_id import NodeID
from tests.conftest import FakeTransport, make_manager


TARGET = NodeID(b"\x11" * 20)
OTHER = NodeID(b"\x22" * 20)


def _node() -> MeshNode:
    node = MeshNode(transport_manager=make_manager())
    node._running = True
    return node


def _probed(loss: float, probes: int = _LOSS_RESCUE_PROBES * 2) -> LinkQuality:
    """A probe history as the recent window records one: an outcome per probe,
    a round trip or nothing at all."""
    quality = LinkQuality()
    lost = round(probes * loss)
    for index in range(probes):
        quality.sent(index, 0.0)
        if index >= lost:
            quality.answered(index, 0.01)
    quality.expire(1000.0, 1.0)          # the rest never came back
    return quality


def _link(node: MeshNode, target: NodeID, *, uri: str = "fake://a:1",
          loss: float = 0.0, rtt_ms: float = 10.0) -> _Peer:
    peer = _Peer(FakeTransport(), is_client_side=True)
    peer.authenticated_id = target
    peer.session = object()
    peer.remote_addr = uri
    peer.quality = _probed(loss)
    peer.last_rtt = rtt_ms / 1000.0
    node._peers.append(peer)
    return peer


def _dials(node: MeshNode, *, answer=None) -> list[str]:
    """Record what is dialled, and hand back what `answer` decides."""
    seen: list[str] = []

    async def _fake_dial(node_id, uri, timeout, *, probe=False):
        seen.append(uri)
        peer = None if answer is None else answer(node_id, uri)
        if peer is not None:
            peer.probation = probe
        return peer

    node._dial_uri = _fake_dial
    return seen


def _measures(node: MeshNode, ms) -> None:
    """Skip the real probes: `_measure_peer` is `test_address_retry.py`'s."""
    async def _fake(peer):
        return ms(peer)

    node._measure_peer = _fake


class TestWhatCountsAsFailing:
    def test_the_recent_window_decides_not_the_lifetime_share(self):
        """A link that worked all afternoon and broke ten minutes ago still
        shows a lifetime share near zero — a thousand good probes outvote the
        dead ones — which is exactly the complaint."""
        node = _node()
        peer = _link(node, TARGET)
        for index in range(2000):
            peer.quality.sent(("old", index), 0.0)
            peer.quality.answered(("old", index), 0.01)
        for index in range(_LOSS_RESCUE_PROBES * 2):
            peer.quality.sent(("new", index), 0.0)
        peer.quality.expire(10_000.0, 1.0)
        assert peer.quality.loss() < 0.02          # what it has *been*
        assert node._link_is_failing(peer)         # what it *is*

    def test_a_share_under_the_threshold_is_not_failing(self):
        node = _node()
        assert not node._link_is_failing(
            _link(node, TARGET, loss=_LOSS_RESCUE_SHARE / 2))

    def test_a_share_over_it_is(self):
        node = _node()
        assert node._link_is_failing(
            _link(node, TARGET, loss=_LOSS_RESCUE_SHARE + 0.2))

    def test_too_few_probes_is_unknown_and_never_a_verdict(self):
        """A link with three probes behind it has proved nothing either way."""
        node = _node()
        peer = _link(node, TARGET)
        peer.quality = _probed(1.0, probes=_LOSS_RESCUE_PROBES - 1)
        assert not node._link_is_failing(peer)

    def test_a_peer_that_cannot_echo_a_token_is_never_judged(self):
        """Its probes leave no outcomes at all (see `ping`), so there is no
        evidence — and absent evidence is not a bad link."""
        node = _node()
        peer = _link(node, TARGET)
        peer.quality = LinkQuality()
        for _ in range(50):
            peer.quality.on_ping()
        assert peer.quality.loss() == 1.0
        assert not node._link_is_failing(peer)


class TestWhichIdentitiesAreNamed:
    def test_a_failing_link_names_its_identity(self):
        node = _node()
        _link(node, TARGET, loss=0.5)
        node._note_failing_links()
        assert TARGET in node._rescue

    def test_a_node_still_reached_over_a_working_medium_is_left_alone(self):
        """`_link_score` already sends the traffic down the one that works;
        opening a third link fixes nothing and costs a handshake."""
        node = _node()
        _link(node, TARGET, uri="fake://a:1", loss=0.5)
        _link(node, TARGET, uri="udp://a:2", loss=0.0)
        node._note_failing_links()
        assert TARGET not in node._rescue

    def test_an_identity_that_recovered_leaves_the_book(self):
        node = _node()
        peer = _link(node, TARGET, loss=0.5)
        node._note_failing_links()
        assert TARGET in node._rescue
        peer.quality = _probed(0.0)
        node._note_failing_links()
        assert TARGET not in node._rescue

    def test_relayed_measured_and_tarpitted_links_are_not_ours_to_rescue(self):
        for attribute, value in (("relay_only", True), ("probation", True),
                                 ("tarpit_until", time.monotonic() + 60)):
            node = _node()
            peer = _link(node, TARGET, loss=0.9)
            setattr(peer, attribute, value)
            node._note_failing_links()
            assert TARGET not in node._rescue, attribute

    def test_the_book_is_bounded(self):
        """A bad minute across the whole network must not cost memory."""
        node = _node()
        for index in range(_RESCUE_TRACKED + 8):
            _link(node, NodeID(bytes([index + 1]) * 20),
                  uri="fake://a:%d" % index, loss=0.9)
        node._note_failing_links()
        assert len(node._rescue) == _RESCUE_TRACKED


class TestTheRescueItself:
    async def test_it_dials_every_address_including_the_one_in_use(self):
        """A half-open TCP connection and an expired NAT mapping are repaired
        by a *new* connection to the same place, not by a different address."""
        node = _node()
        _link(node, TARGET, uri="fake://a:1", loss=0.5)
        node._routing.add(TARGET, ["fake://a:1", "fake://b:2"])
        seen = _dials(node)
        node._note_failing_links()
        await node._rescue_pass()
        assert seen[:2] == ["fake://a:1", "fake://b:2"]

    async def test_it_stops_at_the_first_address_that_answers(self):
        node = _node()
        _link(node, TARGET, uri="fake://a:1", loss=0.5)
        node._routing.add(TARGET, ["fake://a:1", "fake://b:2"])
        fresh = _Peer(FakeTransport(), is_client_side=True)
        fresh.authenticated_id = TARGET
        fresh.session = object()
        fresh.remote_addr = "fake://a:1"
        seen = _dials(node, answer=lambda node_id, uri: fresh)
        _measures(node, lambda peer: 10.0)
        node._note_failing_links()
        await node._rescue_pass()
        assert seen == ["fake://a:1"]

    async def test_a_fresh_link_replaces_the_failing_one(self):
        node = _node()
        old = _link(node, TARGET, uri="fake://a:1", loss=0.5)
        node._routing.add(TARGET, ["fake://a:1"])
        fresh = _link(node, TARGET, uri="fake://a:1", loss=0.0)
        node._peers.remove(fresh)               # the dial puts it back
        _dials(node, answer=lambda node_id, uri: node._peers.append(fresh) or fresh)
        _measures(node, lambda peer: 10.0)
        node._note_failing_links()
        assert await node._rescue_pass() == 1
        assert old not in node._peers and fresh in node._peers
        assert fresh.probation is False

    async def test_a_worse_candidate_is_the_one_that_goes(self):
        """The node never keeps two links to one peer beyond the measurement,
        whichever way the comparison went."""
        node = _node()
        old = _link(node, TARGET, uri="fake://a:1", loss=0.0, rtt_ms=5)
        old.quality = _probed(0.0)
        node._routing.add(TARGET, ["spool://slow:2"])
        bad = _link(node, TARGET, uri="spool://slow:2", loss=0.9, rtt_ms=4000)
        node._peers.remove(bad)
        _dials(node, answer=lambda node_id, uri: node._peers.append(bad) or bad)
        _measures(node, lambda peer: 5.0 if peer is old else 4000.0)
        node._rescue[TARGET] = None
        assert await node._rescue_pass() == 0
        assert old in node._peers and bad not in node._peers

    async def test_an_incumbent_that_answers_nothing_loses_outright(self):
        """That silence is the entire reason we dialled — steering may wait for
        a better measurement, this may not."""
        node = _node()
        old = _link(node, TARGET, uri="fake://a:1", loss=0.9)
        node._routing.add(TARGET, ["spool://slow:2"])
        fresh = _link(node, TARGET, uri="spool://slow:2", loss=0.0, rtt_ms=4000)
        node._peers.remove(fresh)
        _dials(node, answer=lambda node_id, uri: node._peers.append(fresh) or fresh)
        _measures(node, lambda peer: None if peer is old else 4000.0)
        node._note_failing_links()
        assert await node._rescue_pass() == 1
        assert old not in node._peers and fresh in node._peers

    async def test_a_link_that_died_while_we_dialled_leaves_the_candidate(self):
        node = _node()
        old = _link(node, TARGET, uri="fake://a:1", loss=0.5)
        node._routing.add(TARGET, ["fake://a:1"])
        fresh = _Peer(FakeTransport(), is_client_side=True)
        fresh.authenticated_id = TARGET
        fresh.session = object()
        fresh.remote_addr = "fake://a:1"

        def _answer(node_id, uri):
            old.session = None
            node._peers.remove(old)
            node._peers.append(fresh)
            return fresh

        _dials(node, answer=_answer)
        node._note_failing_links()
        assert await node._rescue_pass() == 1
        assert fresh.probation is False

    async def test_a_node_with_no_known_address_dials_nothing(self):
        node = _node()
        _link(node, TARGET, loss=0.9)
        seen = _dials(node)
        node._note_failing_links()
        assert await node._rescue_pass() == 0
        assert seen == []

    async def test_a_link_that_recovered_between_sweep_and_pass_is_not_dialled(self):
        node = _node()
        peer = _link(node, TARGET, loss=0.9)
        node._routing.add(TARGET, ["fake://a:1"])
        seen = _dials(node)
        node._note_failing_links()
        peer.quality = _probed(0.0)
        assert await node._rescue_pass() == 0
        assert seen == []

    async def test_a_node_whose_link_died_outright_is_the_other_book_s(self):
        """Two loops dialling one node is one too many."""
        node = _node()
        peer = _link(node, TARGET, loss=0.9)
        node._routing.add(TARGET, ["fake://a:1"])
        seen = _dials(node)
        node._note_failing_links()
        node._peers.remove(peer)
        assert await node._rescue_pass() == 0
        assert seen == []


class TestTheBoundsHold:
    async def test_one_identity_per_pass(self):
        """A bad minute on the network must not cost a dial per node."""
        node = _node()
        for index in range(5):
            _link(node, NodeID(bytes([index + 1]) * 20),
                  uri="fake://a:%d" % index, loss=0.9)
            node._routing.add(NodeID(bytes([index + 1]) * 20),
                              ["fake://a:%d" % index])
        seen = _dials(node)
        node._note_failing_links()
        await node._rescue_pass()
        assert len(seen) == 1

    async def test_a_rescue_that_changed_nothing_backs_off(self):
        node = _node()
        _link(node, TARGET, uri="fake://a:1", loss=0.9)
        node._routing.add(TARGET, ["fake://a:1"])
        _dials(node)
        node._note_failing_links()
        await node._rescue_pass()
        assert node._rescue_log[TARGET][0] == 1
        gap = node._rescue_log[TARGET][1] - time.monotonic()
        assert _RESCUE_MIN - 1 <= gap <= _RESCUE_MIN + 1

        seen = _dials(node)
        node._note_failing_links()
        assert await node._rescue_pass() == 0
        assert seen == []               # serving the backoff, not dialling

    def test_the_backoff_doubles_to_a_ceiling_and_the_log_is_bounded(self):
        node = _node()
        for _ in range(12):
            node._note_rescue(TARGET, False)
        assert node._rescue_log[TARGET][1] - time.monotonic() <= _RESCUE_MAX + 1
        for index in range(_RESCUE_TRACKED + 8):
            node._note_rescue(NodeID(bytes([index + 1]) * 20), False)
        assert len(node._rescue_log) <= _RESCUE_TRACKED

    def test_a_rescue_that_worked_clears_the_backoff(self):
        node = _node()
        node._note_rescue(TARGET, False)
        node._note_rescue(TARGET, True)
        assert TARGET not in node._rescue_log


class TestTheLoop:
    async def test_a_dial_that_raises_does_not_kill_it(self):
        """This loop dying would be a silent loss of recovery, in the state an
        operator notices last."""
        node = _node()
        calls = []

        async def _boom(node_id, uri, timeout, *, probe=False):
            calls.append(uri)
            raise OSError("no route")

        node._dial_uri = _boom
        _link(node, TARGET, uri="fake://a:1", loss=0.9)
        node._routing.add(TARGET, ["fake://a:1"])
        node._note_failing_links()
        node._ensure_link_rescue()
        node._rescue_wakeup.set()
        try:
            deadline = time.monotonic() + 5.0
            while not calls and time.monotonic() < deadline:
                await asyncio.sleep(0.05)
            task = node._rescue_task
            assert task is not None and not task.done()
        finally:
            await node._stop_link_rescue()
        assert calls

    async def test_an_empty_book_waits_rather_than_ticking(self):
        node = _node()
        node._ensure_link_rescue()
        try:
            await asyncio.sleep(0.1)
            assert not node._rescue
        finally:
            await node._stop_link_rescue()
