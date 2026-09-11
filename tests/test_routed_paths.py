"""
Reaching a node through another node, measured rather than assumed.

A direct link is probed, scored and replaced when it stops working. A routed
path had none of that: the first hop was whichever peer traffic from that id
last arrived through, then XOR distance, and a relay that accepted a packet and
dropped it was indistinguishable from one that delivered it — `peer.send()`
returns either way. So nothing noticed and nothing retried, and a node that had
been reachable a minute ago simply stopped answering until somebody made a
direct link by hand.

What is proved here: a path answers the same three questions a link does; a run
of unanswered probes gives up on it rather than a share that cannot move fast
enough to notice; the book is bounded on both axes and follows what the node is
actually talking to; a first hop we have measured leads over one we guessed;
and a link going away takes its paths with it rather than leaving the send path
resolving them to nothing, once per packet.
"""
import asyncio
import time

import pytest

from src import routed
from src.node import (MeshNode, NodeID, _Peer, _PATH_PROBE_INTERVAL,
                      _PATH_PROBES_PER_PASS, _PATH_PROBE_TIMEOUT)
from tests.conftest import FakeTransport, make_manager


TARGET = NodeID(b"\x11" * 20)
VIA_A = NodeID(b"\xa0" * 20)
VIA_B = NodeID(b"\xb0" * 20)
VIA_C = NodeID(b"\xc0" * 20)


def _node() -> MeshNode:
    node = MeshNode(transport_manager=make_manager())
    node._running = True
    return node


def _link(node: MeshNode, target: NodeID, *, uri: str = "fake://a:1") -> _Peer:
    peer = _Peer(FakeTransport(), is_client_side=True)
    peer.authenticated_id = target
    peer.session = object()
    peer.remote_addr = uri
    node._peers.append(peer)
    return peer


def _answer(path: routed.Path, n: int = 5, rtt: float = 0.02) -> routed.Path:
    for index in range(n):
        token = (id(path), index)
        path.sent(token, 0.0)
        path.answered(token, rtt)
    return path


def _silence(path: routed.Path, n: int = routed.DEAD_PROBES) -> routed.Path:
    for index in range(n):
        path.sent(("lost", id(path), index), 0.0)
    path.quality.expire(1000.0, 1.0)
    return path


class TestAPathIsJudgedLikeALink:
    def test_a_run_of_silence_gives_up_on_it(self):
        """A run, never a share: the lifetime share of a path that worked for
        an hour cannot rise fast enough to notice that it stopped, which is the
        whole of what this has to notice."""
        path = routed.Path(TARGET, VIA_A)
        _answer(path, 200)
        assert not path.dead()
        _silence(path)
        assert path.dead()
        assert path.loss() is not None and path.loss() > 0

    def test_one_missed_probe_is_not_a_dead_path(self):
        path = _answer(routed.Path(TARGET, VIA_A), 10)
        _silence(path, routed.DEAD_PROBES - 1)
        assert not path.dead()

    def test_an_unproven_path_is_not_a_bad_one(self):
        path = routed.Path(TARGET, VIA_A)
        assert path.unproven() and not path.dead()

    def test_loss_is_read_off_the_recent_window(self):
        path = routed.Path(TARGET, VIA_A)
        _answer(path, 200)
        _silence(path, 10)
        assert path.quality.loss() < 0.1          # what it has been
        assert path.loss() > 0.1                  # what it is


class TestTheBook:
    def test_the_best_path_leads(self):
        book = routed.PathBook()
        slow = _answer(book.ensure(TARGET, VIA_A), 10, rtt=0.400)
        quick = _answer(book.ensure(TARGET, VIA_B), 10, rtt=0.010)
        assert book.paths(TARGET)[0] is quick and slow in book.paths(TARGET)

    def test_a_lossy_path_loses_to_a_slower_clean_one(self):
        book = routed.PathBook()
        lossy = book.ensure(TARGET, VIA_A)
        _answer(lossy, 10, rtt=0.005)
        _silence(lossy, 6)
        clean = _answer(book.ensure(TARGET, VIA_B), 16, rtt=0.200)
        assert book.paths(TARGET)[0] is clean

    def test_an_unproven_path_sorts_last_but_is_never_excluded(self):
        """It is how a path becomes proven."""
        book = routed.PathBook()
        _answer(book.ensure(TARGET, VIA_A), 10)
        fresh = book.ensure(TARGET, VIA_B)
        assert book.paths(TARGET)[-1] is fresh
        assert fresh in book.live(TARGET)

    def test_a_dead_path_is_not_offered_and_is_reaped(self):
        book = routed.PathBook()
        dead = _silence(book.ensure(TARGET, VIA_A))
        good = _answer(book.ensure(TARGET, VIA_B), 5)
        assert book.live(TARGET) == [good]
        assert book.reap(TARGET) == [dead]
        assert book.paths(TARGET) == [good]

    def test_both_axes_are_bounded(self):
        book = routed.PathBook(max_targets=2, max_per_target=2)
        for index in range(6):
            target = NodeID(bytes([index + 1]) * 20)
            book.note_interest(target)
            for via in (VIA_A, VIA_B, VIA_C):
                book.ensure(target, via)
        assert len(book.targets()) <= 2
        for target in book.targets():
            assert len(book.paths(target)) <= 2

    def test_interest_decides_what_is_kept(self):
        book = routed.PathBook(max_targets=2)
        for index in range(4):
            book.note_interest(NodeID(bytes([index + 1]) * 20))
        warm = book.warm()
        assert len(warm) == 2
        assert warm[0] == NodeID(b"\x04" * 20)     # most recent first

    def test_interest_lapses(self):
        book = routed.PathBook(interest_ttl=10.0)
        book.note_interest(TARGET, now=0.0)
        book.ensure(TARGET, VIA_A)
        assert book.warm(now=5.0) == [TARGET]
        assert book.warm(now=100.0) == []
        assert not book.has(TARGET)

    def test_forgetting_a_first_hop_drops_every_path_through_it(self):
        book = routed.PathBook()
        other = NodeID(b"\x33" * 20)
        book.ensure(TARGET, VIA_A)
        book.ensure(other, VIA_A)
        book.ensure(other, VIA_B)
        assert book.forget_via(VIA_A) == 2
        assert not book.has(TARGET)
        assert [p.via for p in book.paths(other)] == [VIA_B]

    def test_has_is_false_for_an_id_we_route_nothing_to(self):
        """The send path asks it per packet, and this is the usual answer."""
        assert routed.PathBook().has(TARGET) is False


class TestTheSendPathPrefersWhatItMeasured:
    def test_a_measured_first_hop_leads_over_the_hint(self):
        node = _node()
        _link(node, VIA_A)
        hinted = _link(node, VIA_B)
        node._route_hints[TARGET] = (VIA_B, time.monotonic())
        node._paths.note_interest(TARGET)
        _answer(node._paths.ensure(TARGET, VIA_A), 5)
        candidates = node._route_candidates(TARGET)
        assert candidates[0].authenticated_id == VIA_A
        assert hinted in candidates            # still a fallback, not discarded

    def test_the_hint_still_leads_when_nothing_is_measured(self):
        node = _node()
        _link(node, VIA_A)
        _link(node, VIA_B)
        node._route_hints[TARGET] = (VIA_B, time.monotonic())
        assert node._route_candidates(TARGET)[0].authenticated_id == VIA_B

    def test_a_direct_link_still_leads_over_everything(self):
        node = _node()
        direct = _link(node, TARGET)
        _link(node, VIA_A)
        node._paths.note_interest(TARGET)
        _answer(node._paths.ensure(TARGET, VIA_A), 5)
        assert node._route_candidates(TARGET)[0] is direct

    def test_a_dead_path_is_not_sent_down_while_another_exists(self):
        node = _node()
        _link(node, VIA_A)
        _link(node, VIA_B)
        node._paths.note_interest(TARGET)
        _silence(node._paths.ensure(TARGET, VIA_A))
        _answer(node._paths.ensure(TARGET, VIA_B), 5)
        assert node._route_candidates(TARGET)[0].authenticated_id == VIA_B

    def test_a_path_through_a_link_we_no_longer_hold_resolves_to_nothing(self):
        node = _node()
        node._paths.note_interest(TARGET)
        _answer(node._paths.ensure(TARGET, VIA_A), 5)
        assert node._measured_first_hops(TARGET) == []

    async def test_a_link_dying_takes_its_paths_with_it(self):
        node = _node()
        peer = _link(node, VIA_A)
        node._paths.note_interest(TARGET)
        node._paths.ensure(TARGET, VIA_A)
        await node._reap_peer(peer)
        assert not node._paths.has(TARGET)

    def test_a_send_that_fails_takes_them_too(self):
        node = _node()
        peer = _link(node, VIA_A)
        node._paths.note_interest(TARGET)
        node._paths.ensure(TARGET, VIA_A)
        node._drop_failed_peer(peer)
        assert not node._paths.has(TARGET)


class TestProbing:
    def _probes(self, node: MeshNode, answer=lambda path: True) -> list:
        seen = []

        async def _fake(path):
            seen.append(path)
            return answer(path)

        node._probe_path = _fake
        return seen

    async def test_a_pass_opens_a_path_for_an_id_with_none(self):
        node = _node()
        _link(node, VIA_A)
        node._paths.note_interest(TARGET)
        seen = self._probes(node)
        await node._path_pass()
        assert [p.via for p in seen] == [VIA_A]

    async def test_one_new_path_per_identity_per_pass(self):
        """Opening three at once is three probes for an id we may never route
        to again."""
        node = _node()
        for via in (VIA_A, VIA_B, VIA_C):
            _link(node, via, uri="fake://%s:1" % via.raw[:1].hex())
        node._paths.note_interest(TARGET)
        seen = self._probes(node)
        await node._path_pass()
        assert len(seen) == 1

    async def test_a_pass_is_bounded(self):
        node = _node()
        _link(node, VIA_A)
        for index in range(_PATH_PROBES_PER_PASS + 4):
            target = NodeID(bytes([index + 20]) * 20)
            node._paths.note_interest(target)
        seen = self._probes(node)
        await node._path_pass()
        assert len(seen) == _PATH_PROBES_PER_PASS

    async def test_a_healthy_path_is_re_probed_on_its_interval(self):
        node = _node()
        _link(node, VIA_A)
        node._paths.note_interest(TARGET)
        path = node._paths.ensure(TARGET, VIA_A)
        path.probed_at = time.monotonic()
        seen = self._probes(node)
        await node._path_pass()
        assert seen == []
        path.probed_at = time.monotonic() - _PATH_PROBE_INTERVAL - 1
        await node._path_pass()
        assert seen == [path]

    async def test_an_unanswered_probe_is_charged_as_lost(self):
        """Without it the window only ever grows by answers, so a broken path
        reads as a quiet one."""
        node = _node()
        node._paths.note_interest(TARGET)
        path = node._paths.ensure(TARGET, VIA_A)
        path.sent("token", time.monotonic() - _PATH_PROBE_TIMEOUT - 1)
        self._probes(node)
        await node._path_pass()
        assert path.quality.recent_probes() == 1   # an outcome, not an absence
        assert path.quality.since_pong == 1

    async def test_a_path_that_gave_up_is_dropped_by_the_pass(self):
        node = _node()
        _link(node, VIA_A)
        node._paths.note_interest(TARGET)
        _silence(node._paths.ensure(TARGET, VIA_A))
        self._probes(node)
        await node._path_pass()
        assert not any(p.via == VIA_A for p in node._paths.paths(TARGET))

    async def test_a_healthy_direct_link_gets_exactly_one_warm_standby(self):
        """The hybrid: one physical link and one routed path measured at the
        same time, so losing the physical one costs a turn of the send order
        rather than a reconnect. One, not three — nothing is riding on it."""
        from src.node import _PATH_STANDBY_INTERVAL
        node = _node()
        _link(node, TARGET)
        for via in (VIA_A, VIA_B, VIA_C):
            _link(node, via, uri="fake://%s:1" % via.raw[:1].hex())
        node._paths.note_interest(TARGET)
        seen = self._probes(node)
        await node._path_pass()
        assert len(seen) == 1
        standby = seen[0]
        standby.probed_at = time.monotonic()

        # …and it costs far less than the link it stands behind.
        await node._path_pass()
        assert len(seen) == 1
        standby.probed_at = time.monotonic() - _PATH_PROBE_INTERVAL - 1
        await node._path_pass()
        assert len(seen) == 1
        standby.probed_at = time.monotonic() - _PATH_STANDBY_INTERVAL - 1
        await node._path_pass()
        assert len(seen) == 2

    async def test_a_failing_direct_link_wants_every_way_there(self):
        """A standby is what a *healthy* link is owed. One that is losing a
        fifth of its probes is on its way out, and the answer to that is as
        many measured ways there as can be had, as often as they can be had."""
        node = _node()
        direct = _link(node, TARGET)
        node._link_is_failing = lambda peer: peer is direct
        for via in (VIA_A, VIA_B, VIA_C):
            _link(node, via, uri="fake://%s:1" % via.raw[:1].hex())
        node._paths.note_interest(TARGET)
        seen = self._probes(node)
        for _ in range(routed.MAX_PER_TARGET):
            for path in node._paths.paths(TARGET):
                path.probed_at = 0.0
            await node._path_pass()
        assert len(node._paths.paths(TARGET)) == routed.MAX_PER_TARGET

    async def test_the_loop_survives_a_probe_that_raises(self):
        """This loop dying takes failover with it, silently — which is how this
        whole class of failure presented in the first place."""
        node = _node()
        _link(node, VIA_A)
        node._paths.note_interest(TARGET)
        calls = []

        async def _boom(path):
            calls.append(path)
            raise OSError("no route")

        node._probe_path = _boom
        node._ensure_path_probe()
        try:
            node._path_wakeup.set()
            deadline = time.monotonic() + 5.0
            while not calls and time.monotonic() < deadline:
                await asyncio.sleep(0.05)
            task = node._path_task
            assert task is not None and not task.done()
        finally:
            await node._stop_path_probe()
        assert calls

    async def test_a_probe_whose_first_hop_has_gone_drops_the_path(self):
        node = _node()
        node._paths.note_interest(TARGET)
        path = node._paths.ensure(TARGET, VIA_A)
        assert await node._probe_path(path) is False
        assert not node._paths.has(TARGET)

    async def test_giving_up_is_remembered_for_a_while(self):
        """Otherwise the pass that drops a dead path re-opens it on the next
        one: the thing that chose that hop has not changed and cannot."""
        node = _node()
        _link(node, VIA_A)
        node._paths.note_interest(TARGET)
        _silence(node._paths.ensure(TARGET, VIA_A))
        self._probes(node)
        await node._path_pass()
        assert node._paths.shunned(TARGET, VIA_A)
        assert VIA_A not in node._path_first_hops(TARGET)
        await node._path_pass()
        assert not any(p.via == VIA_A for p in node._paths.paths(TARGET))

    def test_giving_up_twice_costs_longer(self):
        book = routed.PathBook()
        _silence(book.ensure(TARGET, VIA_A))
        book.reap(TARGET, now=0.0)
        assert book.shunned(TARGET, VIA_A, now=routed.SHUN_MIN - 1)
        assert not book.shunned(TARGET, VIA_A, now=routed.SHUN_MIN + 1)
        _silence(book.ensure(TARGET, VIA_A))
        book.reap(TARGET, now=0.0)
        assert book.shunned(TARGET, VIA_A, now=routed.SHUN_MIN + 1)

    def test_a_path_that_works_is_forgiven(self):
        book = routed.PathBook()
        _silence(book.ensure(TARGET, VIA_A))
        book.reap(TARGET)
        book.forgive(TARGET, VIA_A)
        assert not book.shunned(TARGET, VIA_A)

    def test_the_shun_book_is_bounded(self):
        book = routed.PathBook(max_targets=routed.MAX_SHUNNED + 20)
        for index in range(routed.MAX_SHUNNED + 20):
            target = NodeID(bytes([index % 250 + 1]) * 20)
            _silence(book.ensure(target, VIA_A))
            book.reap(target)
        assert len(book._shunned) <= routed.MAX_SHUNNED

    async def test_a_probe_sends_an_echo_down_the_first_hop_it_names(self):
        """Forced: `_route_outbound` would pick a hop for itself, and the
        measurement would then be about whatever it picked."""
        from src.node import ECHO_REQUEST
        node = _node()
        peer = _link(node, VIA_A)
        sent = []
        peer.send = lambda packet: sent.append(packet) or asyncio.sleep(0)
        node._paths.note_interest(TARGET)
        path = node._paths.ensure(TARGET, VIA_A)
        await node._probe_path(path)
        assert len(sent) == 1
        assert sent[0].type == ECHO_REQUEST
        assert sent[0].dst_id == TARGET.raw
        assert path.quality.pings == 1


class TestHybridBundles:
    """HMLO: a bundle whose members are a mix.

    A bundle member is a *way to reach an identity*, and there are two kinds —
    a direct link, and a first hop. The bundle never learns which is which: it
    reads the same three numbers off both, and `_member_peer` turns whichever
    it picked back into a link to send down. That is the whole of the hybrid.
    """

    def _enable(self, node: MeshNode) -> None:
        node._mlo_always = True
        node._transport_manager.setting = lambda scheme, name: (
            True if name == "mlo" else None)

    def test_the_turn_is_taken_by_target_not_by_whoever_leads(self):
        """It used to read `peers[0].authenticated_id`, which is the target
        only while the head is a direct link to it — false of every routed
        bundle, where the head is a neighbour that is not the destination."""
        node = _node()
        via = _link(node, VIA_A)
        node._paths.note_interest(TARGET)
        path = _answer(node._paths.ensure(TARGET, VIA_A), 5)
        bundle = node._bundles[TARGET] = _StubBundle([path, path])
        assert node._stripe(TARGET, [via])[0] is via
        assert bundle.asked

    def test_a_routed_member_resolves_to_its_first_hop(self):
        node = _node()
        via = _link(node, VIA_B)
        node._paths.note_interest(TARGET)
        path = _answer(node._paths.ensure(TARGET, VIA_B), 5)
        assert node._member_peer(path) is via

    def test_a_routed_member_whose_hop_has_gone_resolves_to_nothing(self):
        node = _node()
        node._paths.note_interest(TARGET)
        path = node._paths.ensure(TARGET, VIA_B)
        assert node._member_peer(path) is None

    def test_a_direct_member_is_itself(self):
        node = _node()
        peer = _link(node, TARGET)
        assert node._member_peer(peer) is peer
        assert node._member_peer(peer, exclude=peer) is None

    def test_an_identity_reached_only_through_the_mesh_can_be_bundled(self):
        """MRLO. Two measured routed paths and no direct link at all."""
        node = _node()
        self._enable(node)
        _link(node, VIA_A, uri="fake://a:1")
        _link(node, VIA_B, uri="fake://b:1")
        node._paths.note_interest(TARGET)
        _answer(node._paths.ensure(TARGET, VIA_A), 10, rtt=0.020)
        _answer(node._paths.ensure(TARGET, VIA_B), 10, rtt=0.021)
        node._update_bundles()
        bundle = node._bundles.get(TARGET)
        assert bundle is not None and bundle.active

    def test_one_way_there_is_not_a_bundle(self):
        node = _node()
        self._enable(node)
        _link(node, VIA_A)
        node._paths.note_interest(TARGET)
        _answer(node._paths.ensure(TARGET, VIA_A), 10)
        node._update_bundles()
        assert TARGET not in node._bundles

    def test_a_routed_only_identity_is_never_asked_for_a_second_link(self):
        """`_want_second_link` dials an *address* of that identity, and an
        identity we only reach through the mesh has none worth dialling — that
        book is for a node we already hold a link to."""
        node = _node()
        self._enable(node)
        _link(node, VIA_A)
        node._paths.note_interest(TARGET)
        _answer(node._paths.ensure(TARGET, VIA_A), 10)
        node._update_bundles()
        assert TARGET not in node._mlo_short


class _StubBundle:
    """Just enough of `mlo.Bundle` to see which key the send path asked for."""

    def __init__(self, keys):
        self._keys = list(keys)
        self.asked = False

    @property
    def active(self):
        return len(self._keys) > 1

    def next_key(self):
        self.asked = True
        return self._keys[0]
