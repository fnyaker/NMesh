"""
Getting a node back the moment its link dies.

The gap this closes: neighbourhood maintenance dials to *hold three links* and
to promote an XOR-nearer identity. The node a person is actually talking to is
usually neither, so when its link went away nothing dialled it back — the
address-retry loop only runs on media that declared a `retry_interval`, which
is off by default, and on-demand routing only wakes when an app sends again.
A conversation therefore stayed dead until somebody typed into it.

What is proved here: an established link lost *under us* puts its identity in
a book that is chased hard and then patiently — never abandoned, because the
"ordinary machinery" it used to be handed to does not dial on a stock node; a
link we cut ourselves never enters it; losing one of two media to a node is not
losing the node; losing several nodes at once is evidence about *our own*
addressing and re-verifies it; and every bound holds — the book, the dials in
flight, the backoff, the wait between passes, and the cooldown on that
re-verification.
"""
import asyncio
import time

import pytest

from src import revocation
from src.crypto import CryptoIdentity
from src.node import (MeshNode, _Peer, _MAX_MALFORMED, _DEAD_LINK_PROBES,
                      _DEAD_LINK_SILENCE, _LOSS_BURST_COOLDOWN,
                      _LOSS_BURST_NODES, _LOSS_BURST_TRACKED,
                      _LOSS_BURST_WINDOW,
                      _RECONNECT_BACKOFF_MAX, _RECONNECT_FIRST_DELAY,
                      _RECONNECT_MAX_IN_FLIGHT, _RECONNECT_MIN_TICK,
                      _RECONNECT_NODES_TRACKED, _RECONNECT_PATIENT_MAX,
                      _RECONNECT_WINDOW)
from src.node_id import NodeID
from src.reputation import MAX_WEIGHT, OK
from tests.conftest import FakeTransport, make_manager


TARGET = NodeID(b"\x11" * 20)
OTHER = NodeID(b"\x22" * 20)


def _node() -> MeshNode:
    node = MeshNode(transport_manager=make_manager())
    node._running = True
    return node


def _link(node: MeshNode, target: NodeID, *, uri: str = "fake://a:1") -> _Peer:
    """An established link, as the node holds one after a handshake."""
    peer = _Peer(FakeTransport(), is_client_side=True)
    peer.authenticated_id = target
    peer.session = object()
    peer.remote_addr = uri
    node._peers.append(peer)
    return peer


def _go_silent(peer: _Peer) -> _Peer:
    """A link that has answered nothing for long enough to be cut.

    Both halves: the run of unanswered probes *and* the silence it stands for.
    A run alone stopped being a duration once a link could negotiate its own
    cadence — see `_reap_silent_links`."""
    for _ in range(_DEAD_LINK_PROBES):
        peer.quality.on_ping()
    peer.quality.answered_at = time.monotonic() - _DEAD_LINK_SILENCE - 1.0
    return peer


def _lose(node: MeshNode, peer: _Peer) -> None:
    """The link is gone: what every teardown path does before it enrols."""
    if peer in node._peers:
        node._peers.remove(peer)
    node._note_node_lost(peer)


def _dials(node: MeshNode, *, answer=None) -> list[NodeID]:
    """Record what the pass dials, and hand back what `answer` decides."""
    seen: list[NodeID] = []

    async def _fake_route(node_id, timeout=None):
        seen.append(node_id)
        return None if answer is None else answer(node_id)

    node._ensure_route_to = _fake_route
    return seen


class TestWhatEnrols:
    def test_an_established_link_lost_under_us_is_chased(self):
        node = _node()
        _lose(node, _link(node, TARGET))
        assert TARGET in node._reconnect

    def test_the_first_attempt_is_due_within_a_second(self):
        """The whole point: re-establish at once, not on the next 30 s cycle."""
        node = _node()
        _lose(node, _link(node, TARGET))
        _, next_try, _ = node._reconnect[TARGET]
        assert next_try - time.monotonic() <= _RECONNECT_FIRST_DELAY
        assert node._reconnect_wait() <= _RECONNECT_FIRST_DELAY

    def test_a_link_that_never_authenticated_is_nobody(self):
        """No identity, nothing to dial — and a half-open handshake is not a
        node we were talking to."""
        node = _node()
        peer = _link(node, TARGET)
        peer.session = None
        _lose(node, peer)
        assert not node._reconnect

        node = _node()
        peer = _link(node, TARGET)
        peer.authenticated_id = None
        _lose(node, peer)
        assert not node._reconnect

    def test_a_relayed_or_measured_link_is_not_this_node_s_link(self):
        node = _node()
        for attribute in ("relay_only", "probation"):
            peer = _link(node, TARGET)
            setattr(peer, attribute, True)
            _lose(node, peer)
            assert not node._reconnect, attribute

    def test_losing_one_medium_of_two_is_not_losing_the_node(self):
        """tcp and udp to one node: the node is still reached, so there is
        nothing to recover — that is address steering's business, not this."""
        node = _node()
        dead = _link(node, TARGET, uri="udp://host:2")
        _link(node, TARGET, uri="fake://host:1")
        _lose(node, dead)
        assert not node._reconnect

    def test_a_stopped_node_enrols_nothing(self):
        """Teardown tears down: nothing may schedule work past `stop()`."""
        node = _node()
        peer = _link(node, TARGET)
        node._running = False
        _lose(node, peer)
        assert not node._reconnect


class TestWhatWeCutWeDoNotChase:
    """Dialling back a peer we just cut both undoes the cut and tells it what
    we noticed. The feedback is the thing worth taking away."""

    def test_a_tarpitted_link_is_never_dialled_back(self):
        node = _node()
        peer = _link(node, TARGET)
        node._tarpit(peer)
        _lose(node, peer)
        assert not node._reconnect

    def test_a_link_cut_for_noise_is_never_dialled_back(self):
        node = _node()
        peer = _link(node, TARGET)
        for _ in range(_MAX_MALFORMED + 1):
            peer.note_abuse()
        _lose(node, peer)
        assert not node._reconnect

    def test_our_own_evidence_decides_not_the_crowd_s(self):
        """A node *we* judged is not chased. What the crowd says is
        deliberately not asked: if strangers' accusations could stop us
        reconnecting, anybody able to speak could keep two nodes apart."""
        node = _node()
        for _ in range(3):
            node._reputation.note(TARGET, MAX_WEIGHT, "seen ourselves")
        assert node._reputation.standing(TARGET) != OK
        _lose(node, _link(node, TARGET))
        assert not node._reconnect

        node = _node()
        node._reputation.note(OTHER, MAX_WEIGHT, "seen ourselves")
        for index in range(4):
            node._reputation.note_accusation(
                OTHER, NodeID(bytes([200 + index]) * 20), MAX_WEIGHT, "hearsay")
        assert node._reputation.standing(OTHER) != OK          # the crowd's verdict
        assert node._reputation.direct_standing(OTHER) == OK   # not ours
        _lose(node, _link(node, OTHER))
        assert OTHER in node._reconnect


class TestTheBoundsHold:
    def test_a_second_loss_does_not_re_arm_the_backoff(self):
        """A peer that connects and drops would otherwise buy a dial per drop —
        a loop driven by what a peer does, running flat out."""
        node = _node()
        _lose(node, _link(node, TARGET))
        node._reconnect[TARGET] = (4, time.monotonic() + 60.0,
                                   time.monotonic() + _RECONNECT_WINDOW)
        held = node._reconnect[TARGET]
        _lose(node, _link(node, TARGET))
        attempts, next_try, _ = node._reconnect[TARGET]
        assert (attempts, next_try) == (held[0], held[1])

    def test_a_second_loss_does_extend_the_window(self):
        """Losing it again says it is still worth having, so the chase gets its
        full length back — at the cadence it had already reached."""
        node = _node()
        _lose(node, _link(node, TARGET))
        node._reconnect[TARGET] = (4, time.monotonic() + 1.0, time.monotonic() + 1.0)
        _lose(node, _link(node, TARGET))
        assert node._reconnect[TARGET][2] - time.monotonic() > _RECONNECT_WINDOW / 2

    def test_the_book_is_bounded_and_keeps_the_newest(self):
        """A partition that costs every link must not cost memory too."""
        node = _node()
        for index in range(_RECONNECT_NODES_TRACKED + 8):
            node._peers.clear()
            _lose(node, _link(node, NodeID(bytes([index % 256]) * 20)))
        assert len(node._reconnect) == _RECONNECT_NODES_TRACKED
        newest = NodeID(bytes([_RECONNECT_NODES_TRACKED + 7]) * 20)
        assert newest in node._reconnect

    def test_the_wait_never_reaches_zero(self):
        """A pass leaves whatever the in-flight cap did not reach still due, so
        the next wait is computed from an overdue entry."""
        node = _node()
        past = time.monotonic() - 100.0
        for index in range(_RECONNECT_MAX_IN_FLIGHT + 3):
            node._reconnect[NodeID(bytes([index]) * 20)] = (
                0, past, time.monotonic() + _RECONNECT_WINDOW)
        assert node._reconnect_wait() >= _RECONNECT_MIN_TICK

    def test_an_empty_book_waits_instead_of_ticking(self):
        """The longest gap the book can hold, not for ever: `_note_node_lost`
        wakes the loop, and the ceiling only means a missed wake costs a delay
        rather than the feature."""
        node = _node()
        assert node._reconnect_wait() == _RECONNECT_PATIENT_MAX

    async def test_a_pass_dials_no_more_than_the_cap(self):
        node = _node()
        now = time.monotonic()
        for index in range(_RECONNECT_MAX_IN_FLIGHT + 5):
            node._reconnect[NodeID(bytes([index]) * 20)] = (
                0, now, now + _RECONNECT_WINDOW)
        seen = _dials(node)
        await node._reconnect_pass()
        assert len(seen) == _RECONNECT_MAX_IN_FLIGHT


class TestTheSchedule:
    async def test_each_failure_widens_the_gap_up_to_the_ceiling(self):
        node = _node()
        _lose(node, _link(node, TARGET))
        _dials(node)
        gaps = []
        for _ in range(9):
            node._reconnect[TARGET] = (node._reconnect[TARGET][0],
                                       time.monotonic(),
                                       time.monotonic() + _RECONNECT_WINDOW)
            await node._reconnect_pass()
            gaps.append(node._reconnect[TARGET][1] - time.monotonic())
        assert gaps[0] == pytest.approx(_RECONNECT_FIRST_DELAY, abs=0.2)
        assert gaps[1] > gaps[0] and gaps[2] > gaps[1]
        assert max(gaps) <= _RECONNECT_BACKOFF_MAX + 0.01

    async def test_a_dial_that_works_ends_the_chase(self):
        node = _node()
        _lose(node, _link(node, TARGET))
        node._reconnect[TARGET] = (0, time.monotonic(),
                                   time.monotonic() + _RECONNECT_WINDOW)

        def _answer(node_id):
            return _link(node, node_id)

        _dials(node, answer=_answer)
        await node._reconnect_pass()
        assert TARGET not in node._reconnect

    async def test_a_node_reached_by_any_other_path_leaves_the_book(self):
        """An app dialled it, or it dialled us: the pass must notice rather
        than dial a node we already hold a link to."""
        node = _node()
        _lose(node, _link(node, TARGET))
        _link(node, TARGET)
        seen = _dials(node)
        node._reconnect[TARGET] = (0, time.monotonic(),
                                   time.monotonic() + _RECONNECT_WINDOW)
        await node._reconnect_pass()
        assert TARGET not in node._reconnect and seen == []

    async def test_the_chase_slows_down_rather_than_stopping(self):
        """It used to stop, and handed the identity to "the ordinary
        machinery" — the address-retry loop, which runs on no stock node
        (`retry_interval` is 0 on every transport), and on-demand routing,
        which wakes when an app sends. So a peer that came back four minutes
        later stayed unreached until somebody pressed "retry every address"."""
        node = _node()
        _lose(node, _link(node, TARGET))
        node._reconnect[TARGET] = (3, time.monotonic() - 1.0,
                                   time.monotonic() - 0.01)
        seen = _dials(node)
        await node._reconnect_pass()
        assert seen == [TARGET]
        assert TARGET in node._reconnect
        gap = node._reconnect[TARGET][1] - time.monotonic()
        assert gap == pytest.approx(_RECONNECT_PATIENT_MAX, abs=0.5)

    def test_the_patient_cadence_is_flat_and_not_the_ladder_continued(self):
        """An attempt count stands in for elapsed time only while attempts are
        cheap, and a dial on `_RECOVERY_TIMEOUT` is not: the count at the end
        of the window says how expensive the dials were, not how long we have
        been trying."""
        node = _node()
        urgent = [node._reconnect_delay(n, True) for n in range(1, 20)]
        patient = [node._reconnect_delay(n, False) for n in range(1, 20)]
        assert urgent[0] == _RECONNECT_FIRST_DELAY
        assert max(urgent) == _RECONNECT_BACKOFF_MAX
        assert set(patient) == {_RECONNECT_PATIENT_MAX}

    async def test_a_node_still_out_after_an_hour_is_still_being_dialled(self):
        """The whole point of the patient phase, at the cost it is bounded
        to: one dial per identity per `_RECONNECT_PATIENT_MAX`."""
        node = _node()
        _lose(node, _link(node, TARGET))
        seen = _dials(node)
        for _ in range(20):
            node._reconnect[TARGET] = (node._reconnect[TARGET][0],
                                       time.monotonic() - 1.0,
                                       time.monotonic() - 3600.0)
            await node._reconnect_pass()
        assert len(seen) == 20 and TARGET in node._reconnect

    def test_a_handshake_completing_clears_the_chase(self):
        node = _node()
        _lose(node, _link(node, TARGET))
        node._stop_chasing(TARGET)
        assert TARGET not in node._reconnect
        node._stop_chasing(None)            # a link with no identity: no crash


class TestSeveralNodesLostAtOnce:
    """Losing one node says that node went away. Losing three inside twenty
    seconds says what none of the three says alone: they cannot all have gone
    down together, so the thing that moved is *us* — and every address we
    advertise, and every address we dial out of, is suspect."""

    def _pokes(self, node: MeshNode) -> list[tuple]:
        seen: list[tuple] = []
        node._poke_net = lambda reason, urgent=False: seen.append((reason, urgent))
        return seen

    def _lose_many(self, node: MeshNode, count: int) -> None:
        for index in range(count):
            node._peers.clear()
            _lose(node, _link(node, NodeID(bytes([index + 1]) * 20)))

    def test_one_node_is_not_a_burst(self):
        node = _node()
        seen = self._pokes(node)
        self._lose_many(node, _LOSS_BURST_NODES - 1)
        assert seen == []

    def test_enough_of_them_re_verifies_our_own_addresses(self):
        node = _node()
        seen = self._pokes(node)
        self._lose_many(node, _LOSS_BURST_NODES)
        assert seen and seen[-1][1] is True

    def test_the_same_node_flapping_is_one_node(self):
        """Otherwise a single peer reconnecting and dropping would be enough
        to claim our whole addressing moved."""
        node = _node()
        seen = self._pokes(node)
        for _ in range(_LOSS_BURST_NODES + 3):
            node._peers.clear()
            _lose(node, _link(node, TARGET))
        assert seen == []

    def test_losses_spread_out_are_not_simultaneous(self):
        node = _node()
        seen = self._pokes(node)
        self._lose_many(node, _LOSS_BURST_NODES - 1)
        for lost in list(node._recent_losses):
            node._recent_losses[lost] = time.monotonic() - _LOSS_BURST_WINDOW - 1
        node._peers.clear()
        _lose(node, _link(node, OTHER))
        assert seen == []

    def test_a_peer_flapping_cannot_buy_a_probe_per_flap(self):
        """The poke is urgent, which is a shorter bound and not the absence of
        one; this is the second of the two."""
        node = _node()
        seen = self._pokes(node)
        for round_ in range(6):
            node._recent_losses.clear()
            self._lose_many(node, _LOSS_BURST_NODES)
        assert len(seen) == 1
        node._last_loss_burst = time.monotonic() - _LOSS_BURST_COOLDOWN - 1
        node._recent_losses.clear()
        self._lose_many(node, _LOSS_BURST_NODES)
        assert len(seen) == 2

    def test_the_count_is_bounded(self):
        node = _node()
        self._pokes(node)
        self._lose_many(node, _LOSS_BURST_TRACKED + 10)
        assert len(node._recent_losses) <= _LOSS_BURST_TRACKED

    def test_a_link_we_cut_is_not_evidence_about_us(self):
        """`_note_node_lost` filters to genuine involuntary losses before
        counting: a node re-probing STUN every time it cuts an abuser is a
        lever, not a diagnosis."""
        node = _node()
        seen = self._pokes(node)
        for index in range(_LOSS_BURST_NODES + 2):
            node._peers.clear()
            peer = _link(node, NodeID(bytes([index + 1]) * 20))
            peer.tarpit_until = time.monotonic() + 60.0
            _lose(node, peer)
        assert seen == [] and not node._recent_losses


class TestEveryWayALinkDies:
    async def test_a_receive_loop_that_exits_enrols_the_node(self):
        node = _node()
        peer = _link(node, TARGET)
        await node._reap_peer(peer)
        assert TARGET in node._reconnect

    async def test_a_send_that_fails_enrols_the_node(self):
        node = _node()
        peer = _link(node, TARGET)
        node._drop_failed_peer(peer)
        assert TARGET in node._reconnect

    async def test_a_link_that_answers_no_probe_enrols_the_node(self):
        node = _node()
        peer = _link(node, TARGET)
        _go_silent(peer)
        node._reap_silent_links()
        assert TARGET in node._reconnect

    async def test_two_dead_links_to_one_node_still_enrol_it(self):
        """Judged after both are out of the list: each would otherwise see the
        other still listed and call the node reached."""
        node = _node()
        for uri in ("fake://a:1", "udp://a:2"):
            _go_silent(_link(node, TARGET, uri=uri))
        node._reap_silent_links()
        assert TARGET in node._reconnect

    async def test_a_tarpitted_link_reaped_on_its_timer_enrols_nothing(self):
        node = _node()
        peer = _link(node, TARGET)
        node._tarpit(peer)
        peer.tarpit_until = time.monotonic() - 1.0
        node._reap_expired_tarpits()
        for _ in range(50):
            if peer not in node._peers:
                break
            await asyncio.sleep(0)
        assert peer not in node._peers
        assert not node._reconnect


class TestTheLoop:
    async def test_it_dials_a_lost_node_on_its_own(self):
        node = _node()
        seen = _dials(node)
        _lose(node, _link(node, TARGET))
        node._ensure_reconnect()
        try:
            deadline = time.monotonic() + 5.0
            while not seen and time.monotonic() < deadline:
                await asyncio.sleep(0.05)
        finally:
            await node._stop_reconnect()
        assert seen == [TARGET]

    async def test_a_dial_that_raises_does_not_kill_the_loop(self):
        """Recovery dying quietly is worse than a link dying loudly."""
        node = _node()
        calls = []

        async def _boom(node_id, timeout=None):
            calls.append(node_id)
            raise OSError("no route")

        node._ensure_route_to = _boom
        _lose(node, _link(node, TARGET))
        node._ensure_reconnect()
        try:
            deadline = time.monotonic() + 5.0
            while len(calls) < 2 and time.monotonic() < deadline:
                await asyncio.sleep(0.05)
        finally:
            task = node._reconnect_task
            assert task is not None and not task.done()
            await node._stop_reconnect()
        assert len(calls) >= 2


class TestAMembershipTakenBackEndsIt:
    """A revocation tears down every link to the node it names, and that
    teardown runs through the same reaper a dead socket does. Without a guard,
    revoking a node would have put it straight into the book and dialled it
    back a dozen times over the next two minutes."""

    def _revoke(self, node: MeshNode, subject: NodeID) -> None:
        """A real signed record, absorbed through the store's own door."""
        issuer = CryptoIdentity()
        record = revocation.build(subject, issuer.dsa_public_key, issuer.sign)
        assert node._cert_store.revoke(record, node._identity.verify) is not None

    def test_a_revoked_node_is_never_enrolled(self):
        node = _node()
        self._revoke(node, TARGET)
        _lose(node, _link(node, TARGET))
        assert not node._reconnect

    async def test_a_revocation_ends_a_chase_already_running(self):
        """The link may have died a minute before the revocation arrived."""
        node = _node()
        _lose(node, _link(node, TARGET))
        assert TARGET in node._reconnect
        self._revoke(node, TARGET)
        node._enforce_revocation(TARGET)
        assert TARGET not in node._reconnect

    async def test_forgetting_a_node_stops_chasing_it(self):
        """The operator said forget it. Dialling it back twice a second is not
        forgetting it."""
        node = _node()
        _lose(node, _link(node, TARGET))
        assert TARGET in node._reconnect
        await node.console_forget_node(TARGET.raw.hex())
        assert TARGET not in node._reconnect
