"""
Multi-link operation, and the keepalive accord it needs.

Two links to one node used to mean one link carrying everything and one being
kept alive for nothing. MLO spends both — but only when they measure the same,
only while somebody is using the node, only over media whose operator said a
probe ten times a second is cheap, and only with a peer that said it speaks
this. Every one of those "only"s is a way the feature could break a mesh, so
every one of them is a test here.

Three properties are the ones that would hurt if they rotted:

- **A peer that has never heard of this is untouched.** No tail on its probes,
  no proposal, no bundle — and its probes still get answered exactly as before.
- **A request can never make this node spend more.** The cadence plane exists
  to stop one node imposing a cost on another; a four-byte packet that could
  raise our probe rate would be the same problem with a nicer name.
- **Leaving a bundle is cheap and coming back is not.** One threshold in both
  directions makes a link at the threshold flap on a single probe, which sprays
  traffic down the one link known to be losing it.
"""
import asyncio
import time

import pytest

from src import features, mlo
from src.metrics import LinkQuality
from src.node import (MeshNode, _Peer, KA_PROPOSE, KA_REQUEST, PING, PONG,
                      _KA_GRACE, _KA_PROBE_DEADLINE, _KA_TICK_FLOOR,
                      _KA_TOKEN, _KA_WANTED,
                      _KA_WINDOW, _LINK_KEEPALIVE_INTERVAL,
                      _decode_addresses_at, _decode_ping_tail)
from src.node_id import NodeID
from src.packet import Packet
from tests.conftest import FakeTransport, make_manager

TARGET = NodeID(b"\x11" * 20)
OTHER = NodeID(b"\x22" * 20)

SPEAKS = frozenset({features.CORE, features.KEEPALIVE, features.MLO})


def _node() -> MeshNode:
    node = MeshNode(transport_manager=make_manager())
    node._running = True
    return node


def _link(node: MeshNode, target: NodeID = TARGET, *, uri: str = "fake://a:1",
          speaks=SPEAKS, mean_ms: float | None = None,
          drop: float = 0.0, probes: int = 0, window=(100, 20000)) -> _Peer:
    """An authenticated link with a probe history already behind it.

    The history is written through the same window a real link fills, so a test
    that says "this link measures 20 ms and loses one probe in ten" is saying
    it in the units the bundle reads. ``window`` is what the peer proposed —
    ``None`` for one that has proposed nothing, which is what a node from
    before the accord existed looks like."""
    peer = _Peer(FakeTransport(), is_client_side=True)
    peer.authenticated_id = target
    peer.session = object()
    peer.remote_addr = uri
    peer.agreed = None if speaks is None else frozenset(speaks)
    if window is not None and speaks is not None:
        peer.ka_window = mlo.clamp_window(*window)
        peer.ka_accord = mlo.accord(node.keepalive_window(), peer.ka_window)
        peer.ka_accord_at = time.monotonic()
    quality = LinkQuality()
    for index in range(probes):
        token = ("t", index)
        quality.sent(token, 0.0)
        if index < round(probes * drop):
            quality.expire(1000.0, 0.0)          # never came back
        else:
            quality.answered(token, (mean_ms or 0.0) / 1000.0)
    peer.quality = quality
    node._peers.append(peer)
    return peer


def _ready(node: MeshNode, *schemes: str) -> None:
    """Declare those media MLO-ready, the way an operator's setting does."""
    node._transport_manager.setting = (
        lambda scheme, name: True if name == "mlo" and scheme in schemes else None)


# ---------------------------------------------------------------------------
# The accord — pure arithmetic, computed identically at both ends
# ---------------------------------------------------------------------------

class TestTheAccord:
    def test_the_floor_is_the_higher_of_the_two(self):
        """Neither node may be dragged below what it said it could sustain."""
        assert mlo.accord((100, 60000), (500, 40000))[0] == 500
        assert mlo.accord((500, 40000), (100, 60000))[0] == 500

    def test_the_lower_of_the_two_ceilings_wins(self):
        assert mlo.accord((100, 60000), (500, 40000))[1] == 40000

    def test_both_ends_compute_the_same_thing(self):
        """Nothing is exchanged to settle it, so this is the whole protocol."""
        mine, theirs = (100, 5000), (250, 30000)
        assert mlo.accord(mine, theirs) == mlo.accord(theirs, mine)

    def test_no_overlap_leaves_the_highest_floor_standing(self):
        """One node's ceiling below the other's floor: there is no agreement to
        find, and a floor is the half of a window stated as a limit."""
        assert mlo.accord((100, 200), (5000, 9000))[0] == 5000

    def test_a_peer_can_never_make_this_node_probe_faster(self):
        """The amplifier the ceiling would otherwise be. The floor is a `max`,
        so nobody can be dragged below what they declared; the ceiling is a
        `min`, which is a lever anybody can pull — and this node clamps its own
        cadence into the accord. A peer proposing a 150 ms ceiling would have
        bought six probes a second on every link it opened, for eight bytes."""
        greedy = mlo.accord((100, 20000), (100, 150))
        assert greedy[1] >= mlo.CEILING_MIN_MS
        node = _node()
        peer = _link(node, window=(100, 150))
        assert node._keepalive_interval(peer) == _LINK_KEEPALIVE_INTERVAL

    def test_the_ceiling_floor_is_the_cadence_that_predates_all_of_this(self):
        """Held in step deliberately: the promise is "no faster than it already
        did", and that number lives in `node.py`."""
        assert mlo.CEILING_MIN_MS == _LINK_KEEPALIVE_INTERVAL * 1000

    def test_a_proposal_is_clamped_before_it_is_believed(self):
        low, high = mlo.clamp_window(0, 10 ** 9)
        assert low == mlo.FLOOR_MS and high == mlo.CEILING_MS

    def test_a_floor_above_its_own_ceiling_is_not_a_window(self):
        assert not mlo.well_formed(9000, 100)
        assert not mlo.well_formed(100, 100)      # a window of nothing
        assert mlo.well_formed(100, 20000)

    def test_nonsense_never_raises(self):
        assert mlo.clamp_window("x", None) == (mlo.FLOOR_MS, mlo.CEILING_MS)
        assert not mlo.well_formed(None, "x")
        assert not mlo.inside("x", (1, 2))


# ---------------------------------------------------------------------------
# The bundle
# ---------------------------------------------------------------------------

class TestFormingABundle:
    def test_two_links_that_measure_alike_carry_together(self):
        bundle = mlo.Bundle(mlo.MLOSettings(skew_ms=30))
        keys = bundle.update([mlo.Candidate("a", 10.0, 0.0, 50),
                              mlo.Candidate("b", 20.0, 0.0, 50)])
        assert keys == ("a", "b") and bundle.active
        assert bundle.skew_ms == 10.0

    def test_the_reordering_budget_is_twice_the_skew(self):
        """The number this was asked for, and deliberately generous: the skew
        is a difference of round trips, so the one-way spread it stands for is
        about half of it."""
        bundle = mlo.Bundle(mlo.MLOSettings(skew_ms=100))
        bundle.update([mlo.Candidate("a", 10.0, 0.0, 50),
                       mlo.Candidate("b", 45.0, 0.0, 50)])
        assert bundle.skew_ms == 35.0
        assert bundle.reorder_ms == 70.0

    def test_links_too_far_apart_are_not_bundled(self):
        """Striping across 5 ms and 300 ms does not double anything: it
        delivers half the packets a third of a second late."""
        bundle = mlo.Bundle(mlo.MLOSettings(skew_ms=30))
        assert bundle.update([mlo.Candidate("a", 5.0, 0.0, 50),
                              mlo.Candidate("b", 300.0, 0.0, 50)]) == ()
        assert not bundle.active and bundle.reorder_ms == 0.0

    def test_an_unmeasured_link_is_not_a_good_one(self):
        bundle = mlo.Bundle()
        assert bundle.update([mlo.Candidate("a", 10.0, 0.0, 50),
                              mlo.Candidate("b", None, None, 0)]) == ()

    def test_too_few_probes_is_still_unmeasured(self):
        bundle = mlo.Bundle()
        assert bundle.update([
            mlo.Candidate("a", 10.0, 0.0, 50),
            mlo.Candidate("b", 12.0, 0.0, mlo.MIN_PROBES - 1)]) == ()

    def test_one_link_is_not_a_bundle(self):
        bundle = mlo.Bundle()
        assert bundle.update([mlo.Candidate("a", 10.0, 0.0, 50)]) == ()

    def test_the_bundle_is_capped(self):
        bundle = mlo.Bundle(mlo.MLOSettings(skew_ms=1000))
        keys = bundle.update([mlo.Candidate(name, 10.0, 0.0, 50)
                              for name in "abcd"])
        assert len(keys) == mlo.MAX_MEMBERS

    def test_the_turn_alternates(self):
        bundle = mlo.Bundle()
        bundle.update([mlo.Candidate("a", 10.0, 0.0, 50),
                       mlo.Candidate("b", 12.0, 0.0, 50)])
        turns = [bundle.next_key() for _ in range(6)]
        assert turns.count("a") == 3 and turns.count("b") == 3

    def test_nothing_takes_a_turn_when_there_is_no_bundle(self):
        assert mlo.Bundle().next_key() is None


class TestBenchingALossyMember:
    def test_a_member_over_the_threshold_stops_carrying(self):
        bundle = mlo.Bundle(mlo.MLOSettings(drop_percent=10))
        bundle.update([mlo.Candidate("a", 10.0, 0.0, 50),
                       mlo.Candidate("b", 12.0, 0.0, 50)])
        assert bundle.update([mlo.Candidate("a", 10.0, 0.0, 50),
                              mlo.Candidate("b", 12.0, 0.2, 50)]) == ()
        assert "b" in bundle.benched()

    def test_coming_back_needs_a_lower_share_than_leaving_did(self):
        """The regression this exists to stop: one number in both directions is
        a link that rejoins, drops, leaves and rejoins ten times a second."""
        bundle = mlo.Bundle(mlo.MLOSettings(drop_percent=10))
        bundle.update([mlo.Candidate("a", 10.0, 0.0, 50),
                       mlo.Candidate("b", 12.0, 0.2, 50)])
        assert "b" in bundle.benched()
        # Just under the bench threshold is not yet under the recovery one.
        bundle.update([mlo.Candidate("a", 10.0, 0.0, 50),
                       mlo.Candidate("b", 12.0, 0.09, 50)])
        assert "b" in bundle.benched()
        bundle.update([mlo.Candidate("a", 10.0, 0.0, 50),
                       mlo.Candidate("b", 12.0, 0.04, 50)])
        assert bundle.benched() == () and bundle.active

    def test_a_link_that_is_gone_leaves_the_bench_with_it(self):
        bundle = mlo.Bundle(mlo.MLOSettings(drop_percent=10))
        bundle.update([mlo.Candidate("a", 10.0, 0.0, 50),
                       mlo.Candidate("b", 12.0, 0.5, 50)])
        assert "b" in bundle.benched()
        bundle.update([mlo.Candidate("a", 10.0, 0.0, 50)])
        assert bundle.benched() == ()


# ---------------------------------------------------------------------------
# Probes matched to their own answer
# ---------------------------------------------------------------------------

class TestMatchingAProbeToItsAnswer:
    def test_each_probe_is_resolved_on_its_own(self):
        """What `on_ping`/`on_pong` cannot do: with several probes in flight,
        only one of them is ever the latest."""
        quality = LinkQuality()
        quality.sent(1, 0.0)
        quality.sent(2, 0.1)
        assert quality.answered(1, 0.05) == pytest.approx(0.05)
        assert quality.answered(2, 0.13) == pytest.approx(0.03)
        assert quality.recent_loss() == 0.0

    def test_an_answer_to_nothing_is_not_a_loss(self):
        """A probe already given up on, or a peer too old to echo a token. It
        is still proof the link carries traffic both ways."""
        quality = LinkQuality()
        quality.sent(1, 0.0)
        assert quality.answered(99, 0.05) is None
        assert quality.since_pong == 0
        assert quality.recent_probes() == 0        # nothing was resolved

    def test_a_probe_nobody_answers_is_charged_as_lost(self):
        quality = LinkQuality()
        for index in range(10):
            quality.sent(index, 0.0)
        assert quality.expire(10.0, 3.0) == 10
        assert quality.recent_loss() == 1.0
        assert quality.recent_ms() is None         # unmeasured, never zero

    def test_a_probe_still_young_is_left_pending(self):
        quality = LinkQuality()
        quality.sent(1, 5.0)
        assert quality.expire(6.0, 3.0) == 0
        assert quality.in_flight() == 1

    def test_the_window_is_bounded_and_so_is_what_is_in_flight(self):
        quality = LinkQuality()
        for index in range(LinkQuality.MAX_PENDING * 3):
            quality.sent(index, 0.0)
        assert quality.in_flight() <= LinkQuality.MAX_PENDING
        assert quality.recent_probes() <= LinkQuality.WINDOW

    def test_an_unproven_link_reports_no_loss_rather_than_none_lost(self):
        assert LinkQuality().recent_loss() is None


# ---------------------------------------------------------------------------
# What a peer has to have said
# ---------------------------------------------------------------------------

class TestSilenceMeansTwoDifferentThings:
    def test_a_classic_plane_is_still_spoken_to_a_silent_peer(self):
        """Rule 2 of the negotiation: a node from before it existed keeps
        working exactly as it did."""
        node, peer = _node(), _Peer(FakeTransport())
        assert node.peer_speaks(peer, features.KADEMLIA)

    def test_a_plane_added_since_needs_the_name_to_have_been_said(self):
        """The other half of "exactly as it did": silence about a new name is a
        peer that has never heard of it, and sending it the new thing is a
        message it drops and an answer we then wait for."""
        node, peer = _node(), _Peer(FakeTransport())
        assert not node.peer_announces(peer, features.MLO)
        peer.agreed = frozenset(SPEAKS)
        assert node.peer_announces(peer, features.MLO)

    def test_every_new_name_is_listed_as_new(self):
        """The list is what the strict predicate is asked through, so a name
        added to `SPOKEN` and forgotten here would silently get the lenient
        one."""
        assert features.SINCE_NEGOTIATION <= features.SPOKEN
        assert {features.MLO, features.KEEPALIVE} <= features.SINCE_NEGOTIATION


# ---------------------------------------------------------------------------
# The probe on the wire
# ---------------------------------------------------------------------------

class TestWhatAProbeCarries:
    async def test_a_peer_that_speaks_it_gets_a_tail_and_echoes_it(self):
        node = _node()
        peer = _link(node)
        await node.ping(peer)
        sent = peer.transport.sent[-1]
        addresses, end = _decode_addresses_at(sent.payload)
        tail = _decode_ping_tail(sent.payload, end)
        assert tail is not None
        next_ms, token = tail
        assert next_ms == round(_LINK_KEEPALIVE_INTERVAL * 1000)
        assert peer.quality.in_flight() == 1

        # …and the answer names that very probe.
        answer = _node()
        other = _link(answer, uri="fake://b:1")
        other.authenticated_id = NodeID(sent.src_id)
        await answer._handle_ping(other, sent)
        pong = other.transport.sent[-1]
        assert pong.type == PONG
        assert _KA_TOKEN.unpack(pong.payload)[0] == token
        await node.stop()

    async def test_a_peer_that_never_heard_of_it_gets_the_probe_it_always_got(self):
        """The compatibility test. A tail it cannot echo would leave every
        probe unmatched, and `expire` would charge every one as a loss on a
        link answering perfectly."""
        node = _node()
        peer = _link(node, speaks=None)
        await node.ping(peer)
        sent = peer.transport.sent[-1]
        addresses, end = _decode_addresses_at(sent.payload)
        assert end == len(sent.payload)             # nothing follows
        assert peer.quality.pings == 1 and peer.quality.in_flight() == 0
        await node.stop()

    async def test_an_old_peers_empty_pong_still_measures_the_link(self):
        node = _node()
        peer = _link(node, speaks=None)
        await node.ping(peer)
        await node._handle_pong(peer, Packet.create(PONG, TARGET.raw,
                                                    node.id.raw, b""))
        assert peer.last_rtt is not None and peer.quality.since_pong == 0
        await node.stop()

    async def test_a_pong_body_is_a_token_or_nothing(self):
        node = _node()
        peer = _link(node)
        await node._handle_pong(peer, Packet.create(PONG, TARGET.raw,
                                                    node.id.raw, b"\x00" * 3))
        assert peer._malformed == 1
        await node.stop()

    async def test_a_trailer_this_build_does_not_know_is_ignored(self):
        """A longer tail is what a newer build looks like, and the one thing
        the negotiation exists to stop is reading that as misbehaviour."""
        node = _node()
        peer = _link(node)
        payload = Packet.create(PING, TARGET.raw, b"\xff" * 20, b"\x00").payload
        await node._handle_ping(peer, Packet.create(
            PING, TARGET.raw, b"\xff" * 20, payload + b"\x01" * 40))
        assert peer._malformed == 0 and peer.ka_next_ms is None
        assert peer.transport.sent[-1].type == PONG    # answered all the same
        await node.stop()


# ---------------------------------------------------------------------------
# Negotiating the cadence
# ---------------------------------------------------------------------------

async def _propose(node: MeshNode, peer: _Peer, low: int, high: int) -> None:
    await node._handle_ka_propose(peer, Packet.create(
        KA_PROPOSE, TARGET.raw, b"\xff" * 20, _KA_WINDOW.pack(low, high)))


class TestNegotiatingTheCadence:
    async def test_a_proposal_settles_the_window_both_ends_are_held_to(self):
        node = _node()
        peer = _link(node)
        await _propose(node, peer, 500, 10000)
        assert peer.ka_accord == mlo.accord(node.keepalive_window(), (500, 10000))
        await node.stop()

    async def test_a_window_that_cannot_be_true_is_counted_and_dropped(self):
        """Rule K3. Adopting a window we have just called impossible would be
        the accusation and the compliance in one breath."""
        node = _node()
        peer = _link(node)
        before = peer.ka_accord
        await _propose(node, peer, 9000, 100)
        assert peer.ka_impossible == 1
        assert peer.ka_accord == before and peer._malformed == 0
        await node.stop()

    async def test_a_proposal_of_the_wrong_size_is_a_protocol_violation(self):
        node = _node()
        peer = _link(node)
        await node._handle_ka_propose(peer, Packet.create(
            KA_PROPOSE, TARGET.raw, b"\xff" * 20, b"\x00" * 3))
        assert peer._malformed == 1
        await node.stop()

    async def test_the_plane_is_metered_like_every_other(self):
        node = _node()
        peer = _link(node)
        for index in range(40):
            await _propose(node, peer, 500 + index, 10000)
        # Whatever it sent, it did not get to move the accord forty times.
        assert node._ka_request_rate
        await node.stop()

    async def test_a_silent_peer_is_never_proposed_to(self):
        node = _node()
        peer = _link(node, speaks=None)
        await node._announce_keepalive(peer)
        assert peer.transport.sent == []
        await node.stop()

    async def test_a_peer_that_has_proposed_nothing_keeps_the_classic_cadence(self):
        node = _node()
        peer = _link(node, speaks=None)
        assert node._keepalive_interval(peer) == _LINK_KEEPALIVE_INTERVAL
        await node.stop()


class TestAskingAPeerToSlowDown:
    async def _asked(self, node, peer, wanted_ms):
        await node._handle_ka_request(peer, Packet.create(
            KA_REQUEST, TARGET.raw, b"\xff" * 20, _KA_WANTED.pack(wanted_ms)))

    async def test_a_request_slows_this_node_down(self):
        node = _node()
        node.set_keepalive_window(100, 60000)
        peer = _link(node)
        await _propose(node, peer, 100, 60000)
        await self._asked(node, peer, 45000)
        assert peer.ka_told_ms == 45000
        assert node._keepalive_interval(peer) == 45.0
        await node.stop()

    async def test_a_request_can_never_make_this_node_spend_more(self):
        """The property the whole plane exists for: a four-byte packet that
        could raise our probe rate is the cost-imposition it prevents, wearing
        a nicer name."""
        node = _node()
        peer = _link(node)
        await _propose(node, peer, 100, 60000)
        before = node._keepalive_interval(peer)
        await self._asked(node, peer, mlo.FAST_MS)
        assert peer.ka_told_ms is None
        assert node._keepalive_interval(peer) == before
        await node.stop()

    async def test_a_request_is_clamped_into_the_accord(self):
        """A peer cannot slow us past what the two of us agreed, any more than
        it can speed us up: the accord bounds the plane in both directions."""
        node = _node()
        node.set_keepalive_window(100, 60000)
        peer = _link(node)
        await _propose(node, peer, 100, 60000)
        await self._asked(node, peer, 10 ** 8)
        assert peer.ka_told_ms == 60000
        await node.stop()

    async def test_a_request_of_the_wrong_size_is_a_protocol_violation(self):
        node = _node()
        peer = _link(node)
        await node._handle_ka_request(peer, Packet.create(
            KA_REQUEST, TARGET.raw, b"\xff" * 20, b"\x00" * 9))
        assert peer._malformed == 1
        await node.stop()

    async def test_a_bundle_candidate_takes_the_fast_lane_back(self):
        """Legitimate precisely because it is announced: the next probe
        carries the accord's floor, which is the one refusal defined here."""
        node = _node()
        node.set_keepalive_window(100, 60000)
        peer = _link(node)
        await _propose(node, peer, 100, 60000)
        await self._asked(node, peer, 45000)
        peer.ka_wanted_ms = mlo.FAST_MS
        assert node._keepalive_interval(peer) == mlo.FAST_MS / 1000.0
        await node.stop()


class TestJudgingWhatAPeerAnnounces:
    def _armed(self, node, peer):
        """An accord old enough that a crossing cannot explain anything."""
        peer.ka_accord_at = time.monotonic() - _KA_GRACE - 1.0

    async def test_a_cadence_outside_the_accord_is_a_finding(self):
        node = _node()
        peer = _link(node)
        await _propose(node, peer, 500, 10000)
        self._armed(node, peer)
        node._note_announced_cadence(peer, 50)
        assert peer.ka_outside == 1

    async def test_nothing_is_held_against_a_crossing(self):
        """A proposal travels at the speed of the link, and both ends
        re-propose before probing at a new cadence."""
        node = _node()
        peer = _link(node)
        await _propose(node, peer, 500, 10000)
        node._note_announced_cadence(peer, 50)          # inside the grace
        assert peer.ka_outside == 0

    async def test_a_peer_that_has_agreed_nothing_is_judged_by_nothing(self):
        node = _node()
        peer = _link(node, speaks=None)
        node._note_announced_cadence(peer, 1)
        assert peer.ka_outside == 0 and peer.ka_next_ms == 1

    async def test_honouring_a_request_clears_it(self):
        node = _node()
        node.set_keepalive_window(100, 60000)
        peer = _link(node)
        await _propose(node, peer, 100, 60000)
        self._armed(node, peer)
        peer.ka_asked_ms, peer.ka_asked_at = 45000, time.monotonic() - 60
        node._note_announced_cadence(peer, 50000)
        assert peer.ka_asked_ms is None and peer.ka_ignored == 0

    async def test_announcing_the_floor_refuses_a_request_without_a_finding(self):
        """"I want the fast lane back", said out loud and inside the accord."""
        node = _node()
        node.set_keepalive_window(100, 60000)
        peer = _link(node)
        await _propose(node, peer, 100, 60000)
        self._armed(node, peer)
        peer.ka_asked_ms, peer.ka_asked_at = 45000, time.monotonic() - 60
        node._note_announced_cadence(peer, peer.ka_accord[0])
        assert peer.ka_asked_ms is None and peer.ka_ignored == 0

    async def test_a_third_cadence_is_a_finding(self):
        """Rule K2: neither the cadence asked for nor the announcement that
        refuses it."""
        node = _node()
        node.set_keepalive_window(100, 60000)
        peer = _link(node)
        await _propose(node, peer, 100, 60000)
        self._armed(node, peer)
        peer.ka_asked_ms, peer.ka_asked_at = 45000, time.monotonic() - 60
        node._note_announced_cadence(peer, 20000)
        assert peer.ka_ignored == 1
        assert peer.ka_asked_ms is None      # counted once; asking re-arms it

    async def test_a_request_just_made_is_given_time_to_arrive(self):
        node = _node()
        node.set_keepalive_window(100, 60000)
        peer = _link(node)
        await _propose(node, peer, 100, 60000)
        self._armed(node, peer)
        peer.ka_asked_ms, peer.ka_asked_at = 45000, time.monotonic()
        node._note_announced_cadence(peer, 20000)
        assert peer.ka_ignored == 0 and peer.ka_asked_ms == 45000


# ---------------------------------------------------------------------------
# When the node bundles at all
# ---------------------------------------------------------------------------

class TestWhenTheNodeIsAwake:
    def test_a_node_nobody_is_using_does_not_bundle(self):
        node = _node()
        assert not node.awake() and not node.mlo_active()

    def test_a_moment_wakes_it_and_then_wears_off(self):
        node = _node()
        node.note_awake("console")
        assert node.awake() and node.mlo_active()
        node._awake_since["console"] -= 10 ** 6
        assert not node.awake()

    def test_something_that_is_open_says_so_for_as_long_as_it_is(self):
        """An app attached with nobody typing is still an app open, which is
        why a timestamp alone would have been the wrong shape."""
        node = _node()
        open_now = [True]
        node.hold_awake("app", lambda: open_now[0])
        assert node.awake_sources() == ["app"]
        open_now[0] = False
        assert not node.awake()

    def test_a_probe_that_raises_holds_nothing_awake(self):
        node = _node()
        node.hold_awake("broken", lambda: 1 / 0)
        assert not node.awake()

    def test_always_on_needs_nobody(self):
        node = _node()
        node.set_mlo_always(True)
        assert node.mlo_active() and not node.awake()

    def test_the_awake_book_is_bounded(self):
        node = _node()
        for index in range(200):
            node.note_awake(f"source-{index}")
            node.hold_awake(f"hold-{index}", lambda: False)
        assert len(node._awake_since) <= 16 and len(node._awake_holds) <= 16


class TestFormingABundleOnANode:
    def _pair(self, node):
        _ready(node, "fake", "udp")
        node.note_awake("test")
        return (_link(node, uri="fake://a:1", mean_ms=10.0, probes=50),
                _link(node, uri="udp://a:2", mean_ms=20.0, probes=50))

    async def test_two_ready_links_to_one_node_are_bundled(self):
        node = _node()
        first, second = self._pair(node)
        node._update_bundles()
        bundle = node._bundles[TARGET]
        assert bundle.active and set(bundle.keys) == {first, second}
        assert node.reorder_budget_ms(TARGET) == pytest.approx(20.0, abs=1.0)
        await node.stop()

    async def test_a_candidate_is_probed_on_the_fast_cadence(self):
        """Candidacy, not membership, buys the fast probe: a link only earns
        its place by being measured at that cadence."""
        node = _node()
        first, second = self._pair(node)
        node._update_bundles()
        assert first.ka_wanted_ms == mlo.FAST_MS
        assert node._keepalive_interval(first) == mlo.FAST_MS / 1000.0
        await node.stop()

    async def test_a_medium_the_operator_did_not_tick_is_never_bundled(self):
        node = _node()
        self._pair(node)
        _ready(node, "fake")            # only one of the two media
        node._update_bundles()
        assert TARGET not in node._bundles
        await node.stop()

    async def test_a_transport_that_does_not_know_the_option_is_never_bundled(self):
        """Store-and-forward declares no `mlo` at all, and that absence is the
        right answer rather than a gap."""
        node = _node()
        self._pair(node)
        node._transport_manager.setting = lambda scheme, name: None
        node._update_bundles()
        assert TARGET not in node._bundles
        await node.stop()

    async def test_a_peer_that_does_not_speak_mlo_is_never_bundled(self):
        """Backward compatibility, and it needs only one end to be missing."""
        node = _node()
        _ready(node, "fake", "udp")
        node.note_awake("test")
        _link(node, uri="fake://a:1", mean_ms=10.0, probes=50, speaks=None)
        _link(node, uri="udp://a:2", mean_ms=20.0, probes=50)
        node._update_bundles()
        assert TARGET not in node._bundles
        await node.stop()

    async def test_a_relayed_link_has_no_medium_to_bundle(self):
        node = _node()
        first, second = self._pair(node)
        second.relay_only = True
        node._update_bundles()
        assert TARGET not in node._bundles
        await node.stop()

    async def test_going_to_sleep_puts_every_bundle_down(self):
        node = _node()
        self._pair(node)
        node._update_bundles()
        assert node._bundles
        node._awake_since.clear()
        node._update_bundles()
        assert node._bundles == {}
        await node.stop()

    async def test_two_links_to_different_nodes_are_not_a_bundle(self):
        node = _node()
        _ready(node, "fake")
        node.note_awake("test")
        _link(node, TARGET, uri="fake://a:1", mean_ms=10.0, probes=50)
        _link(node, OTHER, uri="fake://b:1", mean_ms=10.0, probes=50)
        node._update_bundles()
        assert node._bundles == {}
        await node.stop()

    async def test_a_link_that_goes_takes_its_bundle_with_it(self):
        node = _node()
        first, _second = self._pair(node)
        node._update_bundles()
        assert TARGET in node._bundles
        node._forget_bundle(first)
        assert TARGET not in node._bundles
        await node.stop()


class TestSpreadingTheTraffic:
    async def test_the_lead_alternates_between_the_members(self):
        node = _node()
        _ready(node, "fake", "udp")
        node.note_awake("test")
        first = _link(node, uri="fake://a:1", mean_ms=10.0, probes=50)
        second = _link(node, uri="udp://a:2", mean_ms=12.0, probes=50)
        node._update_bundles()
        leads = [node._route_candidates(TARGET)[0] for _ in range(6)]
        assert leads.count(first) == 3 and leads.count(second) == 3
        await node.stop()

    async def test_the_loser_of_a_turn_is_still_a_fallback(self):
        """Only the head is swapped: the rest of the list is what it was, and
        a send that fails still has somewhere to go."""
        node = _node()
        _ready(node, "fake", "udp")
        node.note_awake("test")
        self_links = [_link(node, uri="fake://a:1", mean_ms=10.0, probes=50),
                      _link(node, uri="udp://a:2", mean_ms=12.0, probes=50)]
        node._update_bundles()
        candidates = node._route_candidates(TARGET)
        assert set(candidates) == set(self_links)
        await node.stop()

    async def test_nothing_is_spread_when_nothing_is_bundled(self):
        node = _node()
        first = _link(node, uri="fake://a:1", mean_ms=10.0, probes=50)
        assert node._route_candidates(TARGET)[0] is first
        await node.stop()

    async def test_a_benched_member_carries_nothing(self):
        node = _node()
        _ready(node, "fake", "udp")
        node.note_awake("test")
        good = _link(node, uri="fake://a:1", mean_ms=10.0, probes=50)
        bad = _link(node, uri="udp://a:2", mean_ms=12.0, probes=50, drop=0.5)
        node._update_bundles()
        leads = {node._route_candidates(TARGET)[0] for _ in range(6)}
        assert leads == {good}
        assert bad in node._bundles[TARGET].benched()
        await node.stop()


class TestWhatAnOperatorSees:
    async def test_the_status_names_the_bundle_and_its_cost(self):
        node = _node()
        _ready(node, "fake", "udp")
        node.note_awake("console")
        _link(node, uri="fake://a:1", mean_ms=10.0, probes=50)
        _link(node, uri="udp://a:2", mean_ms=20.0, probes=50)
        node._update_bundles()
        status = node.mlo_status()
        assert status["active"] and status["awake_sources"] == ["console"]
        row = status["bundles"][0]
        assert row["node"] == TARGET.raw.hex() and row["active"]
        assert row["reorder_ms"] == pytest.approx(2 * row["skew_ms"])
        assert {member["scheme"] for member in row["members"]} == {"fake", "udp"}
        assert all(member["carrying"] for member in row["members"])
        await node.stop()

    async def test_the_status_is_json_safe(self):
        import json
        node = _node()
        node.note_awake("console")
        json.dumps(node.mlo_status())
        await node.stop()


class TestWhatAPeerCanMakeThisLoopDo:
    """The keepalive loop is now woken by things a peer sends. That is the
    whole reason it has a floor: no loop driven by what a peer sends may run
    flat out (gotchas §12), and this one sorts and walks every link per pass."""

    async def test_a_wake_shortens_the_wait_but_never_removes_it(self):
        """Woken while it is parked — which is the only way a wake ever lands,
        since the loop clears the event before reading the state it signals."""
        node = _node()
        _link(node)                      # due in a full keepalive interval
        started = time.monotonic()

        async def wake():
            await asyncio.sleep(0)       # let the sleep park first
            node._wake_keepalive()

        waker = asyncio.create_task(wake())
        await node._keepalive_sleep(started + 3600.0)
        await waker
        elapsed = time.monotonic() - started
        assert elapsed >= _KA_TICK_FLOOR            # never removed
        assert elapsed < _LINK_KEEPALIVE_INTERVAL   # but genuinely shortened
        await node.stop()

    async def test_a_capability_record_that_says_nothing_new_wakes_nothing(self):
        """Reachable before authentication by design, so a peer re-announcing
        in a loop would otherwise buy a walk of every link per packet."""
        node = _node()
        peer = _link(node)
        record = Packet.create(0x26, TARGET.raw, b"\xff" * 20,
                               features.encode(SPEAKS))
        await node._handle_capabilities(peer, record)
        node._keepalive_wakeup.clear()
        await node._handle_capabilities(peer, record)      # the same thing again
        assert not node._keepalive_wakeup.is_set()
        await node.stop()

    async def test_an_unauthenticated_peer_wakes_nothing(self):
        node = _node()
        peer = _Peer(FakeTransport())
        node._peers.append(peer)
        node._keepalive_wakeup.clear()
        await node._handle_capabilities(peer, Packet.create(
            0x26, TARGET.raw, b"\xff" * 20, features.encode(SPEAKS)))
        assert peer.agreed is not None          # the record is still read
        assert not node._keepalive_wakeup.is_set()
        await node.stop()


class TestGivingUpOnAProbe:
    """When a probe counts as lost. The number this decides is shown to an
    operator as "loss", so getting it wrong is not a missed optimisation — it
    is a screen saying a working link is broken."""

    async def test_a_slow_link_is_not_marked_lossy_for_being_slow(self):
        """A constant deadline would call every probe on a medium measured in
        minutes lost, on a link answering every one of them."""
        node = _node()
        node.set_keepalive_window(100, 600000)
        peer = _link(node, window=(100, 600000))
        peer.ka_told_ms = 120000                    # two minutes between probes
        deadline = max(_KA_PROBE_DEADLINE, 3.0 * node._keepalive_interval(peer))
        assert deadline >= 3 * 120.0

    async def test_a_fast_link_still_gives_up_promptly(self):
        node = _node()
        peer = _link(node)
        peer.ka_wanted_ms = mlo.FAST_MS
        deadline = max(_KA_PROBE_DEADLINE, 3.0 * node._keepalive_interval(peer))
        assert deadline == _KA_PROBE_DEADLINE       # the floor, not 0.3 s


class TestStripingNeverUndoesAnExclusion:
    """`_route_candidates(target, exclude=…)` excludes the link a packet
    arrived on. A bundle knows which links reach an identity and nothing about
    where the packet came from, so the turn has to be filtered too — otherwise
    a forward could go straight back down the link it came from."""

    async def test_the_excluded_link_never_takes_its_turn(self):
        node = _node()
        _ready(node, "fake", "udp")
        node.note_awake("test")
        first = _link(node, uri="fake://a:1", mean_ms=10.0, probes=50)
        second = _link(node, uri="udp://a:2", mean_ms=12.0, probes=50)
        node._update_bundles()
        assert node._bundles[TARGET].active
        for _ in range(8):
            assert second not in node._route_candidates(TARGET, exclude=second)
            assert first not in node._route_candidates(TARGET, exclude=first)
        await node.stop()
