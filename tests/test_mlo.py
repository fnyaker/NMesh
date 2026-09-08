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
                      _ADDR_GOSSIP_INTERVAL, _NO_ADDRESSES,
                      _KA_BOUNDS, _KA_GRACE, _KA_PROBE_DEADLINE, _KA_TOLD_TTL,
                      _KA_TICK_FLOOR, _KA_TOKEN, _KA_WANTED,
                      _LINK_KEEPALIVE_INTERVAL,
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
          drop: float = 0.0, probes: int = 0, window=mlo.Bounds()) -> _Peer:
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
        peer.ka_window = mlo.clamp_bounds(
            *(window.as_tuple() if isinstance(window, mlo.Bounds) else window))
        peer.ka_accord = mlo.accord(node.keepalive_bounds(), peer.ka_window)
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
    """Four numbers, not two, and the reason is the whole security story.

    With one range the *floor* protects (a `max` across the two nodes) and the
    ceiling is a `min` — a lever anybody can pull. A peer proposing a 150 ms
    ceiling bought six probes a second on that link for eight bytes. With a
    range per mode every agreed cadence is a `max` over something each node
    declared, so there is no expression a peer's number enters where being
    smaller helps it."""

    FAST = mlo.Bounds(100, 1000, 15000, 20000)          # a node on mains power
    BATTERY = mlo.Bounds(2000, 5000, 60000, 300000)     # a phone
    GREEDY = mlo.Bounds(50, 60, 60, 150)                # wants us probing hard

    def test_the_defaults_reproduce_the_cadence_that_predates_all_of_this(self):
        """A node shipped as-is probes an idle link every twenty seconds,
        exactly as every link did before any of this existed."""
        agreed = mlo.accord(mlo.Bounds(), mlo.Bounds())
        assert agreed.slow_ms == _LINK_KEEPALIVE_INTERVAL * 1000
        assert agreed.fast_ms == mlo.DEFAULT_FAST_MIN_MS and agreed.fast_ok

    def test_both_ends_compute_the_same_thing(self):
        """Nothing is exchanged to settle it, so this is the whole protocol."""
        assert (mlo.accord(self.FAST, self.BATTERY)
                == mlo.accord(self.BATTERY, self.FAST))

    def test_the_fast_cadence_is_the_fastest_both_allow(self):
        assert mlo.accord(self.FAST, mlo.Bounds(400, 2000, 15000, 20000)
                          ).fast_ms == 400

    def test_no_cadence_both_call_fast_means_no_bundling(self):
        """Not "one of them pays for the other's idea of fast". A phone
        offering 2–5 s and a server offering 100–500 ms have no overlap, and
        the honest outcome is that the pair is not bundled at all."""
        agreed = mlo.accord(self.FAST, self.BATTERY)
        assert not agreed.fast_ok

    def test_the_idle_cadence_takes_the_cheaper_answer(self):
        """A node that says "leave me alone for a minute" is left alone for a
        minute: the slow cadence is a `max`, so the quieter of the two wins."""
        assert mlo.accord(self.FAST, self.BATTERY).slow_ms == 60000

    def test_nothing_a_peer_sends_lowers_our_own_probe_interval(self):
        """The property the four numbers exist for, stated over both modes and
        over a peer built to attack exactly this."""
        agreed = mlo.accord(self.FAST, self.GREEDY)
        assert agreed.fast_ms >= self.FAST.fast_min
        assert agreed.slow_ms >= self.FAST.slow_min

    def test_no_declaration_at_all_can_lower_either_cadence(self):
        """Swept rather than argued: every corner of the hard range, against a
        node on defaults. If any of them wins, the model is wrong."""
        mine = mlo.Bounds()
        edges = (mlo.FLOOR_MS, 100, 1000, 20000, mlo.CEILING_MS)
        for fast_min in edges:
            for fast_max in edges:
                for slow_min in edges:
                    for slow_max in edges:
                        theirs = mlo.clamp_bounds(fast_min, fast_max,
                                                  slow_min, slow_max)
                        agreed = mlo.accord(mine, theirs)
                        assert agreed.fast_ms >= mine.fast_min
                        assert agreed.slow_ms >= mine.slow_min

    def test_the_window_is_the_two_cadences(self):
        """What rule K1 judges an announcement against: nothing between
        striping and idling is out of bounds, nothing outside them is in."""
        agreed = mlo.accord(self.FAST, self.FAST)
        assert agreed.window == (agreed.fast_ms, agreed.slow_ms)
        assert mlo.inside(agreed.fast_ms, agreed.window)
        assert mlo.inside(agreed.slow_ms, agreed.window)
        assert not mlo.inside(agreed.fast_ms - 1, agreed.window)
        assert not mlo.inside(agreed.slow_ms + 1, agreed.window)

    def test_a_proposal_is_clamped_before_it_is_believed(self):
        clamped = mlo.clamp_bounds(0, 10 ** 9, -5, 10 ** 12)
        assert clamped.fast_min == mlo.FLOOR_MS
        assert clamped.slow_max == mlo.CEILING_MS

    def test_a_declaration_a_correct_node_could_not_have_meant(self):
        assert mlo.well_formed(100, 1000, 15000, 20000)
        assert not mlo.well_formed(1000, 100, 15000, 20000)   # fast reversed
        assert not mlo.well_formed(100, 1000, 20000, 15000)   # slow reversed
        assert not mlo.well_formed(100, 100, 15000, 20000)    # a range of nothing
        # …and the one that costs a hundredfold: the two modes swapped.
        assert not mlo.well_formed(15000, 20000, 100, 1000)

    def test_nonsense_never_raises(self):
        assert mlo.clamp_bounds("x", None, [], {}) == mlo.Bounds()
        assert not mlo.well_formed(None, "x", 1, 2)
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

async def _propose(node: MeshNode, peer: _Peer, *bounds) -> None:
    """A peer stating its four numbers, straight into the handler."""
    await node._handle_ka_propose(peer, Packet.create(
        KA_PROPOSE, TARGET.raw, b"\xff" * 20, _KA_BOUNDS.pack(*bounds)))


class TestNegotiatingTheCadence:
    async def test_a_proposal_settles_what_both_ends_are_held_to(self):
        node = _node()
        peer = _link(node)
        await _propose(node, peer, 500, 2000, 5000, 10000)
        assert peer.ka_accord == mlo.accord(node.keepalive_bounds(),
                                            mlo.Bounds(500, 2000, 5000, 10000))
        # …and it is what the two of them will actually run at.
        assert peer.ka_accord.fast_ms == 500        # the higher of the floors
        assert peer.ka_accord.slow_ms == 15000      # our own idle floor
        await node.stop()

    async def test_a_declaration_that_cannot_be_true_is_counted_and_dropped(self):
        """Rule K3. Adopting a declaration we have just called impossible would be
        the accusation and the compliance in one breath."""
        node = _node()
        peer = _link(node)
        before = peer.ka_accord
        await _propose(node, peer, 9000, 100, 50, 20)
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
            await _propose(node, peer, 500 + index, 2000, 5000, 10000)
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

    async def test_a_request_takes_a_striping_link_back_to_idle(self):
        """What a request is *for*. "Stop probing me so hard" is worth nothing
        if striping ignores it, so it is honoured in both modes."""
        node = _node()
        peer = _link(node)
        agreed = node._accord_with(peer)
        peer.ka_wanted_ms = agreed.fast_ms
        assert node._keepalive_interval(peer) == agreed.fast_ms / 1000.0
        await self._asked(node, peer, agreed.slow_ms)
        assert peer.ka_told_ms == agreed.slow_ms
        assert node._keepalive_interval(peer) == agreed.slow_ms / 1000.0
        await node.stop()

    async def test_a_request_lapses_rather_than_holding_for_ever(self):
        """A request is a "go quiet for now". The durable way not to be probed
        hard is the *declared* fast range, which no request can override."""
        node = _node()
        peer = _link(node)
        agreed = node._accord_with(peer)
        peer.ka_wanted_ms = agreed.fast_ms
        await self._asked(node, peer, agreed.slow_ms)
        peer.ka_told_at -= _KA_TOLD_TTL + 1.0
        assert node._keepalive_interval(peer) == agreed.fast_ms / 1000.0
        await node.stop()

    async def test_a_request_can_never_make_this_node_spend_more(self):
        """The property the whole plane exists for: a four-byte packet that
        could raise our probe rate is the cost-imposition it prevents, wearing
        a nicer name."""
        node = _node()
        peer = _link(node)
        await _propose(node, peer, 100, 1000, 15000, 60000)
        before = node._keepalive_interval(peer)
        await self._asked(node, peer, mlo.DEFAULT_FAST_MIN_MS)
        assert peer.ka_told_ms is None
        assert node._keepalive_interval(peer) == before
        await node.stop()

    async def test_a_request_is_clamped_into_the_accord(self):
        """A peer cannot slow us past what the two of us agreed, any more than
        it can speed us up: the accord bounds the plane in both directions. To
        be left alone for longer, a node declares it — a *request* is not the
        durable mechanism and cannot be turned into one."""
        node = _node()
        peer = _link(node)
        agreed = node._accord_with(peer)
        peer.ka_wanted_ms = agreed.fast_ms
        await self._asked(node, peer, 10 ** 8)
        assert peer.ka_told_ms == agreed.slow_ms
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
        node.set_keepalive_bounds(slow_max_ms=60000)
        peer = _link(node)
        await _propose(node, peer, 100, 1000, 15000, 60000)
        await self._asked(node, peer, 45000)
        peer.ka_wanted_ms = node._accord_with(peer).fast_ms
        assert node._keepalive_interval(peer) == mlo.DEFAULT_FAST_MIN_MS / 1000.0
        await node.stop()


class TestJudgingWhatAPeerAnnounces:
    def _armed(self, node, peer):
        """An accord old enough that a crossing cannot explain anything."""
        peer.ka_accord_at = time.monotonic() - _KA_GRACE - 1.0

    async def test_a_cadence_outside_the_accord_is_a_finding(self):
        node = _node()
        peer = _link(node)
        await _propose(node, peer, 500, 2000, 5000, 10000)
        self._armed(node, peer)
        node._note_announced_cadence(peer, 50)
        assert peer.ka_outside == 1

    async def test_nothing_is_held_against_a_crossing(self):
        """A proposal travels at the speed of the link, and both ends
        re-propose before probing at a new cadence."""
        node = _node()
        peer = _link(node)
        await _propose(node, peer, 500, 2000, 5000, 10000)
        node._note_announced_cadence(peer, 50)          # inside the grace
        assert peer.ka_outside == 0

    async def test_a_peer_that_has_agreed_nothing_is_judged_by_nothing(self):
        node = _node()
        peer = _link(node, speaks=None)
        node._note_announced_cadence(peer, 1)
        assert peer.ka_outside == 0 and peer.ka_next_ms == 1

    async def test_honouring_a_request_clears_it(self):
        node = _node()
        node.set_keepalive_bounds(slow_max_ms=60000)
        peer = _link(node)
        await _propose(node, peer, 100, 1000, 15000, 60000)
        self._armed(node, peer)
        peer.ka_asked_ms, peer.ka_asked_at = 45000, time.monotonic() - 60
        node._note_announced_cadence(peer, 50000)
        assert peer.ka_asked_ms is None and peer.ka_ignored == 0

    async def test_announcing_the_floor_refuses_a_request_without_a_finding(self):
        """"I want the fast lane back", said out loud and inside the accord."""
        node = _node()
        node.set_keepalive_bounds(slow_max_ms=60000)
        peer = _link(node)
        await _propose(node, peer, 100, 1000, 15000, 60000)
        self._armed(node, peer)
        peer.ka_asked_ms, peer.ka_asked_at = 45000, time.monotonic() - 60
        node._note_announced_cadence(peer, peer.ka_accord.fast_ms)
        assert peer.ka_asked_ms is None and peer.ka_ignored == 0

    async def test_a_third_cadence_is_a_finding(self):
        """Rule K2: neither the cadence asked for nor the announcement that
        refuses it."""
        node = _node()
        node.set_keepalive_bounds(slow_max_ms=60000)
        peer = _link(node)
        await _propose(node, peer, 100, 1000, 15000, 60000)
        self._armed(node, peer)
        peer.ka_asked_ms, peer.ka_asked_at = 45000, time.monotonic() - 60
        node._note_announced_cadence(peer, 20000)
        assert peer.ka_ignored == 1
        assert peer.ka_asked_ms is None      # counted once; asking re-arms it

    async def test_a_request_just_made_is_given_time_to_arrive(self):
        node = _node()
        node.set_keepalive_bounds(slow_max_ms=60000)
        peer = _link(node)
        await _propose(node, peer, 100, 1000, 15000, 60000)
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
        assert first.ka_wanted_ms == node._accord_with(first).fast_ms
        assert node._keepalive_interval(first) == mlo.DEFAULT_FAST_MIN_MS / 1000.0
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
        # What the pair agreed and what each link runs at are two claims, and
        # a medium can take some of the second one back. Both are reported,
        # and the per-link one is read off the function the loop schedules
        # with rather than derived beside it.
        assert row["agreed_fast_ms"] == mlo.DEFAULT_FAST_MIN_MS
        assert all(member["probe_ms"] == mlo.DEFAULT_FAST_MIN_MS
                   for member in row["members"])
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
        node.set_keepalive_bounds(slow_min_ms=100000, slow_max_ms=600000)
        peer = _link(node, window=mlo.Bounds(100, 1000, 100000, 600000))
        peer.ka_told_ms = 120000                    # two minutes between probes
        deadline = max(_KA_PROBE_DEADLINE, 3.0 * node._keepalive_interval(peer))
        assert deadline >= 3 * 120.0

    async def test_a_fast_link_still_gives_up_promptly(self):
        node = _node()
        peer = _link(node)
        peer.ka_wanted_ms = node._accord_with(peer).fast_ms
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


class TestNotDrainingSomebodyElse:
    """The whole point of four numbers rather than two, stated as the outcomes
    an operator would notice."""

    async def test_a_phone_is_left_alone_and_never_bundled(self):
        """A node that says "2 to 5 seconds is my idea of fast, and leave me a
        minute when nothing is happening" gets exactly that: no striping, and
        an idle probe once a minute rather than three times."""
        node = _node()
        _ready(node, "fake", "udp")
        node.note_awake("test")
        phone = mlo.Bounds(2000, 5000, 60000, 300000)
        first = _link(node, uri="fake://a:1", mean_ms=10.0, probes=50,
                      window=phone)
        _link(node, uri="udp://a:2", mean_ms=12.0, probes=50, window=phone)
        node._update_bundles()
        assert TARGET not in node._bundles          # no striping at that peer
        assert first.ka_wanted_ms is None
        assert node._keepalive_interval(first) == 60.0
        await node.stop()

    async def test_a_greedy_peer_gets_this_nodes_own_floors(self):
        """Declaring a tight range is how a peer *opts out*, not how it opts
        somebody else in. Nothing in the accord rewards a smaller number."""
        node = _node()
        peer = _link(node, window=mlo.Bounds(50, 60, 60, 150))
        mine = node.keepalive_bounds()
        agreed = node._accord_with(peer)
        assert agreed.fast_ms >= mine.fast_min
        assert agreed.slow_ms >= mine.slow_min
        assert node._keepalive_interval(peer) == mine.slow_min / 1000.0
        await node.stop()

    async def test_the_medium_caps_an_idle_cadence_it_cannot_survive(self):
        """Two nodes can agree to idle slower than the wire under them will
        tolerate, and neither can see that from the accord — it is a fact about
        the transport, not about the pair."""
        node = _node()
        node.set_keepalive_bounds(slow_min_ms=300000, slow_max_ms=300000)
        peer = _link(node, window=mlo.Bounds(100, 1000, 300000, 300000))
        assert node._accord_with(peer).slow_ms == 300000
        peer.transport.idle_timeout = lambda: 60.0     # a TCP-shaped medium
        assert node._keepalive_interval(peer) == 60.0 * mlo.IDLE_TIMEOUT_SHARE
        await node.stop()

    async def test_a_medium_with_no_timeout_is_not_capped(self):
        """Store-and-forward fails on a write, not on a silence. Nothing to
        divide, so nothing is taken back."""
        node = _node()
        node.set_keepalive_bounds(slow_min_ms=300000, slow_max_ms=300000)
        peer = _link(node, window=mlo.Bounds(100, 1000, 300000, 300000))
        assert node._idle_ceiling(peer) is None
        assert node._keepalive_interval(peer) == 300.0
        await node.stop()

    async def test_the_cap_never_takes_the_cadence_below_what_was_agreed(self):
        """It may only ever take back what the medium cannot afford — a
        transport reporting something absurd must not become a way to probe
        faster than the accord."""
        node = _node()
        peer = _link(node)
        peer.transport.idle_timeout = lambda: 0.001
        agreed = node._accord_with(peer)
        assert node._keepalive_interval(peer) == agreed.fast_ms / 1000.0
        await node.stop()

    def test_the_shipped_transports_report_their_own_timeout(self):
        from src.tcp_transport import TCPTransport
        from src.udp_transport import UDPTransport
        assert TCPTransport().idle_timeout() == TCPTransport.setting("read_timeout")
        assert (UDPTransport().idle_timeout()
                == UDPTransport.setting("keepalive_timeout"))


class TestTheStatusNeverShowsACadenceNobodyRuns:
    """The label and the value are one claim. What the pair agreed and what a
    link is actually probed at are two, and a medium that reaps early makes
    them differ — so a screen that showed the agreement beside a link running
    at something else would be lying in the way this project keeps catching."""

    async def test_a_capped_link_reports_what_it_actually_runs_at(self):
        node = _node()
        _ready(node, "fake", "udp")
        node.note_awake("test")
        node.set_keepalive_bounds(slow_min_ms=300000, slow_max_ms=300000)
        slow = mlo.Bounds(100, 1000, 300000, 300000)
        for uri in ("fake://a:1", "udp://a:2"):
            link = _link(node, uri=uri, mean_ms=10.0, probes=50, window=slow)
            link.transport.idle_timeout = lambda: 60.0
        node._update_bundles()
        row = node.mlo_status()["bundles"][0]
        assert row["agreed_slow_ms"] == 300000          # what was agreed
        for member in row["members"]:
            assert member["probe_ms"] == round(
                node._keepalive_interval(
                    next(p for p in node._peers
                         if p.remote_addr == member["remote"])) * 1000)
        await node.stop()


class TestWhatAProbeWeighs:
    """The address gossip rides the probe; it is not what a probe is for.

    That distinction cost nothing while every link was probed every twenty
    seconds. At ten a second the unchanged address list was 71% of the packet
    and half of what answering one costs — measured, not guessed: 312 bytes and
    30 us became 92 bytes and 6.4 us."""

    def _uris(self, node):
        node._addresses = ["tcp://192.168.1.20:9000", "udp://192.168.1.20:9001"]
        node._advertised_key = None          # the cache reads the new list
        return tuple(node.advertised_uris())

    async def test_the_first_probe_on_a_link_carries_them(self):
        node = _node()
        self._uris(node)
        peer = _link(node)
        await node.ping(peer)
        addrs, _ = _decode_addresses_at(peer.transport.sent[-1].payload)
        assert addrs == list(self._uris(node))
        await node.stop()

    async def test_the_next_ones_do_not(self):
        node = _node()
        self._uris(node)
        peer = _link(node)
        await node.ping(peer)
        for _ in range(5):
            await node.ping(peer)
            addrs, _ = _decode_addresses_at(peer.transport.sent[-1].payload)
            assert addrs == []
        await node.stop()

    async def test_a_changed_address_set_goes_out_at_once(self):
        """Not on the next refresh — the whole point of address gossip is that
        a node that moved is reachable again quickly."""
        node = _node()
        self._uris(node)
        peer = _link(node)
        await node.ping(peer)
        await node.ping(peer)
        node._addresses = ["tcp://10.0.0.7:9000"]
        node._advertised_key = None
        await node.ping(peer)
        addrs, _ = _decode_addresses_at(peer.transport.sent[-1].payload)
        assert addrs == ["tcp://10.0.0.7:9000"]
        await node.stop()

    async def test_they_are_re_sent_after_the_refresh_interval(self):
        """The net under a lost probe: a peer that missed the update is told
        again, rather than never."""
        node = _node()
        self._uris(node)
        peer = _link(node)
        await node.ping(peer)
        peer.addrs_sent_at -= _ADDR_GOSSIP_INTERVAL + 1.0
        await node.ping(peer)
        addrs, _ = _decode_addresses_at(peer.transport.sent[-1].payload)
        assert addrs == list(self._uris(node))
        await node.stop()

    async def test_a_link_probed_at_the_classic_interval_is_unchanged(self):
        """A node nobody is bundling behaves exactly as it did: the refresh
        interval *is* the classic probe interval, so every probe carries them."""
        assert _ADDR_GOSSIP_INTERVAL == _LINK_KEEPALIVE_INTERVAL

    async def test_a_probe_with_no_addresses_still_proves_recency(self):
        """The invariant the old unconditional merge protected. A node with
        nothing announceable has always sent exactly this packet, and it must
        keep counting as contact — otherwise a live NATted peer is purged from
        the table for having nothing to say."""
        node = _node()
        peer = _link(node)
        node._routing.add(TARGET, ["fake://a:1"], b"\x01" * 32)
        entry = node._routing.get(TARGET)
        entry.last_seen -= 3600.0
        stale = entry.last_seen
        await node._handle_ping(peer, Packet.create(
            PING, TARGET.raw, b"\xff" * 20, _NO_ADDRESSES))
        assert node._routing.get(TARGET).last_seen > stale
        assert node._known_addresses(TARGET) == ["fake://a:1"]   # kept
        await node.stop()

    async def test_a_probe_from_an_unknown_id_still_creates_its_entry(self):
        """`touch` refuses to invent an entry — recency about a node we have
        never heard of is not one — so this path has to fall back to `add`,
        which is the one door an entry comes through."""
        node = _node()
        peer = _link(node)
        peer.dsa_pub = b"\x02" * 32
        assert node._routing.get(TARGET) is None
        await node._handle_ping(peer, Packet.create(
            PING, TARGET.raw, b"\xff" * 20, _NO_ADDRESSES))
        assert node._routing.get(TARGET) is not None
        await node.stop()


class TestTheAdvertisedSetIsCachedOnItsWholeInput:
    """A cache is only safe when its key is everything the answer depends on.
    Three lists go in; each one is proved to invalidate it, so there is no
    fourth thing to have forgotten."""

    def test_it_is_the_same_answer_twice(self):
        node = _node()
        node._addresses = ["tcp://0.0.0.0:9000"]
        node._local_ips = ["192.168.1.20"]
        assert node.advertised_uris() == node.advertised_uris()

    def test_a_caller_cannot_corrupt_it(self):
        node = _node()
        node._addresses = ["tcp://10.0.0.1:9000"]
        node.advertised_uris().append("tcp://evil:1")
        assert "tcp://evil:1" not in node.advertised_uris()

    def test_every_input_invalidates_it(self):
        node = _node()
        node._addresses = ["tcp://0.0.0.0:9000"]
        node._local_ips = ["192.168.1.20"]
        node._extra_addrs = []
        first = node.advertised_uris()
        node._local_ips = ["192.168.1.20", "10.0.0.5"]
        second = node.advertised_uris()
        assert second != first
        node._extra_addrs = ["81.240.12.33"]
        third = node.advertised_uris()
        assert third != second
        node._addresses = ["udp://0.0.0.0:9001"]
        assert node.advertised_uris() != third
