"""
Noticing a peer that is not playing the protocol.

The rules themselves are the easy half. What these tests are mostly about is the
frame around them, because that is what decides whether a detector defends a
network or attacks it:

  - a rule that fires on everyone is measuring *us*, and must stop talking;
  - a peer is compared to its own transport class, never to a constant;
  - being new, being quiet, or speaking something we have not heard of are not
    signals, and each of those is in the catalogue's anti-rules;
  - nothing here bans anybody — every finding is a weight handed to the ledger.
"""
import pytest

from src import behaviour, reputation
from src.behaviour import BehaviourWatch, Group, Observation, Rule
from src.cert import Certificate
from src.crypto import SessionKey
from src.features import CORE, KADEMLIA, PSEUDO, agree, encode
from src import node as node_module
from src.node import CAPABILITIES, FIND_NODE, PSEUDO_ANNOUNCE
from src.node_id import NodeID
from src.packet import Packet
from src.routing import NodeEntry
from tests.conftest import FakeTransport, make_node, settle


def _obs(**kwargs):
    kwargs.setdefault("node_id", NodeID.generate())
    kwargs.setdefault("transport", "tcp")
    kwargs.setdefault("packets_in", behaviour.MIN_PACKETS * 4)
    return Observation(**kwargs)


def _collect(watch, observations):
    found = []
    watch.sweep(observations, lambda node, weight, rule, summary, response:
                found.append((node, rule, weight)))
    return found


class TestTheFrame:
    def test_a_rule_that_fires_on_everyone_disarms_itself(self):
        """Doctrine 5, and the reason the rest is safe to switch on. If most
        peers look wrong, our clock or our uplink is wrong — and a detector
        that keeps accusing then turns a local fault into a network-wide
        fight."""
        always = Rule(id="X", summary="fires on everybody", weight=1.0,
                      wrong_when="always", test=lambda o, g: True)
        watch = BehaviourWatch(rules=(always,))
        assert _collect(watch, [_obs() for _ in range(8)]) == []
        assert watch.status()["disarmed"] == ["X"]

    def test_a_rule_that_fires_on_one_peer_still_speaks(self):
        villain = _obs()
        only = Rule(id="X", summary="fires on one", weight=1.0,
                    wrong_when="never",
                    test=lambda o, g: o.node_id == villain.node_id)
        watch = BehaviourWatch(rules=(only,))
        others = [_obs() for _ in range(7)]
        found = _collect(watch, [villain] + others)
        assert [rule for _n, rule, _w in found] == ["X"]
        assert watch.status()["disarmed"] == []

    def test_a_rule_that_raises_judges_nobody(self):
        """A detector is not worth a link, so a broken rule is silent rather
        than fatal."""
        broken = Rule(id="X", summary="raises", weight=1.0, wrong_when="n/a",
                      test=lambda o, g: 1 / 0)
        watch = BehaviourWatch(rules=(broken,))
        assert _collect(watch, [_obs() for _ in range(4)]) == []

    def test_transport_classes_are_judged_separately(self):
        """A LoRa peer and a TCP peer share no baseline worth having, so a slow
        medium must never be an outlier in a fast one's group."""
        watch = BehaviourWatch()
        fast = [_obs(transport="tcp", bytes_in=1000, bytes_out=1000)
                for _ in range(6)]
        slow = [_obs(transport="lora", bytes_in=10, bytes_out=10)
                for _ in range(6)]
        assert _collect(watch, fast + slow) == []

    def test_a_group_too_small_to_have_a_median_judges_nobody(self):
        """With three links, "twice the median" is a description of one of
        them."""
        watch = BehaviourWatch()
        peers = [_obs(bytes_in=1, bytes_out=10_000_000) for _ in range(2)]
        assert _collect(watch, peers) == []

    def test_the_rule_id_travels_with_the_finding(self):
        """An operator reading "reported for C1" has to be able to go and read
        C1 and disagree."""
        watch = BehaviourWatch()
        reasons = []
        watch.sweep([_obs(undeclared=3)] + [_obs() for _ in range(5)],
                    lambda node, weight, rule, summary, response:
                        reasons.append((rule, summary)))
        assert reasons and reasons[0][0] == "C1"
        assert "announced" in reasons[0][1]

    def test_every_rule_states_what_would_make_it_wrong(self):
        """A rule whose honest lookalike cannot be stated is a superstition,
        and this is how that gets caught rather than discussed."""
        for rule in behaviour.RULES + behaviour.ISSUER_RULES:
            assert rule.wrong_when.strip(), rule.id
            assert rule.response in (behaviour.SCORE, behaviour.NOTICE), rule.id
            # A scoring rule must be worth something; a notifying one must not
            # be, because nothing it says ever reaches the ledger.
            if rule.response == behaviour.SCORE:
                assert rule.weight > 0, rule.id
            else:
                assert rule.weight == 0, rule.id


class TestTheAntiRules:
    def test_being_new_is_not_a_signal(self):
        """The first entry in the catalogue's anti-rules: every honest node is
        new once."""
        watch = BehaviourWatch()
        newcomer = _obs(packets_in=3, bytes_in=1, bytes_out=100_000)
        established = [_obs(bytes_in=1000, bytes_out=1000) for _ in range(6)]
        found = _collect(watch, [newcomer] + established)
        assert newcomer.node_id not in [node for node, _r, _w in found]

    def test_being_quiet_is_not_a_signal(self):
        """A node that listens and rarely answers is a node."""
        watch = BehaviourWatch()
        quiet = _obs(bytes_in=100_000, bytes_out=1)
        others = [_obs(bytes_in=1000, bytes_out=1000) for _ in range(6)]
        found = _collect(watch, [quiet] + others)
        assert quiet.node_id not in [node for node, _r, _w in found]

    def test_a_peer_that_announced_nothing_is_counted_at_zero(self):
        """"I have never heard what you speak" is not evidence about you. Read
        the other way, the negotiation would be an upgrade that cuts off
        everyone who has not taken it."""
        watch = BehaviourWatch()
        silent = _obs(undeclared=0)      # what the node records for such a peer
        assert _collect(watch, [silent] + [_obs() for _ in range(5)]) == []


class TestTheRules:
    def test_C1_fires_on_a_plane_the_peer_disowned(self):
        watch = BehaviourWatch()
        liar = _obs(undeclared=5)
        found = _collect(watch, [liar] + [_obs() for _ in range(6)])
        assert (liar.node_id, "C1", 2.0) in found

    def test_D2_fires_on_a_peer_far_outside_its_group(self):
        watch = BehaviourWatch()
        sink = _obs(bytes_in=10, bytes_out=1_000_000)
        others = [_obs(bytes_in=1000, bytes_out=1000) for _ in range(6)]
        found = _collect(watch, [sink] + others)
        assert [rule for _n, rule, _w in found] == ["D2"]

    def test_E1_ignores_a_node_that_merely_includes_itself(self):
        """A node legitimately ranks itself among the candidates it returns —
        the answer would otherwise never mention it, and a lookup routed *to*
        it would come back without it."""
        watch = BehaviourWatch()
        normal = [_obs(found_entries=200, found_self=20) for _ in range(6)]
        assert _collect(watch, normal) == []

    def test_E1_fires_on_a_node_that_answers_with_little_else(self):
        watch = BehaviourWatch()
        greedy = _obs(found_entries=200, found_self=190)
        others = [_obs(found_entries=200, found_self=10) for _ in range(6)]
        found = _collect(watch, [greedy] + others)
        assert (greedy.node_id, "E1", 1.0) in found


# ---------------------------------------------------------------------------
# On a node
# ---------------------------------------------------------------------------

async def _two_peers():
    node, first = await make_node()
    second = FakeTransport()
    await node._inject_peer(second)
    for peer in node._peers:
        peer.authenticated_id = NodeID.generate()
        peer.session = SessionKey(b"\x00" * 32)
    return node, first, second


class TestOnANode:
    async def test_the_counter_only_moves_for_a_peer_that_announced(self):
        node, _first, _second = await _two_peers()
        peer = node._peers[0]
        packet = Packet.create(PSEUDO_ANNOUNCE, peer.authenticated_id.raw,
                               b"\xff" * 20, b"")
        try:
            await node._handle_packet(peer, packet)
            assert peer.undeclared == 0          # announced nothing → no claim
            await node._handle_capabilities(peer, Packet.create(
                CAPABILITIES, peer.authenticated_id.raw, b"\xff" * 20,
                encode({CORE, KADEMLIA})))
            await node._handle_packet(peer, packet)
            assert peer.undeclared == 1          # pseudo is not in its set
        finally:
            await node.stop()

    async def test_a_plane_it_did_announce_costs_nothing(self):
        node, _first, _second = await _two_peers()
        peer = node._peers[0]
        try:
            await node._handle_capabilities(peer, Packet.create(
                CAPABILITIES, peer.authenticated_id.raw, b"\xff" * 20,
                encode({CORE, PSEUDO})))
            for _ in range(10):
                await node._handle_packet(peer, Packet.create(
                    PSEUDO_ANNOUNCE, peer.authenticated_id.raw,
                    b"\xff" * 20, b""))
            assert peer.undeclared == 0
        finally:
            await node.stop()

    async def test_a_core_message_can_never_be_undeclared(self):
        """`CORE` is not negotiable — it is the messages that carry the
        negotiation itself — so a peer announcing nothing but core still gets
        to speak it."""
        node, _first, _second = await _two_peers()
        peer = node._peers[0]
        try:
            await node._handle_capabilities(peer, Packet.create(
                CAPABILITIES, peer.authenticated_id.raw, b"\xff" * 20,
                encode([])))
            assert peer.agreed == frozenset({CORE})
            await node._handle_packet(peer, Packet.create(
                0x01, peer.authenticated_id.raw, node._id.raw, b""))
            assert peer.undeclared == 0
        finally:
            await node.stop()

    async def test_the_sweep_reports_through_the_ledger(self):
        """Not a sanction, a weight: the rule says what it saw and the ledger
        decides what it adds up to."""
        node, _first, _second = await _two_peers()
        try:
            node._peers[0].undeclared = 4
            before = node._reputation.score(node._peers[0].authenticated_id)
            node._behaviour_sweep()
            after = node._reputation.score(node._peers[0].authenticated_id)
            assert after > before
            assert node._reputation.score(
                node._peers[1].authenticated_id) == 0.0
        finally:
            await node.stop()

    async def test_a_tarpitted_peer_is_not_swept(self):
        """It is already not being served; judging it again would only let one
        peer keep contributing to the medians everybody else is judged by."""
        node, _first, _second = await _two_peers()
        try:
            node._peers[0].undeclared = 4
            node._tarpit(node._peers[0])
            node._behaviour_sweep()
            assert node._reputation.score(
                node._peers[0].authenticated_id) == 0.0
        finally:
            await node.stop()

    async def test_the_sweep_never_raises(self):
        """It runs inside the keepalive loop, and a detector is not worth the
        keepalive."""
        node, _first, _second = await _two_peers()
        try:
            node._peers[0].counters = None       # as broken as it gets
            node._behaviour_sweep()
        finally:
            await node.stop()

    async def test_routing_answers_are_counted_for_E1(self):
        node, _first, _second = await _two_peers()
        peer = node._peers[0]
        try:
            assert peer.found_entries == 0
            await node._handle_packet(peer, Packet.create(
                FIND_NODE, peer.authenticated_id.raw, node._id.raw, b"x" * 8))
            # A malformed query answers nothing, so nothing is counted either.
            assert peer.found_entries == 0
        finally:
            await node.stop()

    async def test_the_status_names_every_rule(self):
        node, _first, _second = await _two_peers()
        try:
            node._behaviour_sweep()
            rules = node.behaviour_status()["rules"]
            assert {rule["id"] for rule in rules} == {"C1", "D2", "E1", "E2",
                                                      "D5", "A1"}
            assert all(rule["wrong_when"] for rule in rules)
        finally:
            await node.stop()


# ---------------------------------------------------------------------------
# D5 — the peer that was already trusted
# ---------------------------------------------------------------------------

def _settled(book, node_id, *, packets=100, size=500, out=0.5):
    """Feed one peer a steady diet until it has habits worth comparing."""
    totals = [0, 0, 0]
    for _ in range(behaviour.PROFILE_MATURITY + 2):
        totals[0] += packets
        totals[1] += packets * size
        totals[2] += int(packets * size * out)
        book.observe(_obs(node_id=node_id, packets_in=totals[0],
                          bytes_in=totals[1], bytes_out=totals[2]))
    return totals


class TestProfileBook:
    def test_a_peer_with_no_history_is_never_a_break(self):
        """Being new is the first anti-rule, and a profile is worth exactly its
        history."""
        book = behaviour.ProfileBook()
        node = NodeID.generate()
        totals = [0, 0, 0]
        for _ in range(behaviour.PROFILE_MATURITY - 1):
            totals[0] += 100
            totals[1] += 50_000
            totals[2] += 25_000
            assert book.observe(_obs(node_id=node, packets_in=totals[0],
                                     bytes_in=totals[1],
                                     bytes_out=totals[2])) is False

    def test_steady_habits_never_look_like_a_break(self):
        book = behaviour.ProfileBook()
        node = NodeID.generate()
        totals = _settled(book, node)
        for _ in range(10):
            totals[0] += 100
            totals[1] += 50_000
            totals[2] += 25_000
            assert book.observe(_obs(node_id=node, packets_in=totals[0],
                                     bytes_in=totals[1],
                                     bytes_out=totals[2])) is False

    def test_a_different_node_behind_the_same_key_is_seen(self):
        """The compromise signal. Everything else in this file detects a
        stranger; this detects the peer that was already trusted, because an
        attacker who steals a key gets the identity and not the habits."""
        book = behaviour.ProfileBook()
        node = NodeID.generate()
        totals = _settled(book, node)
        totals[0] += 5000            # rate, size and direction all move
        totals[1] += 5000 * 20
        totals[2] += 5000 * 20 * 40
        assert book.observe(_obs(node_id=node, packets_in=totals[0],
                                 bytes_in=totals[1],
                                 bytes_out=totals[2])) is True

    def test_one_dimension_moving_is_weather(self):
        """A rule that fired on a busy afternoon would fire on everybody."""
        book = behaviour.ProfileBook()
        node = NodeID.generate()
        totals = _settled(book, node)
        totals[0] += 100             # same rate and shape…
        totals[1] += 50_000
        totals[2] += 25_000 * 20     # …only the direction moved
        assert book.observe(_obs(node_id=node, packets_in=totals[0],
                                 bytes_in=totals[1],
                                 bytes_out=totals[2])) is False

    def test_an_idle_sweep_teaches_nothing(self):
        """A peer that said nothing has not changed its habits — it has been
        quiet, and counting that as a change would fire on every idle link."""
        book = behaviour.ProfileBook()
        node = NodeID.generate()
        totals = _settled(book, node)
        for _ in range(5):
            assert book.observe(_obs(node_id=node, packets_in=totals[0],
                                     bytes_in=totals[1],
                                     bytes_out=totals[2])) is False

    def test_going_quiet_counts_as_much_as_flooding(self):
        """A compromise can look like either, so `_moved` is symmetric."""
        assert behaviour._moved(1.0, 100.0) is True
        assert behaviour._moved(100.0, 1.0) is True
        assert behaviour._moved(0.0, 100.0) is True
        assert behaviour._moved(0.0, 0.0) is False

    def test_the_book_is_bounded_and_keeps_the_established(self):
        """Backwards from the usual eviction, deliberately: a profile is worth
        its history, so throwing away the longest-observed peer to make room
        for one seen once would spend the only thing this rule has."""
        book = behaviour.ProfileBook(max_profiles=4)
        veteran = NodeID.generate()
        _settled(book, veteran)
        for _ in range(50):
            book.observe(_obs(node_id=NodeID.generate()))
        assert len(book) <= 4
        assert book.mature() == 1

    def test_a_full_book_still_accepts_a_new_peer(self):
        """The entry just inserted is exempt from its own eviction. Without
        that the newcomer is its own least-established profile and goes again
        in the same breath — so a book at capacity would never accept anybody,
        and 1024 throwaway identities would freeze D5 for every peer that
        joined afterwards."""
        book = behaviour.ProfileBook(max_profiles=3)
        for _ in range(3):
            _settled(book, NodeID.generate())
        newcomer = NodeID.generate()
        book.observe(_obs(node_id=newcomer))
        assert len(book) == 3
        assert book.mature() == 2      # it displaced one, not all of them
        book.observe(_obs(node_id=newcomer, packets_in=999, bytes_in=999))
        assert len(book) == 3          # …and it is still there to be observed


class TestD5Notifies:
    async def test_a_habit_change_notifies_and_never_scores(self):
        """The honest lookalike is "the operator upgraded that machine", which
        is the common case by far — scoring it would punish somebody for
        administering their own fleet."""
        node, _first, _second = await _two_peers()
        peer = node._peers[0]
        try:
            for _ in range(behaviour.PROFILE_MATURITY + 2):
                peer.counters.pkts_in += 100
                peer.counters.bytes_in += 50_000
                peer.counters.bytes_out += 25_000
                node._behaviour_sweep()
            assert node.behaviour_status()["notices"] == []
            peer.counters.pkts_in += 5000
            peer.counters.bytes_in += 5000 * 20
            peer.counters.bytes_out += 5000 * 20 * 40
            node._behaviour_sweep()
            notices = node.behaviour_status()["notices"]
            assert [n["rule"] for n in notices] == ["D5"]
            assert notices[0]["node"] == peer.authenticated_id.raw.hex()
            # …and nothing reached the ledger.
            assert node._reputation.score(peer.authenticated_id) == 0.0
        finally:
            await node.stop()

    async def test_the_notice_is_not_repeated_every_sweep(self):
        """A peer whose habits changed keeps looking changed for as long as its
        old average survives, and a notice repeated every twenty seconds is a
        notice nobody reads."""
        node, _first, _second = await _two_peers()
        peer = node._peers[0]
        try:
            for _ in range(behaviour.PROFILE_MATURITY + 2):
                peer.counters.pkts_in += 100
                peer.counters.bytes_in += 50_000
                peer.counters.bytes_out += 25_000
                node._behaviour_sweep()
            for _ in range(5):
                peer.counters.pkts_in += 5000
                peer.counters.bytes_in += 5000 * 20
                peer.counters.bytes_out += 5000 * 20 * 40
                node._behaviour_sweep()
            assert len(node.behaviour_status()["notices"]) == 1
        finally:
            await node.stop()

    async def test_the_operator_can_say_it_was_them(self):
        """There has to be such a button and it has to be local: the whole
        point of D5 is that it cannot tell a compromise from an upgrade, and
        the only thing that can is the person who did or did not do it."""
        node, _first, _second = await _two_peers()
        peer = node._peers[0]
        try:
            for _ in range(behaviour.PROFILE_MATURITY + 2):
                peer.counters.pkts_in += 100
                peer.counters.bytes_in += 50_000
                peer.counters.bytes_out += 25_000
                node._behaviour_sweep()
            peer.counters.pkts_in += 5000
            peer.counters.bytes_in += 5000 * 20
            peer.counters.bytes_out += 5000 * 20 * 40
            node._behaviour_sweep()
            assert node.behaviour_status()["notices"]
            node_hex = peer.authenticated_id.raw.hex()
            assert node.console_accept_change(node_hex) is True
            assert node.behaviour_status()["notices"] == []
            assert node.console_accept_change(node_hex) is False
        finally:
            await node.stop()

    async def test_notices_are_bounded(self):
        node, _first, _second = await _two_peers()
        try:
            for _ in range(200):
                node._note_behaviour(NodeID.generate(), "D5", "changed")
            assert len(node.behaviour_status()["notices"]) <= 64
        finally:
            await node.stop()


# ---------------------------------------------------------------------------
# What a weight means
# ---------------------------------------------------------------------------

class TestChargingAConditionOnce:
    """The doctrine says no single rule ever bans. That was aspiration until
    the sweep and the ledger were held against each other: every rule here
    reads a *cumulative* counter, so a rule that becomes true stays true, and a
    charge per sweep against a ledger that halves every hour made the weakest
    rule in the file decisive within minutes — D2, whose own `wrong_when` says
    it means nothing on its own, would have cut off a quiet consumer."""

    def test_no_single_rule_can_reach_suspect(self):
        """A rule that never stops firing converges on twice its weight. This
        inequality *is* the doctrine, which is why it is asserted and not
        described."""
        assert behaviour.RULE_RECHARGE >= reputation.DEFAULT_HALFLIFE
        worst = max(rule.weight
                    for rule in behaviour.RULES + behaviour.ISSUER_RULES)
        assert 2 * worst < reputation.DEFAULT_SUSPECT

    def test_a_condition_is_charged_once_not_once_per_sweep(self):
        watch = BehaviourWatch()
        liar = _obs(undeclared=5)
        rest = [_obs() for _ in range(6)]
        assert [rule for _n, rule, _w in _collect(watch, [liar] + rest)] == ["C1"]
        assert _collect(watch, [liar] + rest) == []

    def test_the_charge_comes_back_once_the_ledger_has_forgotten(self):
        """Not never again: a peer still doing it an hour later is still doing
        it, and the ledger has halved by then."""
        watch = BehaviourWatch()
        liar = _obs(undeclared=5)
        rest = [_obs() for _ in range(6)]
        found = []
        report = lambda node, weight, rule, summary, response: found.append(rule)
        watch.sweep([liar] + rest, report, now=1000.0)
        watch.sweep([liar] + rest, report,
                    now=1000.0 + behaviour.RULE_RECHARGE - 1)
        assert found == ["C1"]
        watch.sweep([liar] + rest, report,
                    now=1000.0 + behaviour.RULE_RECHARGE)
        assert found == ["C1", "C1"]

    def test_two_rules_still_add_up(self):
        """One rule may not sanction alone; corroboration must still be able
        to. Charging once per condition must not turn into charging once."""
        watch = BehaviourWatch()
        both = _obs(undeclared=5, bytes_in=10, bytes_out=1_000_000)
        rest = [_obs(bytes_in=1000, bytes_out=1000) for _ in range(6)]
        found = {rule for _n, rule, _w in _collect(watch, [both] + rest)}
        assert found == {"C1", "D2"}

    def test_forgetting_a_peer_forgets_what_it_was_charged(self):
        """"That was me" has to reach the charges too, or the next finding
        would be dated from before the operator answered."""
        watch = BehaviourWatch()
        liar = _obs(undeclared=5)
        rest = [_obs() for _ in range(6)]
        assert _collect(watch, [liar] + rest)
        watch.forget(liar.node_id)
        assert _collect(watch, [liar] + rest)

    def test_the_charge_table_is_bounded(self):
        """Nothing an attacker can grow — but bounded anyway, because "nothing
        can" is a claim about code somebody will change."""
        always = Rule(id="X", summary="fires on everybody", weight=1.0,
                      wrong_when="always", test=lambda o, g: True)
        watch = BehaviourWatch(rules=(always,), universal_share=2.0)
        _collect(watch, [_obs() for _ in range(behaviour.MAX_CHARGES + 20)])
        assert len(watch._charged) <= behaviour.MAX_CHARGES


# ---------------------------------------------------------------------------
# E2 — the peer whose view of the network nobody shares
# ---------------------------------------------------------------------------

class TestE2:
    def test_a_peer_nobody_agrees_with_is_seen(self):
        watch = BehaviourWatch()
        odd = _obs(answers_judged=40, answers_disjoint=36)
        others = [_obs(answers_judged=40, answers_disjoint=1) for _ in range(6)]
        found = _collect(watch, [odd] + others)
        assert (odd.node_id, "E2", 1.0) in found

    def test_agreeing_with_everybody_is_never_a_signal(self):
        watch = BehaviourWatch()
        peers = [_obs(answers_judged=40, answers_disjoint=1) for _ in range(6)]
        assert _collect(watch, peers) == []

    def test_a_peer_asked_a_handful_of_times_is_not_judged(self):
        """One lookup round says nothing about anybody, and a peer that has
        only just started answering is new — the first anti-rule."""
        watch = BehaviourWatch()
        odd = _obs(answers_judged=behaviour.MIN_ANSWERS - 1,
                   answers_disjoint=behaviour.MIN_ANSWERS - 1)
        others = [_obs(answers_judged=40, answers_disjoint=1) for _ in range(6)]
        assert _collect(watch, [odd] + others) == []

    def test_a_peer_never_asked_beside_anybody_is_not_judged(self):
        """Zero judged answers must read as "no evidence", never as "agrees
        with nobody" — a peer we never queried alongside others would
        otherwise be the most suspicious node on the mesh."""
        watch = BehaviourWatch()
        silent = _obs(answers_judged=0, answers_disjoint=0)
        others = [_obs(answers_judged=40, answers_disjoint=1) for _ in range(6)]
        assert _collect(watch, [silent] + others) == []

    def test_a_partition_that_takes_most_of_our_peers_says_nothing(self):
        """The honest case its own catalogue entry names, and the group
        comparison answers it before the disarm has to: a majority that sees a
        different network *is* the median, so nobody is an outlier against it.
        The rule does not fire at all — it is not fired and then silenced."""
        watch = BehaviourWatch()
        split = [_obs(answers_judged=40, answers_disjoint=36) for _ in range(6)]
        rest = [_obs(answers_judged=40, answers_disjoint=1) for _ in range(4)]
        assert _collect(watch, split + rest) == []
        fired = {rule["id"]: rule["fired"] for rule in watch.status()["rules"]}
        assert fired["E2"] == 0


class TestAnswerOverlapOnANode:
    """What the lookup counts, before any rule reads it."""

    @staticmethod
    def _entries(*ids):
        return [NodeEntry(node_id) for node_id in ids]

    async def test_one_answer_is_disjoint_from_nothing(self):
        node, _first, _second = await _two_peers()
        peer = node._peers[0]
        try:
            ids = [NodeID.generate() for _ in range(4)]
            node._note_answer_overlap([peer.authenticated_id],
                                      [self._entries(*ids)])
            assert peer.answers_judged == 0
        finally:
            await node.stop()

    async def test_a_shared_view_is_not_disjoint(self):
        node, first_peer, second_peer = await _two_peers()
        one, two = node._peers[0], node._peers[1]
        try:
            ids = [NodeID.generate() for _ in range(4)]
            node._note_answer_overlap(
                [one.authenticated_id, two.authenticated_id],
                [self._entries(*ids), self._entries(*ids)])
            assert (one.answers_judged, one.answers_disjoint) == (1, 0)
            assert (two.answers_judged, two.answers_disjoint) == (1, 0)
        finally:
            await node.stop()

    async def test_a_view_nobody_shares_is_counted(self):
        node, _first, _second = await _two_peers()
        one, two = node._peers[0], node._peers[1]
        try:
            node._note_answer_overlap(
                [one.authenticated_id, two.authenticated_id],
                [self._entries(*[NodeID.generate() for _ in range(4)]),
                 self._entries(*[NodeID.generate() for _ in range(4)])])
            assert one.answers_disjoint == 1
            assert two.answers_disjoint == 1
        finally:
            await node.stop()

    async def test_padding_with_one_id_everybody_knows_does_not_clear_it(self):
        """A test for an *empty* intersection would be cleared by a single
        famous id, which costs an attacker nothing at all."""
        node, _first, _second = await _two_peers()
        one, two = node._peers[0], node._peers[1]
        try:
            common = NodeID.generate()
            honest = [common] + [NodeID.generate() for _ in range(3)]
            steered = [common] + [NodeID.generate() for _ in range(7)]
            node._note_answer_overlap(
                [one.authenticated_id, two.authenticated_id],
                [self._entries(*steered), self._entries(*honest)])
            assert one.answers_disjoint == 1
            assert two.answers_disjoint == 0
        finally:
            await node.stop()

    async def test_a_small_answer_is_never_judged(self):
        """Two nodes may legitimately name two different closest candidates."""
        node, _first, _second = await _two_peers()
        one, two = node._peers[0], node._peers[1]
        try:
            node._note_answer_overlap(
                [one.authenticated_id, two.authenticated_id],
                [self._entries(NodeID.generate()),
                 self._entries(NodeID.generate())])
            assert one.answers_judged == 0
            assert two.answers_judged == 0
        finally:
            await node.stop()

    async def test_only_a_node_we_have_a_link_to_is_counted(self):
        """An answer that reached us through relays was handled by nodes other
        than the one that signed it; charging the far end for what the path did
        would name whoever is innocent."""
        node, _first, _second = await _two_peers()
        one = node._peers[0]
        try:
            stranger = NodeID.generate()
            node._note_answer_overlap(
                [one.authenticated_id, stranger],
                [self._entries(*[NodeID.generate() for _ in range(4)]),
                 self._entries(*[NodeID.generate() for _ in range(4)])])
            assert one.answers_judged == 1
        finally:
            await node.stop()

    async def test_a_lookup_never_raises_on_a_broken_answer(self):
        node, _first, _second = await _two_peers()
        one, two = node._peers[0], node._peers[1]
        try:
            node._note_answer_overlap(
                [one.authenticated_id, two.authenticated_id],
                [None, Exception("timeout")])
            assert one.answers_judged == 0
        finally:
            await node.stop()


# ---------------------------------------------------------------------------
# A1 — the burst under one signature
# ---------------------------------------------------------------------------

def _watched(book, issuer, *, per_window=1):
    """Give one issuer a history worth deviating from."""
    for _ in range(behaviour.ISSUER_MATURITY + 1):
        book.observe(issuer, per_window)


class TestIssuerBook:
    def test_an_issuer_we_have_just_met_is_never_a_burst(self):
        """Joining a network *is* a burst — everything is new to us on the
        first day — and an issuer with no history has nothing to deviate
        from. The catalogue gives it no accusation for exactly that reason."""
        book = behaviour.IssuerBook()
        issuer = NodeID.generate()
        assert book.observe(issuer, 500) is False

    def test_a_steady_issuer_never_bursts(self):
        book = behaviour.IssuerBook()
        issuer = NodeID.generate()
        _watched(book, issuer, per_window=6)
        assert book.observe(issuer, 7) is False

    def test_a_burst_is_seen_once_the_issuer_has_a_history(self):
        book = behaviour.IssuerBook()
        issuer = NodeID.generate()
        _watched(book, issuer, per_window=1)
        assert book.observe(issuer, 200) is True

    def test_a_handful_is_never_a_burst_however_quiet_the_history(self):
        """Without the floor an issuer that admitted nobody for an hour would
        "burst" on its next single member, and every quiet network would
        accuse its own root the moment somebody joined."""
        book = behaviour.IssuerBook()
        issuer = NodeID.generate()
        _watched(book, issuer, per_window=0)
        assert book.observe(issuer, behaviour.ISSUER_FLOOR - 1) is False

    def test_an_issuer_is_compared_to_itself_and_never_to_others(self):
        """A hobbyist's root admitting one node a month and a datacentre's
        admitting thirty a day are both correct."""
        book = behaviour.IssuerBook()
        busy, quiet = NodeID.generate(), NodeID.generate()
        _watched(book, busy, per_window=40)
        _watched(book, quiet, per_window=0)
        assert book.observe(busy, 45) is False
        assert book.observe(quiet, 45) is True

    def test_the_book_is_bounded(self):
        book = behaviour.IssuerBook(max_issuers=8)
        for _ in range(50):
            book.observe(NodeID.generate(), 1)
        assert len(book) == 8

    def test_a_full_book_still_accepts_a_new_issuer(self):
        """The newcomer must be exempt from its own eviction. Otherwise a full
        book drops it in the same breath it was added, and eight throwaway
        identities would freeze the rule for everybody arriving afterwards."""
        book = behaviour.IssuerBook(max_issuers=4)
        established = [NodeID.generate() for _ in range(4)]
        for issuer in established:
            _watched(book, issuer)
        newcomer = NodeID.generate()
        book.observe(newcomer, 1)
        assert newcomer.raw in [getattr(k, "raw", k) for k in book.known()]
        # …and it displaced none of the issuers we actually know something about
        assert book.mature() == 3

    def test_forgetting_an_issuer_forgets_its_rate(self):
        book = behaviour.IssuerBook()
        issuer = NodeID.generate()
        _watched(book, issuer, per_window=1)
        book.forget(issuer)
        assert book.observe(issuer, 500) is False


class TestA1:
    @staticmethod
    def _collect_issuers(watch, arrivals, **kwargs):
        found = []
        watch.sweep_issuers(arrivals, lambda node, weight, rule, summary, resp:
                            found.append((node, rule, weight, resp)), **kwargs)
        return found

    def test_a_burst_notifies_and_never_scores(self):
        """Its honest lookalike is a real deployment rolling out fifty machines
        on a Tuesday. Scoring that would sanction an operator for provisioning
        their own fleet."""
        watch = BehaviourWatch()
        issuer, quiet = NodeID.generate(), NodeID.generate()
        for _ in range(behaviour.ISSUER_MATURITY + 1):
            self._collect_issuers(watch, {issuer: 1, quiet: 1})
        found = self._collect_issuers(watch, {issuer: 200, quiet: 1})
        assert [(rule, weight, resp) for _n, rule, weight, resp in found] == [
            ("A1", 0.0, behaviour.NOTICE)]
        assert found[0][0] == issuer

    def test_admitting_nobody_is_part_of_an_issuer_history(self):
        """An issuer absent from a window has not stopped existing; folding it
        in at zero is what stops a burst hiding behind the quiet before it."""
        watch = BehaviourWatch()
        issuer, other = NodeID.generate(), NodeID.generate()
        self._collect_issuers(watch, {issuer: 1, other: 1})
        for _ in range(behaviour.ISSUER_MATURITY):
            self._collect_issuers(watch, {other: 1})
        found = self._collect_issuers(watch, {issuer: 200, other: 1})
        assert [rule for _n, rule, _w, _r in found] == ["A1"]

    def test_most_issuers_bursting_at_once_disarms_the_rule(self):
        """A node coming back from a partition absorbs everybody's members at
        once. That is a fact about us, and doctrine 5 says so out loud."""
        watch = BehaviourWatch()
        issuers = [NodeID.generate() for _ in range(6)]
        for _ in range(behaviour.ISSUER_MATURITY + 1):
            self._collect_issuers(watch, {issuer: 1 for issuer in issuers})
        assert self._collect_issuers(
            watch, {issuer: 200 for issuer in issuers}) == []
        assert "A1" in watch.status()["disarmed"]

    def test_a_burst_is_charged_once_and_not_once_per_window(self):
        watch = BehaviourWatch()
        issuer, quiet = NodeID.generate(), NodeID.generate()
        for _ in range(behaviour.ISSUER_MATURITY + 1):
            self._collect_issuers(watch, {issuer: 1, quiet: 1}, now=1.0)
        assert self._collect_issuers(watch, {issuer: 400, quiet: 1}, now=1.0)
        assert self._collect_issuers(watch, {issuer: 400, quiet: 1}, now=2.0) == []


class TestCertArrivalsOnANode:
    """What the node counts for A1, before the book ever sees it."""

    @staticmethod
    def _cert(issuer, subject):
        return Certificate(subject, b"subject-key", issuer, b"issuer-key",
                           1, 0, b"signature")

    async def test_a_subject_new_to_us_is_counted_under_its_issuer(self):
        node, _first, _second = await _two_peers()
        try:
            issuer, subject = NodeID.generate(), NodeID.generate()
            node._note_cert_arrival(self._cert(issuer, subject))
            assert node._cert_arrivals == {(issuer.raw, subject.raw)}
        finally:
            await node.stop()

    async def test_a_subject_counts_once_however_often_it_is_offered(self):
        """A peer that could make us count one subject twice — by handing it
        back after the store's own limits evicted it — could manufacture a
        burst under any issuer it chose."""
        node, _first, _second = await _two_peers()
        try:
            issuer, subject = NodeID.generate(), NodeID.generate()
            for _ in range(50):
                node._note_cert_arrival(self._cert(issuer, subject))
            assert len(node._cert_arrivals) == 1
        finally:
            await node.stop()

    async def test_a_root_vouching_for_itself_admits_nobody(self):
        node, _first, _second = await _two_peers()
        try:
            root = NodeID.generate()
            node._note_cert_arrival(self._cert(root, root))
            assert node._cert_arrivals == set()
        finally:
            await node.stop()

    async def test_what_we_issued_ourselves_is_not_news_to_us(self):
        node, _first, _second = await _two_peers()
        try:
            node._note_cert_arrival(self._cert(node._id, NodeID.generate()))
            assert node._cert_arrivals == set()
        finally:
            await node.stop()

    async def test_a_subject_we_already_hold_is_not_an_arrival(self):
        node, _first, _second = await _two_peers()
        try:
            issuer, subject = NodeID.generate(), NodeID.generate()
            node._cert_store._certs[subject.raw] = [self._cert(issuer, subject)]
            node._note_cert_arrival(self._cert(issuer, subject))
            assert node._cert_arrivals == set()
        finally:
            await node.stop()

    async def test_the_window_is_bounded(self):
        node, _first, _second = await _two_peers()
        try:
            issuer = NodeID.generate()
            for _ in range(node_module._CERT_ARRIVALS_MAX + 100):
                node._note_cert_arrival(self._cert(issuer, NodeID.generate()))
            assert len(node._cert_arrivals) <= node_module._CERT_ARRIVALS_MAX
        finally:
            await node.stop()

    async def test_the_sweep_drains_the_window(self):
        """A window that is never emptied is a burst spread over the lifetime
        of the process, which is no burst at all."""
        node, _first, _second = await _two_peers()
        try:
            issuer = NodeID.generate()
            for _ in range(5):
                node._note_cert_arrival(self._cert(issuer, NodeID.generate()))
            node._behaviour_sweep()
            assert node._cert_arrivals == set()
            assert node.behaviour_status()["issuers"] == 1
        finally:
            await node.stop()

    async def test_a_burst_reaches_the_operator_and_not_the_ledger(self):
        node, _first, _second = await _two_peers()
        try:
            issuer, quiet = NodeID.generate(), NodeID.generate()
            for _ in range(behaviour.ISSUER_MATURITY + 1):
                node._note_cert_arrival(self._cert(issuer, NodeID.generate()))
                node._note_cert_arrival(self._cert(quiet, NodeID.generate()))
                node._behaviour_sweep()
            for _ in range(200):
                node._note_cert_arrival(self._cert(issuer, NodeID.generate()))
            node._note_cert_arrival(self._cert(quiet, NodeID.generate()))
            node._behaviour_sweep()
            notices = node.behaviour_status()["notices"]
            assert [n["rule"] for n in notices] == ["A1"]
            assert notices[0]["node"] == issuer.raw.hex()
            assert node._reputation.score(issuer) == 0.0
        finally:
            await node.stop()
