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

from src import behaviour
from src.behaviour import BehaviourWatch, Group, Observation, Rule
from src.crypto import SessionKey
from src.features import CORE, KADEMLIA, PSEUDO, agree, encode
from src.node import CAPABILITIES, FIND_NODE, PSEUDO_ANNOUNCE
from src.node_id import NodeID
from src.packet import Packet
from tests.conftest import FakeTransport, make_node, settle


def _obs(**kwargs):
    kwargs.setdefault("node_id", NodeID.generate())
    kwargs.setdefault("transport", "tcp")
    kwargs.setdefault("packets_in", behaviour.MIN_PACKETS * 4)
    return Observation(**kwargs)


def _collect(watch, observations):
    found = []
    watch.sweep(observations, lambda node, weight, rule, summary:
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
                    lambda node, weight, rule, summary:
                        reasons.append((rule, summary)))
        assert reasons and reasons[0][0] == "C1"
        assert "announced" in reasons[0][1]

    def test_every_rule_states_what_would_make_it_wrong(self):
        """A rule whose honest lookalike cannot be stated is a superstition,
        and this is how that gets caught rather than discussed."""
        for rule in behaviour.RULES:
            assert rule.wrong_when.strip(), rule.id
            assert rule.weight > 0, rule.id


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
            assert {rule["id"] for rule in rules} == {"C1", "D2", "E1"}
            assert all(rule["wrong_when"] for rule in rules)
        finally:
            await node.stop()
