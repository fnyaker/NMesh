"""
Zero trust: what a node thinks of the nodes it talks to.

Being in the network is not being trusted. This is the layer that says so, and
it is the one with the most dangerous failure mode in the tree: if hearsay could
get a node cut off, anybody able to speak on the mesh could cut anybody off it,
and we would have built a censorship primitive with a reputation label on it.

So the tests that matter most here are the ones about what an accusation may
*not* do — and about the silence, because a node told it has been detected
changes identity and starts again.
"""
import asyncio
import time

import pytest

from src import accusation
from src.crypto import CryptoIdentity, SessionKey, verify_signature
from src.node import ABUSE_REPORT, PONG, PING, _encode_addresses
from src.node_id import NodeID
from src.packet import Packet
from src.reputation import (DEFAULT_SUSPECT, HOSTILE, MAX_WEIGHT, OK, SUSPECT,
                            RateGate, Reputation)
from tests.conftest import FakeTransport, make_node, settle


def _identity_and_id():
    identity = CryptoIdentity()
    return identity, NodeID.from_public_key(identity.dsa_public_key)


def parsed_at(raw: bytes) -> int:
    """The moment a record claims, so a test can re-sign the same statement."""
    return accusation.parse(raw, verify_signature)["issued_at"]


def _condemn(node, node_id, times: int = 12) -> str:
    """Report a node until it is held hostile.

    Deliberately several calls: one report is never on its own decisive, and a
    test that leant on a single maximal one would be asserting the opposite of
    what `MAX_WEIGHT` is for."""
    standing = OK
    for _ in range(times):
        standing = node.report_abuse(node_id, 1000.0, "flooding")
    return standing


class TestTheLedger:
    def test_evidence_accumulates_to_a_standing(self):
        rep = Reputation(suspect=3.0, hostile=6.0)
        node = NodeID.generate()
        assert rep.standing(node) == OK
        assert rep.note(node, 3.5) == SUSPECT
        assert rep.note(node, 3.5) == HOSTILE

    def test_evidence_fades(self):
        """A node that misbehaved once and then behaved comes back, without
        anybody having to do anything about it."""
        rep = Reputation(suspect=3.0, hostile=6.0, halflife=100.0)
        node = NodeID.generate()
        rep.note(node, 4.0, now=0.0)
        assert rep.standing(node, now=0.0) == SUSPECT
        assert rep.standing(node, now=200.0) == OK      # two half-lives

    def test_one_report_is_never_on_its_own_decisive(self):
        """Two things at once: an app with a bug in its own accounting cannot
        bring a peer down in a single call, and the worst thing any caller can
        say is still worth strictly less than the first threshold. When the two
        constants were equal, a maximal report landed exactly on the line and
        the first decay tick put it back under — the strongest statement an app
        could make changed nothing, for ever, and nothing said why."""
        rep = Reputation()
        node = NodeID.generate()
        assert rep.note(node, 1e12) == OK
        assert rep.score(node) == pytest.approx(MAX_WEIGHT)
        assert MAX_WEIGHT < DEFAULT_SUSPECT

    def test_shouting_louder_buys_nothing(self):
        """What means something is how many distinct members say it. Repeating
        an accusation is free to send, so counting repetitions would price the
        mechanism at whatever the loudest node feels like paying."""
        rep = Reputation(suspect=3.0, hostile=6.0)
        node, accuser = NodeID.generate(), NodeID.generate()
        for _ in range(100):
            rep.note_accusation(node, accuser)
        assert rep.score(node) <= 1.0

    def test_hearsay_alone_never_reaches_hostile(self):
        """The whole safety property. A swarm of accusers may make this node
        wary; it may never make it cut anybody off."""
        rep = Reputation(suspect=3.0, hostile=6.0)
        node = NodeID.generate()
        for _ in range(500):
            rep.note_accusation(node, NodeID.generate())
        assert rep.standing(node) == SUSPECT
        assert rep.standing(node) != HOSTILE

    def test_hearsay_plus_something_we_saw_does_reach_hostile(self):
        """The cap is not a wall against evidence, only against evidence we did
        not gather. A crowd corroborating what we saw ourselves counts."""
        rep = Reputation(suspect=3.0, hostile=6.0)
        node = NodeID.generate()
        for _ in range(20):
            rep.note_accusation(node, NodeID.generate())
        rep.note(node, 2.0)
        assert rep.standing(node) == HOSTILE

    def test_nobody_accuses_themselves(self):
        rep = Reputation(suspect=3.0, hostile=6.0)
        node = NodeID.generate()
        rep.note_accusation(node, node)
        assert rep.score(node) == 0.0

    def test_an_operator_can_overrule_us(self):
        rep = Reputation(suspect=3.0, hostile=6.0)
        node = NodeID.generate()
        rep.note(node, 10.0)
        assert rep.forgive(node) is True
        assert rep.standing(node) == OK
        assert rep.forgive(node) is False

    def test_the_least_suspect_is_evicted_first(self):
        """Oldest-first would be exactly backwards: identities are free to
        mint, so an attacker would flood fresh ones until the node it actually
        cares about aged out, and walk back in clean."""
        rep = Reputation(suspect=3.0, hostile=6.0, max_tracked=8)
        villain = NodeID.generate()
        rep.note(villain, 5.0)
        for _ in range(50):
            rep.note(NodeID.generate(), 0.1)
        assert rep.score(villain) > 0.0
        assert len(rep) <= 8

    def test_accusers_per_subject_are_bounded(self):
        rep = Reputation(suspect=3.0, hostile=6.0)
        node = NodeID.generate()
        for _ in range(500):
            rep.note_accusation(node, NodeID.generate())
        assert len(rep._standings[node.raw].accusers) <= 64

    def test_rows_leave_out_what_is_held_against_nobody(self):
        rep = Reputation()
        rep.note(NodeID.generate(), 1.0, "flooding")
        assert len(rep.rows()) == 1
        assert rep.rows()[0]["reason"] == "flooding"


class TestRateGate:
    def test_it_allows_up_to_the_ceiling_then_stops(self):
        gate = RateGate(3, 10.0)
        sender = NodeID.generate()
        assert [gate.allow(sender, now=0.0) for _ in range(4)] == \
            [True, True, True, False]

    def test_the_window_moves_on(self):
        gate = RateGate(2, 10.0)
        sender = NodeID.generate()
        assert gate.allow(sender, now=0.0) and gate.allow(sender, now=1.0)
        assert gate.allow(sender, now=2.0) is False
        assert gate.allow(sender, now=20.0) is True

    def test_senders_are_bounded(self):
        """Tracking a flood must not itself become the memory the flood was
        after."""
        gate = RateGate(2, 10.0, max_senders=4)
        for _ in range(100):
            gate.allow(NodeID.generate(), now=0.0)
        assert len(gate._seen) <= 4

    def test_one_sender_does_not_spend_another_s_allowance(self):
        gate = RateGate(1, 10.0)
        a, b = NodeID.generate(), NodeID.generate()
        assert gate.allow(a, now=0.0) is True
        assert gate.allow(b, now=0.0) is True
        assert gate.allow(a, now=0.0) is False


class TestTheRecord:
    def test_round_trip(self):
        accuser, accuser_id = _identity_and_id()
        _subject, subject_id = _identity_and_id()
        raw = accusation.build(subject_id, accuser.dsa_public_key, accuser.sign,
                               severity=3, kind=accusation.KIND_FLOOD)
        parsed = accusation.parse(raw, verify_signature)
        assert parsed["accuser_id"] == accuser_id
        assert parsed["subject_id"] == subject_id
        assert parsed["severity"] == 3

    def test_a_stale_accusation_is_a_replay_not_evidence(self):
        accuser, _accuser_id = _identity_and_id()
        _subject, subject_id = _identity_and_id()
        old = accusation.build(subject_id, accuser.dsa_public_key, accuser.sign,
                               issued_at=int(time.time()) - accusation.MAX_AGE - 60)
        assert accusation.parse(old, verify_signature) is None

    def test_an_accusation_from_the_future_is_refused(self):
        accuser, _accuser_id = _identity_and_id()
        _subject, subject_id = _identity_and_id()
        ahead = accusation.build(subject_id, accuser.dsa_public_key, accuser.sign,
                                 issued_at=int(time.time()) + accusation.MAX_SKEW + 60)
        assert accusation.parse(ahead, verify_signature) is None

    def test_a_tampered_record_does_not_verify(self):
        accuser, _accuser_id = _identity_and_id()
        _subject, subject_id = _identity_and_id()
        raw = bytearray(accusation.build(subject_id, accuser.dsa_public_key,
                                         accuser.sign))
        raw[-1] ^= 1
        assert accusation.parse(bytes(raw), verify_signature) is None

    def test_an_identity_accusing_itself_is_noise(self):
        accuser, accuser_id = _identity_and_id()
        raw = accusation.build(accuser_id, accuser.dsa_public_key, accuser.sign)
        assert accusation.parse(raw, verify_signature) is None

    @pytest.mark.parametrize("blob", [
        b"", b"\x00", b"\x01" * 8, b"\xff" * 300,
        bytes([2]) + b"\x00" * 60, bytes([1]) + b"\x00" * 40,
    ])
    def test_no_hostile_byte_string_raises(self, blob):
        assert accusation.parse(blob, verify_signature) is None


# ---------------------------------------------------------------------------
# On a node
# ---------------------------------------------------------------------------

async def _node_with_two_peers():
    node, first_link = await make_node()
    second_link = FakeTransport()
    await node._inject_peer(second_link)
    for peer in node._peers:
        peer.authenticated_id = NodeID.generate()
        peer.session = SessionKey(b"\x00" * 32)
    return node, first_link, second_link


class TestSanction:
    async def test_a_suspect_peer_stops_being_served_without_being_told(self):
        node, link, _other = await _node_with_two_peers()
        peer = node._peers[0]
        try:
            _condemn(node, peer.authenticated_id)
            assert peer.tarpit_until      # held, not closed
            link.sent.clear()
            await node._handle_packet(peer, Packet.create(
                PING, peer.authenticated_id.raw, b"\xff" * 20,
                _encode_addresses(["tcp://127.0.0.1:1"])))
            assert not link.sent          # not even a refusal
            assert peer in node._peers    # the socket stays up, and quiet
        finally:
            await node.stop()

    async def test_the_hold_is_not_the_same_length_twice(self):
        """A fixed delay before the link goes is a message too, only slower."""
        node, _link, _other = await _node_with_two_peers()
        try:
            holds = set()
            for _ in range(12):
                peer = node._peers[0]
                peer.tarpit_until = 0.0
                node._tarpit(peer)
                holds.add(round(peer.tarpit_until, 4))
            assert len(holds) > 1
        finally:
            await node.stop()

    async def test_an_expired_hold_lets_the_link_go(self):
        node, _link, _other = await _node_with_two_peers()
        peer = node._peers[0]
        try:
            node._tarpit(peer)
            peer.tarpit_until = time.monotonic() - 1
            node._reap_expired_tarpits()
            await settle(node)
            assert peer not in node._peers
        finally:
            await node.stop()

    async def test_we_never_report_ourselves(self):
        """A bug in an app must not be able to make a node stop serving its own
        operator."""
        node, _link, _other = await _node_with_two_peers()
        try:
            assert node.report_abuse(node._id, 1000.0, "bug") == OK
            assert node._reputation.score(node._id) == 0.0
        finally:
            await node.stop()

    async def test_a_hostile_node_is_refused_a_fresh_link(self):
        node, _link, _other = await _node_with_two_peers()
        stranger, stranger_id = _identity_and_id()
        try:
            assert _condemn(node, stranger_id) == HOSTILE
            peer = node._peers[1]
            peer.authenticated_id = None
            peer.pending_challenge = b"\x00" * 32
            await node._handle_handshake(peer, Packet.create(
                0x08, stranger_id.raw, node._id.raw,
                b"\x00\x00" + len(stranger.dsa_public_key).to_bytes(2, "big")
                + b"\x00\x00" + stranger.dsa_public_key))
            assert peer.authenticated_id is None
            assert any("hostile" in row["reason"]
                       for row in node.handshake_refusals())
        finally:
            await node.stop()


class TestPropagation:
    async def _accuse(self, node, peer, accuser, subject_id, **kwargs):
        raw = accusation.build(subject_id, accuser.dsa_public_key,
                               accuser.sign, **kwargs)
        await node._handle_abuse_report(peer, Packet.create(
            ABUSE_REPORT, peer.authenticated_id.raw, node._id.raw, raw))
        return raw

    async def test_a_stranger_s_opinion_of_a_stranger_is_not_evidence(self):
        node, _link, _other = await _node_with_two_peers()
        accuser, _accuser_id = _identity_and_id()
        subject = NodeID.generate()
        try:
            await self._accuse(node, node._peers[0], accuser, subject)
            assert node._reputation.score(subject) == 0.0
        finally:
            await node.stop()

    async def test_a_member_counts_as_one_accuser(self):
        node, _link, _other = await _node_with_two_peers()
        accuser, accuser_id = _identity_and_id()
        node._cert_store.add(node._identity.issue_cert(
            accuser_id, accuser.dsa_public_key))
        subject = NodeID.generate()
        try:
            await self._accuse(node, node._peers[0], accuser, subject,
                               severity=accusation.MAX_SEVERITY)
            # Severity is what the accuser claims; a member's word is worth one
            # accuser whatever number it writes in the field.
            assert 0 < node._reputation.score(subject) <= 1.0
        finally:
            await node.stop()

    async def test_no_crowd_of_members_can_get_a_node_cut_off(self):
        """The property the whole design exists to keep. Members accusing is
        allowed to make this node wary and nothing more."""
        node, _link, _other = await _node_with_two_peers()
        subject = NodeID.generate()
        try:
            for _ in range(200):
                accuser, accuser_id = _identity_and_id()
                node._cert_store.add(node._identity.issue_cert(
                    accuser_id, accuser.dsa_public_key))
                await self._accuse(node, node._peers[0], accuser, subject,
                                   severity=accusation.MAX_SEVERITY)
            assert node._reputation.standing(subject) != HOSTILE
        finally:
            await node.stop()

    async def test_a_designated_witness_is_believed_like_our_own_eyes(self):
        node, _link, _other = await _node_with_two_peers()
        accuser, accuser_id = _identity_and_id()
        node._cert_store.add(node._identity.issue_cert(
            accuser_id, accuser.dsa_public_key))
        assert node.console_add_witness(accuser_id.raw.hex()) is True
        subject = NodeID.generate()
        try:
            # Distinct moments, because one accuser saying one thing at one
            # moment counts once however it is re-signed or re-carried.
            now = int(time.time())
            for offset in range(8):
                await self._accuse(node, node._peers[0], accuser, subject,
                                   severity=accusation.MAX_SEVERITY,
                                   issued_at=now - offset)
            # Eight reports from one node, and it gets there — where two hundred
            # ordinary members could not. That gap is the operator's decision,
            # made once, and it is the only thing that opens it.
            assert node._reputation.standing(subject) == HOSTILE
        finally:
            await node.stop()

    async def test_an_accuser_we_already_hold_as_suspect_is_ignored(self):
        node, _link, _other = await _node_with_two_peers()
        accuser, accuser_id = _identity_and_id()
        node._cert_store.add(node._identity.issue_cert(
            accuser_id, accuser.dsa_public_key))
        _condemn(node, accuser_id)
        subject = NodeID.generate()
        try:
            await self._accuse(node, node._peers[0], accuser, subject)
            assert node._reputation.score(subject) == 0.0
        finally:
            await node.stop()

    async def test_a_case_against_us_is_neither_acted_on_nor_relayed(self):
        """A node cannot be asked to spread the case against itself, and a
        receiver that did would make every accusation self-amplifying."""
        node, link, other = await _node_with_two_peers()
        accuser, accuser_id = _identity_and_id()
        node._cert_store.add(node._identity.issue_cert(
            accuser_id, accuser.dsa_public_key))
        try:
            link.sent.clear()
            other.sent.clear()
            await self._accuse(node, node._peers[0], accuser, node._id)
            await settle(node)
            assert node._reputation.score(node._id) == 0.0
            assert not [p for p in other.sent if p.type == ABUSE_REPORT]
        finally:
            await node.stop()

    async def test_the_accused_is_not_among_the_nodes_told(self):
        """It will find out — its traffic stops being answered — but not from
        us, and not with a timestamp it can use to work out which of the things
        it tried was the one that was noticed."""
        node, _link, other = await _node_with_two_peers()
        accused = node._peers[1].authenticated_id
        try:
            other.sent.clear()
            _condemn(node, accused)
            await settle(node)
            assert not [p for p in other.sent if p.type == ABUSE_REPORT]
        finally:
            await node.stop()

    async def test_a_node_under_attack_does_not_become_the_flood(self):
        """An accusation is a broadcast, and the node making one is by
        definition under pressure."""
        node, _link, other = await _node_with_two_peers()
        subject = NodeID.generate()
        try:
            other.sent.clear()
            for _ in range(50):
                _condemn(node, subject)
            await settle(node)
            assert len([p for p in other.sent if p.type == ABUSE_REPORT]) <= 1
        finally:
            await node.stop()

    async def test_the_same_record_is_absorbed_once_however_often_it_arrives(self):
        """Two things at once. An accusation stays valid for an hour, so a
        record re-gossiped unconditionally circulates between neighbours for
        that whole hour; and without this a single designated witness's
        statement, re-signed, was an unbounded score.

        Deduplication is on **what it says**, not on the bytes: ML-DSA
        signatures are randomised, so signing one statement twice gives two
        different records and a byte-wise check would have caught the relay loop
        and nothing else."""
        node, _link, other = await _node_with_two_peers()
        accuser, accuser_id = _identity_and_id()
        node._cert_store.add(node._identity.issue_cert(
            accuser_id, accuser.dsa_public_key))
        assert node.console_add_witness(accuser_id.raw.hex()) is True
        subject = NodeID.generate()
        raw = accusation.build(subject, accuser.dsa_public_key, accuser.sign,
                               severity=accusation.MAX_SEVERITY)
        packet = Packet.create(ABUSE_REPORT, node._peers[0].authenticated_id.raw,
                               node._id.raw, raw)
        try:
            other.sent.clear()
            for _ in range(30):
                await node._handle_abuse_report(node._peers[0], packet)
            # …and the same statement signed afresh is still the same statement.
            for _ in range(30):
                await self._accuse(node, node._peers[0], accuser, subject,
                                   severity=accusation.MAX_SEVERITY,
                                   issued_at=parsed_at(raw))
            await settle(node)
            assert node._reputation.standing(subject) != HOSTILE
            assert len([p for p in other.sent if p.type == ABUSE_REPORT]) == 1
        finally:
            await node.stop()

    async def test_an_unverifiable_report_is_charged_to_the_sender(self):
        node, _link, _other = await _node_with_two_peers()
        peer = node._peers[0]
        try:
            before = peer._malformed
            await node._handle_abuse_report(peer, Packet.create(
                ABUSE_REPORT, peer.authenticated_id.raw, node._id.raw,
                b"\xff" * 120))
            assert peer._malformed > before
        finally:
            await node.stop()

    async def test_gossip_can_be_switched_off_entirely(self):
        """For an operator who wants a node that judges only what it sees."""
        node, _link, other = await _node_with_two_peers()
        node._gossip_abuse = False
        accuser, accuser_id = _identity_and_id()
        node._cert_store.add(node._identity.issue_cert(
            accuser_id, accuser.dsa_public_key))
        subject = NodeID.generate()
        try:
            await self._accuse(node, node._peers[0], accuser, subject)
            assert node._reputation.score(subject) == 0.0
            other.sent.clear()
            _condemn(node, NodeID.generate())
            await settle(node)
            assert not [p for p in other.sent if p.type == ABUSE_REPORT]
        finally:
            await node.stop()


class TestConsoleSurface:
    async def test_forgiving_clears_the_slate(self):
        node, _link, _other = await _node_with_two_peers()
        subject = NodeID.generate()
        try:
            _condemn(node, subject)
            assert node.abuse_status()["nodes"]
            assert node.console_forgive(subject.raw.hex()) is True
            assert node.abuse_status()["nodes"] == []
            assert node.console_forgive(subject.raw.hex()) is False
        finally:
            await node.stop()

    async def test_witnesses_are_added_and_removed_locally(self):
        node, _link, _other = await _node_with_two_peers()
        _witness, witness_id = _identity_and_id()
        try:
            assert node.console_add_witness(witness_id.raw.hex()) is True
            assert witness_id.raw.hex() in node.abuse_status()["witnesses"]
            assert node.console_remove_witness(witness_id.raw.hex()) is True
            assert node.abuse_status()["witnesses"] == []
            assert node.console_remove_witness(witness_id.raw.hex()) is False
        finally:
            await node.stop()

    async def test_we_are_never_our_own_witness(self):
        node, _link, _other = await _node_with_two_peers()
        try:
            assert node.console_add_witness(node._id.raw.hex()) is False
        finally:
            await node.stop()
