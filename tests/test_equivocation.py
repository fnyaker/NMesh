"""
The one report a stranger can hand over that stands on its own.

Everything else a node hears about another node is an opinion, weighed and
capped precisely because the speaker could be lying (`test_reputation.py` is
mostly about that). An equivocation proof is the exception: two records signed
by **the same key** that cannot both have been meant. Forging one needs the
private key it accuses, so there is nothing to trust the messenger about.

So the tests split in two. What must verify: a genuine contradiction, of each
kind. And — far more of them — what must not, because a proof that accepts a
near-miss is a way to get an honest node blamed. A publisher rebuilding, a node
renaming, one record shown twice, two records from two different keys: none of
those is an equivocation, and each is what an attacker would reach for.
"""
import json

import pytest

from src import core_release as cr
from src import equivocation
from src.crypto import CryptoIdentity
from src.node_id import NodeID
from src.pseudo_dir import PseudoBook, build_claim, parse_claim


ONE = cr.build_package({"src/version.py": b'__version__ = "0.2.0"\n',
                        "start.sh": b"#!/bin/sh\n"})
TWO = cr.build_package({"src/version.py": b'__version__ = "0.2.0"\n',
                        "start.sh": b"#!/bin/sh\n# and a back door\n"})


def _release(identity, version="0.2.0", ts=1000, package=ONE):
    return cr.build_release(package, version, identity.dsa_public_key,
                            identity.sign, ts, "")


def _claim(identity, pseudo="alice", ts=1000):
    return build_claim(pseudo, identity.dsa_public_key, identity.sign, ts)


class TestAGenuineContradiction:
    def test_one_publisher_two_programs_one_version(self):
        idn = CryptoIdentity()
        proof = equivocation.build(equivocation.KIND_RELEASE,
                                   _release(idn, package=ONE),
                                   _release(idn, ts=1001, package=TWO))
        found = equivocation.verify(proof, idn.verify)
        assert found is not None
        assert found["kind_name"] == "release"
        assert found["subject_pub"] == idn.dsa_public_key
        assert found["subject_id"] == NodeID.from_public_key(idn.dsa_public_key)
        assert "0.2.0" in found["about"]

    def test_one_node_two_names_one_instant(self):
        idn = CryptoIdentity()
        proof = equivocation.build(equivocation.KIND_PSEUDO,
                                   _claim(idn, "alice"), _claim(idn, "bob"))
        found = equivocation.verify(proof, idn.verify)
        assert found is not None
        assert found["kind_name"] == "name claim"
        assert found["subject_id"].raw == NodeID.from_public_key(
            idn.dsa_public_key).raw

    def test_the_order_of_the_two_says_nothing(self):
        """Which half arrived first is a fact about the network, never about
        the signer. A proof that depended on it is a proof to argue with."""
        idn = CryptoIdentity()
        first, second = _release(idn, package=ONE), _release(idn, ts=1001,
                                                             package=TWO)
        one = equivocation.verify(
            equivocation.build(equivocation.KIND_RELEASE, first, second),
            idn.verify)
        two = equivocation.verify(
            equivocation.build(equivocation.KIND_RELEASE, second, first),
            idn.verify)
        assert one is not None and two is not None
        assert one["subject_pub"] == two["subject_pub"]


class TestWhatIsNotAContradiction:
    def test_two_publishers_disagreeing_is_a_fork(self):
        """Two keys signing different content for one version is what an
        accidental fork looks like. It stops an unattended install elsewhere;
        it accuses nobody, and must not be dressed up as a proof."""
        one, two = CryptoIdentity(), CryptoIdentity()
        proof = equivocation.build(equivocation.KIND_RELEASE,
                                   _release(one, package=ONE),
                                   _release(two, package=TWO))
        assert equivocation.verify(proof, one.verify) is None

    def test_two_versions_from_one_publisher_is_publishing(self):
        idn = CryptoIdentity()
        proof = equivocation.build(equivocation.KIND_RELEASE,
                                   _release(idn, version="0.2.0", package=ONE),
                                   _release(idn, version="0.2.1", ts=1001,
                                            package=TWO))
        assert equivocation.verify(proof, idn.verify) is None

    def test_the_same_program_signed_twice_is_a_rebuild(self):
        idn = CryptoIdentity()
        proof = equivocation.build(equivocation.KIND_RELEASE,
                                   _release(idn, ts=1000),
                                   _release(idn, ts=2000))
        assert equivocation.verify(proof, idn.verify) is None

    def test_one_record_shown_twice_is_one_statement(self):
        idn = CryptoIdentity()
        blob = _release(idn)
        proof = equivocation.build(equivocation.KIND_RELEASE, blob, blob)
        assert equivocation.verify(proof, idn.verify) is None

    def test_a_rename_is_not_an_equivocation(self):
        """A node is entitled to change its name; the book keeps the newest
        claim precisely so it can. Only two names at *one* instant contradict."""
        idn = CryptoIdentity()
        proof = equivocation.build(equivocation.KIND_PSEUDO,
                                   _claim(idn, "alice", ts=1000),
                                   _claim(idn, "bob", ts=1001))
        assert equivocation.verify(proof, idn.verify) is None

    def test_two_nodes_with_the_same_name_are_not_one_liar(self):
        one, two = CryptoIdentity(), CryptoIdentity()
        proof = equivocation.build(equivocation.KIND_PSEUDO,
                                   _claim(one, "alice"), _claim(two, "bob"))
        assert equivocation.verify(proof, one.verify) is None


class TestHostileInput:
    def test_a_forged_half_does_not_verify(self):
        """The whole argument rests on this: the accuser cannot write either
        half. A descriptor edited after signing fails its own parser."""
        idn = CryptoIdentity()
        doc = json.loads(_release(idn, package=ONE))
        doc["sha256"] = "b" * 64
        proof = equivocation.build(equivocation.KIND_RELEASE,
                                   _release(idn, package=ONE),
                                   json.dumps(doc).encode())
        assert equivocation.verify(proof, idn.verify) is None

    def test_a_half_signed_by_somebody_else_does_not_verify(self):
        """Lifting one honest record and pairing it with your own is the
        cheapest attempt there is."""
        victim, attacker = CryptoIdentity(), CryptoIdentity()
        proof = equivocation.build(equivocation.KIND_RELEASE,
                                   _release(victim, package=ONE),
                                   _release(attacker, package=TWO))
        assert equivocation.verify(proof, victim.verify) is None

    @pytest.mark.parametrize("blob", [
        b"", b"\x00", b"\x01", b"\x01\x01\x00\x02ab", b"\xff" * 200,
        bytes(range(256)), "not bytes", None, 42, [],
        b"\x02\x01\x00\x01\x00\x01ab",          # unknown version
        b"\x01\x63\x00\x01\x00\x01ab",          # unknown kind
        b"\x01\x01\x00\x00\x00\x00",            # two empty records
        b"\x01\x01\xff\xff\xff\xffab",          # lengths that do not fit
    ])
    def test_nothing_malformed_ever_raises(self, blob):
        idn = CryptoIdentity()
        assert equivocation.verify(blob, idn.verify) is None

    def test_an_oversized_proof_is_refused_before_any_parsing(self):
        idn = CryptoIdentity()
        assert equivocation.verify(b"\x01\x01\x00\x01\x00\x01"
                                   + b"a" * equivocation.MAX_PROOF,
                                   idn.verify) is None

    def test_a_verifier_that_throws_is_not_a_verdict(self):
        def explode(message, signature, public_key):
            raise RuntimeError("boom")

        idn = CryptoIdentity()
        proof = equivocation.build(equivocation.KIND_RELEASE,
                                   _release(idn, package=ONE),
                                   _release(idn, ts=1001, package=TWO))
        assert equivocation.verify(proof, explode) is None

    def test_a_verifier_that_says_yes_to_everything_still_needs_a_contradiction(self):
        """A caller cannot be made to accept a pair that does not contradict,
        however broken its signature check is: the two questions are separate."""
        idn = CryptoIdentity()
        proof = equivocation.build(equivocation.KIND_RELEASE,
                                   _release(idn, package=ONE),
                                   _release(idn, ts=1001, package=ONE))
        assert equivocation.verify(proof, lambda *a: True) is None

    def test_build_refuses_what_it_cannot_frame(self):
        with pytest.raises(equivocation.EquivocationError):
            equivocation.build(99, b"a", b"b")
        with pytest.raises(equivocation.EquivocationError):
            equivocation.build(equivocation.KIND_RELEASE, b"", b"b")
        with pytest.raises(equivocation.EquivocationError):
            equivocation.build(equivocation.KIND_RELEASE, b"a" * (65 * 1024), b"b")


class TestTheReleaseBookCatchesIt:
    def test_one_publisher_signing_one_version_twice_is_kept(self):
        idn = CryptoIdentity()
        catalogue = cr.ReleaseBook()
        catalogue.offer(_release(idn, ts=1000, package=ONE), idn.verify)
        catalogue.offer(_release(idn, ts=1001, package=TWO), idn.verify)
        key = cr.publisher_id(idn.dsa_public_key)
        proof = catalogue.equivocated(key)
        assert proof is not None
        assert catalogue.equivocated(idn.dsa_public_key) == proof
        found = equivocation.verify(proof, idn.verify)
        assert found is not None and found["subject_pub"] == idn.dsa_public_key

    def test_the_older_half_arriving_second_is_still_caught(self):
        """Order does not matter any more — the book keeps both releases — but
        the property is the one worth keeping: a publisher cannot hide a
        contradiction by choosing which half to show first."""
        idn = CryptoIdentity()
        catalogue = cr.ReleaseBook()
        catalogue.offer(_release(idn, ts=1001, package=TWO), idn.verify)
        catalogue.offer(_release(idn, ts=1000, package=ONE), idn.verify)
        assert catalogue.equivocated(cr.publisher_id(idn.dsa_public_key)) is not None

    def test_an_honest_publisher_is_never_recorded(self):
        idn = CryptoIdentity()
        catalogue = cr.ReleaseBook()
        catalogue.offer(_release(idn, version="0.2.0", ts=1000, package=ONE),
                        idn.verify)
        catalogue.offer(_release(idn, version="0.2.1", ts=1001, package=TWO),
                        idn.verify)
        assert catalogue.equivocations() == {}

    def test_the_table_is_bounded(self):
        catalogue = cr.ReleaseBook()
        for _ in range(cr.MAX_EQUIVOCATIONS + 4):
            idn = CryptoIdentity()
            catalogue.offer(_release(idn, ts=1000, package=ONE), idn.verify)
            catalogue.offer(_release(idn, ts=1001, package=TWO), idn.verify)
        assert len(catalogue.equivocations()) == cr.MAX_EQUIVOCATIONS

    def test_a_pinned_publisher_still_gets_room_when_it_is_full(self):
        """The table's whole use is refusing an unattended install, so the keys
        that could actually cause one are the ones worth the room. A flood of
        strangers contradicting themselves must not hide the pinned key doing
        the same."""
        catalogue = cr.ReleaseBook()
        for _ in range(cr.MAX_EQUIVOCATIONS):
            idn = CryptoIdentity()
            catalogue.offer(_release(idn, ts=1000, package=ONE), idn.verify)
            catalogue.offer(_release(idn, ts=1001, package=TWO), idn.verify)
        pinned = CryptoIdentity()
        trusted = lambda key: key == pinned.dsa_public_key
        catalogue.offer(_release(pinned, ts=1000, package=ONE), pinned.verify,
                        trusted)
        catalogue.offer(_release(pinned, ts=1001, package=TWO), pinned.verify,
                        trusted)
        assert catalogue.equivocated(pinned.dsa_public_key) is not None
        assert len(catalogue.equivocations()) == cr.MAX_EQUIVOCATIONS

    def test_a_proof_is_kept_once_and_not_rewritten(self):
        idn = CryptoIdentity()
        catalogue = cr.ReleaseBook()
        catalogue.offer(_release(idn, ts=1000, package=ONE), idn.verify)
        catalogue.offer(_release(idn, ts=1001, package=TWO), idn.verify)
        first = catalogue.equivocated(idn.dsa_public_key)
        catalogue.offer(_release(idn, ts=1002, package=TWO), idn.verify)
        assert catalogue.equivocated(idn.dsa_public_key) == first


class TestTheBookCatchesIt:
    def _offer(self, book, identity, pseudo, ts):
        raw = _claim(identity, pseudo, ts)
        return book.offer(parse_claim(raw, identity.verify), raw)

    def test_two_names_for_one_instant_are_kept(self):
        idn = CryptoIdentity()
        book = PseudoBook()
        self._offer(book, idn, "alice", 1000)
        self._offer(book, idn, "bob", 1000)
        node_id = NodeID.from_public_key(idn.dsa_public_key).raw
        proof = book.equivocated(node_id)
        assert proof is not None
        found = equivocation.verify(proof, idn.verify)
        assert found is not None and found["subject_id"].raw == node_id

    def test_the_name_we_hold_does_not_change(self):
        """Catching the contradiction must not hand the attacker the rename it
        was trying for: the claim is still not newer, so it is still dropped."""
        idn = CryptoIdentity()
        book = PseudoBook()
        self._offer(book, idn, "alice", 1000)
        assert self._offer(book, idn, "bob", 1000) is False
        node_id = NodeID.from_public_key(idn.dsa_public_key).raw
        assert book.pseudo_of(node_id) == "alice"

    def test_renaming_is_not_recorded(self):
        idn = CryptoIdentity()
        book = PseudoBook()
        self._offer(book, idn, "alice", 1000)
        self._offer(book, idn, "bob", 1001)
        assert book.equivocations() == {}

    def test_the_same_claim_twice_is_not_recorded(self):
        idn = CryptoIdentity()
        book = PseudoBook()
        self._offer(book, idn, "alice", 1000)
        self._offer(book, idn, "alice", 1000)
        assert book.equivocations() == {}

    def test_forgetting_the_name_keeps_the_record(self):
        """A node able to clear its own record by renaming twice more would
        have a way to launder it."""
        idn = CryptoIdentity()
        book = PseudoBook()
        self._offer(book, idn, "alice", 1000)
        self._offer(book, idn, "bob", 1000)
        node_id = NodeID.from_public_key(idn.dsa_public_key).raw
        book.forget(node_id)
        assert book.equivocated(node_id) is not None

    def test_the_table_is_bounded(self):
        book = PseudoBook()
        for index in range(12):
            idn = CryptoIdentity()
            self._offer(book, idn, "alice", 1000)
            self._offer(book, idn, "bob", 1000)
        assert len(book.equivocations()) <= 8


class TestTheNodeActsOnIt:
    """A proof nobody reads is decoration. Three consequences, and only the
    third is a matter of taste: nothing installs itself from that key any more,
    the operator is told before they install it by hand, and it shows up in the
    feed of what the node just saw."""

    def _node(self):
        from src.node import MeshNode
        from tests.conftest import make_manager
        return MeshNode(transport_manager=make_manager())

    def _caught(self, node, publisher):
        node.trust_publisher(publisher.dsa_public_key.hex(), "them", auto=True)
        node._releases.offer(_release(publisher, ts=1000, package=ONE),
                             node._identity.verify, node._trusts_publisher)
        second = _release(publisher, ts=1001, package=TWO)
        node._releases.offer(second, node._identity.verify,
                             node._trusts_publisher)
        return node._releases.get(cr.descriptor_key(second))

    async def test_a_pinned_publisher_that_contradicts_itself_installs_nothing(self):
        node, publisher = self._node(), CryptoIdentity()
        try:
            entry = self._caught(node, publisher)
            allowed, why = node.may_auto_install(entry)
            assert allowed is False
            assert "two different programs" in why
        finally:
            await node.stop()

    async def test_without_the_contradiction_the_same_pin_would_install(self):
        """The control. Otherwise the refusal above could be about anything."""
        node, publisher = self._node(), CryptoIdentity()
        try:
            node.trust_publisher(publisher.dsa_public_key.hex(), "them",
                                 auto=True)
            blob = _release(publisher, ts=1000, package=ONE)
            node._releases.offer(blob, node._identity.verify,
                                 node._trusts_publisher)
            entry = node._releases.get(cr.descriptor_key(blob))
            assert node.may_auto_install(entry)[0] is True
        finally:
            await node.stop()

    async def test_the_operator_is_told_on_the_row(self):
        node, publisher = self._node(), CryptoIdentity()
        try:
            self._caught(node, publisher)
            rows = node.release_overview()["releases"]
            assert rows and all(row["equivocated"] for row in rows)
        finally:
            await node.stop()

    async def test_an_honest_publisher_is_not_flagged(self):
        node, publisher = self._node(), CryptoIdentity()
        try:
            node._releases.offer(_release(publisher, ts=1000, package=ONE),
                                 node._identity.verify, node._trusts_publisher)
            rows = node.release_overview()["releases"]
            assert rows and not any(row["equivocated"] for row in rows)
        finally:
            await node.stop()

    async def test_it_reaches_the_feed_when_the_pair_arrives_from_the_network(self):
        """End to end, on the path it will actually happen on: two announces
        from a peer, and the node saying what it saw in its own vocabulary."""
        from src.node import RELEASE_ANNOUNCE
        from src.packet import Packet
        from tests.test_release_mesh import _FakePeer

        node, publisher = self._node(), CryptoIdentity()
        try:
            peer = _FakePeer()
            node._peers = [peer]
            for blob in (_release(publisher, ts=1000, package=ONE),
                         _release(publisher, ts=1001, package=TWO)):
                await node._handle_release_announce(
                    peer, Packet.create(RELEASE_ANNOUNCE,
                                        peer.authenticated_id.raw,
                                        b"\xff" * 20, b"\x00" + blob))
            assert node._releases.equivocated(publisher.dsa_public_key) is not None
            rows = node._activity.recent()
            assert any(row["kind"] == "warn" and "contradictory" in row["text"]
                       for row in rows), rows
        finally:
            await node.stop()

    async def test_the_pseudo_book_pair_reaches_the_feed_too(self):
        node, other = self._node(), CryptoIdentity()
        try:
            from tests.test_release_mesh import _FakePeer
            peer = _FakePeer()
            for pseudo in ("alice", "bob"):
                node._absorb_claim(peer, _claim(other, pseudo, ts=1000))
            node_id = NodeID.from_public_key(other.dsa_public_key).raw
            assert node._pseudo_book.equivocated(node_id) is not None
            assert any("contradictory" in row["text"]
                       for row in node._activity.recent())
        finally:
            await node.stop()

    async def test_nothing_is_said_about_a_publisher_that_did_not(self):
        node = self._node()
        try:
            node._note_equivocation("publisher", b"\x01" * 20, None)
            assert node._activity.recent() == []
        finally:
            await node.stop()
