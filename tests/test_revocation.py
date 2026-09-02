"""
Taking a membership back.

Expiry is the slow way out of a network; this is the fast one, for the key that
leaked this morning. It is also the most dangerous thing to get wrong in the
trust system: a revocation anyone could write, or one that reaches somebody
else's members, is a primitive for cutting nodes off the mesh. So most of what
follows is negative — who may not say it, what it may not reach, and what a
hostile record must never do to a receive loop.
"""
import asyncio
import time

import pytest

from src import revocation
from src.cert_store import CertStore
from src.crypto import CryptoIdentity, SessionKey, verify_signature
from src.node import CERT_REVOKE
from src.node_id import NodeID
from src.packet import Packet
from tests.conftest import make_node, settle


DAY = 86400


def _identity_and_id():
    identity = CryptoIdentity()
    return identity, NodeID.from_public_key(identity.dsa_public_key)


def _revoke_record(issuer, subject_id, **kwargs):
    return revocation.build(subject_id, issuer.dsa_public_key, issuer.sign,
                            **kwargs)


class TestTheRecord:
    def test_round_trip(self):
        issuer, issuer_id = _identity_and_id()
        _subject, subject_id = _identity_and_id()
        parsed = revocation.parse(
            _revoke_record(issuer, subject_id,
                           reason=revocation.REASON_COMPROMISED),
            verify_signature)
        assert parsed is not None
        assert parsed["issuer_id"] == issuer_id
        assert parsed["subject_id"] == subject_id
        assert parsed["reason"] == revocation.REASON_COMPROMISED

    def test_the_issuer_id_is_derived_not_claimed(self):
        """There is no issuer field to lie about: it is the hash of the key the
        signature was made with."""
        issuer, issuer_id = _identity_and_id()
        _subject, subject_id = _identity_and_id()
        parsed = revocation.parse(_revoke_record(issuer, subject_id),
                                  verify_signature)
        assert parsed["issuer_id"] == NodeID.from_public_key(parsed["issuer_pub"])
        assert parsed["issuer_id"] == issuer_id

    def test_a_tampered_record_does_not_verify(self):
        issuer, _issuer_id = _identity_and_id()
        _subject, subject_id = _identity_and_id()
        raw = bytearray(_revoke_record(issuer, subject_id))
        raw[-1] ^= 1
        assert revocation.parse(bytes(raw), verify_signature) is None

    def test_a_revocation_naming_its_own_issuer_is_refused(self):
        """A root disowning itself is either noise or an attempt to make an
        anchor unusable network-wide; dropping an anchor is local, and local
        only, because there is nobody above a root to appeal to."""
        issuer, issuer_id = _identity_and_id()
        assert revocation.parse(_revoke_record(issuer, issuer_id),
                                verify_signature) is None

    @pytest.mark.parametrize("blob", [
        b"", b"\x00", b"\x01" * 8, b"\xff" * 200,
        bytes([2]) + b"\x00" * 60,             # unknown version
        bytes([1]) + b"\x00" * 40,             # truncated header
    ])
    def test_no_hostile_byte_string_raises(self, blob):
        assert revocation.parse(blob, verify_signature) is None

    def test_trailing_bytes_are_refused(self):
        """Two encodings of one record is two chances for a bound keyed on the
        record to be counted twice."""
        issuer, _issuer_id = _identity_and_id()
        _subject, subject_id = _identity_and_id()
        raw = _revoke_record(issuer, subject_id)
        assert revocation.parse(raw + b"\x00", verify_signature) is None

    def test_an_oversized_record_is_refused_before_any_verification(self):
        assert revocation.parse(b"\x01" * (revocation.MAX_RECORD + 1),
                                lambda *_: pytest.fail("verified oversized input")
                                ) is None


class TestTheStore:
    def _store_with_member(self, ttl: int = 365 * DAY):
        root, root_id = _identity_and_id()
        member, member_id = _identity_and_id()
        store = CertStore(NodeID.generate())
        store.add(root.self_signed_cert())
        store.add_root(root_id)
        cert = root.issue_cert(member_id, member.dsa_public_key, ttl_seconds=ttl)
        store.add(cert)
        return store, root, root_id, member, member_id, cert

    def test_a_revoked_chain_stops_verifying(self):
        store, root, _root_id, _member, member_id, cert = self._store_with_member()
        chain = [cert, root.self_signed_cert()]
        assert store.verify_chain(chain) is not None
        store.revoke(_revoke_record(root, member_id), verify_signature)
        assert store.verify_chain(chain) is None

    def test_a_revoked_certificate_is_dropped_from_the_store(self):
        """Filtering it out of every walk is enough to be correct, but it would
        go on holding a slot in a bounded list and being written to disk."""
        store, root, _root_id, _member, member_id, _cert = self._store_with_member()
        assert store.certs_for(member_id)
        store.revoke(_revoke_record(root, member_id), verify_signature)
        assert store.certs_for(member_id) == []

    def test_a_revoked_certificate_is_never_re_absorbed(self):
        store, root, _root_id, member, member_id, cert = self._store_with_member()
        store.revoke(_revoke_record(root, member_id), verify_signature)
        assert store.add(cert) is False

    def test_only_the_issuer_can_reach_its_members(self):
        """A revocation signed by anybody else names a pair we hold nothing
        for, so it voids nothing. This is what stops it being a way to cut
        other people's nodes off the network."""
        store, root, _root_id, _member, member_id, cert = self._store_with_member()
        stranger, _stranger_id = _identity_and_id()
        store.revoke(_revoke_record(stranger, member_id), verify_signature)
        assert store.verify_chain([cert, root.self_signed_cert()]) is not None
        assert store.certs_for(member_id)

    def test_a_later_certificate_outlives_the_revocation(self):
        """A revocation names a moment. An issuer that changes its mind signs
        again, which keeps readmission a deliberate act rather than a race."""
        store, root, _root_id, member, member_id, _cert = self._store_with_member()
        now = int(time.time())
        store.revoke(_revoke_record(root, member_id, issued_at=now - 10),
                     verify_signature)
        readmitted = root.issue_cert(member_id, member.dsa_public_key)
        assert readmitted.issued_at > now - 10
        assert store.add(readmitted) is True
        assert store.verify_chain(
            [readmitted, root.self_signed_cert()]) is not None

    def test_every_certificate_at_or_before_the_moment_is_void(self):
        """Naming one certificate would leave whichever copy the attacker kept
        quiet about — and a subject may hold several from one issuer."""
        store, root, _root_id, member, member_id, first = self._store_with_member()
        second = root.issue_cert(member_id, member.dsa_public_key,
                                 ttl_seconds=200 * DAY)
        store.add(second)
        store.revoke(_revoke_record(root, member_id), verify_signature)
        assert store.is_revoked(first) and store.is_revoked(second)
        assert store.certs_for(member_id) == []

    def test_a_replayed_older_revocation_changes_nothing(self):
        store, root, _root_id, _member, member_id, _cert = self._store_with_member()
        now = int(time.time())
        assert store.revoke(_revoke_record(root, member_id, issued_at=now),
                            verify_signature) is not None
        assert store.revoke(_revoke_record(root, member_id, issued_at=now - 60),
                            verify_signature) is None

    def test_the_same_revocation_twice_is_not_news(self):
        """What decides whether an epidemic keeps going."""
        store, root, _root_id, _member, member_id, _cert = self._store_with_member()
        raw = _revoke_record(root, member_id)
        assert store.revoke(raw, verify_signature) is not None
        assert store.revoke(raw, verify_signature) is None

    def test_revocations_survive_a_restart(self, tmp_path):
        """One that only held while the process happened to be running would be
        undone by a restart — the moment a compromised member most wants."""
        store, root, _root_id, member, member_id, cert = self._store_with_member()
        store.revoke(_revoke_record(root, member_id), verify_signature)
        path = str(tmp_path / "certs.json")
        store.save(path)
        reloaded = CertStore.load(path, store._own_id)
        assert reloaded.is_revoked(cert)
        assert reloaded.add(cert) is False
        assert reloaded.verify_chain([cert, root.self_signed_cert()]) is None

    def test_a_root_said_it_is_never_evicted_by_a_flood(self):
        """Otherwise anyone able to mint revocations of their own members could
        flush the table and bring a revoked node back."""
        root, root_id = _identity_and_id()
        store = CertStore(NodeID.generate(), max_revocations=4)
        store.add_root(root_id)
        _member, member_id = _identity_and_id()
        store.revoke(_revoke_record(root, member_id), verify_signature)
        flooder, _flooder_id = _identity_and_id()
        for _ in range(20):
            store.revoke(_revoke_record(flooder, NodeID.generate()),
                         verify_signature)
        assert store.revocation_for(member_id) is not None


class TestRoots:
    def test_an_anchor_can_be_dropped(self):
        own = NodeID.generate()
        store = CertStore(own)
        stranger = NodeID.generate()
        store.add_root(stranger)
        assert store.remove_root(stranger) is True
        assert store.is_root(stranger) is False
        assert store.remove_root(stranger) is False

    def test_our_own_root_is_not_removable(self):
        """A node that is not its own root can no longer present anything."""
        own = NodeID.generate()
        store = CertStore(own)
        assert store.remove_root(own) is False
        assert store.is_root(own) is True

    def test_dropping_an_anchor_voids_what_chained_to_it(self):
        root, root_id = _identity_and_id()
        member, member_id = _identity_and_id()
        store = CertStore(NodeID.generate())
        store.add(root.self_signed_cert())
        store.add_root(root_id)
        cert = root.issue_cert(member_id, member.dsa_public_key)
        store.add(cert)
        chain = [cert, root.self_signed_cert()]
        assert store.verify_chain(chain) is not None
        store.remove_root(root_id)
        assert store.verify_chain(chain) is None


# ---------------------------------------------------------------------------
# On the wire
# ---------------------------------------------------------------------------

async def _node_with_member():
    """A node that admitted one member, with a live link to it."""
    node, fake = await make_node()
    member, member_id = _identity_and_id()
    cert = node._identity.issue_cert(member_id, member.dsa_public_key)
    node._cert_store.add(cert)
    node._peers[0].authenticated_id = member_id
    node._peers[0].session = SessionKey(b"\x00" * 32)
    node._routing.add(member_id, [], member.dsa_public_key)
    return node, fake, member, member_id, cert


class TestOnTheWire:
    async def test_revoking_ends_the_links_that_node_holds(self):
        """A revocation that only changed what future handshakes decide has
        revoked nothing an attacker is currently using."""
        node, fake, _member, member_id, _cert = await _node_with_member()
        try:
            assert node.console_revoke_member(member_id.raw.hex()) is True
            await settle(node)
            assert node._cert_store.revocation_for(member_id) is not None
            assert not [p for p in node._peers
                        if p.authenticated_id == member_id]
            assert any(p.type == CERT_REVOKE for p in fake.sent)
        finally:
            await node.stop()

    async def test_we_cannot_revoke_somebody_else_s_member(self):
        node, _fake, _member, _member_id, _cert = await _node_with_member()
        stranger = NodeID.generate()
        try:
            # It signs, and it is ours to sign — but it names a pair nobody
            # holds a certificate for, so it voids nothing anywhere.
            assert node.console_revoke_member(stranger.raw.hex()) is True
            assert node._cert_store.revocation_for(stranger)["issued_at"] > 0
        finally:
            await node.stop()

    async def test_we_cannot_revoke_ourselves(self):
        node, _fake, _member, _member_id, _cert = await _node_with_member()
        try:
            assert node.console_revoke_member(node._id.raw.hex()) is False
        finally:
            await node.stop()

    async def test_a_revocation_heard_once_is_passed_on_once(self):
        node, fake, _member, member_id, _cert = await _node_with_member()
        issuer, _issuer_id = _identity_and_id()
        raw = _revoke_record(issuer, NodeID.generate())
        packet = Packet.create(CERT_REVOKE, member_id.raw, node._id.raw, raw)
        try:
            await node._handle_cert_revoke(node._peers[0], packet)
            await settle(node)
            first = len([p for p in fake.sent if p.type == CERT_REVOKE])
            await node._handle_cert_revoke(node._peers[0], packet)
            await settle(node)
            assert len([p for p in fake.sent if p.type == CERT_REVOKE]) == first
        finally:
            await node.stop()

    async def test_an_unverifiable_record_is_charged_to_the_sender(self):
        """An honest relay verifies before re-sending, so whoever hands us a
        bad one either forged it or forwarded without looking."""
        node, _fake, _member, member_id, _cert = await _node_with_member()
        try:
            before = node._peers[0]._malformed
            await node._handle_cert_revoke(
                node._peers[0],
                Packet.create(CERT_REVOKE, member_id.raw, node._id.raw,
                              b"\xff" * 120))
            assert node._peers[0]._malformed > before
        finally:
            await node.stop()

    async def test_a_revocation_we_already_knew_costs_the_sender_nothing(self):
        """The ordinary end of an epidemic is not an offence."""
        node, _fake, _member, member_id, _cert = await _node_with_member()
        issuer, _issuer_id = _identity_and_id()
        raw = _revoke_record(issuer, NodeID.generate())
        packet = Packet.create(CERT_REVOKE, member_id.raw, node._id.raw, raw)
        try:
            await node._handle_cert_revoke(node._peers[0], packet)
            await settle(node)
            before = node._peers[0]._malformed
            await node._handle_cert_revoke(node._peers[0], packet)
            await settle(node)
            assert node._peers[0]._malformed == before
        finally:
            await node.stop()

    async def test_dropping_an_anchor_from_the_console(self):
        node, _fake, _member, _member_id, _cert = await _node_with_member()
        root, root_id = _identity_and_id()
        try:
            assert node.console_add_root(
                root.self_signed_cert().serialize().hex()) is True
            assert node.trust_status()["roots"] == 2
            assert node.console_remove_root(root_id.raw.hex()) is True
            await settle(node)
            assert node.trust_status()["roots"] == 1
            assert node.console_remove_root(root_id.raw.hex()) is False
        finally:
            await node.stop()
