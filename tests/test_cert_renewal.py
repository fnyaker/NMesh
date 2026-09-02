"""
The certificate lifecycle: expiry, pruning, and renewal.

A membership certificate lasts a year and nothing used to renew it, so every
node deployed carried a dated outage: on the day it expired the node kept
presenting a chain every peer refuses, dropped out of the mesh, and reported
nothing. These tests hold the two halves of the fix — a store that knows when
its own chain dies and never walks a corpse, and an exchange that re-signs the
binding while the node can still be heard — plus the refusals that keep the
exchange from becoming a way in.
"""
import asyncio
import time

import pytest

from src.cert import Certificate
from src.cert_store import CertStore
from src.crypto import CryptoIdentity, SessionKey
from src.node import CERT_RENEW, CERT_RENEWED, _CERT_RENEW_ACCEPT
from src.node_id import NodeID
from src.packet import Packet
from tests.conftest import make_node


DAY = 86400


def _identity_and_id():
    identity = CryptoIdentity()
    return identity, NodeID.from_public_key(identity.dsa_public_key)


def _link(node, node_id: NodeID, public_key: bytes) -> None:
    """Make the node's one fake link a usable route to ``node_id``.

    Routing only ever hands a packet to a link that is authenticated *and*
    keyed, so a peer with an id but no session is not a candidate."""
    node._peers[0].authenticated_id = node_id
    node._peers[0].session = SessionKey(b"\x00" * 32)
    node._routing.add(node_id, [], public_key)


def _member_store(ttl: int = 365 * DAY):
    """A store holding a full network chain: root → member, from the member's
    point of view. Returns (store, root_identity, member_identity, member_cert)."""
    root, root_id = _identity_and_id()
    member, member_id = _identity_and_id()
    store = CertStore(member_id)
    store.add(member.self_signed_cert())
    store.add(root.self_signed_cert())
    store.add_root(root_id)
    cert = root.issue_cert(member_id, member.dsa_public_key, ttl_seconds=ttl)
    store.add(cert)
    return store, root, member, cert


class TestExpiryIsOneNotion:
    def test_chain_expires_with_its_shortest_lived_link(self):
        store, _root, member, cert = _member_store(ttl=10 * DAY)
        member_id = NodeID.from_public_key(member.dsa_public_key)
        assert store.chain_expires_at(member_id) == cert.expires_at

    def test_a_self_rooted_chain_never_expires(self):
        identity, own_id = _identity_and_id()
        store = CertStore(own_id)
        store.add(identity.self_signed_cert())
        assert store.chain_expires_at(own_id) == 0

    def test_an_unknown_node_has_no_expiry(self):
        _identity, own_id = _identity_and_id()
        store = CertStore(own_id)
        assert store.chain_expires_at(NodeID.generate()) is None

    def test_an_expired_certificate_is_never_absorbed(self):
        """It proves nothing and never will again, but it still costs a slot in
        a bounded list — so replaying old certificates could crowd out the live
        one for a subject an attacker picked."""
        root, _root_id = _identity_and_id()
        member, member_id = _identity_and_id()
        store = CertStore(member_id)
        cert = root.issue_cert(member_id, member.dsa_public_key, ttl_seconds=10)
        cert.expires_at = int(time.time()) - 1
        assert store.add(cert) is False
        assert store.certs_for(member_id) == []

    def test_pruning_drops_the_dead_and_keeps_the_living(self):
        store, root, member, live = _member_store()
        member_id = NodeID.from_public_key(member.dsa_public_key)
        stale = root.issue_cert(member_id, member.dsa_public_key, ttl_seconds=10)
        store.add(stale)
        stale.expires_at = int(time.time()) - 1
        assert store.prune_expired() == 1
        held = {c.signature for c in store.certs_for(member_id)}
        assert live.signature in held
        assert stale.signature not in held

    def test_a_root_self_signed_cert_is_never_pruned(self):
        store, root, _member, _cert = _member_store()
        root_id = NodeID.from_public_key(root.dsa_public_key)
        store.prune_expired(now=int(time.time()) + 100 * 365 * DAY)
        assert any(c.is_self_signed for c in store.certs_for(root_id))


class TestTheWalkSkipsCorpses:
    def test_an_expired_link_is_not_presented(self):
        """A chain carrying an expired certificate is refused by every peer, so
        returning it is not a degraded answer — it is a wrong one."""
        store, _root, member, cert = _member_store(ttl=10 * DAY)
        member_id = NodeID.from_public_key(member.dsa_public_key)
        assert len(store.get_chain_to_root(member_id)) == 2
        cert.expires_at = int(time.time()) - 1
        store._chains.clear()          # as a restart or any store change would
        chain = store.get_chain_to_root(member_id)
        assert chain is not None and len(chain) == 1
        assert chain[0].is_self_signed   # fell back to our own root, as designed

    def test_the_cache_does_not_outlive_the_chain_it_holds(self):
        """The one way a memoised chain rots with nothing changing: a
        certificate in it expiring. Nothing cleared the cache for that, so the
        node would serve a chain every peer refuses until something else
        happened to touch the store."""
        store, _root, member, cert = _member_store(ttl=10 * DAY)
        member_id = NodeID.from_public_key(member.dsa_public_key)
        assert len(store.get_chain_to_root(member_id)) == 2   # memoised now
        later = cert.expires_at + 1
        assert len(store.get_chain_to_root(member_id, now=later)) == 1
        # …and asking about another moment must not poison the cache for this one
        assert len(store.get_chain_to_root(member_id)) == 2

    def test_a_renewal_takes_over_from_the_certificate_it_replaces(self):
        """Both are valid, so walking insertion order kept presenting the old
        one until the day it died: the renewal changed nothing an operator
        could see and the countdown never moved."""
        store, root, member, old = _member_store(ttl=5 * DAY)
        member_id = NodeID.from_public_key(member.dsa_public_key)
        fresh = root.issue_cert(member_id, member.dsa_public_key,
                                ttl_seconds=365 * DAY)
        store.add(fresh)
        assert store.get_chain_to_root(member_id)[0].signature == fresh.signature
        assert store.chain_expires_at(member_id) == fresh.expires_at
        assert fresh.expires_at > old.expires_at

    def test_verify_chain_still_refuses_an_expired_chain(self):
        store, root, member, cert = _member_store(ttl=10 * DAY)
        root_id = NodeID.from_public_key(root.dsa_public_key)
        chain = [cert, root.self_signed_cert()]
        assert store.verify_chain(chain) == root_id
        cert.expires_at = int(time.time()) - 1
        assert store.verify_chain(chain) is None


# ---------------------------------------------------------------------------
# The exchange
# ---------------------------------------------------------------------------

async def _member_node(ttl: int):
    """A started node holding a membership issued by a separate root, with the
    root reachable over its one link — a renewal is routed to its issuer, so a
    node with nowhere to send it proves nothing."""
    node, fake = await make_node()
    root, root_id = _identity_and_id()
    cert = root.issue_cert(node._id, node._identity.dsa_public_key,
                           ttl_seconds=ttl)
    node._cert_store.add(root.self_signed_cert())
    node._cert_store.add_root(root_id)
    node._cert_store.add(cert)
    _link(node, root_id, root.dsa_public_key)
    return node, fake, root, root_id, cert


class TestAskingForRenewal:
    async def test_a_membership_running_out_is_renewed(self):
        node, fake, _root, root_id, _cert = await _member_node(ttl=5 * DAY)
        try:
            assert await node._renew_own_membership() is True
            sent = [p for p in fake.sent if p.type == CERT_RENEW]
            assert len(sent) == 1
            assert NodeID(sent[0].dst_id) == root_id
        finally:
            await node.stop()

    async def test_a_membership_with_a_year_left_is_left_alone(self):
        node, fake, _root, _root_id, _cert = await _member_node(ttl=365 * DAY)
        try:
            assert await node._renew_own_membership() is False
            assert not [p for p in fake.sent if p.type == CERT_RENEW]
        finally:
            await node.stop()

    async def test_a_node_that_is_only_its_own_root_asks_nobody(self):
        """Nothing issued it anything, so there is nothing to renew and no
        issuer to ask — not an error, and not a packet either."""
        node, fake = await make_node()
        try:
            assert await node._renew_own_membership() is False
            assert not [p for p in fake.sent if p.type == CERT_RENEW]
        finally:
            await node.stop()


class TestServingRenewal:
    async def _issuer_with_member(self, ttl: int):
        """A node acting as issuer, plus a member it certified."""
        issuer, fake = await make_node()
        member, member_id = _identity_and_id()
        cert = issuer._identity.issue_cert(member_id, member.dsa_public_key,
                                           ttl_seconds=ttl)
        issuer._cert_store.add(cert)
        _link(issuer, member_id, member.dsa_public_key)
        return issuer, fake, member, member_id, cert

    async def test_the_issuer_re_signs_the_same_binding(self):
        issuer, fake, member, member_id, cert = await self._issuer_with_member(
            ttl=5 * DAY)
        try:
            await issuer._handle_cert_renew(
                issuer._peers[0],
                Packet.create(CERT_RENEW, member_id.raw, issuer._id.raw,
                              cert.serialize()))
            replies = [p for p in fake.sent if p.type == CERT_RENEWED]
            assert len(replies) == 1
            fresh = Certificate.deserialize(replies[0].payload)
            assert fresh.subject_id == member_id
            assert fresh.subject_pub == member.dsa_public_key
            assert fresh.issuer_id == issuer._id
            assert fresh.expires_at > cert.expires_at
        finally:
            await issuer.stop()

    async def test_a_certificate_we_did_not_sign_is_not_ours_to_renew(self):
        issuer, fake, _member, _member_id, _cert = await self._issuer_with_member(
            ttl=5 * DAY)
        stranger, _stranger_id = _identity_and_id()
        other, other_id = _identity_and_id()
        foreign = stranger.issue_cert(other_id, other.dsa_public_key,
                                      ttl_seconds=5 * DAY)
        try:
            await issuer._handle_cert_renew(
                issuer._peers[0],
                Packet.create(CERT_RENEW, other_id.raw, issuer._id.raw,
                              foreign.serialize()))
            assert not [p for p in fake.sent if p.type == CERT_RENEWED]
        finally:
            await issuer.stop()

    async def test_only_the_subject_may_ask_for_its_own(self):
        issuer, fake, _member, _member_id, cert = await self._issuer_with_member(
            ttl=5 * DAY)
        try:
            await issuer._handle_cert_renew(
                issuer._peers[0],
                Packet.create(CERT_RENEW, NodeID.generate().raw,
                              issuer._id.raw, cert.serialize()))
            assert not [p for p in fake.sent if p.type == CERT_RENEWED]
        finally:
            await issuer.stop()

    async def test_an_expired_membership_is_not_readmitted(self):
        """Expiry is how a node that left stops being a member. Re-signing one
        would be a readmission with no human anywhere in it."""
        issuer, fake, _member, member_id, cert = await self._issuer_with_member(
            ttl=5 * DAY)
        cert.expires_at = int(time.time()) - 1
        try:
            await issuer._handle_cert_renew(
                issuer._peers[0],
                Packet.create(CERT_RENEW, member_id.raw, issuer._id.raw,
                              cert.serialize()))
            assert not [p for p in fake.sent if p.type == CERT_RENEWED]
        finally:
            await issuer.stop()

    async def test_a_membership_nowhere_near_expiry_is_not_re_signed(self):
        issuer, fake, _member, member_id, cert = await self._issuer_with_member(
            ttl=_CERT_RENEW_ACCEPT + 30 * DAY)
        try:
            await issuer._handle_cert_renew(
                issuer._peers[0],
                Packet.create(CERT_RENEW, member_id.raw, issuer._id.raw,
                              cert.serialize()))
            assert not [p for p in fake.sent if p.type == CERT_RENEWED]
        finally:
            await issuer.stop()

    async def test_the_second_ask_in_an_hour_is_refused(self):
        """One signature per subject per hour: reconnecting must not buy a
        fresh allowance, which is the hole the invite lockout once had."""
        issuer, fake, _member, member_id, cert = await self._issuer_with_member(
            ttl=5 * DAY)
        packet = Packet.create(CERT_RENEW, member_id.raw, issuer._id.raw,
                               cert.serialize())
        try:
            await issuer._handle_cert_renew(issuer._peers[0], packet)
            await issuer._handle_cert_renew(issuer._peers[0], packet)
            assert len([p for p in fake.sent if p.type == CERT_RENEWED]) == 1
        finally:
            await issuer.stop()

    async def test_a_malformed_payload_is_dropped_in_silence(self):
        issuer, fake, _member, member_id, _cert = await self._issuer_with_member(
            ttl=5 * DAY)
        try:
            for payload in (b"", b"\x00" * 40, b"\xff" * 9000):
                await issuer._handle_cert_renew(
                    issuer._peers[0],
                    Packet.create(CERT_RENEW, member_id.raw, issuer._id.raw,
                                  payload))
            assert not [p for p in fake.sent if p.type == CERT_RENEWED]
            assert issuer._peers[0]._malformed == 0   # the relay is not charged
        finally:
            await issuer.stop()


class TestAbsorbingTheAnswer:
    async def test_a_renewal_pushes_our_expiry_out(self):
        node, _fake, root, root_id, cert = await _member_node(ttl=5 * DAY)
        was = node._cert_store.chain_expires_at(node._id)
        fresh = root.issue_cert(node._id, node._identity.dsa_public_key,
                                ttl_seconds=365 * DAY)
        try:
            await node._handle_cert_renewed(
                node._peers[0],
                Packet.create(CERT_RENEWED, root_id.raw, node._id.raw,
                              fresh.serialize()))
            assert node._cert_store.chain_expires_at(node._id) > was
        finally:
            await node.stop()

    async def test_a_certificate_for_somebody_else_is_ignored(self):
        node, _fake, root, root_id, _cert = await _member_node(ttl=5 * DAY)
        other, other_id = _identity_and_id()
        theirs = root.issue_cert(other_id, other.dsa_public_key,
                                 ttl_seconds=365 * DAY)
        try:
            await node._handle_cert_renewed(
                node._peers[0],
                Packet.create(CERT_RENEWED, root_id.raw, node._id.raw,
                              theirs.serialize()))
            assert node._cert_store.certs_for(other_id) == []
        finally:
            await node.stop()

    async def test_an_issuer_that_never_certified_us_is_not_renewing(self):
        """It authenticates nothing — it anchors on a root we do not trust —
        but absorbing it would let any node fill our own bounded slot list."""
        node, _fake, _root, _root_id, _cert = await _member_node(ttl=5 * DAY)
        stranger, stranger_id = _identity_and_id()
        unsolicited = stranger.issue_cert(node._id,
                                          node._identity.dsa_public_key,
                                          ttl_seconds=365 * DAY)
        held = len(node._cert_store.certs_for(node._id))
        try:
            await node._handle_cert_renewed(
                node._peers[0],
                Packet.create(CERT_RENEWED, stranger_id.raw, node._id.raw,
                              unsolicited.serialize()))
            assert len(node._cert_store.certs_for(node._id)) == held
        finally:
            await node.stop()

    async def test_a_certificate_whose_sender_is_not_its_issuer_is_ignored(self):
        node, _fake, root, _root_id, _cert = await _member_node(ttl=5 * DAY)
        fresh = root.issue_cert(node._id, node._identity.dsa_public_key,
                                ttl_seconds=365 * DAY)
        held = len(node._cert_store.certs_for(node._id))
        try:
            await node._handle_cert_renewed(
                node._peers[0],
                Packet.create(CERT_RENEWED, NodeID.generate().raw,
                              node._id.raw, fresh.serialize()))
            assert len(node._cert_store.certs_for(node._id)) == held
        finally:
            await node.stop()


class TestTrustStatus:
    async def test_it_reports_the_countdown_a_node_can_still_act_on(self):
        node, _fake, _root, root_id, cert = await _member_node(ttl=5 * DAY)
        try:
            status = node.trust_status()
            assert status["chain_length"] == 2
            assert status["self_rooted"] is False
            assert status["anchor"] == root_id.raw.hex()
            assert status["issuer"] == root_id.raw.hex()
            assert status["expires_at"] == cert.expires_at
            assert 0 < status["seconds_left"] <= 5 * DAY
            assert status["renewing"] is True
        finally:
            await node.stop()

    async def test_a_self_rooted_node_says_so(self):
        node, _fake = await make_node()
        try:
            status = node.trust_status()
            assert status["self_rooted"] is True
            assert status["expires_at"] == 0
            assert status["renewing"] is False
        finally:
            await node.stop()
