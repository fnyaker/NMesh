"""
Tests des classes Certificate et CertStore (plan section 8).
"""
import asyncio
import os
import tempfile
import time
import pytest
from src.cert import Certificate, _CERT_HEADER
from src.cert_store import CertStore
from src.crypto import CryptoIdentity
from src.node_id import NodeID
from src.node import (MeshNode, HANDSHAKE, HANDSHAKE_ACK, FOUND_NODE,
                      _encode_handshake, _decode_handshake_ack,
                      _encode_entries, _decode_entries)
from src.packet import Packet
from src.routing import NodeEntry
from tests.conftest import FakeTransport, make_manager, make_node


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_identity():
    return CryptoIdentity()


def make_store_with_self(identity: CryptoIdentity) -> CertStore:
    own_id = NodeID.from_public_key(identity.dsa_public_key)
    store = CertStore(own_id)
    store.add(identity.self_signed_cert())
    return store


# ---------------------------------------------------------------------------
# test_cert_self_signed_valid
# ---------------------------------------------------------------------------

class TestCertSelfSigned:
    def test_self_signed_cert_serialises(self):
        identity = make_identity()
        cert = identity.self_signed_cert()
        data = cert.serialize()
        restored = Certificate.deserialize(data)
        own_id = NodeID.from_public_key(identity.dsa_public_key)
        assert restored.subject_id == own_id
        assert restored.issuer_id == own_id
        assert restored.is_self_signed

    def test_self_signed_cert_verifies(self):
        identity = make_identity()
        cert = identity.self_signed_cert()
        store = make_store_with_self(identity)
        own_id = NodeID.from_public_key(identity.dsa_public_key)
        store.add_root(own_id)
        assert store.verify_chain([cert]) is not None

    def test_issued_cert_verifies(self):
        issuer = make_identity()
        subject = make_identity()
        issuer_id = NodeID.from_public_key(issuer.dsa_public_key)
        subject_id = NodeID.from_public_key(subject.dsa_public_key)
        cert = issuer.issue_cert(subject_id, subject.dsa_public_key)
        assert cert.subject_id == subject_id
        assert cert.issuer_id == issuer_id
        assert not cert.is_self_signed


# ---------------------------------------------------------------------------
# test_cert_store
# ---------------------------------------------------------------------------

class TestCertStore:
    def test_add_and_verify(self):
        issuer = make_identity()
        subject = make_identity()
        issuer_id = NodeID.from_public_key(issuer.dsa_public_key)
        subject_id = NodeID.from_public_key(subject.dsa_public_key)

        store = CertStore(subject_id)
        issuer_self = issuer.self_signed_cert()
        store.add(issuer_self)
        store.add_root(issuer_id)

        cert = issuer.issue_cert(subject_id, subject.dsa_public_key)
        store.add(cert)

        chain = [cert, issuer_self]
        anchor = store.verify_chain(chain)
        assert anchor is not None

    def test_unknown_root_rejected(self):
        own = make_identity()
        own_id = NodeID.from_public_key(own.dsa_public_key)
        stranger = make_identity()
        stranger_id = NodeID.from_public_key(stranger.dsa_public_key)
        stranger_cert = stranger.self_signed_cert()
        store = CertStore(own_id)
        store.add(stranger_cert)
        # stranger_id is not in roots → chain unverifiable
        assert store.verify_chain([stranger_cert]) is None

    def test_cert_expiry(self):
        identity = make_identity()
        own_id = NodeID.from_public_key(identity.dsa_public_key)
        cert = identity.self_signed_cert()
        store = CertStore(own_id)
        store.add(cert)
        store.add_root(own_id)
        # Manually expire
        cert.expires_at = int(time.time()) - 1
        assert store.verify_chain([cert]) is None

    def test_persist_and_reload(self):
        identity = make_identity()
        own_id = NodeID.from_public_key(identity.dsa_public_key)

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "store.db")
            store = CertStore(own_id)
            cert = identity.self_signed_cert()
            store.add(cert)
            store.add_root(own_id)
            store.save(path)

            store2 = CertStore.load(path, own_id)
            assert store2.verify_chain([cert]) is not None

    def test_trusting_a_root_survives_a_restart(self):
        """A root pinned from the console must still be one after a restart.

        `console_add_root` marked the store dirty *before* pinning, so on the
        path that writes inline the file went out without the root and the
        dirty flag was already cleared. Nothing errored: the operator was told
        the certificate was trusted, and the next start had never heard of it."""
        stranger = make_identity()
        stranger_id = NodeID.from_public_key(stranger.dsa_public_key)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "certs.json")
            node = MeshNode(transport_manager=make_manager(),
                            cert_store_path=path)
            assert node.console_add_root(
                stranger.self_signed_cert().serialize().hex())
            reloaded = CertStore.load(path, node._id)
            assert reloaded.is_root(stranger_id)


# ---------------------------------------------------------------------------
# test_node_handshake_cert_integration
# ---------------------------------------------------------------------------

class TestNodeHandshakeCertIntegration:
    async def test_handshake_without_invite_requires_chain(self):
        """Handshake with no invite_accepted and no cert chain → rejected."""
        node_a, fake_a = await make_node()
        node_b, fake_b = await make_node()

        import os
        challenge = os.urandom(32)
        node_b._peers[0].pending_challenge = challenge
        node_a._peers[0].received_challenge = challenge
        # node_b.invite_accepted stays False → chain required

        await node_a.initiate_handshake(node_a._peers[0])
        fake_b.inject(fake_a.sent[0])
        await asyncio.sleep(0.1)
        b_peer = node_b._peers[0] if node_b._peers else None
        await node_a.stop()
        await node_b.stop()
        assert b_peer is None or b_peer.authenticated_id is None

    async def test_handshake_with_invite_accepted_issues_cert(self):
        """Post-invite handshake: server issues cert, client stores it."""
        node_a, fake_a = await make_node()
        node_b, fake_b = await make_node()

        import os
        challenge = os.urandom(32)
        node_b._peers[0].pending_challenge = challenge
        node_a._peers[0].received_challenge = challenge
        node_b._peers[0].invite_accepted = True

        await node_a.initiate_handshake(node_a._peers[0])
        fake_b.inject(fake_a.sent[0])
        await asyncio.sleep(0.1)
        ack = next(p for p in fake_b.sent if p.type == HANDSHAKE_ACK)
        fake_a.inject(ack)
        await asyncio.sleep(0.1)
        await node_a.stop()
        await node_b.stop()
        assert any(p.type == HANDSHAKE_ACK for p in fake_b.sent)


# ---------------------------------------------------------------------------
# test_found_node_with_invalid_chain_dropped
# ---------------------------------------------------------------------------

class TestFoundNodeChainValidation:
    async def test_invalid_chain_entry_dropped(self):
        """FOUND_NODE with an unverifiable chain → the entry is ignored."""
        node, fake = await make_node()
        sender_id = NodeID.generate()
        node._peers[0].authenticated_id = sender_id

        stranger = CryptoIdentity()
        stranger_id = NodeID.from_public_key(stranger.dsa_public_key)
        victim = CryptoIdentity()
        victim_id = NodeID.from_public_key(victim.dsa_public_key)
        cert = stranger.issue_cert(victim_id, victim.dsa_public_key)
        self_s = stranger.self_signed_cert()
        chain = [cert, self_s]

        entry = NodeEntry(victim_id, ["tcp://127.0.0.1:9099"], victim.dsa_public_key, chain)

        node._pending_finds[b"\x00" * 8] = asyncio.get_running_loop().create_future()
        pkt = Packet.create(FOUND_NODE, sender_id.raw, node.id.raw,
                            b"\x00" * 8 + _encode_entries([entry]))
        fake.inject(pkt)
        await asyncio.sleep(0.1)
        await node.stop()
        assert node._routing.get(victim_id) is None

    async def test_valid_chain_entry_accepted(self):
        """FOUND_NODE with a valid chain → the entry is added to routing."""
        node, fake = await make_node()
        sender_id = NodeID.generate()
        node._peers[0].authenticated_id = sender_id

        victim = CryptoIdentity()
        victim_id = NodeID.from_public_key(victim.dsa_public_key)
        cert = node._identity.issue_cert(victim_id, victim.dsa_public_key)
        self_node = node._identity.self_signed_cert()
        chain = [cert, self_node]

        entry = NodeEntry(victim_id, ["tcp://127.0.0.1:9100"], victim.dsa_public_key, chain)

        node._pending_finds[b"\x00" * 8] = asyncio.get_running_loop().create_future()
        pkt = Packet.create(FOUND_NODE, sender_id.raw, node.id.raw,
                            b"\x00" * 8 + _encode_entries([entry]))
        fake.inject(pkt)
        await asyncio.sleep(0.1)
        await node.stop()
        assert node._routing.get(victim_id) is not None


class TestStoreBounds:
    """Certificates arrive from the network — three handlers absorb them — and
    one is ~7 kB. `get_chain_to_root` is a BFS over the store and
    `_handle_find_node` runs it once per candidate, so an unbounded store made
    a 28-byte packet buy an unbounded graph walk."""

    def test_subjects_are_bounded(self):
        root = CryptoIdentity()
        store = CertStore(NodeID.from_public_key(root.dsa_public_key),
                          max_subjects=8)
        for _ in range(64):
            subject = CryptoIdentity()
            store.add(root.issue_cert(
                NodeID.from_public_key(subject.dsa_public_key),
                subject.dsa_public_key))
        assert len(store._certs) <= 8

    def test_certificates_per_subject_are_bounded(self):
        subject = CryptoIdentity()
        subject_id = NodeID.from_public_key(subject.dsa_public_key)
        store = CertStore(subject_id, max_per_subject=3)
        for _ in range(20):
            issuer = CryptoIdentity()
            store.add(issuer.issue_cert(subject_id, subject.dsa_public_key))
        assert len(store._certs[subject_id.raw]) <= 3

    def test_a_root_is_never_evicted(self):
        """Losing a root means every chain anchored there stops verifying — a
        bound that can do that is an outage, not a bound."""
        me, anchor = CryptoIdentity(), CryptoIdentity()
        anchor_id = NodeID.from_public_key(anchor.dsa_public_key)
        store = CertStore(NodeID.from_public_key(me.dsa_public_key),
                          max_subjects=4)
        store.add(anchor.self_signed_cert())
        store.add_root(anchor_id)
        for _ in range(50):
            subject = CryptoIdentity()
            store.add(anchor.issue_cert(
                NodeID.from_public_key(subject.dsa_public_key),
                subject.dsa_public_key))
        assert anchor_id.raw in store._certs

    def test_the_chain_cache_follows_the_graph(self):
        """A memoised chain that outlived its graph is a chain that no longer
        verifies."""
        root, subject = CryptoIdentity(), CryptoIdentity()
        root_id = NodeID.from_public_key(root.dsa_public_key)
        subject_id = NodeID.from_public_key(subject.dsa_public_key)
        store = CertStore(root_id)
        store.add(root.self_signed_cert())
        assert store.get_chain_to_root(subject_id) is None      # cached None
        store.add(root.issue_cert(subject_id, subject.dsa_public_key))
        chain = store.get_chain_to_root(subject_id)
        assert chain and store.verify_chain(chain) == root_id


class TestTheBoundNeverCostsUsOurOwnChain:
    """A store full of strangers must not cost us the certificates that prove
    who we are.

    The bound evicts the subject nobody has mentioned for longest, and pinned
    the roots and ourselves. It did not pin what joins the two: the issuer that
    invited us, and its issuer, and so on up. Evict one of those and the chain
    we present stops short of a root — every peer refuses it, in silence,
    because a chain that does not reach a trusted anchor is exactly what a
    forged one looks like. Nothing errors; the node simply stops being able to
    connect to anything, for good."""

    def _fleet(self, depth: int):
        """A chain `depth` issuers long: root invites A, A invites B, …"""
        root = CryptoIdentity()
        root_id = NodeID.from_public_key(root.dsa_public_key)
        certs = [root.issue_cert(root_id, root.dsa_public_key)]
        issuer, issuer_id = root, root_id
        line = [root_id]
        for _ in range(depth):
            member = CryptoIdentity()
            member_id = NodeID.from_public_key(member.dsa_public_key)
            certs.append(issuer.issue_cert(member_id, member.dsa_public_key))
            issuer, issuer_id = member, member_id
            line.append(member_id)
        return root_id, line, certs, issuer

    def _fill(self, store, count):
        """Certificates for `count` strangers, each its own self-signed root."""
        for _ in range(count):
            stranger = CryptoIdentity()
            sid = NodeID.from_public_key(stranger.dsa_public_key)
            store.add(stranger.issue_cert(sid, stranger.dsa_public_key))

    def test_an_intermediate_is_never_evicted(self):
        root_id, line, certs, _issuer = self._fleet(2)
        own_id = line[-1]
        store = CertStore(own_id, max_subjects=6)
        store.add_root(root_id)
        store.add_all(certs)
        assert store.get_chain_to_root(own_id) is not None
        self._fill(store, 20)          # far past the bound
        chain = store.get_chain_to_root(own_id)
        assert chain is not None
        assert chain[-1].subject_id == root_id

    def test_the_chain_still_verifies_after_the_store_fills(self):
        """The only test that matters to a peer: it has to accept what we send."""
        root_id, line, certs, _issuer = self._fleet(2)
        own_id = line[-1]
        store = CertStore(own_id, max_subjects=6)
        store.add_root(root_id)
        store.add_all(certs)
        self._fill(store, 20)
        far_end = CertStore(NodeID(b"\x09" * 20))
        far_end.add_root(root_id)
        assert far_end.verify_chain(store.get_chain_to_root(own_id)) == root_id

    def test_a_strangers_certificates_are_still_evicted(self):
        """Pinning what we need must not turn the bound off."""
        root_id, line, certs, _issuer = self._fleet(1)
        store = CertStore(line[-1], max_subjects=4)
        store.add_root(root_id)
        store.add_all(certs)
        self._fill(store, 30)
        assert len(store._certs) <= 4

    def test_our_own_certificate_survives_a_run_of_new_ones(self):
        """Re-joining issues a fresh certificate for us each time. The per-
        subject bound must drop one of those, never the one in use."""
        root_id, line, certs, issuer = self._fleet(1)
        own_id = line[-1]
        store = CertStore(own_id, max_per_subject=3)
        store.add_root(root_id)
        store.add_all(certs)
        in_use = store.get_chain_to_root(own_id)[0]
        for _ in range(10):
            spare = CryptoIdentity()
            store.add(spare.issue_cert(own_id, certs[-1].subject_pub))
        assert in_use.signature in {c.signature for c in store._certs[own_id.raw]}
        assert len(store._certs[own_id.raw]) <= 3
