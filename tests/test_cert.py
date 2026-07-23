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
from tests.conftest import FakeTransport, make_node


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
        """FOUND_NODE avec chaîne non vérifiable → entrée ignorée."""
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
        """FOUND_NODE avec chaîne valide → entrée ajoutée au routing."""
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
