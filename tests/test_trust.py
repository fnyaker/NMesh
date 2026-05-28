"""Tests de CertStore — remplace les anciens tests TrustTable."""
import pytest
from src.cert_store import CertStore
from src.crypto import CryptoIdentity
from src.node_id import NodeID


def _make_identity():
    return CryptoIdentity()


class TestCertStoreBasics:
    def test_own_id_is_root(self):
        identity = _make_identity()
        own_id = NodeID.from_public_key(identity.dsa_public_key)
        store = CertStore(own_id)
        assert store.is_root(own_id)

    def test_add_self_signed_cert(self):
        identity = _make_identity()
        own_id = NodeID.from_public_key(identity.dsa_public_key)
        store = CertStore(own_id)
        cert = identity.self_signed_cert()
        assert store.add(cert)

    def test_add_cert_deduplication(self):
        identity = _make_identity()
        own_id = NodeID.from_public_key(identity.dsa_public_key)
        store = CertStore(own_id)
        cert = identity.self_signed_cert()
        store.add(cert)
        assert store.add(cert)  # second add is idempotent

    def test_add_root(self):
        identity = _make_identity()
        own_id = NodeID.from_public_key(identity.dsa_public_key)
        store = CertStore(own_id)
        other_id = NodeID.generate()
        assert not store.is_root(other_id)
        store.add_root(other_id)
        assert store.is_root(other_id)

    def test_chain_to_root_returns_self_signed(self):
        identity = _make_identity()
        own_id = NodeID.from_public_key(identity.dsa_public_key)
        store = CertStore(own_id)
        cert = identity.self_signed_cert()
        store.add(cert)
        chain = store.get_chain_to_root(own_id)
        assert chain is not None
        assert len(chain) == 1
        assert chain[0].is_self_signed

    def test_chain_to_root_issued_cert(self):
        root = _make_identity()
        root_id = NodeID.from_public_key(root.dsa_public_key)
        peer = _make_identity()
        peer_id = NodeID.from_public_key(peer.dsa_public_key)

        store = CertStore(root_id)
        store.add(root.self_signed_cert())
        cert_peer = root.issue_cert(peer_id, peer.dsa_public_key)
        store.add(cert_peer)

        chain = store.get_chain_to_root(peer_id)
        assert chain is not None
        assert chain[0].subject_id == peer_id
        assert chain[-1].is_self_signed
        assert chain[-1].subject_id == root_id

    def test_chain_to_unknown_node_returns_none(self):
        identity = _make_identity()
        own_id = NodeID.from_public_key(identity.dsa_public_key)
        store = CertStore(own_id)
        assert store.get_chain_to_root(NodeID.generate()) is None

    def test_verify_chain_valid(self):
        root = _make_identity()
        root_id = NodeID.from_public_key(root.dsa_public_key)
        peer = _make_identity()
        peer_id = NodeID.from_public_key(peer.dsa_public_key)

        store = CertStore(root_id)
        store.add(root.self_signed_cert())
        cert_peer = root.issue_cert(peer_id, peer.dsa_public_key)
        store.add(cert_peer)

        chain = store.get_chain_to_root(peer_id)
        assert store.verify_chain(chain) == root_id

    def test_verify_chain_empty_returns_none(self):
        identity = _make_identity()
        own_id = NodeID.from_public_key(identity.dsa_public_key)
        store = CertStore(own_id)
        assert store.verify_chain([]) is None

    def test_verify_chain_wrong_root_returns_none(self):
        root = _make_identity()
        root_id = NodeID.from_public_key(root.dsa_public_key)
        peer = _make_identity()
        peer_id = NodeID.from_public_key(peer.dsa_public_key)

        # Build a valid chain but store with DIFFERENT root
        other_root_id = NodeID.from_public_key(_make_identity().dsa_public_key)
        store = CertStore(other_root_id)

        cert_peer = root.issue_cert(peer_id, peer.dsa_public_key)
        root_self  = root.self_signed_cert()
        chain = [cert_peer, root_self]
        # root_id is not in store's roots
        assert store.verify_chain(chain) is None
