import pytest
from src.trust import TrustTable
from src.node_id import NodeID


class TestAdd:
    def test_first_contact_accepted(self):
        tt = TrustTable()
        nid = NodeID.generate()
        assert tt.add(nid, b"pubkey_a") is True

    def test_same_key_accepted(self):
        tt = TrustTable()
        nid = NodeID.generate()
        tt.add(nid, b"pubkey_a")
        assert tt.add(nid, b"pubkey_a") is True

    def test_changed_key_rejected(self):
        tt = TrustTable()
        nid = NodeID.generate()
        tt.add(nid, b"pubkey_a")
        assert tt.add(nid, b"pubkey_b") is False

    def test_different_nodes_independent(self):
        tt = TrustTable()
        nid1, nid2 = NodeID.generate(), NodeID.generate()
        tt.add(nid1, b"key_1")
        tt.add(nid2, b"key_2")
        assert tt.add(nid1, b"key_1") is True
        assert tt.add(nid2, b"key_2") is True


class TestContains:
    def test_unknown_node(self):
        assert not TrustTable().contains(NodeID.generate())

    def test_known_node(self):
        tt = TrustTable()
        nid = NodeID.generate()
        tt.add(nid, b"pubkey")
        assert tt.contains(nid)


class TestGetKey:
    def test_returns_none_for_unknown(self):
        assert TrustTable().get_key(NodeID.generate()) is None

    def test_returns_stored_key(self):
        tt = TrustTable()
        nid = NodeID.generate()
        tt.add(nid, b"pubkey")
        assert tt.get_key(nid) == b"pubkey"


class TestRemove:
    def test_remove_known_node(self):
        tt = TrustTable()
        nid = NodeID.generate()
        tt.add(nid, b"pubkey")
        tt.remove(nid)
        assert not tt.contains(nid)

    def test_remove_unknown_node_no_error(self):
        tt = TrustTable()
        tt.remove(NodeID.generate())

    def test_removed_node_can_be_readded(self):
        tt = TrustTable()
        nid = NodeID.generate()
        tt.add(nid, b"pubkey_a")
        tt.remove(nid)
        assert tt.add(nid, b"pubkey_b") is True


class TestLen:
    def test_empty(self):
        assert len(TrustTable()) == 0

    def test_grows_with_adds(self):
        tt = TrustTable()
        for _ in range(5):
            tt.add(NodeID.generate(), b"key")
        assert len(tt) == 5

    def test_same_node_does_not_grow(self):
        tt = TrustTable()
        nid = NodeID.generate()
        tt.add(nid, b"key")
        tt.add(nid, b"key")
        assert len(tt) == 1
