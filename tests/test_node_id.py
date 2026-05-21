import pytest
from src.node_id import NodeID


class TestGeneration:
    def test_generate_is_20_bytes(self):
        assert len(NodeID.generate().raw) == 20

    def test_generate_is_unique(self):
        assert NodeID.generate() != NodeID.generate()

    def test_from_hex_roundtrip(self):
        n = NodeID.generate()
        assert NodeID.from_hex(n.raw.hex()) == n

    def test_invalid_size_raises(self):
        with pytest.raises(ValueError):
            NodeID(b"\x00" * 19)

    def test_from_hex_invalid_size_raises(self):
        with pytest.raises(ValueError):
            NodeID.from_hex("aabb")


class TestDistance:
    def test_distance_to_self_is_zero(self):
        n = NodeID.generate()
        assert n.distance(n) == 0

    def test_distance_is_symmetric(self):
        a = NodeID.generate()
        b = NodeID.generate()
        assert a.distance(b) == b.distance(a)

    def test_distance_known_value(self):
        a = NodeID(b"\x00" * 20)
        b = NodeID(b"\xff" * 20)
        assert a.distance(b) == (1 << 160) - 1

    def test_closer_node(self):
        origin = NodeID(b"\x00" * 20)
        close  = NodeID(b"\x00" * 19 + b"\x01")
        far    = NodeID(b"\xff" * 20)
        assert origin.distance(close) < origin.distance(far)


class TestEquality:
    def test_equal(self):
        raw = b"\xab" * 20
        assert NodeID(raw) == NodeID(raw)

    def test_not_equal(self):
        assert NodeID(b"\x00" * 20) != NodeID(b"\xff" * 20)

    def test_hashable(self):
        n = NodeID.generate()
        d = {n: "value"}
        assert d[n] == "value"

    def test_usable_in_set(self):
        a = NodeID(b"\x00" * 20)
        assert len({a, a}) == 1
