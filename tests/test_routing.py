import pytest
from src.routing import KBucket, RoutingTable, NodeEntry
from src.node_id import NodeID
from src.crypto import CryptoIdentity


def make_id(byte: int) -> NodeID:
    return NodeID(bytes([byte]) + b"\x00" * 19)


class TestKBucket:
    def test_add_single(self):
        b = KBucket()
        entry = NodeEntry(make_id(1), ["addr1"])
        result = b.add(entry)
        assert result is None
        assert len(b) == 1

    def test_add_updates_existing(self):
        b = KBucket()
        n = make_id(1)
        b.add(NodeEntry(n, ["addr1"]))
        b.add(NodeEntry(n, ["addr2"]))
        assert len(b) == 1
        assert b.get(n).addresses == ["addr2"]

    def test_updated_node_moves_to_end(self):
        b = KBucket()
        n1 = make_id(1)
        n2 = make_id(2)
        b.add(NodeEntry(n1, ["addr1"]))
        b.add(NodeEntry(n2, ["addr2"]))
        b.add(NodeEntry(n1, ["addr1_updated"]))
        assert b.entries[-1].node_id == n1

    def test_full_bucket_returns_oldest(self):
        b = KBucket()
        for i in range(KBucket.K):
            b.add(NodeEntry(make_id(i), [f"addr{i}"]))
        oldest = b.oldest
        candidate = b.add(NodeEntry(make_id(100), ["new"]))
        assert candidate == oldest

    def test_evict_oldest(self):
        b = KBucket()
        for i in range(KBucket.K):
            b.add(NodeEntry(make_id(i), [f"addr{i}"]))
        new_entry = NodeEntry(make_id(200), ["new"])
        b.evict_oldest(new_entry)
        assert len(b) == KBucket.K
        assert b.entries[-1] == new_entry

    def test_remove(self):
        b = KBucket()
        n = make_id(1)
        b.add(NodeEntry(n, ["addr"]))
        b.remove(n)
        assert len(b) == 0

    def test_oldest_empty_bucket(self):
        assert KBucket().oldest is None


class TestRoutingTable:
    def setup_method(self):
        self.own = NodeID(b"\x00" * 20)
        self.rt = RoutingTable(self.own)

    def test_add_self_ignored(self):
        self.rt.add(self.own, ["self"])
        assert self.rt.get_closest(self.own) == []

    def test_add_empty_addresses_creates_addressless_entry(self):
        """Empty-address add is allowed (used at handshake to store dsa_pub before PING)."""
        n = make_id(1)
        dsa = b"\xab" * 32
        self.rt.add(n, [], dsa_pub=dsa)
        entry = self.rt.get(n)
        assert entry is not None
        assert entry.addresses == []
        assert entry.dsa_pub == dsa

    def test_add_and_find(self):
        n = make_id(1)
        self.rt.add(n, ["addr1"])
        closest = self.rt.get_closest(n, 1)
        assert closest[0].node_id == n

    def test_add_stores_multiple_addresses(self):
        n = make_id(1)
        self.rt.add(n, ["tcp://a:1", "ble://aa"])
        assert self.rt.get(n).addresses == ["tcp://a:1", "ble://aa"]

    def test_addresses_are_newest_first_and_bounded(self):
        n = make_id(1)
        self.rt.add(n, [f"tcp://old-{i}:1" for i in range(8)])
        self.rt.add(n, ["tcp://fresh:1", "tcp://old-7:1"])
        entry = self.rt.get(n)
        assert entry.addresses[0] == "tcp://fresh:1"
        assert len(entry.addresses) == 8

    def test_remove(self):
        n = make_id(1)
        self.rt.add(n, ["addr1"])
        self.rt.remove(n)
        assert self.rt.get_closest(n) == []

    def test_get_closest_sorted_by_distance(self):
        nodes = [make_id(i) for i in range(1, 6)]
        for n in nodes:
            self.rt.add(n, [f"addr{n.raw[0]}"])
        target = make_id(3)
        closest = self.rt.get_closest(target, 3)
        distances = [target.distance(e.node_id) for e in closest]
        assert distances == sorted(distances)

    def test_get_closest_count_respected(self):
        for i in range(1, 10):
            self.rt.add(make_id(i), [f"addr{i}"])
        assert len(self.rt.get_closest(make_id(1), 3)) == 3

    def test_evict_and_add(self):
        for i in range(KBucket.K):
            self.rt.add(NodeID(bytes([0x80 | i]) + b"\x00" * 19), [f"addr{i}"])
        new_id = NodeID(bytes([0xff]) + b"\x00" * 19)
        self.rt.evict_and_add(new_id, ["new_addr"])
        closest = self.rt.get_closest(new_id)
        assert any(e.node_id == new_id for e in closest)

    def test_last_seen_tracks_recency(self):
        # Entries carry a last_seen timestamp; sorting by it gives the most
        # recently added/refreshed nodes first (drives the console's list).
        a, b, c = make_id(1), make_id(2), make_id(3)
        self.rt.add(a, [])
        self.rt.add(b, [])
        self.rt.add(c, [])
        newest_first = sorted(self.rt.all_entries(),
                              key=lambda e: e.last_seen, reverse=True)
        assert [e.node_id for e in newest_first] == [c, b, a]
        # Refreshing an existing node bumps it to the front.
        self.rt.add(a, ["addr"])
        newest_first = sorted(self.rt.all_entries(),
                              key=lambda e: e.last_seen, reverse=True)
        assert newest_first[0].node_id == a


class TestExportImport:
    def test_roundtrip(self):
        rt = RoutingTable(make_id(0))
        first = CryptoIdentity()
        second = CryptoIdentity()
        first_id = NodeID.from_public_key(first.dsa_public_key)
        second_id = NodeID.from_public_key(second.dsa_public_key)
        rt.add(first_id, ["tcp://a:1"], first.dsa_public_key)
        rt.add(second_id, ["tcp://b:2", "spool:///x"], second.dsa_public_key)
        rt.add(make_id(3), ["tcp://c:3"])  # no dsa_pub → not exportable

        exported = rt.export_entries()
        assert len(exported) == 2  # entry 3 skipped (no key to re-auth with)

        rt2 = RoutingTable(make_id(0))
        rt2.import_entries(exported)
        assert rt2.get(first_id).addresses == ["tcp://a:1"]
        assert rt2.get(second_id).dsa_pub == second.dsa_public_key
        assert rt2.get(make_id(3)) is None

    def test_import_rejects_unbound_key_and_invalid_addresses(self):
        rt = RoutingTable(make_id(0))
        identity = CryptoIdentity()
        node_id = NodeID.from_public_key(identity.dsa_public_key)
        rt.import_entries([{
            "id": node_id.raw.hex(),
            "dsa_pub": CryptoIdentity().dsa_public_key.hex(),
            "addresses": ["tcp://valid:1"],
        }, {
            "id": node_id.raw.hex(),
            "dsa_pub": identity.dsa_public_key.hex(),
            "addresses": ["not a uri", "tcp://valid:1"],
        }])
        assert rt.get(node_id).addresses == ["tcp://valid:1"]

    def test_import_ignores_garbage(self):
        rt = RoutingTable(make_id(0))
        rt.import_entries("not a list")
        rt.import_entries([{"id": "zz"}, {"bad": 1}, 42, {"id": "00", "dsa_pub": "gg"}])
        assert rt.all_entries() == []
